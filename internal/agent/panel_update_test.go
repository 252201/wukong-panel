package agent

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/store"
)

func TestPanelUpdateDemoMode(t *testing.T) {
	dataDir := t.TempDir()
	db, err := store.Open(filepath.Join(dataDir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	m := NewManager(config.Config{DataDir: dataDir, Demo: true}, db, nil)
	if err := m.PanelUpdate(context.Background(), "1.7.30"); err != nil {
		t.Fatalf("unexpected error in demo mode: %v", err)
	}
}

func TestPanelUpdateSuccessWithValidSHA256(t *testing.T) {
	dataDir := t.TempDir()
	db, err := store.Open(filepath.Join(dataDir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	arch := runtime.GOARCH
	assetName := fmt.Sprintf("wukong-panel-linux-%s", arch)

	// Create mock binary that outputs "wukong-panel 1.7.30\n" when executed with version
	mockBinaryContent := []byte("#!/bin/sh\necho 'wukong-panel 1.7.30'\n")
	hasher := sha256.New()
	hasher.Write(mockBinaryContent)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	sumsContent := fmt.Sprintf("%s  %s\n", expectedHash, assetName)

	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch filepath.Base(r.URL.Path) {
		case "SHA256SUMS":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sumsContent))
		case assetName:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mockBinaryContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("WUKONG_TEST_PANEL_DOWNLOAD_URL", server.URL)
	testDestBin := filepath.Join(dataDir, "bin", "wukong-panel")
	_ = os.MkdirAll(filepath.Dir(testDestBin), 0755)
	_ = os.WriteFile(testDestBin, []byte("#!/bin/sh\necho 'old version'\n"), 0755)
	t.Setenv("WUKONG_TEST_PANEL_BIN", testDestBin)
	t.Setenv("WUKONG_TEST_NO_RESTART", "1")

	m := NewManager(config.Config{DataDir: dataDir, Demo: false}, db, nil)
	if err := m.PanelUpdate(context.Background(), "1.7.30"); err != nil {
		t.Fatalf("panel update failed: %v", err)
	}

	// Verify new binary is installed
	newContent, err := os.ReadFile(testDestBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(newContent) != string(mockBinaryContent) {
		t.Fatalf("installed content mismatch, got %q", string(newContent))
	}

	// Verify backup was created
	backups, err := filepath.Glob(filepath.Join(dataDir, "backups", "update-*"))
	if err != nil || len(backups) == 0 {
		t.Fatalf("expected backup directory to be created, got %v", backups)
	}
	oldSaved, err := os.ReadFile(filepath.Join(backups[0], "wukong-panel"))
	if err != nil || !stringsContains(string(oldSaved), "old version") {
		t.Fatalf("expected backup to contain old binary, got %s", string(oldSaved))
	}
}

func TestPruneUpdateBackupsRetainsLatestThreeAndPreservesRollbackMarker(t *testing.T) {
	dataDir := t.TempDir()
	backupRoot := filepath.Join(dataDir, "backups")
	for _, ts := range []string{
		"20260901-000001",
		"20260901-000002",
		"20260901-000003",
		"20260901-000004",
		"20260901-000005",
	} {
		if err := os.MkdirAll(filepath.Join(backupRoot, "update-"+ts), 0700); err != nil {
			t.Fatal(err)
		}
	}
	// Mark the oldest backup as requiring rollback so it is never pruned
	if err := os.WriteFile(filepath.Join(backupRoot, "update-20260901-000001", ".rollback-required"), nil, 0600); err != nil {
		t.Fatal(err)
	}
	// Unrelated backup directory must not be touched
	if err := os.MkdirAll(filepath.Join(backupRoot, "sing-box"), 0700); err != nil {
		t.Fatal(err)
	}

	m := NewManager(config.Config{DataDir: dataDir, Demo: false}, nil, nil)
	m.PruneUpdateBackups(defaultUpdateBackupRetention)

	// 000001 preserved due to .rollback-required
	if _, err := os.Stat(filepath.Join(backupRoot, "update-20260901-000001")); err != nil {
		t.Fatalf("rollback-required backup was removed: %v", err)
	}
	// 000002 pruned
	if _, err := os.Stat(filepath.Join(backupRoot, "update-20260901-000002")); !os.IsNotExist(err) {
		t.Fatalf("expected oldest completed backup 000002 to be pruned, got err=%v", err)
	}
	// 000003, 000004, 000005 retained
	for _, ts := range []string{"20260901-000003", "20260901-000004", "20260901-000005"} {
		if _, err := os.Stat(filepath.Join(backupRoot, "update-"+ts)); err != nil {
			t.Fatalf("expected newest backup %s to be retained: %v", ts, err)
		}
	}
	// Unrelated directory preserved
	if _, err := os.Stat(filepath.Join(backupRoot, "sing-box")); err != nil {
		t.Fatalf("expected sing-box directory to be preserved: %v", err)
	}
}

func stringsContains(s, sub string) bool {
	return len(s) >= len(sub) && (s == sub || len(sub) == 0 || (len(s) > 0 && len(sub) > 0 && containsHelper(s, sub)))
}

func containsHelper(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestReplaceExecutable(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "src-bin")
	dst := filepath.Join(tempDir, "bin", "target-bin")

	if err := os.WriteFile(src, []byte("new-binary-content"), 0755); err != nil {
		t.Fatal(err)
	}

	// 1. Initial replace when dst does not exist yet
	if err := replaceExecutable(src, dst, 0755); err != nil {
		t.Fatalf("replaceExecutable on new file failed: %v", err)
	}
	content, err := os.ReadFile(dst)
	if err != nil || string(content) != "new-binary-content" {
		t.Fatalf("expected new-binary-content, got %s (err: %v)", string(content), err)
	}
	info, err := os.Stat(dst)
	if err != nil || info.Mode().Perm() != 0755 {
		t.Fatalf("expected mode 0755, got %v", info.Mode().Perm())
	}

	// 2. Overwrite existing target
	if err := os.WriteFile(src, []byte("updated-content-v2"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutable(src, dst, 0755); err != nil {
		t.Fatalf("replaceExecutable on existing file failed: %v", err)
	}
	content, err = os.ReadFile(dst)
	if err != nil || string(content) != "updated-content-v2" {
		t.Fatalf("expected updated-content-v2, got %s", string(content))
	}

	// 3. Symlink target resolves and replaces target file
	realTarget := filepath.Join(tempDir, "real-bin")
	if err := os.WriteFile(realTarget, []byte("real-target-v1"), 0755); err != nil {
		t.Fatal(err)
	}
	symlinkPath := filepath.Join(tempDir, "symlink-bin")
	if err := os.Symlink(realTarget, symlinkPath); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(src, []byte("symlink-updated-v3"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutable(src, symlinkPath, 0755); err != nil {
		t.Fatalf("replaceExecutable with symlink failed: %v", err)
	}
	content, err = os.ReadFile(realTarget)
	if err != nil || string(content) != "symlink-updated-v3" {
		t.Fatalf("expected real target to be updated, got %s", string(content))
	}
}
