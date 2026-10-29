package agent

import (
	"bytes"
	"context"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/componentupdate"
	"github.com/252201/wukong-panel/internal/model"
)

func TestSingBoxUpdatePreparationMigratesWithoutTouchingLiveFiles(t *testing.T) {
	m, db := newDemoManager(t)
	os.MkdirAll(m.cfg.ConfigDir, 0700)
	path := filepath.Join(m.cfg.ConfigDir, "node.json")
	original := []byte(`{"inbounds":[{"type":"socks","listen":"127.0.0.1","listen_port":19239,"sniff":true}],"outbounds":[{"type":"direct"}]}`)
	os.WriteFile(path, original, 0600)
	n := model.Node{ID: "one", Ownership: "managed", ConfigPath: path, ServiceName: "sing-box-wukong-one", ServiceManager: "systemd", Protocol: "socks5"}
	if e := db.UpsertNode(t.Context(), n, ""); e != nil {
		t.Fatal(e)
	}
	binary := filepath.Join(t.TempDir(), "candidate")
	// The candidate rejects any configuration which still contains a legacy field.
	os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = check ]; then ! grep -q '\"sniff\":' \"$3\"; else exit 1; fi\n"), 0755)
	files, e := m.prepareSingBoxUpdate(t.Context(), binary, "1.14.2")
	if e != nil || len(files) != 1 {
		t.Fatal(files, e)
	}
	if !bytes.Equal(files[0].Old, original) || bytes.Contains(files[0].New, []byte(`"sniff":`)) {
		t.Fatal("migration snapshot wrong")
	}
	live, _ := os.ReadFile(path)
	if !bytes.Equal(live, original) {
		t.Fatal("preparation changed live files")
	}
	os.WriteFile(binary, []byte("#!/bin/sh\nexit 1\n"), 0755)
	if _, e = m.prepareSingBoxUpdate(t.Context(), binary, "1.14.2"); e == nil {
		t.Fatal("candidate rejection was ignored")
	}
	os.WriteFile(filepath.Join(m.cfg.ConfigDir, "external.json"), []byte(`{}`), 0600)
	if _, e = m.ownedSingBoxConfigs(context.Background()); e == nil {
		t.Fatal("unmanaged config accepted")
	}
	os.Remove(filepath.Join(m.cfg.ConfigDir, "external.json"))
	os.Remove(path)
	os.Symlink(binary, path)
	if _, e = m.ownedSingBoxConfigs(t.Context()); e == nil {
		t.Fatal("symlink accepted")
	}
}
func TestSingBoxSupportedTargetProfile(t *testing.T) {
	m, _ := newDemoManager(t)
	c := m.singBoxUpdater()
	for _, v := range []string{"1.14.1", "1.14.2", "1.14.99"} {
		if !c.AllowedTarget(v) {
			t.Fatal("supported patch blocked", v)
		}
	}
	for _, v := range []string{"1.15.0", "2.0.0", "1.13.14", "1.14.2-beta"} {
		if c.AllowedTarget(v) {
			t.Fatal("unsupported profile allowed", v)
		}
	}
}

func TestSingBoxRecoverySkipsAlreadyStoppedOpenRCService(t *testing.T) {
	m, _ := newDemoManager(t)
	m.cfg.Demo = false
	dir := t.TempDir()
	marker := filepath.Join(dir, "stop-called")
	script := "#!/bin/sh\nif [ \"$2\" = status ]; then exit 1; fi\nprintf called > " + marker + "\nexit 1\n"
	if e := os.WriteFile(filepath.Join(dir, "rc-service"), []byte(script), 0755); e != nil {
		t.Fatal(e)
	}
	t.Setenv("PATH", dir+string(os.PathListSeparator)+os.Getenv("PATH"))
	if e := m.singBoxUpdater().Stop(t.Context(), componentupdate.Service{Name: "sing-box-wukong-test", Manager: "openrc"}); e != nil {
		t.Fatal(e)
	}
	if _, e := os.Stat(marker); !os.IsNotExist(e) {
		t.Fatal("inactive service was stopped again")
	}
}

func TestReconcileSingBoxUpdatePeriodicCheck(t *testing.T) {
	m, _ := newDemoManager(t)

	// Demo mode returns nil without performing check
	if err := m.reconcileSingBoxUpdate(t.Context()); err != nil {
		t.Fatal(err)
	}

	m.cfg.Demo = false
	// Not installed returns nil without performing check
	if err := m.reconcileSingBoxUpdate(t.Context()); err != nil {
		t.Fatal(err)
	}

	// Set up dummy sing-box binary
	binDir := t.TempDir()
	binPath := filepath.Join(binDir, "sing-box")
	if err := os.WriteFile(binPath, []byte("#!/bin/sh\nif [ \"$1\" = \"version\" ]; then echo \"sing-box version 1.14.4\"; else exit 0; fi\n"), 0755); err != nil {
		t.Fatal(err)
	}
	m.cfg.SingBoxBin = binPath

	// Pre-create state.json with recent CheckedAt (e.g. 1 hour ago)
	secretsDir := m.cfg.SecretDir
	updateDir := filepath.Join(secretsDir, "sing-box-update")
	_ = os.MkdirAll(updateDir, 0700)
	recentState := []byte(`{"checkedAt":"` + time.Now().Add(-1*time.Hour).Format(time.RFC3339) + `","currentVersion":"1.14.4","installed":true}`)
	if err := os.WriteFile(filepath.Join(updateDir, "state.json"), recentState, 0600); err != nil {
		t.Fatal(err)
	}

	// Because CheckedAt is 1 hour ago (< 24h), reconcileSingBoxUpdate must skip check and return nil
	if err := m.reconcileSingBoxUpdate(t.Context()); err != nil {
		t.Fatal(err)
	}

	// When CheckedAt is 25 hours ago (> 24h), reconcileSingBoxUpdate attempts a check.
	// Since there is no internet in test, Check fails to download and audit records failure.
	staleState := []byte(`{"checkedAt":"` + time.Now().Add(-25*time.Hour).Format(time.RFC3339) + `","currentVersion":"1.14.4","installed":true}`)
	if err := os.WriteFile(filepath.Join(updateDir, "state.json"), staleState, 0600); err != nil {
		t.Fatal(err)
	}
	// Attempt check (network error expected in sandbox, but check WAS attempted)
	_ = m.reconcileSingBoxUpdate(t.Context())
	// Verify state.json was updated with a newer CheckedAt
	freshState, _ := os.ReadFile(filepath.Join(updateDir, "state.json"))
	if bytes.Contains(freshState, []byte(`"checkedAt":"`+time.Now().Add(-25*time.Hour).Format(time.RFC3339))) {
		t.Fatal("reconcileSingBoxUpdate did not attempt check when state was stale")
	}
}
