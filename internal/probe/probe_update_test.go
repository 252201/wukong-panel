package probe

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestProbeUpdateExecution(t *testing.T) {
	arch := runtime.GOARCH
	assetName := fmt.Sprintf("wukong-probe-linux-%s", arch)

	mockBinaryContent := []byte("#!/bin/sh\necho '1.7.30'\n")
	hasher := sha256.New()
	hasher.Write(mockBinaryContent)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	sumsContent := fmt.Sprintf("%s  %s\n", expectedHash, assetName)

	var reportedResult model.FleetCommandResult
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/SHA256SUMS":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sumsContent))
		case r.URL.Path == "/"+assetName:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mockBinaryContent)
		case stringsContains(r.URL.Path, "/result"):
			_ = json.NewDecoder(r.Body).Decode(&reportedResult)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("WUKONG_TEST_PROBE_DOWNLOAD_URL", server.URL)
	tempDir := t.TempDir()
	testDestBin := filepath.Join(tempDir, "bin", "wukong-probe")
	_ = os.MkdirAll(filepath.Dir(testDestBin), 0755)
	_ = os.WriteFile(testDestBin, []byte("#!/bin/sh\necho '1.7.27'\n"), 0755)
	t.Setenv("WUKONG_TEST_PROBE_BIN", testDestBin)
	t.Setenv("WUKONG_TEST_NO_EXIT", "1")

	client := &Client{
		Config: Config{
			ControllerURL: server.URL + "/",
			HostID:        "test-host",
			HostName:      "test-probe",
		},
		Token: "test-token",
		HTTP:  server.Client(),
	}

	command := model.FleetCommand{
		ID:      "cmd-1",
		Kind:    "probe.update",
		Payload: json.RawMessage(`{"targetVersion":"1.7.30"}`),
	}

	client.handleProbeUpdate(context.Background(), command)

	if reportedResult.Status != "success" {
		t.Fatalf("expected command result success, got %s: %s", reportedResult.Status, reportedResult.Error)
	}

	installed, err := os.ReadFile(testDestBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != string(mockBinaryContent) {
		t.Fatalf("installed binary content mismatch, got %q", string(installed))
	}
}

func TestProbeUpdateWithRedirects(t *testing.T) {
	arch := runtime.GOARCH
	assetName := fmt.Sprintf("wukong-probe-linux-%s", arch)

	mockBinaryContent := []byte("#!/bin/sh\necho '1.7.30'\n")
	hasher := sha256.New()
	hasher.Write(mockBinaryContent)
	expectedHash := hex.EncodeToString(hasher.Sum(nil))

	sumsContent := fmt.Sprintf("%s  %s\n", expectedHash, assetName)

	var reportedResult model.FleetCommandResult
	server := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch {
		case r.URL.Path == "/SHA256SUMS":
			http.Redirect(w, r, "/cdn/SHA256SUMS", http.StatusFound)
		case r.URL.Path == "/cdn/SHA256SUMS":
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write([]byte(sumsContent))
		case r.URL.Path == "/"+assetName:
			http.Redirect(w, r, "/cdn/"+assetName, http.StatusFound)
		case r.URL.Path == "/cdn/"+assetName:
			w.WriteHeader(http.StatusOK)
			_, _ = w.Write(mockBinaryContent)
		case stringsContains(r.URL.Path, "/result"):
			_ = json.NewDecoder(r.Body).Decode(&reportedResult)
			w.WriteHeader(http.StatusNoContent)
		default:
			http.NotFound(w, r)
		}
	}))
	defer server.Close()

	t.Setenv("WUKONG_TEST_PROBE_DOWNLOAD_URL", server.URL)
	tempDir := t.TempDir()
	testDestBin := filepath.Join(tempDir, "bin", "wukong-probe")
	_ = os.MkdirAll(filepath.Dir(testDestBin), 0755)
	_ = os.WriteFile(testDestBin, []byte("#!/bin/sh\necho '1.7.27'\n"), 0755)
	t.Setenv("WUKONG_TEST_PROBE_BIN", testDestBin)
	t.Setenv("WUKONG_TEST_NO_EXIT", "1")

	client := &Client{
		Config: Config{
			ControllerURL: server.URL + "/",
			HostID:        "test-host",
			HostName:      "test-probe",
		},
		Token: "test-token",
		HTTP:  newHTTPClient(), // controller client strictly rejects redirects
	}

	command := model.FleetCommand{
		ID:      "cmd-redirect",
		Kind:    "probe.update",
		Payload: json.RawMessage(`{"targetVersion":"1.7.30"}`),
	}

	client.handleProbeUpdate(context.Background(), command)

	if reportedResult.Status != "success" {
		t.Fatalf("expected command result success with redirects, got %s: %s", reportedResult.Status, reportedResult.Error)
	}

	installed, err := os.ReadFile(testDestBin)
	if err != nil {
		t.Fatal(err)
	}
	if string(installed) != string(mockBinaryContent) {
		t.Fatalf("installed binary content mismatch, got %q", string(installed))
	}
}

func stringsContains(s, sub string) bool {
	for i := 0; i+len(sub) <= len(s); i++ {
		if s[i:i+len(sub)] == sub {
			return true
		}
	}
	return false
}

func TestProbeReplaceExecutable(t *testing.T) {
	tempDir := t.TempDir()
	src := filepath.Join(tempDir, "src-probe")
	dst := filepath.Join(tempDir, "bin", "wukong-probe")

	if err := os.WriteFile(src, []byte("new-probe-binary"), 0755); err != nil {
		t.Fatal(err)
	}
	if err := replaceExecutable(src, dst, 0755); err != nil {
		t.Fatalf("replaceExecutable failed: %v", err)
	}
	content, err := os.ReadFile(dst)
	if err != nil || string(content) != "new-probe-binary" {
		t.Fatalf("expected new-probe-binary, got %s (err: %v)", string(content), err)
	}
}
