package agent

import (
	"encoding/json"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/componentupdate"
	"github.com/252201/wukong-panel/internal/model"
)

func TestCloudflaredTokenFileVersionGate(t *testing.T) {
	for _, output := range []string{
		"cloudflared version 2025.4.0 (built 2025-04-08)",
		"cloudflared version 2026.7.1 (built 2026-07-09)",
	} {
		if !cloudflaredSupportsTokenFile(output) {
			t.Fatalf("supported cloudflared rejected: %s", output)
		}
	}
	for _, output := range []string{
		"cloudflared version 2025.3.1 (built 2025-03-20)",
		"cloudflared version unknown",
		"not cloudflared output",
	} {
		if cloudflaredSupportsTokenFile(output) {
			t.Fatalf("unsupported cloudflared accepted: %s", output)
		}
	}
}

func TestTunnelCredentialEnvelopeIsPrivateButComplete(t *testing.T) {
	token := "eyJ" + strings.Repeat("a", 90) + ".signature"
	encoded, err := encodeProtocolCredentials(protocolCredentials{
		UUID:          "d342d11e-d424-4583-b36e-524ab1f0afa4",
		WebSocketPath: "/wukong-test",
		TunnelToken:   token,
	})
	if err != nil {
		t.Fatal(err)
	}
	var decoded protocolCredentials
	if err = json.Unmarshal([]byte(encoded), &decoded); err != nil {
		t.Fatal(err)
	}
	if decoded.TunnelToken != token || decoded.WebSocketPath != "/wukong-test" || decoded.UUID == "" {
		t.Fatalf("incomplete tunnel credential envelope: %#v", decoded)
	}
}

func TestCloudflaredNodeKeySharesOnlyManagedDeviceGroups(t *testing.T) {
	managed := model.Node{ID: "device-one", Ownership: "managed", SharedGroup: "devices-group"}
	if got := cloudflaredNodeKey(managed); got != "devices-group" {
		t.Fatalf("managed device group did not share connector key: %q", got)
	}
	imported := model.Node{ID: "imported-one", Ownership: "imported", SharedGroup: "shared-config"}
	if got := cloudflaredNodeKey(imported); got != imported.ID {
		t.Fatalf("imported shared config unexpectedly changed connector key: %q", got)
	}
	individual := model.Node{ID: "single", Ownership: "managed"}
	if got := cloudflaredNodeKey(individual); got != individual.ID {
		t.Fatalf("individual node connector key changed: %q", got)
	}
}

func TestCloudflaredUpdateProgressWiresToStore(t *testing.T) {
	m, db := newDemoManager(t)
	m.cfg.Demo = false
	job, err := db.CreateJob("cloudflared.update", "local")
	if err != nil {
		t.Fatal(err)
	}

	ctx := componentupdate.WithProgress(t.Context(), func(progress int, message string) {
		_ = m.store.UpdateJob(job.ID, "running", progress, message, "")
	})

	c := componentupdate.New(t.TempDir(), filepath.Join(t.TempDir(), "cf"), "amd64")
	c.ReportProgress(ctx, 49, "正在下载 cloudflared (24.8 MB / 40.3 MB)…")

	updated, err := db.Job(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if updated.Progress != 49 || !strings.Contains(updated.Message, "24.8 MB / 40.3 MB") {
		t.Fatalf("job progress not recorded in store: %#v", updated)
	}
}
