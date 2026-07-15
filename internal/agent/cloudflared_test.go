package agent

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCloudflaredPinnedAssets(t *testing.T) {
	for _, architecture := range []string{"amd64", "arm64"} {
		asset, err := cloudflaredAsset(architecture)
		if err != nil {
			t.Fatal(err)
		}
		if !strings.HasPrefix(asset.Name, "cloudflared-linux-") || len(asset.SHA256) != 64 {
			t.Fatalf("invalid pinned asset for %s: %#v", architecture, asset)
		}
	}
	if _, err := cloudflaredAsset("386"); err == nil {
		t.Fatal("unsupported cloudflared architecture accepted")
	}
}

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
