package agent

import (
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/config"
)

func TestTrustedFleetHTTPClientRejectsHTTPSDowngrade(t *testing.T) {
	client := NewTrustedFleetHTTPClient(time.Second)
	err := client.CheckRedirect(&http.Request{URL: &url.URL{Scheme: "http", Host: "controller.example"}}, nil)
	if err == nil {
		t.Fatal("insecure redirect was accepted")
	}
	if err = client.CheckRedirect(&http.Request{URL: &url.URL{Scheme: "https", Host: "controller.example"}}, nil); err != nil {
		t.Fatalf("trusted HTTPS redirect rejected: %v", err)
	}
}

func TestLoadFleetClientConfigRequiresTrustedHTTPS(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "fleet.json")
	tokenPath := filepath.Join(dir, "fleet.token")
	if err := os.WriteFile(tokenPath, []byte("secret\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(configPath, []byte(`{"controllerUrl":"http://controller.example/panel/","hostId":"host-a"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	cfg := config.Config{FleetConfigFile: configPath, FleetTokenFile: tokenPath}
	if _, _, err := LoadFleetClientConfig(cfg); err == nil {
		t.Fatal("plaintext controller URL was accepted")
	}
	if err := os.WriteFile(configPath, []byte(`{"controllerUrl":"https://controller.example/panel/","hostId":"host-a","hostName":"A"}`), 0o600); err != nil {
		t.Fatal(err)
	}
	client, token, err := LoadFleetClientConfig(cfg)
	if err != nil {
		t.Fatal(err)
	}
	if client.HostID != "host-a" || token != "secret" {
		t.Fatalf("client=%+v token=%q", client, token)
	}
}

func TestFleetEndpointMaskingNeverUploadsRawClientIP(t *testing.T) {
	for input, want := range map[string]string{"192.0.2.55:443": "192.***.***.55:443", "[2001:db8::55]:443": "[****:****]:443", "cloudflare-tunnel": "Cloudflare Tunnel", "invalid": "***"} {
		if got := maskFleetEndpoint(input); got != want {
			t.Fatalf("maskFleetEndpoint(%q)=%q want %q", input, got, want)
		}
	}
}
