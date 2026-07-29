package agent

import (
	"context"
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/singboxconfig"
	"github.com/252201/wukong-panel/internal/store"
)

func newSOCKSTestManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	database, err := store.Open(filepath.Join(dir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	vault, err := security.OpenVault(filepath.Join(dir, "secrets"))
	if err != nil {
		t.Fatal(err)
	}
	manager := NewManager(config.Config{
		DataDir:   dir,
		SecretDir: filepath.Join(dir, "secrets"),
		ConfigDir: filepath.Join(dir, "configs"),
		Demo:      true,
	}, database, vault)
	return manager, database
}

func TestConfigureSOCKSExitEncryptsPasswordAndPreservesIt(t *testing.T) {
	manager, _ := newSOCKSTestManager(t)
	request := model.SOCKSExitRequest{
		Server: "proxy.example.com", Port: 1080, Version: "5",
		Username: "wukong", Password: "not-plaintext-on-disk", Network: "both",
		ExpectedExitIP: "203.0.113.18",
	}
	result, err := manager.ConfigureSOCKSExit(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.Configured || !result.HasPassword || result.ProbeExitIP == "" {
		t.Fatalf("unexpected SOCKS result: %#v", result)
	}
	data, err := os.ReadFile(manager.socksStatePath())
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(data), request.Password) {
		t.Fatal("SOCKS password was stored in plaintext")
	}
	if mode := fileMode(t, manager.socksStatePath()); mode != 0o600 {
		t.Fatalf("unexpected SOCKS state mode: %o", mode)
	}
	request.Password = ""
	result, err = manager.ConfigureSOCKSExit(t.Context(), request)
	if err != nil {
		t.Fatal(err)
	}
	if !result.HasPassword {
		t.Fatal("blank update did not preserve the existing password")
	}
	attached, err := manager.attachSOCKSOutbound(model.NodeCreateRequest{Egress: "socks"})
	if err != nil {
		t.Fatal(err)
	}
	if attached.SOCKSOutbound == nil || attached.SOCKSOutbound.Password != "not-plaintext-on-disk" {
		t.Fatal("encrypted SOCKS password was not restored for config generation")
	}
}

func TestBuildSOCKSConfigIsFailClosed(t *testing.T) {
	request := model.NodeCreateRequest{
		Egress: "socks",
		SOCKSOutbound: &model.SOCKSOutbound{
			Server: "2001:db8::10", Port: 1080, Version: "5",
			Username: "user", Password: "secret", Network: "both",
		},
	}
	payload, err := buildConfigWithInbounds(request, []any{map[string]any{
		"type": "shadowsocks", "tag": "in", "listen": "::", "listen_port": 45080,
		"method": "2022-blake3-aes-128-gcm", "password": "inbound-secret",
	}}, "1.13.14")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	outbounds := root["outbounds"].([]any)
	if len(outbounds) != 1 {
		t.Fatalf("SOCKS config unexpectedly contains fallback outbounds: %#v", outbounds)
	}
	outbound := outbounds[0].(map[string]any)
	if outbound["type"] != "socks" || outbound["server"] != "2001:db8::10" || outbound["password"] != "secret" {
		t.Fatalf("unexpected SOCKS outbound: %#v", outbound)
	}
	route := root["route"].(map[string]any)
	if route["final"] != "out-socks" {
		t.Fatalf("SOCKS route can fall back: %#v", route)
	}
}

func TestSOCKSExitValidationAndReferenceProtection(t *testing.T) {
	manager, database := newSOCKSTestManager(t)
	if _, err := normalizeSOCKSExitRequest(model.SOCKSExitRequest{Server: "https://proxy.example.com", Port: 1080, Version: "5", Network: "both"}); err == nil {
		t.Fatal("SOCKS URL was accepted as a server")
	}
	if _, err := normalizeSOCKSExitRequest(model.SOCKSExitRequest{Server: "proxy.example.com", Port: 1080, Version: "4a", Password: "bad", Network: "tcp"}); err == nil {
		t.Fatal("SOCKS4a password was accepted")
	}
	if _, err := normalizeSOCKSExitRequest(model.SOCKSExitRequest{Server: "2001:db8::10", Port: 1080, Version: "5", Network: "both"}); err != nil {
		t.Fatalf("IPv6 SOCKS server was rejected: %v", err)
	}
	initial := model.SOCKSExitRequest{Server: "proxy.example.com", Port: 1080, Version: "5", Network: "both"}
	if _, err := manager.ConfigureSOCKSExit(t.Context(), initial); err != nil {
		t.Fatal(err)
	}
	node := model.Node{
		ID: "socks-node", Name: "SOCKS node", Protocol: "shadowsocks", Mode: "v4only", Egress: "socks",
		ListenPort: 45080, Server: "node.example.com", ServiceName: "sing-box-test", ServiceManager: "systemd",
		ConfigPath: "/etc/s-box/test.json", ConfigVersion: "1.13.14", Ownership: "managed", Status: "active",
	}
	if err := database.UpsertNode(context.Background(), node, "cipher"); err != nil {
		t.Fatal(err)
	}
	changed := initial
	changed.Port = 1081
	if _, err := manager.ConfigureSOCKSExit(t.Context(), changed); err == nil {
		t.Fatal("in-use SOCKS configuration was changed")
	}
	if err := manager.RemoveSOCKSExit(t.Context(), "REMOVE"); err == nil {
		t.Fatal("in-use SOCKS configuration was removed")
	}
	if err := database.DeleteNode(node.ID); err != nil {
		t.Fatal(err)
	}
	if err := manager.RemoveSOCKSExit(t.Context(), "REMOVE"); err != nil {
		t.Fatal(err)
	}
}

func TestBuildSOCKSOutboundVersionFields(t *testing.T) {
	outbound, dns := buildSOCKSOutbound(model.SOCKSOutbound{
		Server: "proxy.example.com", Port: 1080, Version: "4a", Username: "user", Network: "tcp",
	}, singboxconfig.CapabilitiesFor("1.13.14"))
	if outbound["network"] != "tcp" || outbound["username"] != "user" || outbound["password"] != nil {
		t.Fatalf("unexpected SOCKS4a outbound: %#v", outbound)
	}
	if outbound["domain_resolver"] == nil || dns == nil {
		t.Fatalf("modern DNS resolver missing: outbound=%#v dns=%#v", outbound, dns)
	}
}

func fileMode(t *testing.T, path string) os.FileMode {
	t.Helper()
	info, err := os.Stat(path)
	if err != nil {
		t.Fatal(err)
	}
	return info.Mode().Perm()
}
