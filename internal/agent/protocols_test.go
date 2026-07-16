package agent

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

func TestGenerateProtocolCredentials(t *testing.T) {
	for _, protocol := range []string{protocolHysteria2, protocolVLESS, protocolVLESSWSTunnel, protocolShadowsocks, protocolTUIC, protocolTrojan} {
		t.Run(protocol, func(t *testing.T) {
			credentials, err := generateProtocolCredentials(protocol, "")
			if err != nil {
				t.Fatal(err)
			}
			switch protocol {
			case protocolVLESS:
				if !validUUID(credentials.UUID) || credentials.RealityPrivateKey == "" || credentials.RealityPublicKey == "" || len(credentials.RealityShortID) != 16 {
					t.Fatalf("invalid VLESS credentials: %#v", credentials)
				}
				if realityPublicKey(credentials.RealityPrivateKey) != credentials.RealityPublicKey {
					t.Fatal("REALITY public key does not match generated private key")
				}
			case protocolVLESSWSTunnel:
				if !validUUID(credentials.UUID) || credentials.RealityPrivateKey != "" || credentials.Password != "" {
					t.Fatalf("invalid VLESS WebSocket credentials: %#v", credentials)
				}
			case protocolShadowsocks:
				key, decodeErr := base64.StdEncoding.DecodeString(credentials.Password)
				if decodeErr != nil || len(key) != 16 || credentials.Method != shadowsocks2022 {
					t.Fatalf("invalid Shadowsocks 2022 credentials: %#v", credentials)
				}
			case protocolTUIC:
				if !validUUID(credentials.UUID) || credentials.Password == "" {
					t.Fatalf("invalid TUIC credentials: %#v", credentials)
				}
			default:
				if credentials.Password == "" {
					t.Fatal("empty generated password")
				}
			}
		})
	}
}

func TestCredentialEnvelopeNeverStoresRealityPrivateKey(t *testing.T) {
	credentials, err := generateProtocolCredentials(protocolVLESS, "")
	if err != nil {
		t.Fatal(err)
	}
	encoded, err := encodeProtocolCredentials(credentials)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(encoded, credentials.RealityPrivateKey) || !strings.Contains(encoded, credentials.RealityPublicKey) {
		t.Fatalf("unsafe or incomplete credential envelope: %s", encoded)
	}
}

func TestRealityDefaultSNIIsCloudflare(t *testing.T) {
	if realityDefaultSNI != "www.cloudflare.com" {
		t.Fatalf("unexpected REALITY default SNI: %s", realityDefaultSNI)
	}
}

func TestBuildConfigForEverySupportedProtocol(t *testing.T) {
	for _, protocol := range []string{protocolHysteria2, protocolVLESS, protocolVLESSWSTunnel, protocolShadowsocks, protocolTUIC, protocolTrojan} {
		t.Run(protocol, func(t *testing.T) {
			request := baseRequest()
			request.Protocol = protocol
			request.Domain = "node.example.com"
			if protocol == protocolVLESS {
				request.Domain = realityDefaultSNI
			}
			credentials, err := generateProtocolCredentials(protocol, "")
			if err != nil {
				t.Fatal(err)
			}
			if protocol == protocolVLESSWSTunnel {
				credentials.WebSocketPath = "/wukong-test"
			}
			payload, err := buildConfig(request, 44321, credentials, "/tmp/node.cer", "/tmp/node.key", "1.13.14")
			if err != nil {
				t.Fatal(err)
			}
			var root map[string]any
			if err = json.Unmarshal(payload, &root); err != nil {
				t.Fatal(err)
			}
			inbound := root["inbounds"].([]any)[0].(map[string]any)
			wantType := protocol
			if protocol == protocolVLESSWSTunnel {
				wantType = protocolVLESS
			}
			if inbound["type"] != wantType || int(inbound["listen_port"].(float64)) != 44321 {
				t.Fatalf("wrong inbound: %#v", inbound)
			}
			switch protocol {
			case protocolVLESS:
				tlsConfig := inbound["tls"].(map[string]any)
				reality := tlsConfig["reality"].(map[string]any)
				if tlsConfig["server_name"] != realityDefaultSNI || reality["private_key"] != credentials.RealityPrivateKey || inbound["users"].([]any)[0].(map[string]any)["flow"] != "xtls-rprx-vision" {
					t.Fatal("VLESS REALITY fields missing")
				}
			case protocolVLESSWSTunnel:
				transport := inbound["transport"].(map[string]any)
				if inbound["listen"] != "127.0.0.1" || transport["type"] != "ws" || transport["path"] != "/wukong-test" || inbound["tls"] != nil {
					t.Fatalf("VLESS WebSocket origin fields are incorrect: %#v", inbound)
				}
			case protocolShadowsocks:
				if inbound["method"] != shadowsocks2022 || inbound["tls"] != nil {
					t.Fatal("Shadowsocks 2022 fields are incorrect")
				}
			case protocolTUIC:
				if inbound["congestion_control"] != "bbr" || inbound["zero_rtt_handshake"] != false {
					t.Fatal("TUIC safety defaults are incorrect")
				}
			case protocolTrojan:
				if inbound["tls"] == nil {
					t.Fatal("Trojan TLS is missing")
				}
			}
		})
	}
}

func TestShareURIForEverySupportedProtocol(t *testing.T) {
	for index, protocol := range []string{protocolHysteria2, protocolVLESS, protocolVLESSWSTunnel, protocolShadowsocks, protocolTUIC, protocolTrojan} {
		node := model.Node{Name: "测试节点", Protocol: protocol, Server: "node.example.com", Domain: "node.example.com", ListenPort: 45080 + index}
		credentials, err := generateProtocolCredentials(protocol, "")
		if err != nil {
			t.Fatal(err)
		}
		if protocol == protocolVLESSWSTunnel {
			credentials.WebSocketPath = "/wukong-test"
			node.PreferredServer = "preferred.example.com"
		}
		share, err := buildShareURI(node, credentials, false)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(share)
		wantServer := node.Server
		if node.PreferredServer != "" {
			wantServer = node.PreferredServer
		}
		if err != nil || parsed.Scheme == "" || parsed.Hostname() != wantServer || parsed.Port() == "" {
			t.Fatalf("invalid %s share URI: %s (%v)", protocol, share, err)
		}
		if protocol == protocolVLESS && (parsed.Query().Get("security") != "reality" || parsed.Query().Get("pbk") != credentials.RealityPublicKey) {
			t.Fatalf("VLESS REALITY share fields missing: %s", share)
		}
		if protocol == protocolVLESSWSTunnel && (parsed.Port() != "443" || parsed.Query().Get("security") != "tls" || parsed.Query().Get("type") != "ws" || parsed.Query().Get("path") != "/wukong-test" || parsed.Query().Get("sni") != node.Server || parsed.Query().Get("host") != node.Server) {
			t.Fatalf("VLESS WebSocket Tunnel share fields missing: %s", share)
		}
	}
}

func TestValidateCreateRequiresProtocolAddressing(t *testing.T) {
	request := baseRequest()
	request.Server = ""
	if validateCreate(request) == nil {
		t.Fatal("node without public server accepted")
	}
	request.Server = "node.example.com"
	request.Protocol = protocolTrojan
	request.Domain = ""
	if validateCreate(request) == nil {
		t.Fatal("certificate protocol without TLS domain accepted")
	}
}

func TestValidateCreateRequiresCloudflareTunnelInputs(t *testing.T) {
	request := baseRequest()
	request.Protocol = protocolVLESSWSTunnel
	request.Server = "edge.example.com"
	request.Domain = request.Server
	request.WebSocketPath = "/wukong-test"
	request.TunnelToken = "eyJ" + strings.Repeat("a", 90) + ".signature"
	if err := validateCreate(request); err != nil {
		t.Fatalf("valid Cloudflare Tunnel request rejected: %v", err)
	}
	request.TunnelToken = "short"
	if validateCreate(request) == nil {
		t.Fatal("short Tunnel token accepted")
	}
	request.TunnelToken = "eyJ" + strings.Repeat("a", 90) + "=="
	if err := validateCreate(request); err != nil {
		t.Fatalf("padded Tunnel token rejected: %v", err)
	}
	request.TunnelToken = "eyJ" + strings.Repeat("a+/", 30) + "=="
	if err := validateCreate(request); err != nil {
		t.Fatalf("standard Base64 Tunnel token rejected: %v", err)
	}
	request.TunnelToken = "eyJ" + strings.Repeat("a", 90) + ".signature"
	request.PreferredServer = "best.cloudflare.example"
	if err := validateCreate(request); err != nil {
		t.Fatalf("valid preferred endpoint rejected: %v", err)
	}
	request.PreferredServer = "104.16.0.1"
	if err := validateCreate(request); err != nil {
		t.Fatalf("preferred IP rejected: %v", err)
	}
	request.PreferredServer = "https://best.cloudflare.example"
	if validateCreate(request) == nil {
		t.Fatal("preferred endpoint URL accepted")
	}
	request.PreferredServer = "best.cloudflare.example:443"
	if validateCreate(request) == nil {
		t.Fatal("preferred endpoint with port accepted")
	}
	request.PreferredServer = ""
	request.WebSocketPath = "missing-leading-slash"
	if validateCreate(request) == nil {
		t.Fatal("invalid WebSocket path accepted")
	}
	request.WebSocketPath = "/valid"
	request.Server = "https://edge.example.com"
	if validateCreate(request) == nil {
		t.Fatal("URL accepted as a Tunnel hostname")
	}
}

func TestNormalizePreferredServer(t *testing.T) {
	if got := normalizePreferredServer(" BEST.Cloudflare.Example. "); got != "best.cloudflare.example" {
		t.Fatalf("hostname not normalized: %q", got)
	}
	if got := normalizePreferredServer("[2001:0db8::1]"); got != "2001:db8::1" {
		t.Fatalf("IPv6 not normalized: %q", got)
	}
}

func TestGeneratedConfigsPassRealSingBoxCheck(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BIN")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BIN to run sing-box integration checks")
	}
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "node.cer"), filepath.Join(dir, "node.key")
	if err := generateSelfSigned(keyPath, certPath, "node.example.com"); err != nil {
		t.Fatal(err)
	}
	for index, protocol := range []string{protocolHysteria2, protocolVLESS, protocolVLESSWSTunnel, protocolShadowsocks, protocolTUIC, protocolTrojan} {
		t.Run(protocol, func(t *testing.T) {
			request := baseRequest()
			request.Protocol = protocol
			request.Domain = "node.example.com"
			if protocol == protocolVLESS {
				request.Domain = realityDefaultSNI
			}
			credentials, err := generateProtocolCredentials(protocol, "")
			if err != nil {
				t.Fatal(err)
			}
			if protocol == protocolVLESSWSTunnel {
				credentials.WebSocketPath = "/wukong-test"
			}
			payload, err := buildConfig(request, 46000+index, credentials, certPath, keyPath, "1.13.14")
			if err != nil {
				t.Fatal(err)
			}
			configPath := filepath.Join(dir, protocol+".json")
			if err = os.WriteFile(configPath, payload, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, checkErr := exec.Command(binary, "check", "-c", configPath).CombinedOutput(); checkErr != nil {
				t.Fatalf("sing-box rejected generated %s config: %v\n%s\n%s", protocol, checkErr, output, payload)
			}
		})
	}
}

func TestScanDiscoversEveryImportableProtocolAndSkipsWebSocketTunnel(t *testing.T) {
	dir := t.TempDir()
	certPath, keyPath := filepath.Join(dir, "node.cer"), filepath.Join(dir, "node.key")
	if err := generateSelfSigned(keyPath, certPath, "node.example.com"); err != nil {
		t.Fatal(err)
	}
	inbounds := make([]any, 0, 5)
	for index, protocol := range []string{protocolHysteria2, protocolVLESS, protocolShadowsocks, protocolTUIC, protocolTrojan} {
		request := baseRequest()
		request.Protocol = protocol
		request.Name = protocol
		request.Domain = "node.example.com"
		if protocol == protocolVLESS {
			request.Domain = realityDefaultSNI
		}
		credentials, err := generateProtocolCredentials(protocol, "")
		if err != nil {
			t.Fatal(err)
		}
		inbound, err := buildProtocolInbound(request, 47000+index, credentials, certPath, keyPath)
		if err != nil {
			t.Fatal(err)
		}
		inbounds = append(inbounds, inbound)
	}
	payload, _ := json.Marshal(map[string]any{"inbounds": inbounds, "outbounds": []any{map[string]any{"type": "direct", "tag": "direct", "domain_resolver": map[string]any{"server": "local", "strategy": "prefer_ipv6"}}}})
	if err := os.WriteFile(filepath.Join(dir, "importable-protocols.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(dir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := NewManager(config.Config{ConfigDir: dir, Demo: true}, database, nil)
	candidates, err := manager.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 5 {
		t.Fatalf("expected five protocol candidates, got %#v", candidates)
	}
	seen := map[string]bool{}
	for _, candidate := range candidates {
		seen[candidate.Protocol] = true
		if candidate.Name == "in" || candidate.Secret == "" {
			t.Fatalf("candidate metadata is incomplete: %#v", candidate)
		}
	}
	for protocol := range supportedProtocols {
		if protocol == protocolVLESSWSTunnel {
			continue
		}
		if !seen[protocol] {
			t.Fatalf("scanner missed %s", protocol)
		}
	}
	wsCredentials, err := generateProtocolCredentials(protocolVLESSWSTunnel, "")
	if err != nil {
		t.Fatal(err)
	}
	wsCredentials.WebSocketPath = "/wukong-test"
	request := baseRequest()
	request.Protocol = protocolVLESSWSTunnel
	wsInbound, err := buildProtocolInbound(request, 47999, wsCredentials, "", "")
	if err != nil {
		t.Fatal(err)
	}
	payload, _ = json.Marshal(map[string]any{"inbounds": []any{wsInbound}})
	if err = os.WriteFile(filepath.Join(dir, "ws-without-tunnel-token.json"), payload, 0o600); err != nil {
		t.Fatal(err)
	}
	candidates, err = manager.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 5 {
		t.Fatalf("VLESS WebSocket inbound without Tunnel metadata was imported: %#v", candidates)
	}
}

func TestScanSkipsRegisteredManagedAndImportedInbounds(t *testing.T) {
	dir := t.TempDir()
	configPath := filepath.Join(dir, "shared.json")
	payload := []byte(`{
  "inbounds": [
    {"type":"hysteria2","tag":"hy2-managed-in","listen_port":47101,"users":[{"password":"managed-secret"}]},
    {"type":"hysteria2","tag":"hy2-imported-in","listen_port":47102,"users":[{"password":"imported-secret"}]},
    {"type":"hysteria2","tag":"hy2-external-in","listen_port":47103,"users":[{"password":"external-secret"}]}
  ]
}`)
	if err := os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(dir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	for _, node := range []model.Node{
		{ID: "managed", Name: "Managed", Protocol: protocolHysteria2, Mode: "prefer_v6", ListenPort: 47101, ConfigPath: configPath, ConfigVersion: "1.13.14", Ownership: "managed", Status: "active"},
		{ID: "imported", Name: "Imported", Protocol: protocolHysteria2, Mode: "prefer_v6", ListenPort: 47102, ConfigPath: filepath.Join(dir, ".", "shared.json"), ConfigVersion: "1.13.14", Ownership: "imported", Status: "active"},
	} {
		if err = database.UpsertNode(t.Context(), node, "encrypted"); err != nil {
			t.Fatal(err)
		}
	}

	manager := NewManager(config.Config{ConfigDir: dir, Demo: true}, database, nil)
	candidates, err := manager.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 1 || candidates[0].ListenPort != 47103 || candidates[0].Name != "external" {
		t.Fatalf("registered inbounds leaked into scan results: %#v", candidates)
	}
	if candidates[0].SharedGroup != configPath {
		t.Fatalf("unregistered shared inbound lost group metadata: %#v", candidates[0])
	}
}

func TestDeleteCandidateRemovesOnlySelectedSharedInbound(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	configPath := filepath.Join(dir, "shared.json")
	original := []byte(`{
  "inbounds": [
    {"type":"hysteria2","tag":"hy2-first-in","listen_port":47201,"users":[{"password":"first-secret"}]},
    {"type":"hysteria2","tag":"hy2-second-in","listen_port":47202,"users":[{"password":"second-secret"}]},
    {"type":"hysteria2","tag":"hy2-third-in","listen_port":47203,"users":[{"password":"third-secret"}]}
  ]
}`)
	if err := os.WriteFile(configPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(dir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := NewManager(config.Config{ConfigDir: dir, DataDir: dataDir, Demo: true}, database, nil)
	candidates, err := manager.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var target model.NodeCandidate
	for _, candidate := range candidates {
		if candidate.ListenPort == 47202 {
			target = candidate
		}
	}
	if target.Fingerprint == "" {
		t.Fatalf("shared deletion target missing: %#v", candidates)
	}
	if err = manager.DeleteCandidate(t.Context(), target.Fingerprint, "wrong-name"); err == nil || !strings.Contains(err.Error(), "confirmation") {
		t.Fatalf("candidate deletion accepted the wrong confirmation: %v", err)
	}
	if current, readErr := os.ReadFile(configPath); readErr != nil || string(current) != string(original) {
		t.Fatalf("wrong confirmation changed config: err=%v payload=%s", readErr, current)
	}
	if err = manager.DeleteCandidate(t.Context(), target.Fingerprint, target.Name); err != nil {
		t.Fatal(err)
	}
	current, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal(current, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("shared config has %d inbounds after deleting one: %s", len(inbounds), current)
	}
	for _, item := range inbounds {
		if int(numberValue(item.(map[string]any)["listen_port"])) == 47202 {
			t.Fatalf("deleted inbound remains in shared config: %s", current)
		}
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("shared config mode changed: mode=%v", info.Mode().Perm())
	}
	backups, err := filepath.Glob(filepath.Join(dataDir, "backups", "*-"+target.Fingerprint, "shared.json"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("candidate backup missing: backups=%v err=%v", backups, err)
	}
	candidates, err = manager.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if len(candidates) != 2 {
		t.Fatalf("deleted candidate was still discovered: %#v", candidates)
	}
}

func TestDeleteCandidateCheckFailurePreservesSharedConfig(t *testing.T) {
	dir := t.TempDir()
	dataDir := filepath.Join(dir, "data")
	configPath := filepath.Join(dir, "shared.json")
	original := []byte(`{
  "inbounds": [
    {"type":"hysteria2","tag":"hy2-keep-in","listen_port":47211,"users":[{"password":"keep-secret"}]},
    {"type":"hysteria2","tag":"hy2-delete-in","listen_port":47212,"users":[{"password":"delete-secret"}]}
  ]
}`)
	if err := os.WriteFile(configPath, original, 0o640); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(dir, "sing-box")
	if err := os.WriteFile(binary, []byte("#!/bin/sh\nif [ \"$1\" = version ]; then echo 'sing-box version 1.13.14'; exit 0; fi\necho 'invalid generated config' >&2\nexit 1\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	database, err := store.Open(filepath.Join(dir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	manager := NewManager(config.Config{ConfigDir: dir, DataDir: dataDir, SingBoxBin: binary}, database, nil)
	candidates, err := manager.Scan(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	var target model.NodeCandidate
	for _, candidate := range candidates {
		if candidate.ListenPort == 47212 {
			target = candidate
		}
	}
	if target.Fingerprint == "" {
		t.Fatalf("shared deletion target missing: %#v", candidates)
	}
	if err = manager.DeleteCandidate(t.Context(), target.Fingerprint, target.Name); err == nil || !strings.Contains(err.Error(), "configuration check failed") {
		t.Fatalf("candidate deletion ignored the failed config check: %v", err)
	}
	current, err := os.ReadFile(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if string(current) != string(original) {
		t.Fatalf("failed config check changed shared config:\n%s", current)
	}
	info, err := os.Stat(configPath)
	if err != nil {
		t.Fatal(err)
	}
	if info.Mode().Perm() != 0o640 {
		t.Fatalf("failed config check changed mode: %v", info.Mode().Perm())
	}
	backups, err := filepath.Glob(filepath.Join(dataDir, "backups", "*-"+target.Fingerprint, "shared.json"))
	if err != nil || len(backups) != 1 {
		t.Fatalf("failed deletion backup missing: backups=%v err=%v", backups, err)
	}
}

func TestDeleteCandidateRemovesLastConfigAndRefusesRegisteredNode(t *testing.T) {
	t.Run("last candidate", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "single.json")
		if err := os.WriteFile(configPath, []byte(`{"inbounds":[{"type":"hysteria2","tag":"hy2-single-in","listen_port":47301,"users":[{"password":"secret"}]}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		database, err := store.Open(filepath.Join(dir, "wukong.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		manager := NewManager(config.Config{ConfigDir: dir, DataDir: filepath.Join(dir, "data"), Demo: true}, database, nil)
		candidates, err := manager.Scan(t.Context())
		if err != nil || len(candidates) != 1 {
			t.Fatalf("single candidate scan failed: candidates=%#v err=%v", candidates, err)
		}
		if err = manager.DeleteCandidate(t.Context(), candidates[0].Fingerprint, candidates[0].Name); err != nil {
			t.Fatal(err)
		}
		if _, err = os.Stat(configPath); !os.IsNotExist(err) {
			t.Fatalf("last candidate config still exists: %v", err)
		}
	})

	t.Run("registered candidate", func(t *testing.T) {
		dir := t.TempDir()
		configPath := filepath.Join(dir, "managed.json")
		if err := os.WriteFile(configPath, []byte(`{"inbounds":[{"type":"hysteria2","tag":"hy2-managed-in","listen_port":47302,"users":[{"password":"secret"}]}]}`), 0o600); err != nil {
			t.Fatal(err)
		}
		database, err := store.Open(filepath.Join(dir, "wukong.db"))
		if err != nil {
			t.Fatal(err)
		}
		defer database.Close()
		node := model.Node{ID: "managed", Name: "Managed", Protocol: protocolHysteria2, Mode: "prefer_v6", ListenPort: 47302, ConfigPath: configPath, ConfigVersion: "1.13.14", Ownership: "managed", Status: "active"}
		if err = database.UpsertNode(t.Context(), node, "encrypted"); err != nil {
			t.Fatal(err)
		}
		manager := NewManager(config.Config{ConfigDir: dir, DataDir: filepath.Join(dir, "data"), Demo: true}, database, nil)
		id := fingerprint(configPath, 47302, "hy2-managed-in")
		if err = manager.DeleteCandidate(t.Context(), id, "managed"); err == nil || !strings.Contains(err.Error(), "already registered") {
			t.Fatalf("registered node was accepted for candidate deletion: %v", err)
		}
		if _, err = os.Stat(configPath); err != nil {
			t.Fatalf("registered node config was removed: %v", err)
		}
	})
}
