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
	for _, protocol := range []string{protocolHysteria2, protocolVLESS, protocolShadowsocks, protocolTUIC, protocolTrojan} {
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
	for _, protocol := range []string{protocolHysteria2, protocolVLESS, protocolShadowsocks, protocolTUIC, protocolTrojan} {
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
			payload, err := buildConfig(request, 44321, credentials, "/tmp/node.cer", "/tmp/node.key", "1.13.14")
			if err != nil {
				t.Fatal(err)
			}
			var root map[string]any
			if err = json.Unmarshal(payload, &root); err != nil {
				t.Fatal(err)
			}
			inbound := root["inbounds"].([]any)[0].(map[string]any)
			if inbound["type"] != protocol || int(inbound["listen_port"].(float64)) != 44321 {
				t.Fatalf("wrong inbound: %#v", inbound)
			}
			switch protocol {
			case protocolVLESS:
				tlsConfig := inbound["tls"].(map[string]any)
				reality := tlsConfig["reality"].(map[string]any)
				if tlsConfig["server_name"] != realityDefaultSNI || reality["private_key"] != credentials.RealityPrivateKey || inbound["users"].([]any)[0].(map[string]any)["flow"] != "xtls-rprx-vision" {
					t.Fatal("VLESS REALITY fields missing")
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
	for index, protocol := range []string{protocolHysteria2, protocolVLESS, protocolShadowsocks, protocolTUIC, protocolTrojan} {
		node := model.Node{Name: "测试节点", Protocol: protocol, Server: "node.example.com", Domain: "node.example.com", ListenPort: 45080 + index}
		credentials, err := generateProtocolCredentials(protocol, "")
		if err != nil {
			t.Fatal(err)
		}
		share, err := buildShareURI(node, credentials, false)
		if err != nil {
			t.Fatal(err)
		}
		parsed, err := url.Parse(share)
		if err != nil || parsed.Scheme == "" || parsed.Hostname() != node.Server || parsed.Port() == "" {
			t.Fatalf("invalid %s share URI: %s (%v)", protocol, share, err)
		}
		if protocol == protocolVLESS && (parsed.Query().Get("security") != "reality" || parsed.Query().Get("pbk") != credentials.RealityPublicKey) {
			t.Fatalf("VLESS REALITY share fields missing: %s", share)
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
	for index, protocol := range []string{protocolHysteria2, protocolVLESS, protocolShadowsocks, protocolTUIC, protocolTrojan} {
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

func TestScanDiscoversEverySupportedProtocol(t *testing.T) {
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
	if err := os.WriteFile(filepath.Join(dir, "five-protocols.json"), payload, 0o600); err != nil {
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
		if !seen[protocol] {
			t.Fatalf("scanner missed %s", protocol)
		}
	}
}
