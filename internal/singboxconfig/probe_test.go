package singboxconfig

import (
	"context"
	"crypto/ecdh"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"os"
	"os/exec"
	"path/filepath"
	"testing"
	"time"
)

func TestBuildHY2Probe(t *testing.T) {
	inbound := map[string]any{"type": "hysteria2", "listen": "::", "listen_port": float64(443), "users": []any{map[string]any{"password": "secret"}}}
	data, err := buildHY2Probe(inbound, "", "")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if json.Unmarshal(data, &root) != nil {
		t.Fatal("probe config is invalid JSON")
	}
	outbound := root["outbounds"].([]any)[0].(map[string]any)
	if outbound["server"] != "::1" || outbound["password"] != "secret" {
		t.Fatalf("unexpected probe outbound: %+v", outbound)
	}
}

func TestProbeConfigInboundSelectsNodeAndCapturesExitIP(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nodes.json")
	root := map[string]any{"inbounds": []any{
		map[string]any{"type": "hysteria2", "tag": "first", "listen": "::", "listen_port": 45115, "users": []any{map[string]any{"password": "first-secret"}}},
		map[string]any{"type": "hysteria2", "tag": "second", "listen": "::", "listen_port": 45116, "users": []any{map[string]any{"password": "second-secret"}}},
	}}
	data, err := json.Marshal(root)
	if err != nil {
		t.Fatal(err)
	}
	if err = os.WriteFile(configPath, data, 0o600); err != nil {
		t.Fatal(err)
	}
	binary := filepath.Join(t.TempDir(), "sing-box")
	if err = os.WriteFile(binary, []byte("#!/bin/sh\nprintf 'ip=203.0.113.9\\n'\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	ctx, cancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer cancel()
	result, err := ProbeConfigInbound(ctx, binary, configPath, "hysteria2", 45116)
	if err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.Inbound != "second" || result.Port != 45116 || result.ExitIP != "203.0.113.9" || result.Target != "www.cloudflare.com" || result.LatencyMS < 1 {
		t.Fatalf("unexpected node probe result: %#v", result)
	}
}

func TestProbeConfigInboundRejectsMissingEndpoint(t *testing.T) {
	configPath := filepath.Join(t.TempDir(), "nodes.json")
	if err := os.WriteFile(configPath, []byte(`{"inbounds":[]}`), 0o600); err != nil {
		t.Fatal(err)
	}
	if _, err := ProbeConfigInbound(t.Context(), "/unused", configPath, "tuic", 45116); err == nil {
		t.Fatal("missing inbound was accepted")
	}
}

func TestBuildHY2ProbeRequiresPassword(t *testing.T) {
	_, err := buildHY2Probe(map[string]any{"listen_port": float64(443)}, "", "")
	if err == nil {
		t.Fatal("missing password accepted")
	}
}

func TestBuildHY2ProbeServerOverride(t *testing.T) {
	inbound := map[string]any{"listen": "::", "listen_port": float64(443), "users": []any{map[string]any{"password": "secret"}}}
	data, err := buildHY2Probe(inbound, "node.example.com", "node.example.com")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	_ = json.Unmarshal(data, &root)
	outbound := root["outbounds"].([]any)[0].(map[string]any)
	if outbound["server"] != "node.example.com" || outbound["tls"].(map[string]any)["insecure"] != false {
		t.Fatalf("server override ignored: %+v", outbound)
	}
}

func TestBuildProbeForEverySupportedProtocol(t *testing.T) {
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	privateValue := base64.RawURLEncoding.EncodeToString(privateKey.Bytes())
	tests := []struct {
		protocol string
		inbound  map[string]any
		want     string
	}{
		{"hysteria2", map[string]any{"users": []any{map[string]any{"password": "secret"}}}, "password"},
		{"vless", map[string]any{"users": []any{map[string]any{"uuid": "d342d11e-d424-4583-b36e-524ab1f0afa4", "flow": "xtls-rprx-vision"}}, "tls": map[string]any{"server_name": "www.google.com", "reality": map[string]any{"private_key": privateValue, "short_id": []any{"0123456789abcdef"}, "handshake": map[string]any{"server": "www.google.com"}}}}, "tls"},
		{"vless-ws", map[string]any{"type": "vless", "users": []any{map[string]any{"uuid": "d342d11e-d424-4583-b36e-524ab1f0afa4"}}, "transport": map[string]any{"type": "ws", "path": "/wukong-test"}}, "transport"},
		{"shadowsocks", map[string]any{"method": "2022-blake3-aes-128-gcm", "password": "QUJDREVGR0hJSktMTU5PUA=="}, "method"},
		{"tuic", map[string]any{"users": []any{map[string]any{"uuid": "d342d11e-d424-4583-b36e-524ab1f0afa4", "password": "secret"}}}, "congestion_control"},
		{"trojan", map[string]any{"users": []any{map[string]any{"password": "secret"}}}, "password"},
	}
	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			if test.inbound["type"] == nil {
				test.inbound["type"] = test.protocol
			}
			test.inbound["listen"] = "::"
			test.inbound["listen_port"] = float64(443)
			data, buildErr := buildProtocolProbe(test.inbound, "", "")
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			var root map[string]any
			if err := json.Unmarshal(data, &root); err != nil {
				t.Fatal(err)
			}
			outbound := root["outbounds"].([]any)[0].(map[string]any)
			wantType := test.protocol
			if test.protocol == "vless-ws" {
				wantType = "vless"
			}
			if outbound["type"] != wantType || outbound[test.want] == nil {
				t.Fatalf("incomplete %s probe outbound: %#v", test.protocol, outbound)
			}
			if test.protocol == "vless-ws" && outbound["tls"] != nil {
				t.Fatalf("local VLESS WebSocket probe unexpectedly enabled TLS: %#v", outbound)
			}
		})
	}
}

func TestGeneratedProbesPassRealSingBoxCheck(t *testing.T) {
	binary := os.Getenv("SING_BOX_TEST_BIN")
	if binary == "" {
		t.Skip("set SING_BOX_TEST_BIN to run sing-box integration checks")
	}
	privateKey, err := ecdh.X25519().GenerateKey(rand.Reader)
	if err != nil {
		t.Fatal(err)
	}
	inbounds := []map[string]any{
		{"type": "hysteria2", "listen": "::", "listen_port": float64(48000), "users": []any{map[string]any{"password": "secret"}}},
		{"type": "vless", "listen": "::", "listen_port": float64(48001), "users": []any{map[string]any{"uuid": "d342d11e-d424-4583-b36e-524ab1f0afa4", "flow": "xtls-rprx-vision"}}, "tls": map[string]any{"server_name": "www.google.com", "reality": map[string]any{"private_key": base64.RawURLEncoding.EncodeToString(privateKey.Bytes()), "short_id": []any{"0123456789abcdef"}, "handshake": map[string]any{"server": "www.google.com"}}}},
		{"type": "shadowsocks", "listen": "::", "listen_port": float64(48002), "method": "2022-blake3-aes-128-gcm", "password": "QUJDREVGR0hJSktMTU5PUA=="},
		{"type": "tuic", "listen": "::", "listen_port": float64(48003), "users": []any{map[string]any{"uuid": "d342d11e-d424-4583-b36e-524ab1f0afa4", "password": "secret"}}},
		{"type": "trojan", "listen": "::", "listen_port": float64(48004), "users": []any{map[string]any{"password": "secret"}}},
	}
	for _, inbound := range inbounds {
		protocol := stringValue(inbound["type"])
		t.Run(protocol, func(t *testing.T) {
			data, buildErr := buildProtocolProbe(inbound, "", "")
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			path := filepath.Join(t.TempDir(), protocol+".json")
			if err := os.WriteFile(path, data, 0o600); err != nil {
				t.Fatal(err)
			}
			if output, checkErr := exec.Command(binary, "check", "-c", path).CombinedOutput(); checkErr != nil {
				t.Fatalf("sing-box rejected %s probe: %v\n%s\n%s", protocol, checkErr, output, data)
			}
		})
	}
}
