package probe

import (
	"os"
	"path/filepath"
	"testing"
)

func TestScanDirectories(t *testing.T) {
	tempDir := t.TempDir()

	// Sing-box config
	sbConfig := `{
		"inbounds": [
			{
				"type": "hysteria2",
				"tag": "my-hy2",
				"listen_port": 14433,
				"users": [{"password": "secret-pass"}],
				"tls": {"enabled": true, "server_name": "hy2.example.com"}
			},
			{
				"type": "vless",
				"tag": "my-reality",
				"listen_port": 24433,
				"users": [{"uuid": "11111111-2222-3333-4444-555555555555"}],
				"tls": {
					"enabled": true,
					"server_name": "gateway.example.com",
					"reality": {
						"enabled": true,
						"public_key": "some-public-key",
						"short_id": "0123456789abcdef",
						"handshake": {"server": "gateway.example.com"}
					}
				}
			},
			{
				"type": "shadowsocks",
				"tag": "my-ss",
				"listen_port": 34433,
				"method": "2022-blake3-aes-128-gcm",
				"password": "pass"
			}
		]
	}`

	if err := os.WriteFile(filepath.Join(tempDir, "sing-box.json"), []byte(sbConfig), 0644); err != nil {
		t.Fatal(err)
	}

	nodes := ScanDirectories("203.0.113.10", tempDir)
	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}

	// Verify Hysteria2
	var hy2Node *string
	for _, n := range nodes {
		if n.Protocol == "hysteria2" {
			if n.Port != 14433 {
				t.Errorf("hy2 port mismatch: %d", n.Port)
			}
			if n.Name != "my-hy2" {
				t.Errorf("hy2 name mismatch: %s", n.Name)
			}
			if n.Domain != "hy2.example.com" {
				t.Errorf("hy2 domain mismatch: %s", n.Domain)
			}
			hy2Node = &n.ShareURI
		}
	}
	if hy2Node == nil || *hy2Node == "" {
		t.Errorf("missing hysteria2 share URI")
	}

	// Verify Reality
	for _, n := range nodes {
		if n.Protocol == "vless" {
			if n.Port != 24433 {
				t.Errorf("reality port mismatch: %d", n.Port)
			}
			if n.Domain != "gateway.example.com" {
				t.Errorf("reality domain mismatch: %s", n.Domain)
			}
		}
	}
}

func TestScanXrayConfig(t *testing.T) {
	tempDir := t.TempDir()

	xrayConfig := `{
		"inbounds": [
			{
				"port": 443,
				"protocol": "vless",
				"tag": "xray-reality",
				"settings": {
					"clients": [{"id": "aaaaaaaa-bbbb-cccc-dddd-eeeeeeeeeeee", "flow": "xtls-rprx-vision"}],
					"decryption": "none"
				},
				"streamSettings": {
					"network": "tcp",
					"security": "reality",
					"realitySettings": {
						"publicKey": "xray-pbk",
						"shortIds": ["abcdef01"],
						"serverNames": ["xray.example.com"]
					}
				}
			}
		]
	}`

	if err := os.WriteFile(filepath.Join(tempDir, "xray.json"), []byte(xrayConfig), 0644); err != nil {
		t.Fatal(err)
	}

	nodes := ScanDirectories("198.51.100.5", tempDir)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	node := nodes[0]
	if node.Protocol != "vless" || node.Port != 443 {
		t.Errorf("unexpected node: %+v", node)
	}
	if node.Domain != "xray.example.com" {
		t.Errorf("unexpected domain: %s", node.Domain)
	}
}

func TestScanHysteria2YAML(t *testing.T) {
	tempDir := t.TempDir()

	hy2YAML := `
listen: :44332
tls:
  cert: /etc/hysteria/server.crt
  key: /etc/hysteria/server.key
  sni: hy2-yaml.example.com
auth:
  type: password
  password: my-yaml-secret
`
	if err := os.WriteFile(filepath.Join(tempDir, "config.yaml"), []byte(hy2YAML), 0644); err != nil {
		t.Fatal(err)
	}

	nodes := ScanDirectories("198.51.100.9", tempDir)
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	node := nodes[0]
	if node.Protocol != "hysteria2" || node.Port != 44332 {
		t.Fatalf("unexpected node: %+v", node)
	}
	if node.Domain != "hy2-yaml.example.com" {
		t.Errorf("unexpected domain: %s", node.Domain)
	}
	if node.ShareURI == "" {
		t.Errorf("missing share URI")
	}
}
