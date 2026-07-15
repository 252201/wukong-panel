package web

import (
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestClashProxyYAMLForEveryProtocol(t *testing.T) {
	tests := []struct {
		protocol string
		share    string
		want     []string
	}{
		{"hysteria2", "hysteria2://secret@node.example.com:443/?sni=node.example.com", []string{"type: hysteria2", `password: "secret"`}},
		{"vless", "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@node.example.com:443?security=reality&pbk=public&sid=0123456789abcdef", []string{"type: vless", "reality-opts:", `public-key: "public"`}},
		{"vless-ws-tunnel", "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@edge.example.com:443?security=tls&type=ws&path=%2Fwukong-test", []string{"port: 443", "type: vless", "network: ws", `path: "/wukong-test"`, `Host: "node.example.com"`}},
		{"shadowsocks", "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206QUJDREVGR0hJSktMTU5PUA@node.example.com:443", []string{"type: ss", `cipher: "2022-blake3-aes-128-gcm"`, `password: "ABCDEFGHIJKLMNOP"`}},
		{"tuic", "tuic://d342d11e-d424-4583-b36e-524ab1f0afa4:secret@node.example.com:443?sni=node.example.com", []string{"type: tuic", "congestion-controller: bbr"}},
		{"trojan", "trojan://secret@node.example.com:443?security=tls&sni=node.example.com", []string{"type: trojan", `password: "secret"`}},
	}
	for _, test := range tests {
		t.Run(test.protocol, func(t *testing.T) {
			node := model.Node{Name: "node", Protocol: test.protocol, Server: "node.example.com", Domain: "node.example.com", ListenPort: 443}
			value, err := clashProxyYAML(node, test.share)
			if err != nil {
				t.Fatal(err)
			}
			for _, want := range test.want {
				if !strings.Contains(value, want) {
					t.Fatalf("%q missing from YAML:\n%s", want, value)
				}
			}
		})
	}
}

func TestClashTunnelKeepsPublishedHostnameWithPreferredEndpoint(t *testing.T) {
	node := model.Node{
		Name:            "node",
		Protocol:        "vless-ws-tunnel",
		Server:          "origin.example.com",
		Domain:          "origin.example.com",
		PreferredServer: "preferred.example.com",
		ListenPort:      45119,
	}
	share := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@preferred.example.com:443?security=tls&type=ws&sni=origin.example.com&host=origin.example.com&path=%2Fwukong-test"
	value, err := clashProxyYAML(node, share)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`server: "preferred.example.com"`, `servername: "origin.example.com"`, `Host: "origin.example.com"`} {
		if !strings.Contains(value, want) {
			t.Fatalf("%q missing from YAML:\n%s", want, value)
		}
	}
}
