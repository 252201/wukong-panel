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
