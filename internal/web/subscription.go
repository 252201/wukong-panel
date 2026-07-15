package web

import (
	"encoding/base64"
	"errors"
	"fmt"
	"net/url"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
)

func clashProxyYAML(node model.Node, shareURI string) (string, error) {
	parsed, err := url.Parse(shareURI)
	if err != nil || parsed.User == nil {
		return "", errors.New("invalid share URI")
	}
	server := node.Server
	if server == "" {
		server = node.Domain
	}
	query := parsed.Query()
	insecure := query.Get("insecure") == "1" || query.Get("allow_insecure") == "1" || query.Get("allowInsecure") == "1"
	port := node.ListenPort
	if strings.EqualFold(node.Protocol, "vless-ws-tunnel") {
		port = 443
	}
	var builder strings.Builder
	fmt.Fprintf(&builder, "  - name: %q\n    server: %q\n    port: %d\n", node.Name, server, port)
	switch strings.ToLower(node.Protocol) {
	case "hysteria2":
		fmt.Fprintf(&builder, "    type: hysteria2\n    password: %q\n    sni: %q\n    alpn: [h3]\n    skip-cert-verify: %t\n", parsed.User.Username(), node.Domain, insecure)
	case "vless":
		fmt.Fprintf(&builder, "    type: vless\n    uuid: %q\n    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n    servername: %q\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %q\n      short-id: %q\n", parsed.User.Username(), node.Domain, query.Get("pbk"), query.Get("sid"))
	case "vless-ws-tunnel":
		fmt.Fprintf(&builder, "    type: vless\n    uuid: %q\n    network: ws\n    tls: true\n    udp: true\n    servername: %q\n    client-fingerprint: chrome\n    ws-opts:\n      path: %q\n      headers:\n        Host: %q\n", parsed.User.Username(), node.Server, query.Get("path"), node.Server)
	case "shadowsocks":
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(parsed.User.Username())
		if decodeErr != nil {
			return "", decodeErr
		}
		method, password, found := strings.Cut(string(decoded), ":")
		if !found || method == "" || password == "" {
			return "", errors.New("invalid Shadowsocks share URI")
		}
		fmt.Fprintf(&builder, "    type: ss\n    cipher: %q\n    password: %q\n    udp: true\n", method, password)
	case "tuic":
		password, _ := parsed.User.Password()
		fmt.Fprintf(&builder, "    type: tuic\n    uuid: %q\n    password: %q\n    sni: %q\n    alpn: [h3]\n    udp-relay-mode: native\n    congestion-controller: bbr\n    reduce-rtt: false\n    skip-cert-verify: %t\n", parsed.User.Username(), password, node.Domain, insecure)
	case "trojan":
		fmt.Fprintf(&builder, "    type: trojan\n    password: %q\n    sni: %q\n    network: tcp\n    udp: true\n    skip-cert-verify: %t\n", parsed.User.Username(), node.Domain, insecure)
	default:
		return "", fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
	return builder.String(), nil
}
