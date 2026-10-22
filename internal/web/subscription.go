package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/url"
	"strconv"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
)

func clashProxyYAML(node model.Node, shareURI string) (string, error) {
	if strings.EqualFold(node.Protocol, "vmess") || strings.HasPrefix(strings.ToLower(shareURI), "vmess://") {
		encoded := strings.TrimPrefix(shareURI, "vmess://")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(encoded)
		}
		if err != nil {
			return "", errors.New("invalid vmess share URI")
		}
		var vm map[string]any
		if err := json.Unmarshal(decoded, &vm); err != nil {
			return "", errors.New("invalid vmess json")
		}
		server := fmt.Sprintf("%v", vm["add"])
		if server == "" || server == "<nil>" {
			server = node.Server
		}
		portVal := fmt.Sprintf("%v", vm["port"])
		port, _ := strconv.Atoi(portVal)
		if port <= 0 {
			port = node.ListenPort
		}
		if port <= 0 {
			port = 443
		}
		uuid, _ := vm["id"].(string)
		net, _ := vm["net"].(string)
		tls := vm["tls"] == "tls"
		path, _ := vm["path"].(string)
		hostHdr, _ := vm["host"].(string)
		var builder strings.Builder
		fmt.Fprintf(&builder, "  - name: %q\n    server: %q\n    port: %d\n", node.Name, server, port)
		if net == "ws" {
			fmt.Fprintf(&builder, "    type: vmess\n    uuid: %q\n    alterId: 0\n    cipher: auto\n    network: ws\n    tls: %t\n    udp: true\n    servername: %q\n    ws-opts:\n      path: %q\n      headers:\n        Host: %q\n", uuid, tls, server, path, hostHdr)
		} else {
			fmt.Fprintf(&builder, "    type: vmess\n    uuid: %q\n    alterId: 0\n    cipher: auto\n    network: tcp\n    tls: %t\n    udp: true\n    servername: %q\n", uuid, tls, server)
		}
		return builder.String(), nil
	}

	parsed, err := url.Parse(shareURI)
	if err != nil || parsed.User == nil {
		return "", errors.New("invalid share URI")
	}
	server := strings.TrimSpace(parsed.Hostname())
	if server == "" {
		server = strings.TrimSpace(node.Server)
	}
	if server == "" {
		server = node.Domain
	}
	query := parsed.Query()
	insecure := query.Get("insecure") == "1" || query.Get("allow_insecure") == "1" || query.Get("allowInsecure") == "1"
	port := node.ListenPort
	if strings.EqualFold(node.Protocol, "vless-ws-tunnel") {
		port = 443
	}
	if port == 0 && parsed.Port() != "" {
		if p, err := strconv.Atoi(parsed.Port()); err == nil && p > 0 {
			port = p
		}
	}
	sni := query.Get("sni")
	if sni == "" {
		sni = node.Domain
	}
	if sni == "" {
		sni = server
	}

	var builder strings.Builder
	fmt.Fprintf(&builder, "  - name: %q\n    server: %q\n    port: %d\n", node.Name, server, port)
	switch strings.ToLower(node.Protocol) {
	case "hysteria2":
		fmt.Fprintf(&builder, "    type: hysteria2\n    password: %q\n    sni: %q\n    alpn: [h3]\n    skip-cert-verify: %t\n", parsed.User.Username(), sni, insecure)
	case "vless":
		if query.Get("pbk") != "" || query.Get("security") == "reality" {
			fmt.Fprintf(&builder, "    type: vless\n    uuid: %q\n    network: tcp\n    tls: true\n    udp: true\n    flow: xtls-rprx-vision\n    servername: %q\n    client-fingerprint: chrome\n    reality-opts:\n      public-key: %q\n      short-id: %q\n", parsed.User.Username(), sni, query.Get("pbk"), query.Get("sid"))
		} else if strings.EqualFold(query.Get("type"), "ws") {
			path := query.Get("path")
			hostHdr := query.Get("host")
			if hostHdr == "" {
				hostHdr = sni
			}
			tls := query.Get("security") == "tls"
			fmt.Fprintf(&builder, "    type: vless\n    uuid: %q\n    network: ws\n    tls: %t\n    udp: true\n    servername: %q\n    client-fingerprint: chrome\n    ws-opts:\n      path: %q\n      headers:\n        Host: %q\n", parsed.User.Username(), tls, sni, path, hostHdr)
		} else {
			tls := query.Get("security") == "tls"
			fmt.Fprintf(&builder, "    type: vless\n    uuid: %q\n    network: tcp\n    tls: %t\n    udp: true\n    servername: %q\n", parsed.User.Username(), tls, sni)
		}
	case "vless-ws-tunnel":
		serverName := node.Server
		if serverName == "" {
			serverName = sni
		}
		fmt.Fprintf(&builder, "    type: vless\n    uuid: %q\n    network: ws\n    tls: true\n    udp: true\n    servername: %q\n    client-fingerprint: chrome\n    ws-opts:\n      path: %q\n      headers:\n        Host: %q\n", parsed.User.Username(), serverName, query.Get("path"), serverName)
	case "ss", "shadowsocks":
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(parsed.User.Username())
		if decodeErr != nil {
			decoded, decodeErr = base64.StdEncoding.DecodeString(parsed.User.Username())
		}
		if decodeErr == nil {
			method, password, found := strings.Cut(string(decoded), ":")
			if found && method != "" && password != "" {
				fmt.Fprintf(&builder, "    type: ss\n    cipher: %q\n    password: %q\n    udp: true\n", method, password)
				break
			}
		}
		cipher := query.Get("cipher")
		password := parsed.User.Username()
		if p, ok := parsed.User.Password(); ok {
			cipher = parsed.User.Username()
			password = p
		}
		if cipher == "" {
			cipher = "2022-blake3-aes-128-gcm"
		}
		fmt.Fprintf(&builder, "    type: ss\n    cipher: %q\n    password: %q\n    udp: true\n", cipher, password)
	case "tuic":
		password, _ := parsed.User.Password()
		fmt.Fprintf(&builder, "    type: tuic\n    uuid: %q\n    password: %q\n    sni: %q\n    alpn: [h3]\n    udp-relay-mode: native\n    congestion-controller: bbr\n    reduce-rtt: false\n    skip-cert-verify: %t\n", parsed.User.Username(), password, sni, insecure)
	case "trojan":
		fmt.Fprintf(&builder, "    type: trojan\n    password: %q\n    sni: %q\n    network: tcp\n    udp: true\n    skip-cert-verify: %t\n", parsed.User.Username(), sni, insecure)
	case "anytls":
		fmt.Fprintf(&builder, "    type: anytls\n    password: %q\n    sni: %q\n    client-fingerprint: chrome\n    udp: true\n    idle-session-check-interval: 30\n    idle-session-timeout: 30\n    min-idle-session: 0\n    skip-cert-verify: %t\n", parsed.User.Username(), sni, insecure)
	default:
		return "", fmt.Errorf("unsupported protocol %q", node.Protocol)
	}
	return builder.String(), nil
}
