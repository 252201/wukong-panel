package probe

import (
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
)

var defaultScanDirs = []string{
	"/etc/s-box",
	"/etc/sing-box",
	"/etc/xray",
	"/usr/local/etc/xray",
	"/etc/v2ray",
}

// ScanDirectories scans config directories for proxy inbounds and builds FleetProbeNode list.
func ScanDirectories(serverHost string, dirs ...string) []model.FleetProbeNode {
	if len(dirs) == 0 {
		dirs = defaultScanDirs
	}
	serverHost = strings.TrimSpace(serverHost)
	if serverHost == "" {
		serverHost = "127.0.0.1"
	}

	seen := make(map[string]bool)
	var nodes []model.FleetProbeNode

	for _, dir := range dirs {
		stat, err := os.Stat(dir)
		if err != nil {
			continue
		}
		var files []string
		if stat.IsDir() {
			matches, _ := filepath.Glob(filepath.Join(dir, "*.json"))
			files = append(files, matches...)
		} else {
			files = append(files, dir)
		}

		for _, file := range files {
			parsedNodes := parseConfigFile(file, serverHost)
			for _, node := range parsedNodes {
				key := fmt.Sprintf("%s:%d", node.Protocol, node.Port)
				if seen[key] {
					continue
				}
				seen[key] = true
				nodes = append(nodes, node)
			}
		}
	}

	sort.Slice(nodes, func(i, j int) bool {
		if nodes[i].Protocol == nodes[j].Protocol {
			return nodes[i].Port < nodes[j].Port
		}
		return nodes[i].Protocol < nodes[j].Protocol
	})

	return nodes
}

func parseConfigFile(path, serverHost string) []model.FleetProbeNode {
	data, err := os.ReadFile(path)
	if err != nil || len(data) == 0 {
		return nil
	}

	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		return nil
	}

	inboundsRaw, _ := root["inbounds"].([]any)
	if len(inboundsRaw) == 0 {
		return nil
	}

	var nodes []model.FleetProbeNode
	for _, item := range inboundsRaw {
		inbound, ok := item.(map[string]any)
		if !ok {
			continue
		}
		node, ok := convertInboundToNode(inbound, serverHost)
		if ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func convertInboundToNode(inbound map[string]any, serverHost string) (model.FleetProbeNode, bool) {
	protocol := strings.ToLower(getString(inbound, "type"))
	if protocol == "" {
		protocol = strings.ToLower(getString(inbound, "protocol"))
	}
	if protocol == "" {
		return model.FleetProbeNode{}, false
	}

	port := getInt(inbound, "listen_port")
	if port <= 0 {
		port = getInt(inbound, "port")
	}
	if port < 1 || port > 65535 {
		return model.FleetProbeNode{}, false
	}

	tag := getString(inbound, "tag")
	name := tag
	if name == "" {
		name = fmt.Sprintf("%s-%d", strings.ToUpper(protocol), port)
	}

	id := fmt.Sprintf("scan_%s_%d", protocol, port)

	shareURI, domain := buildInboundShareURI(protocol, name, serverHost, port, inbound)
	if shareURI == "" {
		return model.FleetProbeNode{}, false
	}

	if domain == "" {
		domain = serverHost
	}

	return model.FleetProbeNode{
		ID:       id,
		Name:     name,
		Protocol: protocol,
		Server:   serverHost,
		Port:     port,
		Domain:   domain,
		ShareURI: shareURI,
		Source:   "scan",
		RawName:  name,
	}, true
}

func buildInboundShareURI(protocol, name, serverHost string, port int, inbound map[string]any) (string, string) {
	tagEscaped := url.QueryEscape(name)

	switch protocol {
	case "hysteria2", "hy2":
		password := extractPassword(inbound)
		if password == "" {
			return "", ""
		}
		sni := extractSNI(inbound)
		if sni == "" {
			sni = serverHost
		}
		uri := fmt.Sprintf("hysteria2://%s@%s:%d/?sni=%s&insecure=0#%s",
			url.QueryEscape(password), serverHost, port, url.QueryEscape(sni), tagEscaped)
		return uri, sni

	case "vless":
		uuid := extractUUID(inbound)
		if uuid == "" {
			return "", ""
		}
		// Check reality
		pbk, sid, sni := extractReality(inbound)
		if pbk != "" {
			if sni == "" {
				sni = serverHost
			}
			uri := fmt.Sprintf("vless://%s@%s:%d?security=reality&encryption=none&pbk=%s&sid=%s&sni=%s&fp=chrome&type=tcp&flow=xtls-rprx-vision#%s",
				uuid, serverHost, port, url.QueryEscape(pbk), url.QueryEscape(sid), url.QueryEscape(sni), tagEscaped)
			return uri, sni
		}
		// Check ws transport
		wsPath, wsHost := extractWSTransport(inbound)
		if wsPath != "" {
			tlsSNI := extractSNI(inbound)
			if tlsSNI == "" {
				tlsSNI = wsHost
			}
			if tlsSNI == "" {
				tlsSNI = serverHost
			}
			uri := fmt.Sprintf("vless://%s@%s:%d?security=tls&encryption=none&type=ws&path=%s&host=%s&sni=%s#%s",
				uuid, serverHost, port, url.QueryEscape(wsPath), url.QueryEscape(wsHost), url.QueryEscape(tlsSNI), tagEscaped)
			return uri, tlsSNI
		}
		// Standard TLS or TCP
		sni = extractSNI(inbound)
		if sni == "" {
			sni = serverHost
		}
		uri := fmt.Sprintf("vless://%s@%s:%d?security=tls&encryption=none&sni=%s#%s",
			uuid, serverHost, port, url.QueryEscape(sni), tagEscaped)
		return uri, sni

	case "shadowsocks", "ss":
		method, password := extractSSMethodPassword(inbound)
		if method == "" || password == "" {
			return "", ""
		}
		auth := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
		uri := fmt.Sprintf("ss://%s@%s:%d#%s", auth, serverHost, port, tagEscaped)
		return uri, serverHost

	case "tuic":
		uuid := extractUUID(inbound)
		password := extractPassword(inbound)
		if uuid == "" || password == "" {
			return "", ""
		}
		sni := extractSNI(inbound)
		if sni == "" {
			sni = serverHost
		}
		uri := fmt.Sprintf("tuic://%s:%s@%s:%d?sni=%s&alpn=h3&congestion_controller=bbr#%s",
			url.QueryEscape(uuid), url.QueryEscape(password), serverHost, port, url.QueryEscape(sni), tagEscaped)
		return uri, sni

	case "trojan":
		password := extractPassword(inbound)
		if password == "" {
			return "", ""
		}
		sni := extractSNI(inbound)
		if sni == "" {
			sni = serverHost
		}
		uri := fmt.Sprintf("trojan://%s@%s:%d?security=tls&sni=%s#%s",
			url.QueryEscape(password), serverHost, port, url.QueryEscape(sni), tagEscaped)
		return uri, sni

	case "anytls":
		password := extractPassword(inbound)
		if password == "" {
			return "", ""
		}
		sni := extractSNI(inbound)
		if sni == "" {
			sni = serverHost
		}
		uri := fmt.Sprintf("anytls://%s@%s:%d?sni=%s#%s",
			url.QueryEscape(password), serverHost, port, url.QueryEscape(sni), tagEscaped)
		return uri, sni

	case "vmess":
		uuid := extractUUID(inbound)
		if uuid == "" {
			return "", ""
		}
		wsPath, wsHost := extractWSTransport(inbound)
		net := "tcp"
		if wsPath != "" {
			net = "ws"
		}
		tls := "tls"
		vmMap := map[string]any{
			"v":    "2",
			"ps":   name,
			"add":  serverHost,
			"port": port,
			"id":   uuid,
			"aid":  0,
			"scy":  "auto",
			"net":  net,
			"type": "none",
			"host": wsHost,
			"path": wsPath,
			"tls":  tls,
		}
		b, _ := json.Marshal(vmMap)
		uri := "vmess://" + base64.StdEncoding.EncodeToString(b)
		return uri, serverHost
	}

	return "", ""
}

func extractPassword(inbound map[string]any) string {
	if p := getString(inbound, "password"); p != "" {
		return p
	}
	// sing-box users: [{"password": "..."}]
	if users, ok := inbound["users"].([]any); ok && len(users) > 0 {
		if u, ok := users[0].(map[string]any); ok {
			if p := getString(u, "password"); p != "" {
				return p
			}
		}
	}
	// xray settings.password or settings.clients[0].password
	if settings, ok := inbound["settings"].(map[string]any); ok {
		if p := getString(settings, "password"); p != "" {
			return p
		}
		if clients, ok := settings["clients"].([]any); ok && len(clients) > 0 {
			if c, ok := clients[0].(map[string]any); ok {
				if p := getString(c, "password"); p != "" {
					return p
				}
			}
		}
	}
	return ""
}

func extractUUID(inbound map[string]any) string {
	if u := getString(inbound, "uuid"); u != "" {
		return u
	}
	// sing-box users: [{"uuid": "..."}]
	if users, ok := inbound["users"].([]any); ok && len(users) > 0 {
		if u, ok := users[0].(map[string]any); ok {
			if uid := getString(u, "uuid"); uid != "" {
				return uid
			}
		}
	}
	// xray settings.clients[0].id
	if settings, ok := inbound["settings"].(map[string]any); ok {
		if clients, ok := settings["clients"].([]any); ok && len(clients) > 0 {
			if c, ok := clients[0].(map[string]any); ok {
				if id := getString(c, "id"); id != "" {
					return id
				}
			}
		}
	}
	return ""
}

func extractSNI(inbound map[string]any) string {
	if tls, ok := inbound["tls"].(map[string]any); ok {
		if sni := getString(tls, "server_name"); sni != "" {
			return sni
		}
	}
	if stream, ok := inbound["streamSettings"].(map[string]any); ok {
		if tls, ok := stream["tlsSettings"].(map[string]any); ok {
			if sni := getString(tls, "serverName"); sni != "" {
				return sni
			}
		}
		if reality, ok := stream["realitySettings"].(map[string]any); ok {
			if names, ok := reality["serverNames"].([]any); ok && len(names) > 0 {
				return fmt.Sprintf("%v", names[0])
			}
		}
	}
	return ""
}

func extractReality(inbound map[string]any) (pbk, sid, sni string) {
	// sing-box style: tls.reality
	if tls, ok := inbound["tls"].(map[string]any); ok {
		if reality, ok := tls["reality"].(map[string]any); ok {
			pbk = getString(reality, "public_key")
			if pbk == "" {
				pbk = deriveRealityPublicKey(getString(reality, "private_key"))
			}
			sid = getString(reality, "short_id")
			if sid == "" {
				if sids, ok := reality["short_id"].([]any); ok && len(sids) > 0 {
					sid = fmt.Sprintf("%v", sids[0])
				}
			}
			if handshake, ok := reality["handshake"].(map[string]any); ok {
				sni = getString(handshake, "server")
			}
			if sni == "" {
				sni = getString(tls, "server_name")
			}
			return pbk, sid, sni
		}
	}

	// xray style: streamSettings.realitySettings
	if stream, ok := inbound["streamSettings"].(map[string]any); ok {
		if reality, ok := stream["realitySettings"].(map[string]any); ok {
			pbk = getString(reality, "publicKey")
			if pbk == "" {
				pbk = deriveRealityPublicKey(getString(reality, "privateKey"))
			}
			if sids, ok := reality["shortIds"].([]any); ok && len(sids) > 0 {
				sid = fmt.Sprintf("%v", sids[0])
			}
			if names, ok := reality["serverNames"].([]any); ok && len(names) > 0 {
				sni = fmt.Sprintf("%v", names[0])
			}
			return pbk, sid, sni
		}
	}

	return "", "", ""
}

func extractWSTransport(inbound map[string]any) (path, host string) {
	// sing-box style: transport.type == "ws"
	if transport, ok := inbound["transport"].(map[string]any); ok {
		if getString(transport, "type") == "ws" {
			path = getString(transport, "path")
			if headers, ok := transport["headers"].(map[string]any); ok {
				host = getString(headers, "Host")
			}
			return path, host
		}
	}

	// xray style: streamSettings.wsSettings
	if stream, ok := inbound["streamSettings"].(map[string]any); ok {
		if getString(stream, "network") == "ws" {
			if ws, ok := stream["wsSettings"].(map[string]any); ok {
				path = getString(ws, "path")
				if headers, ok := ws["headers"].(map[string]any); ok {
					host = getString(headers, "Host")
				}
				return path, host
			}
		}
	}

	return "", ""
}

func extractSSMethodPassword(inbound map[string]any) (method, password string) {
	method = getString(inbound, "method")
	password = getString(inbound, "password")
	if method != "" && password != "" {
		return method, password
	}
	if settings, ok := inbound["settings"].(map[string]any); ok {
		m := getString(settings, "method")
		p := getString(settings, "password")
		if m != "" && p != "" {
			return m, p
		}
	}
	return "", ""
}

func deriveRealityPublicKey(privateValue string) string {
	privateValue = strings.TrimSpace(privateValue)
	if privateValue == "" {
		return ""
	}
	privateBytes, err := base64.RawURLEncoding.DecodeString(privateValue)
	if err != nil {
		privateBytes, err = base64.StdEncoding.DecodeString(privateValue)
	}
	if err != nil {
		return ""
	}
	key, err := ecdh.X25519().NewPrivateKey(privateBytes)
	if err != nil {
		return ""
	}
	return base64.RawURLEncoding.EncodeToString(key.PublicKey().Bytes())
}

func getString(m map[string]any, key string) string {
	if val, ok := m[key]; ok && val != nil {
		return strings.TrimSpace(fmt.Sprintf("%v", val))
	}
	return ""
}

func getInt(m map[string]any, key string) int {
	if val, ok := m[key]; ok && val != nil {
		switch v := val.(type) {
		case float64:
			return int(v)
		case int:
			return v
		case string:
			var res int
			fmt.Sscanf(v, "%d", &res)
			return res
		}
	}
	return 0
}
