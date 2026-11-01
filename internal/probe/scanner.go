package probe

import (
	"bufio"
	"crypto/ecdh"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/url"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
)

var defaultScanDirs = []string{
	"/etc/s-box",
	"/etc/sing-box",
	"/etc/sing-box/conf",
	"/etc/xray",
	"/etc/xray/conf",
	"/usr/local/etc/xray",
	"/etc/v2ray",
	"/usr/local/x-ui",
	"/usr/local/x-ui/bin",
	"/etc/v2ray-agent/sing-box/conf",
	"/etc/v2ray-agent/xray/conf",
	"/etc/hysteria",
	"/etc/tuic",
	"/root",
}

// ScanDirectories scans config directories and active process cmdlines for proxy inbounds.
func ScanDirectories(serverHost string, dirs ...string) []model.FleetProbeNode {
	return ScanDirectoriesWithIPv6(serverHost, "", dirs...)
}

// ScanDirectoriesWithIPv6 scans config directories and active process cmdlines for proxy inbounds,
// routing v6-tagged or v6-bound inbounds to ipv6Host and detecting Cloudflare Tunnel ingress configurations.
func ScanDirectoriesWithIPv6(serverHost, ipv6Host string, dirs ...string) []model.FleetProbeNode {
	serverHost = strings.TrimSpace(serverHost)
	if serverHost == "" {
		serverHost = "127.0.0.1"
	}
	ipv6Host = strings.TrimSpace(ipv6Host)

	cfMap := scanCloudflaredIngress()

	var allTargets []string
	if len(dirs) == 0 {
		// 1. Actively running process configs via /proc
		allTargets = append(allTargets, findProcessConfigs()...)
		// 2. Default standard directories
		allTargets = append(allTargets, defaultScanDirs...)
	} else {
		allTargets = dirs
	}

	seen := make(map[string]bool)
	var nodes []model.FleetProbeNode

	for _, target := range allTargets {
		stat, err := os.Stat(target)
		if err != nil {
			continue
		}
		var files []string
		if stat.IsDir() {
			jsonMatches, _ := filepath.Glob(filepath.Join(target, "*.json"))
			yamlMatches, _ := filepath.Glob(filepath.Join(target, "*.yaml"))
			ymlMatches, _ := filepath.Glob(filepath.Join(target, "*.yml"))
			files = append(files, jsonMatches...)
			files = append(files, yamlMatches...)
			files = append(files, ymlMatches...)
		} else {
			files = append(files, target)
		}

		for _, file := range files {
			ext := strings.ToLower(filepath.Ext(file))
			var parsedNodes []model.FleetProbeNode
			if ext == ".yaml" || ext == ".yml" {
				parsedNodes = parseYAMLConfigFile(file, serverHost, ipv6Host)
			} else {
				parsedNodes = parseConfigFile(file, serverHost, ipv6Host, cfMap)
			}

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

func scanCloudflaredIngress() map[int]string {
	portToDomain := make(map[int]string)
	cfDirs := []string{
		"/etc/cloudflared",
		"/usr/local/etc/cloudflared",
		"/root/.cloudflared",
	}
	if home, err := os.UserHomeDir(); err == nil && home != "" {
		cfDirs = append(cfDirs, filepath.Join(home, ".cloudflared"))
	}

	ingressHostRe := regexp.MustCompile(`(?i)^\s*-\s*hostname\s*:\s*"?([^"\s]+)"?`)
	ingressServiceRe := regexp.MustCompile(`(?i)^\s*service\s*:\s*(?:https?://)?(?:localhost|127\.0\.0\.1|0\.0\.0\.0|\[::1\]):(\d+)`)

	for _, dir := range cfDirs {
		matches, _ := filepath.Glob(filepath.Join(dir, "*.y*ml"))
		for _, file := range matches {
			f, err := os.Open(file)
			if err != nil {
				continue
			}
			scanner := bufio.NewScanner(f)
			currentHost := ""
			for scanner.Scan() {
				line := scanner.Text()
				if m := ingressHostRe.FindStringSubmatch(line); len(m) > 1 {
					currentHost = strings.TrimSpace(m[1])
				} else if m := ingressServiceRe.FindStringSubmatch(line); len(m) > 1 && currentHost != "" {
					if p, err := strconv.Atoi(m[1]); err == nil && p > 0 {
						portToDomain[p] = currentHost
					}
					currentHost = ""
				}
			}
			f.Close()
		}
	}
	return portToDomain
}

func findProcessConfigs() []string {
	entries, err := os.ReadDir("/proc")
	if err != nil {
		return nil
	}
	var configs []string
	seen := make(map[string]bool)

	for _, entry := range entries {
		if !entry.IsDir() {
			continue
		}
		name := entry.Name()
		if len(name) == 0 || name[0] < '0' || name[0] > '9' {
			continue
		}
		cmdline, err := os.ReadFile(filepath.Join("/proc", name, "cmdline"))
		if err != nil || len(cmdline) == 0 {
			continue
		}
		args := strings.Split(string(cmdline), "\x00")
		if len(args) == 0 {
			continue
		}
		exe := filepath.Base(args[0])
		if !isProxyExecutable(exe) {
			continue
		}
		for i, arg := range args {
			if (arg == "-c" || arg == "--config" || arg == "-config" || arg == "-C") && i+1 < len(args) {
				cfgPath := strings.TrimSpace(args[i+1])
				if cfgPath != "" && !seen[cfgPath] {
					seen[cfgPath] = true
					configs = append(configs, cfgPath)
				}
			}
		}
	}
	return configs
}

func isProxyExecutable(name string) bool {
	lower := strings.ToLower(name)
	return strings.Contains(lower, "sing-box") ||
		strings.Contains(lower, "xray") ||
		strings.Contains(lower, "v2ray") ||
		strings.Contains(lower, "hysteria") ||
		strings.Contains(lower, "tuic")
}

func formatHostPort(host string, port int) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return fmt.Sprintf("[%s]:%d", host, port)
	}
	return fmt.Sprintf("%s:%d", host, port)
}

func parseConfigFile(path, serverHost, ipv6Host string, cfMap map[int]string) []model.FleetProbeNode {
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
		node, ok := convertInboundToNode(inbound, serverHost, ipv6Host, cfMap)
		if ok {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

var (
	yamlListenRe   = regexp.MustCompile(`(?i)^\s*listen\s*:\s*"?([^"\s]+)"?`)
	yamlPasswordRe = regexp.MustCompile(`(?i)^\s*password\s*:\s*"?([^"\s]+)"?`)
	yamlSniRe      = regexp.MustCompile(`(?i)^\s*sni\s*:\s*"?([^"\s]+)"?`)
)

func parseYAMLConfigFile(path, serverHost, ipv6Host string) []model.FleetProbeNode {
	file, err := os.Open(path)
	if err != nil {
		return nil
	}
	defer file.Close()

	scanner := bufio.NewScanner(file)
	var listenStr, password, sni string

	for scanner.Scan() {
		line := scanner.Text()
		if m := yamlListenRe.FindStringSubmatch(line); len(m) > 1 && listenStr == "" {
			listenStr = m[1]
		}
		if m := yamlPasswordRe.FindStringSubmatch(line); len(m) > 1 && password == "" {
			password = m[1]
		}
		if m := yamlSniRe.FindStringSubmatch(line); len(m) > 1 && sni == "" {
			sni = m[1]
		}
	}

	if listenStr == "" || password == "" {
		return nil
	}

	port := 0
	if idx := strings.LastIndex(listenStr, ":"); idx != -1 {
		p, _ := strconv.Atoi(listenStr[idx+1:])
		port = p
	} else {
		p, _ := strconv.Atoi(listenStr)
		port = p
	}

	if port < 1 || port > 65535 {
		return nil
	}

	nodeHost := serverHost
	if ipv6Host != "" && strings.Contains(listenStr, ":") && !strings.HasPrefix(listenStr, ":") {
		nodeHost = ipv6Host
	}

	if sni == "" {
		sni = nodeHost
	}

	name := fmt.Sprintf("HY2-%d", port)
	tagEscaped := url.QueryEscape(name)
	uri := fmt.Sprintf("hysteria2://%s@%s/?sni=%s&insecure=0#%s",
		url.QueryEscape(password), formatHostPort(nodeHost, port), url.QueryEscape(sni), tagEscaped)

	return []model.FleetProbeNode{
		{
			ID:       fmt.Sprintf("scan_hysteria2_%d", port),
			Name:     name,
			Protocol: "hysteria2",
			Server:   nodeHost,
			Port:     port,
			Domain:   sni,
			ShareURI: uri,
			Source:   "scan",
			RawName:  name,
		},
	}
}

func convertInboundToNode(inbound map[string]any, serverHost, ipv6Host string, cfMap map[int]string) (model.FleetProbeNode, bool) {
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

	nodeHost := serverHost
	lowerTag := strings.ToLower(tag)
	if ipv6Host != "" && (strings.Contains(lowerTag, "v6") || strings.Contains(lowerTag, "ipv6") || strings.Contains(getString(inbound, "listen"), ":")) {
		nodeHost = ipv6Host
	}

	// Cloudflare Tunnel ingress check
	if cfDomain, ok := cfMap[port]; ok && cfDomain != "" {
		uuid := extractUUID(inbound)
		wsPath, _ := extractWSTransport(inbound)
		if wsPath == "" {
			wsPath = "/"
		}
		cfServer := "cf.877774.xyz"
		cfPort := 443
		tagEscaped := url.QueryEscape(name)
		shareURI := fmt.Sprintf("vless://%s@%s:%d?security=tls&encryption=none&type=ws&path=%s&host=%s&sni=%s#%s",
			uuid, cfServer, cfPort, url.QueryEscape(wsPath), url.QueryEscape(cfDomain), url.QueryEscape(cfDomain), tagEscaped)

		return model.FleetProbeNode{
			ID:       id,
			Name:     name,
			Protocol: protocol,
			Server:   cfServer,
			Port:     cfPort,
			Domain:   cfDomain,
			ShareURI: shareURI,
			Source:   "scan",
			RawName:  name,
		}, true
	}

	shareURI, domain := buildInboundShareURI(protocol, name, nodeHost, port, inbound)
	if shareURI == "" {
		return model.FleetProbeNode{}, false
	}

	if domain == "" {
		domain = nodeHost
	}

	return model.FleetProbeNode{
		ID:       id,
		Name:     name,
		Protocol: protocol,
		Server:   nodeHost,
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
		uri := fmt.Sprintf("hysteria2://%s@%s/?sni=%s&insecure=0#%s",
			url.QueryEscape(password), formatHostPort(serverHost, port), url.QueryEscape(sni), tagEscaped)
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
			uri := fmt.Sprintf("vless://%s@%s?security=reality&encryption=none&pbk=%s&sid=%s&sni=%s&fp=chrome&type=tcp&flow=xtls-rprx-vision#%s",
				uuid, formatHostPort(serverHost, port), url.QueryEscape(pbk), url.QueryEscape(sid), url.QueryEscape(sni), tagEscaped)
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
			uri := fmt.Sprintf("vless://%s@%s?security=tls&encryption=none&type=ws&path=%s&host=%s&sni=%s#%s",
				uuid, formatHostPort(serverHost, port), url.QueryEscape(wsPath), url.QueryEscape(wsHost), url.QueryEscape(tlsSNI), tagEscaped)
			return uri, tlsSNI
		}
		// Standard TLS or TCP
		sni = extractSNI(inbound)
		if sni == "" {
			sni = serverHost
		}
		uri := fmt.Sprintf("vless://%s@%s?security=tls&encryption=none&sni=%s#%s",
			uuid, formatHostPort(serverHost, port), url.QueryEscape(sni), tagEscaped)
		return uri, sni

	case "shadowsocks", "ss":
		method, password := extractSSMethodPassword(inbound)
		if method == "" || password == "" {
			return "", ""
		}
		auth := base64.RawURLEncoding.EncodeToString([]byte(method + ":" + password))
		uri := fmt.Sprintf("ss://%s@%s#%s", auth, formatHostPort(serverHost, port), tagEscaped)
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
		uri := fmt.Sprintf("tuic://%s:%s@%s?sni=%s&alpn=h3&congestion_controller=bbr#%s",
			url.QueryEscape(uuid), url.QueryEscape(password), formatHostPort(serverHost, port), url.QueryEscape(sni), tagEscaped)
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
		uri := fmt.Sprintf("trojan://%s@%s?security=tls&sni=%s#%s",
			url.QueryEscape(password), formatHostPort(serverHost, port), url.QueryEscape(sni), tagEscaped)
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
		uri := fmt.Sprintf("anytls://%s@%s?sni=%s#%s",
			url.QueryEscape(password), formatHostPort(serverHost, port), url.QueryEscape(sni), tagEscaped)
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
			if sids, ok := reality["short_id"].([]any); ok && len(sids) > 0 {
				sid = fmt.Sprintf("%v", sids[0])
			} else if sids, ok := reality["short_id"].([]string); ok && len(sids) > 0 {
				sid = sids[0]
			} else {
				sid = getString(reality, "short_id")
			}
			sid = strings.Trim(sid, "[]\"' \t\r\n")
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
			} else if sids, ok := reality["shortIds"].([]string); ok && len(sids) > 0 {
				sid = sids[0]
			}
			sid = strings.Trim(sid, "[]\"' \t\r\n")
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
		switch v := val.(type) {
		case string:
			return strings.TrimSpace(v)
		case []any:
			if len(v) > 0 {
				return strings.TrimSpace(fmt.Sprintf("%v", v[0]))
			}
			return ""
		case []string:
			if len(v) > 0 {
				return strings.TrimSpace(v[0])
			}
			return ""
		default:
			return strings.TrimSpace(fmt.Sprintf("%v", val))
		}
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
