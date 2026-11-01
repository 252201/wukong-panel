package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/url"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/store"
)

var privateCIDRs []*net.IPNet

func init() {
	cidrs := []string{
		"127.0.0.0/8",
		"10.0.0.0/8",
		"172.16.0.0/12",
		"192.168.0.0/16",
		"169.254.0.0/16",
		"100.64.0.0/10",
		"198.18.0.0/15",
		"::1/128",
		"::/128",
		"fc00::/7",
		"fe80::/10",
		"0.0.0.0/8",
		"224.0.0.0/4",
		"240.0.0.0/4",
		"ff00::/8",
	}
	for _, cidr := range cidrs {
		_, block, err := net.ParseCIDR(cidr)
		if err == nil {
			privateCIDRs = append(privateCIDRs, block)
		}
	}
}

func isPrivateOrLocalIP(ip net.IP) bool {
	if ip == nil || ip.IsUnspecified() || ip.IsLoopback() || ip.IsLinkLocalUnicast() || ip.IsLinkLocalMulticast() || ip.IsPrivate() {
		return true
	}
	if ip4 := ip.To4(); ip4 != nil {
		if ip4.IsLoopback() || ip4.IsPrivate() || ip4.IsUnspecified() {
			return true
		}
	}
	for _, block := range privateCIDRs {
		if block.Contains(ip) {
			return true
		}
		if ip4 := ip.To4(); ip4 != nil && block.Contains(ip4) {
			return true
		}
	}
	return false
}

func isBlockedHost(host string) bool {
	if host == "" {
		return true
	}
	if strings.EqualFold(host, "localhost") || strings.HasSuffix(strings.ToLower(host), ".local") {
		return true
	}
	if ip := net.ParseIP(host); ip != nil {
		return isPrivateOrLocalIP(ip)
	}
	ips, err := net.LookupIP(host)
	if err == nil {
		for _, ip := range ips {
			if isPrivateOrLocalIP(ip) {
				return true
			}
		}
	}
	return false
}

type ExternalSubscriptionFetcher struct {
	AllowLoopback bool
	Timeout       time.Duration
}

func (f *ExternalSubscriptionFetcher) safeClient(proxyURL string) (*http.Client, error) {
	timeout := f.Timeout
	if timeout <= 0 {
		timeout = 15 * time.Second
	}

	dialer := &net.Dialer{
		Timeout:   10 * time.Second,
		KeepAlive: 30 * time.Second,
	}

	var proxyFunc func(*http.Request) (*url.URL, error)
	var hasProxy bool
	if trimmed := strings.TrimSpace(proxyURL); trimmed != "" {
		if !strings.Contains(trimmed, "://") {
			trimmed = "http://" + trimmed
		}
		p, err := url.Parse(trimmed)
		if err != nil {
			return nil, fmt.Errorf("invalid proxy URL: %w", err)
		}
		scheme := strings.ToLower(p.Scheme)
		if scheme != "http" && scheme != "https" && scheme != "socks5" && scheme != "socks5h" {
			return nil, fmt.Errorf("unsupported proxy scheme %q: must be http, https, socks5, or socks5h", p.Scheme)
		}
		proxyFunc = http.ProxyURL(p)
		hasProxy = true
	}

	transport := &http.Transport{
		Proxy: proxyFunc,
		DialContext: func(ctx context.Context, network, addr string) (net.Conn, error) {
			host, port, err := net.SplitHostPort(addr)
			if err != nil {
				return nil, err
			}

			// If connecting via an outbound proxy, addr is the proxy server itself.
			// Local proxies (127.0.0.1 / localhost) on the panel host are valid egress paths.
			if hasProxy {
				return dialer.DialContext(ctx, network, addr)
			}

			ips, err := net.DefaultResolver.LookupIP(ctx, "ip", host)
			if err != nil {
				return nil, err
			}
			if len(ips) == 0 {
				return nil, fmt.Errorf("no IP resolved for %s", host)
			}

			var validIPs []net.IP
			for _, ip := range ips {
				if !f.AllowLoopback && isPrivateOrLocalIP(ip) {
					return nil, fmt.Errorf("SSRF blocked: host %s resolves to private/loopback IP %s", host, ip.String())
				}
				validIPs = append(validIPs, ip)
			}

			if len(validIPs) == 0 {
				return nil, fmt.Errorf("no usable IP resolved for %s", host)
			}

			var lastErr error
			for _, ip := range validIPs {
				conn, err := dialer.DialContext(ctx, network, net.JoinHostPort(ip.String(), port))
				if err == nil {
					return conn, nil
				}
				lastErr = err
			}

			return nil, lastErr
		},
		TLSHandshakeTimeout: 10 * time.Second,
	}

	return &http.Client{
		Transport: transport,
		Timeout:   timeout,
		CheckRedirect: func(req *http.Request, via []*http.Request) error {
			if len(via) >= 10 {
				return errors.New("stopped after 10 redirects")
			}
			scheme := strings.ToLower(req.URL.Scheme)
			if scheme != "http" && scheme != "https" {
				return fmt.Errorf("SSRF blocked: unsupported redirect scheme %q", req.URL.Scheme)
			}
			if !f.AllowLoopback && isBlockedHost(req.URL.Hostname()) {
				return fmt.Errorf("SSRF blocked: redirect target %s is private or loopback", req.URL.Hostname())
			}
			return nil
		},
	}, nil
}

func (f *ExternalSubscriptionFetcher) Fetch(ctx context.Context, sub model.ExternalSubscription) ([]byte, http.Header, error) {
	subURL := strings.TrimSpace(sub.URL)
	rawContent := strings.TrimSpace(sub.RawContent)

	// Direct Paste / Raw Content Mode:
	if subURL == "manual" || subURL == "" {
		if rawContent == "" {
			return nil, nil, errors.New("配置内容为空，请直接粘贴节点链接或订阅配置")
		}
		return []byte(rawContent), make(http.Header), nil
	}

	parsedTarget, err := url.Parse(subURL)
	if err != nil {
		return nil, nil, fmt.Errorf("invalid subscription URL: %w", err)
	}
	scheme := strings.ToLower(parsedTarget.Scheme)
	if scheme != "http" && scheme != "https" {
		return nil, nil, errors.New("invalid subscription URL scheme: must be http or https")
	}

	if !f.AllowLoopback && isBlockedHost(parsedTarget.Hostname()) {
		return nil, nil, fmt.Errorf("SSRF blocked: host %s resolves to private/loopback IP", parsedTarget.Hostname())
	}

	req, err := http.NewRequestWithContext(ctx, http.MethodGet, subURL, nil)
	if err != nil {
		return nil, nil, err
	}

	ua := strings.TrimSpace(sub.UserAgent)
	if ua == "" {
		ua = "ClashMeta/v1.18.0"
	}
	req.Header.Set("User-Agent", ua)
	req.Header.Set("Accept", "*/*")

	client, err := f.safeClient(sub.ProxyURL)
	if err != nil {
		return nil, nil, err
	}
	resp, err := client.Do(req)
	if err != nil {
		return nil, nil, err
	}
	defer resp.Body.Close()

	if resp.StatusCode < 200 || resp.StatusCode >= 300 {
		return nil, resp.Header, fmt.Errorf("HTTP error %d %s", resp.StatusCode, resp.Status)
	}

	// 10MB limit to prevent memory exhaustion
	limitReader := io.LimitReader(resp.Body, 10*1024*1024)
	body, err := io.ReadAll(limitReader)
	if err != nil {
		return nil, resp.Header, err
	}

	return body, resp.Header, nil
}

type ExternalUserinfo struct {
	UploadBytes   int64
	DownloadBytes int64
	TotalBytes    int64
	ExpiresAt     string
}

func ParseSubscriptionUserinfo(header http.Header) ExternalUserinfo {
	info := ExternalUserinfo{}
	raw := header.Get("Subscription-Userinfo")
	if raw == "" {
		return info
	}

	parts := strings.Split(raw, ";")
	for _, part := range parts {
		kv := strings.SplitN(strings.TrimSpace(part), "=", 2)
		if len(kv) != 2 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(kv[0]))
		v := strings.TrimSpace(kv[1])
		switch k {
		case "upload":
			info.UploadBytes, _ = strconv.ParseInt(v, 10, 64)
		case "download":
			info.DownloadBytes, _ = strconv.ParseInt(v, 10, 64)
		case "total":
			info.TotalBytes, _ = strconv.ParseInt(v, 10, 64)
		case "expire":
			if sec, err := strconv.ParseInt(v, 10, 64); err == nil && sec > 0 {
				info.ExpiresAt = time.Unix(sec, 0).UTC().Format(time.RFC3339)
			} else {
				info.ExpiresAt = v
			}
		}
	}
	return info
}

var (
	trafficPairRegex   = regexp.MustCompile(`(?i)(?:traffic|流量|剩余流量|已用流量)[\s:：]+([0-9.]+\s*[KMGT]?B)\s*[/／]\s*([0-9.]+\s*[KMGT]?B)`)
	trafficSingleRegex = regexp.MustCompile(`(?i)(?:traffic|流量|剩余流量|已用流量)[\s:：]+([0-9.]+\s*[KMGT]?B)`)
	expireRegex        = regexp.MustCompile(`(?i)(?:expire|expires|expired|到期|到期时间|过期时间|套餐到期)[\s:：]+(\d{4}[-/]\d{1,2}[-/]\d{1,2}(?:\s+\d{1,2}:\d{2}(?::\d{2})?)?)`)
)

func parseBytesFromString(s string) int64 {
	s = strings.TrimSpace(strings.ToUpper(s))
	multiplier := int64(1)
	if strings.HasSuffix(s, "TB") {
		multiplier = 1024 * 1024 * 1024 * 1024
		s = strings.TrimSpace(strings.TrimSuffix(s, "TB"))
	} else if strings.HasSuffix(s, "GB") {
		multiplier = 1024 * 1024 * 1024
		s = strings.TrimSpace(strings.TrimSuffix(s, "GB"))
	} else if strings.HasSuffix(s, "MB") {
		multiplier = 1024 * 1024
		s = strings.TrimSpace(strings.TrimSuffix(s, "MB"))
	} else if strings.HasSuffix(s, "KB") {
		multiplier = 1024
		s = strings.TrimSpace(strings.TrimSuffix(s, "KB"))
	} else if strings.HasSuffix(s, "B") {
		s = strings.TrimSpace(strings.TrimSuffix(s, "B"))
	}
	f, err := strconv.ParseFloat(s, 64)
	if err != nil || f < 0 {
		return 0
	}
	return int64(f * float64(multiplier))
}

func isDummyAnnouncementNode(name string) (bool, ExternalUserinfo) {
	nameTrimmed := strings.TrimSpace(name)
	nameLower := strings.ToLower(nameTrimmed)
	info := ExternalUserinfo{}

	if m := trafficPairRegex.FindStringSubmatch(nameTrimmed); len(m) == 3 {
		info.DownloadBytes = parseBytesFromString(m[1])
		info.TotalBytes = parseBytesFromString(m[2])
		return true, info
	}
	if m := trafficSingleRegex.FindStringSubmatch(nameTrimmed); len(m) == 2 {
		info.TotalBytes = parseBytesFromString(m[1])
		return true, info
	}
	if m := expireRegex.FindStringSubmatch(nameTrimmed); len(m) == 2 {
		info.ExpiresAt = strings.ReplaceAll(m[1], "/", "-")
		return true, info
	}

	announcementPrefixes := []string{
		"traffic:", "traffic：", "expire:", "expire：", "expires:", "expired:",
		"剩余流量", "到期时间", "过期时间", "套餐到期", "官网", "群组", "重置日",
		"距离重置", "下次重置", "公告", "通知", "提示", "tg群", "telegram",
		"防失联", "客服", "发布页", "网站", "更新时间",
	}
	for _, prefix := range announcementPrefixes {
		if strings.HasPrefix(nameLower, prefix) || strings.HasPrefix(nameTrimmed, prefix) {
			return true, info
		}
	}

	if strings.Contains(nameLower, "expire date") || strings.Contains(nameLower, "traffic info") ||
		strings.Contains(nameLower, "reset day") || strings.Contains(nameLower, "剩余天数") {
		return true, info
	}

	return false, info
}

func ParseExternalSubscription(raw []byte, header http.Header, subID string) ([]model.Node, ExternalUserinfo, error) {
	userinfo := ParseSubscriptionUserinfo(header)
	content := string(raw)

	var rawNodes []model.Node
	// 1. Try Clash YAML first if content contains proxies:
	if strings.Contains(content, "proxies:") || strings.Contains(content, "Proxy:") {
		rawNodes = parseClashProxiesYAML(content, subID)
	}

	// 2. Try Base64 or URI list
	if len(rawNodes) == 0 {
		rawNodes = parseBase64OrURIList(content, subID)
	}

	if len(rawNodes) == 0 {
		return nil, userinfo, errors.New("unable to parse any valid proxy nodes from subscription content")
	}

	var validNodes []model.Node
	for _, node := range rawNodes {
		isDummy, extracted := isDummyAnnouncementNode(node.Name)
		if isDummy {
			if userinfo.TotalBytes == 0 && extracted.TotalBytes > 0 {
				userinfo.TotalBytes = extracted.TotalBytes
				userinfo.DownloadBytes = extracted.DownloadBytes
				userinfo.UploadBytes = extracted.UploadBytes
			}
			if userinfo.ExpiresAt == "" && extracted.ExpiresAt != "" {
				userinfo.ExpiresAt = extracted.ExpiresAt
			}
			continue
		}
		if node.Server == "127.0.0.1" || node.Server == "0.0.0.0" || strings.EqualFold(node.Server, "localhost") {
			continue
		}
		validNodes = append(validNodes, node)
	}

	if len(validNodes) == 0 {
		return nil, userinfo, errors.New("subscription only contained announcement or dummy nodes")
	}

	return validNodes, userinfo, nil
}

func parseFlowMapping(line string) map[string]string {
	start := strings.Index(line, "{")
	end := strings.LastIndex(line, "}")
	if start < 0 || end <= start {
		return nil
	}
	content := line[start+1 : end]
	res := make(map[string]string)
	var tokens []string
	var cur strings.Builder
	inQuotes := false
	var quoteChar rune
	for _, r := range content {
		if (r == '"' || r == '\'') && !inQuotes {
			inQuotes = true
			quoteChar = r
			cur.WriteRune(r)
		} else if inQuotes && r == quoteChar {
			inQuotes = false
			cur.WriteRune(r)
		} else if r == ',' && !inQuotes {
			tokens = append(tokens, cur.String())
			cur.Reset()
		} else {
			cur.WriteRune(r)
		}
	}
	if cur.Len() > 0 {
		tokens = append(tokens, cur.String())
	}
	for _, t := range tokens {
		t = strings.TrimSpace(t)
		colon := strings.Index(t, ":")
		if colon > 0 {
			k := strings.ToLower(strings.TrimSpace(t[:colon]))
			v := strings.TrimSpace(t[colon+1:])
			v = strings.Trim(v, `"' `)
			res[k] = v
		}
	}
	return res
}

func parseClashProxiesYAML(content string, subID string) []model.Node {
	lines := strings.Split(content, "\n")
	inProxies := false
	var nodes []model.Node

	type proxyItem struct {
		name        string
		pType       string
		server      string
		port        int
		password    string
		uuid        string
		cipher      string
		sni         string
		flow        string
		fp          string
		pbk         string
		sid         string
		path        string
		host        string
		insecure    bool
		alpn        string
		udp         bool
		network     string
		subMapName  string
	}

	var current *proxyItem

	saveCurrent := func() {
		if current == nil || current.name == "" || current.server == "" || current.pType == "" {
			return
		}
		if current.pType == "hy2" {
			current.pType = "hysteria2"
		}
		if current.port <= 0 {
			current.port = 443
		}
		if current.sni == "" {
			current.sni = current.server
		}

		node := model.Node{
			ID:         fmt.Sprintf("ext-%s-%d", subID, len(nodes)+1),
			Name:       current.name,
			Protocol:   current.pType,
			Server:     current.server,
			ListenPort: current.port,
			Domain:     current.sni,
			Status:     "active",
		}

		// Rebuild standard share URI so it can be exported to Base64 and Sing-box
		switch current.pType {
		case "ss", "shadowsocks":
			cipher := current.cipher
			if cipher == "" {
				cipher = "2022-blake3-aes-128-gcm"
			}
			userinfo := base64.RawURLEncoding.EncodeToString([]byte(cipher + ":" + current.password))
			node.ShareURI = fmt.Sprintf("ss://%s@%s:%d#%s", userinfo, current.server, current.port, url.QueryEscape(current.name))

		case "hysteria2", "hy2":
			node.Protocol = "hysteria2"
			query := "sni=" + url.QueryEscape(current.sni)
			if current.insecure {
				query += "&insecure=1"
			}
			node.ShareURI = fmt.Sprintf("hysteria2://%s@%s:%d/?%s#%s", url.QueryEscape(current.password), current.server, current.port, query, url.QueryEscape(current.name))

		case "trojan":
			query := "security=tls&sni=" + url.QueryEscape(current.sni)
			if current.insecure {
				query += "&allowInsecure=1"
			}
			node.ShareURI = fmt.Sprintf("trojan://%s@%s:%d?%s#%s", url.QueryEscape(current.password), current.server, current.port, query, url.QueryEscape(current.name))

		case "tuic":
			query := fmt.Sprintf("congestion_control=bbr&udp_relay_mode=native&alpn=h3&sni=%s", url.QueryEscape(current.sni))
			if current.insecure {
				query += "&allow_insecure=1"
			}
			node.ShareURI = fmt.Sprintf("tuic://%s:%s@%s:%d?%s#%s", url.QueryEscape(current.uuid), url.QueryEscape(current.password), current.server, current.port, query, url.QueryEscape(current.name))

		case "vless":
			if current.pbk != "" {
				flow := current.flow
				if flow == "" {
					flow = "xtls-rprx-vision"
				}
				fp := current.fp
				if fp == "" {
					fp = "chrome"
				}
				query := fmt.Sprintf("encryption=none&flow=%s&security=reality&sni=%s&fp=%s&pbk=%s&sid=%s&type=tcp", flow, url.QueryEscape(current.sni), fp, url.QueryEscape(current.pbk), url.QueryEscape(current.sid))
				node.ShareURI = fmt.Sprintf("vless://%s@%s:%d?%s#%s", url.QueryEscape(current.uuid), current.server, current.port, query, url.QueryEscape(current.name))
			} else if current.network == "ws" || current.path != "" {
				pathVal := current.path
				if pathVal == "" {
					pathVal = "/"
				}
				hostVal := current.host
				if hostVal == "" {
					hostVal = current.sni
				}
				query := fmt.Sprintf("encryption=none&security=tls&sni=%s&fp=chrome&type=ws&host=%s&path=%s", url.QueryEscape(current.sni), url.QueryEscape(hostVal), url.QueryEscape(pathVal))
				node.ShareURI = fmt.Sprintf("vless://%s@%s:%d?%s#%s", url.QueryEscape(current.uuid), current.server, current.port, query, url.QueryEscape(current.name))
			} else {
				query := fmt.Sprintf("encryption=none&security=tls&sni=%s", url.QueryEscape(current.sni))
				node.ShareURI = fmt.Sprintf("vless://%s@%s:%d?%s#%s", url.QueryEscape(current.uuid), current.server, current.port, query, url.QueryEscape(current.name))
			}

		case "vmess":
			netType := current.network
			if netType == "" {
				netType = "tcp"
			}
			vm := map[string]any{
				"v":    "2",
				"ps":   current.name,
				"add":  current.server,
				"port": current.port,
				"id":   current.uuid,
				"aid":  0,
				"scy":  "auto",
				"net":  netType,
				"type": "none",
				"host": current.host,
				"path": current.path,
				"tls":  "tls",
				"sni":  current.sni,
			}
			vmBytes, _ := json.Marshal(vm)
			node.ShareURI = "vmess://" + base64.StdEncoding.EncodeToString(vmBytes)
		}

		nodes = append(nodes, node)
	}

	for _, line := range lines {
		trimmed := strings.TrimSpace(line)
		if trimmed == "" || strings.HasPrefix(trimmed, "#") {
			continue
		}

		if strings.HasPrefix(trimmed, "proxies:") || strings.HasPrefix(trimmed, "Proxy:") {
			inProxies = true
			continue
		}

		if inProxies && !strings.HasPrefix(line, " ") && !strings.HasPrefix(line, "\t") && !strings.HasPrefix(trimmed, "-") {
			if strings.HasSuffix(trimmed, ":") {
				// Left the proxies block
				break
			}
		}

		if !inProxies {
			continue
		}

		// Handle inline flow style: - { name: ..., server: ... }
		if strings.HasPrefix(trimmed, "-") && strings.Contains(trimmed, "{") && strings.Contains(trimmed, "}") {
			saveCurrent()
			current = nil
			flowMap := parseFlowMapping(trimmed)
			if len(flowMap) > 0 {
				item := &proxyItem{
					name:     flowMap["name"],
					pType:    strings.ToLower(flowMap["type"]),
					server:   flowMap["server"],
					password: flowMap["password"],
					uuid:     flowMap["uuid"],
					cipher:   flowMap["cipher"],
					sni:      flowMap["sni"],
					flow:     flowMap["flow"],
					fp:       flowMap["client-fingerprint"],
					pbk:      flowMap["public-key"],
					sid:      flowMap["short-id"],
					path:     flowMap["path"],
					host:     flowMap["host"],
					network:  strings.ToLower(flowMap["network"]),
					insecure: flowMap["skip-cert-verify"] == "true" || flowMap["skip-cert-verify"] == "1",
				}
				if item.sni == "" {
					item.sni = flowMap["servername"]
				}
				if port, err := strconv.Atoi(flowMap["port"]); err == nil {
					item.port = port
				}
				current = item
				saveCurrent()
				current = nil
			}
			continue
		}

		if strings.HasPrefix(trimmed, "- ") {
			saveCurrent()
			current = &proxyItem{}
			trimmed = strings.TrimSpace(strings.TrimPrefix(trimmed, "- "))
		}

		if current == nil {
			continue
		}

		// Check for submap
		if strings.HasPrefix(line, "    ") && strings.HasSuffix(trimmed, ":") {
			current.subMapName = strings.TrimSuffix(trimmed, ":")
			continue
		}

		colonIdx := strings.Index(trimmed, ":")
		if colonIdx <= 0 {
			continue
		}
		k := strings.ToLower(strings.TrimSpace(trimmed[:colonIdx]))
		v := strings.TrimSpace(trimmed[colonIdx+1:])
		v = strings.Trim(v, `"'`)

		if strings.HasPrefix(line, "      ") {
			// Submap properties
			switch current.subMapName {
			case "reality-opts":
				switch k {
				case "public-key":
					current.pbk = v
				case "short-id":
					current.sid = v
				}
			case "ws-opts":
				switch k {
				case "path":
					current.path = v
				case "host":
					current.host = v
				}
			}
			continue
		}

		switch k {
		case "name":
			current.name = v
		case "type":
			current.pType = strings.ToLower(v)
		case "server":
			current.server = v
		case "port":
			current.port, _ = strconv.Atoi(v)
		case "password":
			current.password = v
		case "uuid":
			current.uuid = v
		case "cipher":
			current.cipher = v
		case "sni", "servername":
			current.sni = v
		case "flow":
			current.flow = v
		case "client-fingerprint":
			current.fp = v
		case "network":
			current.network = strings.ToLower(v)
		case "skip-cert-verify":
			current.insecure = v == "true" || v == "1"
		}
	}
	saveCurrent()
	return nodes
}

func decodeBase64Clean(raw string) ([]byte, error) {
	clean := strings.Map(func(r rune) rune {
		if r == '\r' || r == '\n' || r == '\t' || r == ' ' {
			return -1
		}
		return r
	}, strings.TrimSpace(raw))

	if b, err := base64.StdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.RawStdEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.URLEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	if b, err := base64.RawURLEncoding.DecodeString(clean); err == nil {
		return b, nil
	}
	return nil, errors.New("invalid base64")
}

func parseBase64OrURIList(content string, subID string) []model.Node {
	raw := strings.TrimSpace(content)
	text := content
	if decoded, err := decodeBase64Clean(raw); err == nil && (strings.Contains(string(decoded), "://") || len(decoded) > 0) {
		text = string(decoded)
	}

	lines := strings.Split(text, "\n")
	var nodes []model.Node

	for _, line := range lines {
		line = strings.TrimSpace(line)
		if line == "" || strings.HasPrefix(line, "#") {
			continue
		}
		node, err := parseSingleURI(line, subID, len(nodes)+1)
		if err == nil && node.Server != "" {
			nodes = append(nodes, node)
		}
	}
	return nodes
}

func parseSingleURI(uriStr, subID string, index int) (model.Node, error) {
	node := model.Node{
		ID:       fmt.Sprintf("ext-%s-%d", subID, index),
		ShareURI: uriStr,
		Status:   "active",
	}

	if strings.HasPrefix(strings.ToLower(uriStr), "vmess://") {
		encoded := strings.TrimPrefix(uriStr, "vmess://")
		decoded, err := decodeBase64Clean(encoded)
		if err != nil {
			return node, errors.New("invalid vmess uri")
		}
		var vm map[string]any
		if err := json.Unmarshal(decoded, &vm); err != nil {
			return node, errors.New("invalid vmess json")
		}

		name, _ := vm["ps"].(string)
		server, _ := vm["add"].(string)
		portVal := fmt.Sprintf("%v", vm["port"])
		port, _ := strconv.Atoi(portVal)
		sni, _ := vm["sni"].(string)
		if sni == "" {
			sni, _ = vm["host"].(string)
		}

		node.Name = name
		node.Protocol = "vmess"
		node.Server = server
		node.ListenPort = port
		node.Domain = sni
		if node.Name == "" {
			node.Name = fmt.Sprintf("VMess-%s:%d", server, port)
		}
		return node, nil
	}

	parsed, err := url.Parse(uriStr)
	if err != nil {
		return node, err
	}

	protocol := strings.ToLower(parsed.Scheme)
	if protocol == "hy2" {
		protocol = "hysteria2"
	}
	node.Protocol = protocol
	node.Server = parsed.Hostname()
	if p, err := strconv.Atoi(parsed.Port()); err == nil {
		node.ListenPort = p
	}

	// Support legacy single-base64 Shadowsocks URI: ss://BASE64(method:password@server:port)#name
	if (protocol == "ss" || protocol == "shadowsocks") && parsed.User == nil && !strings.Contains(parsed.Host, "@") {
		if dec, err := decodeBase64Clean(parsed.Host); err == nil {
			decStr := string(dec)
			if atIdx := strings.LastIndex(decStr, "@"); atIdx > 0 {
				userInfo := decStr[:atIdx]
				serverPort := decStr[atIdx+1:]
				host, portStr, err := net.SplitHostPort(serverPort)
				if err == nil {
					node.Server = host
					if p, err := strconv.Atoi(portStr); err == nil {
						node.ListenPort = p
					}
					b64User := base64.RawURLEncoding.EncodeToString([]byte(userInfo))
					nameFragment := ""
					if parsed.Fragment != "" {
						nameFragment = "#" + parsed.Fragment
					}
					node.ShareURI = fmt.Sprintf("ss://%s@%s:%d%s", b64User, node.Server, node.ListenPort, nameFragment)
				}
			}
		}
	}

	// Name from fragment
	name := parsed.Fragment
	if unescaped, err := url.QueryUnescape(name); err == nil && unescaped != "" {
		name = unescaped
	}
	if name == "" {
		name = fmt.Sprintf("%s-%s:%d", strings.ToUpper(protocol), node.Server, node.ListenPort)
	}
	node.Name = name

	query := parsed.Query()
	sni := query.Get("sni")
	if sni == "" {
		sni = query.Get("host")
	}
	if sni == "" {
		sni = node.Server
	}
	node.Domain = sni

	return node, nil
}

// Web API Handlers

func (s *Server) listExternalSubscriptions(w http.ResponseWriter, r *http.Request, session store.Session) {
	subs, err := s.store.ExternalSubscriptions()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, subs)
}

func (s *Server) createExternalSubscription(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input model.ExternalSubscription
	if !decode(w, r, &input) {
		return
	}

	input.Name = strings.TrimSpace(input.Name)
	input.URL = strings.TrimSpace(input.URL)
	input.ProxyURL = strings.TrimSpace(input.ProxyURL)
	input.RawContent = strings.TrimSpace(input.RawContent)

	if input.Name == "" {
		writeError(w, http.StatusBadRequest, "订阅名称不能为空")
		return
	}
	if input.URL == "" && input.RawContent == "" {
		writeError(w, http.StatusBadRequest, "订阅链接与直接粘贴内容至少需填写一项")
		return
	}
	if input.URL == "" {
		input.URL = "manual"
	}

	if input.ID == "" {
		token, _ := security.RandomToken(12)
		input.ID = "sub-" + token
	}
	if input.SyncIntervalHours <= 0 {
		input.SyncIntervalHours = 12
	}
	input.Enabled = true

	// Initial save
	if err := s.store.SaveExternalSubscription(input); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	// Perform immediate sync
	fetcher := &ExternalSubscriptionFetcher{Timeout: 15 * time.Second}
	body, header, fetchErr := fetcher.Fetch(r.Context(), input)
	var nodes []model.Node
	var userinfo ExternalUserinfo
	var parseErr error
	if fetchErr == nil {
		nodes, userinfo, parseErr = ParseExternalSubscription(body, header, input.ID)
	}

	finalErr := fetchErr
	if finalErr == nil {
		finalErr = parseErr
	}

	_ = s.store.UpdateExternalSubscriptionSyncResult(input.ID, userinfo.UploadBytes, userinfo.DownloadBytes, userinfo.TotalBytes, userinfo.ExpiresAt, nodes, finalErr)

	saved, err := s.store.ExternalSubscription(input.ID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.Audit(session.Username, "create_external_subscription", "external_subscription", input.Name)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) updateExternalSubscription(w http.ResponseWriter, r *http.Request, session store.Session) {
	id := r.PathValue("id")
	existing, err := s.store.ExternalSubscription(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "外部订阅不存在")
		return
	}

	var input struct {
		Name              *string   `json:"name"`
		URL               *string   `json:"url"`
		ProxyURL          *string   `json:"proxyUrl"`
		RawContent        *string   `json:"rawContent"`
		UserAgent         *string   `json:"userAgent"`
		Enabled           *bool     `json:"enabled"`
		AutoSync          *bool     `json:"autoSync"`
		SyncIntervalHours *int      `json:"syncIntervalHours"`
		SelectedNodeIDs   *[]string `json:"selectedNodeIds"`
	}
	if !decode(w, r, &input) {
		return
	}

	if input.Name != nil && strings.TrimSpace(*input.Name) != "" {
		existing.Name = strings.TrimSpace(*input.Name)
	}
	shouldResync := false
	if input.URL != nil {
		newURL := strings.TrimSpace(*input.URL)
		if newURL == "" && existing.RawContent != "" {
			newURL = "manual"
		}
		if newURL != existing.URL {
			existing.URL = newURL
			shouldResync = true
		}
	}
	if input.ProxyURL != nil {
		newProxy := strings.TrimSpace(*input.ProxyURL)
		if newProxy != existing.ProxyURL {
			existing.ProxyURL = newProxy
			shouldResync = true
		}
	}
	if input.RawContent != nil {
		newRaw := strings.TrimSpace(*input.RawContent)
		if newRaw != existing.RawContent {
			existing.RawContent = newRaw
			if existing.URL == "manual" || existing.URL == "" {
				shouldResync = true
			}
		}
	}
	if input.UserAgent != nil {
		existing.UserAgent = strings.TrimSpace(*input.UserAgent)
	}
	if input.Enabled != nil {
		existing.Enabled = *input.Enabled
	}
	if input.AutoSync != nil {
		existing.AutoSync = *input.AutoSync
	}
	if input.SyncIntervalHours != nil && *input.SyncIntervalHours > 0 {
		existing.SyncIntervalHours = *input.SyncIntervalHours
	}
	if input.SelectedNodeIDs != nil {
		existing.SelectedNodeIDs = *input.SelectedNodeIDs
	}

	if err := s.store.SaveExternalSubscription(existing); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	if shouldResync {
		fetcher := &ExternalSubscriptionFetcher{Timeout: 15 * time.Second}
		body, header, fetchErr := fetcher.Fetch(r.Context(), existing)
		var nodes []model.Node
		var userinfo ExternalUserinfo
		var parseErr error
		if fetchErr == nil {
			nodes, userinfo, parseErr = ParseExternalSubscription(body, header, existing.ID)
		}
		finalErr := fetchErr
		if finalErr == nil {
			finalErr = parseErr
		}
		_ = s.store.UpdateExternalSubscriptionSyncResult(existing.ID, userinfo.UploadBytes, userinfo.DownloadBytes, userinfo.TotalBytes, userinfo.ExpiresAt, nodes, finalErr)
	}

	saved, err := s.store.ExternalSubscription(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.Audit(session.Username, "update_external_subscription", "external_subscription", existing.Name)
	writeJSON(w, http.StatusOK, saved)
}

func (s *Server) deleteExternalSubscription(w http.ResponseWriter, r *http.Request, session store.Session) {
	id := r.PathValue("id")
	existing, err := s.store.ExternalSubscription(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "外部订阅不存在")
		return
	}

	if err := s.store.DeleteExternalSubscription(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.Audit(session.Username, "delete_external_subscription", "external_subscription", existing.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) syncExternalSubscription(w http.ResponseWriter, r *http.Request, session store.Session) {
	id := r.PathValue("id")
	sub, err := s.store.ExternalSubscription(id)
	if err != nil {
		writeError(w, http.StatusNotFound, "外部订阅不存在")
		return
	}

	fetcher := &ExternalSubscriptionFetcher{Timeout: 15 * time.Second}
	body, header, fetchErr := fetcher.Fetch(r.Context(), sub)
	var nodes []model.Node
	var userinfo ExternalUserinfo
	var parseErr error
	if fetchErr == nil {
		nodes, userinfo, parseErr = ParseExternalSubscription(body, header, sub.ID)
	}

	finalErr := fetchErr
	if finalErr == nil {
		finalErr = parseErr
	}

	_ = s.store.UpdateExternalSubscriptionSyncResult(sub.ID, userinfo.UploadBytes, userinfo.DownloadBytes, userinfo.TotalBytes, userinfo.ExpiresAt, nodes, finalErr)

	updated, err := s.store.ExternalSubscription(id)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.Audit(session.Username, "sync_external_subscription", "external_subscription", sub.Name)
	writeJSON(w, http.StatusOK, updated)
}

// StartExternalSubscriptionBackgroundSync starts a background loop to periodically sync subscriptions
func (s *Server) StartExternalSubscriptionBackgroundSync(ctx context.Context) {
	ticker := time.NewTicker(5 * time.Minute)
	go func() {
		defer ticker.Stop()
		for {
			select {
			case <-ctx.Done():
				return
			case <-ticker.C:
				subs, err := s.store.ExternalSubscriptions()
				if err != nil {
					continue
				}
				fetcher := &ExternalSubscriptionFetcher{Timeout: 15 * time.Second}
				for _, sub := range subs {
					if !sub.Enabled || !sub.AutoSync {
						continue
					}
					interval := time.Duration(sub.SyncIntervalHours) * time.Hour
					if interval <= 0 {
						interval = 12 * time.Hour
					}
					if !sub.LastSyncAt.IsZero() && time.Since(sub.LastSyncAt) < interval {
						continue
					}
					body, header, fetchErr := fetcher.Fetch(ctx, sub)
					var nodes []model.Node
					var userinfo ExternalUserinfo
					var parseErr error
					if fetchErr == nil {
						nodes, userinfo, parseErr = ParseExternalSubscription(body, header, sub.ID)
					}
					finalErr := fetchErr
					if finalErr == nil {
						finalErr = parseErr
					}
					_ = s.store.UpdateExternalSubscriptionSyncResult(sub.ID, userinfo.UploadBytes, userinfo.DownloadBytes, userinfo.TotalBytes, userinfo.ExpiresAt, nodes, finalErr)
				}
			}
		}
	}()
}
