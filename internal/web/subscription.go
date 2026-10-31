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

type SubscriptionTemplate string

const (
	TemplateMinimal  SubscriptionTemplate = "minimal"
	TemplateStandard SubscriptionTemplate = "standard"
	TemplateSmart    SubscriptionTemplate = "smart"
)

func NormalizeSubscriptionTemplate(tpl string) SubscriptionTemplate {
	switch strings.ToLower(strings.TrimSpace(tpl)) {
	case string(TemplateMinimal):
		return TemplateMinimal
	case string(TemplateSmart):
		return TemplateSmart
	default:
		return TemplateStandard
	}
}

type SubscriptionNode struct {
	Node     model.Node
	ShareURI string
}

type RenderSubscriptionOptions struct {
	Title     string
	GroupName string // Used for minimal template, defaults to "Wukong" if empty
	Template  SubscriptionTemplate
	Items     []SubscriptionNode
	Comments  []string
}

func RenderClashSubscription(opts RenderSubscriptionOptions) (string, error) {
	tpl := opts.Template
	if tpl == "" {
		tpl = TemplateStandard
	}

	// Deduplicate node names to ensure valid Clash YAML
	items := make([]SubscriptionNode, len(opts.Items))
	copy(items, opts.Items)
	seenNames := make(map[string]int)
	for i := range items {
		baseName := items[i].Node.Name
		count := seenNames[baseName]
		seenNames[baseName]++
		if count > 0 {
			items[i].Node.Name = fmt.Sprintf("%s (%d)", baseName, count+1)
		}
	}

	var sb strings.Builder

	for _, comment := range opts.Comments {
		trimmed := strings.TrimSpace(comment)
		if trimmed != "" {
			if !strings.HasPrefix(trimmed, "#") {
				sb.WriteString("# ")
			}
			sb.WriteString(trimmed)
			sb.WriteByte('\n')
		}
	}

	sb.WriteString("proxies:\n")
	proxyNames := make([]string, 0, len(items))
	for _, item := range items {
		entry, err := clashProxyYAML(item.Node, item.ShareURI)
		if err != nil {
			continue
		}
		sb.WriteString(entry)
		proxyNames = append(proxyNames, item.Node.Name)
	}

	groupName := opts.GroupName
	if groupName == "" {
		groupName = "Wukong"
	}

	switch tpl {
	case TemplateMinimal:
		renderMinimalGroupsAndRules(&sb, groupName, proxyNames)
	case TemplateSmart:
		renderSmartGroupsAndRules(&sb, proxyNames)
		renderSmartDNS(&sb)
	case TemplateStandard:
		fallthrough
	default:
		renderStandardGroupsAndRules(&sb, proxyNames)
		renderStandardDNS(&sb)
	}

	return sb.String(), nil
}

func renderMinimalGroupsAndRules(sb *strings.Builder, groupName string, proxyNames []string) {
	fmt.Fprintf(sb, "proxy-groups:\n  - name: %s\n    type: select\n    proxies:\n", groupName)
	if len(proxyNames) == 0 {
		sb.WriteString("      - DIRECT\n")
	} else {
		for _, name := range proxyNames {
			fmt.Fprintf(sb, "      - %q\n", name)
		}
	}
	fmt.Fprintf(sb, "rules:\n  - MATCH,%s\n", groupName)
}

func renderStandardGroupsAndRules(sb *strings.Builder, proxyNames []string) {
	sb.WriteString("proxy-groups:\n")

	sb.WriteString("  - name: 🚀 节点选择\n    type: select\n    proxies:\n      - ♻️ 自动选择\n      - 🎯 全球直连\n")
	for _, name := range proxyNames {
		fmt.Fprintf(sb, "      - %q\n", name)
	}

	sb.WriteString("  - name: ♻️ 自动选择\n    type: url-test\n    url: http://cp.cloudflare.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n")
	if len(proxyNames) == 0 {
		sb.WriteString("      - DIRECT\n")
	} else {
		for _, name := range proxyNames {
			fmt.Fprintf(sb, "      - %q\n", name)
		}
	}

	sb.WriteString("  - name: 🎯 全球直连\n    type: select\n    proxies:\n      - DIRECT\n")

	sb.WriteString("  - name: 🛑 广告拦截\n    type: select\n    proxies:\n      - REJECT\n      - DIRECT\n")

	sb.WriteString("  - name: 🐟 漏网之鱼\n    type: select\n    proxies:\n      - 🚀 节点选择\n      - ♻️ 自动选择\n      - 🎯 全球直连\n")
	for _, name := range proxyNames {
		fmt.Fprintf(sb, "      - %q\n", name)
	}

	sb.WriteString("rules:\n")
	sb.WriteString("  - GEOIP,private,DIRECT,no-resolve\n")
	sb.WriteString("  - GEOSITE,category-ads-all,🛑 广告拦截\n")
	sb.WriteString("  - GEOSITE,cn,🎯 全球直连\n")
	sb.WriteString("  - GEOIP,CN,🎯 全球直连\n")
	sb.WriteString("  - MATCH,🐟 漏网之鱼\n")
}

func renderSmartGroupsAndRules(sb *strings.Builder, proxyNames []string) {
	sb.WriteString("proxy-groups:\n")

	sb.WriteString("  - name: 🚀 节点选择\n    type: select\n    proxies:\n      - ♻️ 自动选择\n      - 🎯 全球直连\n")
	for _, name := range proxyNames {
		fmt.Fprintf(sb, "      - %q\n", name)
	}

	sb.WriteString("  - name: ♻️ 自动选择\n    type: url-test\n    url: http://cp.cloudflare.com/generate_204\n    interval: 300\n    tolerance: 50\n    proxies:\n")
	if len(proxyNames) == 0 {
		sb.WriteString("      - DIRECT\n")
	} else {
		for _, name := range proxyNames {
			fmt.Fprintf(sb, "      - %q\n", name)
		}
	}

	sb.WriteString("  - name: 🤖 AI 服务\n    type: select\n    proxies:\n      - 🚀 节点选择\n      - ♻️ 自动选择\n      - 🎯 全球直连\n")
	for _, name := range proxyNames {
		fmt.Fprintf(sb, "      - %q\n", name)
	}

	sb.WriteString("  - name: 🎬 国际流媒体\n    type: select\n    proxies:\n      - 🚀 节点选择\n      - ♻️ 自动选择\n      - 🎯 全球直连\n")
	for _, name := range proxyNames {
		fmt.Fprintf(sb, "      - %q\n", name)
	}

	sb.WriteString("  - name: 🎯 全球直连\n    type: select\n    proxies:\n      - DIRECT\n")

	sb.WriteString("  - name: 🛑 广告拦截\n    type: select\n    proxies:\n      - REJECT\n      - DIRECT\n")

	sb.WriteString("  - name: 🐟 漏网之鱼\n    type: select\n    proxies:\n      - 🚀 节点选择\n      - ♻️ 自动选择\n      - 🎯 全球直连\n")
	for _, name := range proxyNames {
		fmt.Fprintf(sb, "      - %q\n", name)
	}

	sb.WriteString("rules:\n")
	sb.WriteString("  - GEOIP,private,DIRECT,no-resolve\n")
	sb.WriteString("  - GEOSITE,category-ads-all,🛑 广告拦截\n")

	// AI rules
	sb.WriteString("  - GEOSITE,openai,🤖 AI 服务\n")
	sb.WriteString("  - GEOSITE,anthropic,🤖 AI 服务\n")
	sb.WriteString("  - DOMAIN-SUFFIX,oaistatic.com,🤖 AI 服务\n")
	sb.WriteString("  - DOMAIN-SUFFIX,oaiusercontent.com,🤖 AI 服务\n")
	sb.WriteString("  - DOMAIN-SUFFIX,openai.com,🤖 AI 服务\n")
	sb.WriteString("  - DOMAIN-SUFFIX,chatgpt.com,🤖 AI 服务\n")
	sb.WriteString("  - DOMAIN-SUFFIX,anthropic.com,🤖 AI 服务\n")
	sb.WriteString("  - DOMAIN-SUFFIX,claude.ai,🤖 AI 服务\n")

	// Streaming rules
	sb.WriteString("  - GEOSITE,youtube,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,youtube.com,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,googlevideo.com,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,ytimg.com,🎬 国际流媒体\n")
	sb.WriteString("  - GEOSITE,netflix,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,netflix.com,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,netflix.net,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,nflximg.net,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,nflxvideo.net,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,nflxso.net,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,nflxext.com,🎬 国际流媒体\n")
	sb.WriteString("  - GEOSITE,disney,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,disneyplus.com,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,disney-plus.net,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,dssott.com,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,disneystreaming.com,🎬 国际流媒体\n")
	sb.WriteString("  - GEOSITE,spotify,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,spotify.com,🎬 国际流媒体\n")
	sb.WriteString("  - DOMAIN-SUFFIX,scdn.co,🎬 国际流媒体\n")

	// Domestic direct
	sb.WriteString("  - GEOSITE,cn,🎯 全球直连\n")
	sb.WriteString("  - GEOIP,CN,🎯 全球直连\n")

	// Fallback
	sb.WriteString("  - MATCH,🐟 漏网之鱼\n")
}

func renderStandardDNS(sb *strings.Builder) {
	sb.WriteString("dns:\n")
	sb.WriteString("  enable: true\n")
	sb.WriteString("  ipv6: false\n")
	sb.WriteString("  enhanced-mode: fake-ip\n")
	sb.WriteString("  fake-ip-range: 198.18.0.1/16\n")
	sb.WriteString("  fake-ip-filter:\n")
	sb.WriteString("    - \"*.lan\"\n")
	sb.WriteString("    - \"*.local\"\n")
	sb.WriteString("    - \"localhost\"\n")
	sb.WriteString("    - \"*.msftncsi.com\"\n")
	sb.WriteString("    - \"msftconnecttest.com\"\n")
	sb.WriteString("  nameserver:\n")
	sb.WriteString("    - 223.5.5.5\n")
	sb.WriteString("    - 119.29.29.29\n")
	sb.WriteString("    - https://dns.alidns.com/dns-query\n")
	sb.WriteString("  fallback:\n")
	sb.WriteString("    - https://1.1.1.1/dns-query\n")
	sb.WriteString("    - https://8.8.8.8/dns-query\n")
	sb.WriteString("  fallback-filter:\n")
	sb.WriteString("    geoip: true\n")
	sb.WriteString("    geoip-code: CN\n")
	sb.WriteString("    geosite:\n")
	sb.WriteString("      - gfw\n")
	sb.WriteString("    ipcidr:\n")
	sb.WriteString("      - 240.0.0.0/4\n")
}

func renderSmartDNS(sb *strings.Builder) {
	renderStandardDNS(sb)
	sb.WriteString("  nameserver-policy:\n")
	sb.WriteString("    \"geosite:youtube,netflix,disney,spotify\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"geosite:openai,anthropic\": \"https://1.1.1.1/dns-query#🤖 AI 服务\"\n")
	sb.WriteString("    \"+.openai.com\": \"https://1.1.1.1/dns-query#🤖 AI 服务\"\n")
	sb.WriteString("    \"+.chatgpt.com\": \"https://1.1.1.1/dns-query#🤖 AI 服务\"\n")
	sb.WriteString("    \"+.anthropic.com\": \"https://1.1.1.1/dns-query#🤖 AI 服务\"\n")
	sb.WriteString("    \"+.claude.ai\": \"https://1.1.1.1/dns-query#🤖 AI 服务\"\n")
	sb.WriteString("    \"+.oaistatic.com\": \"https://1.1.1.1/dns-query#🤖 AI 服务\"\n")
	sb.WriteString("    \"+.oaiusercontent.com\": \"https://1.1.1.1/dns-query#🤖 AI 服务\"\n")
	sb.WriteString("    \"+.youtube.com\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"+.googlevideo.com\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"+.ytimg.com\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"+.netflix.com\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"+.netflix.net\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"+.nflxvideo.net\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"+.disneyplus.com\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"+.spotify.com\": \"https://1.1.1.1/dns-query#🎬 国际流媒体\"\n")
	sb.WriteString("    \"geosite:cn\":\n")
	sb.WriteString("      - 223.5.5.5\n")
	sb.WriteString("      - 119.29.29.29\n")
}
