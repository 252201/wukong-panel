package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"path"
	"strconv"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
)

type ClientFormat string

const (
	FormatAuto    ClientFormat = "auto"
	FormatClash   ClientFormat = "clash"
	FormatBase64  ClientFormat = "base64"
	FormatSingbox ClientFormat = "singbox"
)

func NormalizeClientFormat(val string) ClientFormat {
	switch strings.ToLower(strings.TrimSpace(val)) {
	case "clash", "meta", "mihomo", "stash", "yaml", "yml":
		return FormatClash
	case "base64", "b64", "v2ray", "v2rayn", "v2rayng", "shadowrocket", "happ", "raw", "txt":
		return FormatBase64
	case "singbox", "sing-box", "sbox", "json":
		return FormatSingbox
	default:
		return FormatAuto
	}
}

// DetectClientFormat negotiates the response format according to:
// 1. Explicit query param (?format=... or ?target=...)
// 2. URL path extension (.yaml, .txt, .json)
// 3. User-Agent heuristic detection
func DetectClientFormat(r *http.Request) ClientFormat {
	if format := r.URL.Query().Get("format"); format != "" {
		if normalized := NormalizeClientFormat(format); normalized != FormatAuto {
			return normalized
		}
	}
	if target := r.URL.Query().Get("target"); target != "" {
		if normalized := NormalizeClientFormat(target); normalized != FormatAuto {
			return normalized
		}
	}

	ext := strings.ToLower(path.Ext(r.URL.Path))
	switch ext {
	case ".yaml", ".yml":
		return FormatClash
	case ".txt":
		return FormatBase64
	case ".json":
		return FormatSingbox
	}

	ua := strings.ToLower(r.UserAgent())
	switch {
	case strings.Contains(ua, "sing-box") || strings.Contains(ua, "sfi/") || strings.Contains(ua, "sfa/") || strings.Contains(ua, "sfm/"):
		return FormatSingbox
	case strings.Contains(ua, "clash") || strings.Contains(ua, "mihomo") || strings.Contains(ua, "stash") || strings.Contains(ua, "meta"):
		return FormatClash
	case strings.Contains(ua, "shadowrocket") || strings.Contains(ua, "v2ray") || strings.Contains(ua, "happ") || strings.Contains(ua, "quantumult") || strings.Contains(ua, "surge") || strings.Contains(ua, "loon"):
		return FormatBase64
	case strings.Contains(ua, "mozilla/") || strings.Contains(ua, "chrome/") || strings.Contains(ua, "safari/") || strings.Contains(ua, "firefox/") || strings.Contains(ua, "edge/"):
		return FormatClash
	default:
		return FormatBase64
	}
}

func RenderBase64Subscription(opts RenderSubscriptionOptions) (string, error) {
	var uris []string
	for _, item := range opts.Items {
		uri := strings.TrimSpace(item.ShareURI)
		if uri == "" {
			continue
		}
		uris = append(uris, uri)
	}
	raw := strings.Join(uris, "\n")
	if len(uris) > 0 {
		raw += "\n"
	}
	return base64.StdEncoding.EncodeToString([]byte(raw)), nil
}

func singboxOutbound(node model.Node, shareURI string, dialerProxy ...string) (map[string]any, error) {
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
			return nil, errors.New("invalid vmess share URI")
		}
		var vm map[string]any
		if err := json.Unmarshal(decoded, &vm); err != nil {
			return nil, errors.New("invalid vmess json")
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
		netType, _ := vm["net"].(string)
		tls := vm["tls"] == "tls"
		path, _ := vm["path"].(string)
		hostHdr, _ := vm["host"].(string)

		outbound := map[string]any{
			"type":        "vmess",
			"tag":         node.Name,
			"server":      server,
			"server_port": port,
			"uuid":        uuid,
			"security":    "auto",
			"alter_id":    0,
		}
		if tls {
			outbound["tls"] = map[string]any{
				"enabled":     true,
				"server_name": server,
			}
		}
		if netType == "ws" {
			outbound["transport"] = map[string]any{
				"type": "ws",
				"path": path,
				"headers": map[string]any{
					"Host": hostHdr,
				},
			}
		}
		if len(dialerProxy) > 0 && dialerProxy[0] != "" {
			outbound["detour"] = dialerProxy[0]
		}
		return outbound, nil
	}

	parsed, err := url.Parse(shareURI)
	if err != nil || parsed.User == nil {
		return nil, errors.New("invalid share URI")
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

	outbound := map[string]any{
		"tag":         node.Name,
		"server":      server,
		"server_port": port,
	}

	switch strings.ToLower(node.Protocol) {
	case "hysteria2", "hy2":
		outbound["type"] = "hysteria2"
		outbound["password"] = parsed.User.Username()
		tlsMap := map[string]any{
			"enabled":     true,
			"server_name": sni,
		}
		if insecure {
			tlsMap["insecure"] = true
		}
		outbound["tls"] = tlsMap

	case "vless":
		outbound["type"] = "vless"
		outbound["uuid"] = parsed.User.Username()
		if query.Get("pbk") != "" || query.Get("security") == "reality" {
			flow := query.Get("flow")
			if flow == "" || flow == "none" {
				flow = "xtls-rprx-vision"
			}
			fp := query.Get("fp")
			if fp == "" {
				fp = "chrome"
			}
			pbk := strings.TrimSpace(query.Get("pbk"))
			sid := SanitizeRealityShortID(query.Get("sid"))

			outbound["flow"] = flow
			realityMap := map[string]any{
				"enabled":    true,
				"public_key": pbk,
			}
			if sid != "" {
				realityMap["short_id"] = sid
			}
			tlsMap := map[string]any{
				"enabled":     true,
				"server_name": sni,
				"utls": map[string]any{
					"enabled":     true,
					"fingerprint": fp,
				},
				"reality": realityMap,
			}
			if insecure {
				tlsMap["insecure"] = true
			}
			outbound["tls"] = tlsMap
		} else if strings.EqualFold(query.Get("type"), "ws") {
			path := query.Get("path")
			hostHdr := query.Get("host")
			if hostHdr == "" {
				hostHdr = sni
			}
			tls := query.Get("security") == "tls"
			if tls {
				tlsMap := map[string]any{
					"enabled":     true,
					"server_name": sni,
				}
				if insecure {
					tlsMap["insecure"] = true
				}
				outbound["tls"] = tlsMap
			}
			outbound["transport"] = map[string]any{
				"type": "ws",
				"path": path,
				"headers": map[string]any{
					"Host": hostHdr,
				},
			}
		} else {
			tls := query.Get("security") == "tls"
			if tls {
				tlsMap := map[string]any{
					"enabled":     true,
					"server_name": sni,
				}
				if insecure {
					tlsMap["insecure"] = true
				}
				outbound["tls"] = tlsMap
			}
		}

	case "vless-ws-tunnel":
		outbound["type"] = "vless"
		outbound["uuid"] = parsed.User.Username()
		serverName := node.Server
		if serverName == "" {
			serverName = sni
		}
		path := query.Get("path")
		if path == "" {
			path = "/"
		}
		tlsMap := map[string]any{
			"enabled":     true,
			"server_name": serverName,
		}
		if insecure {
			tlsMap["insecure"] = true
		}
		outbound["tls"] = tlsMap
		outbound["transport"] = map[string]any{
			"type": "ws",
			"path": path,
			"headers": map[string]any{
				"Host": serverName,
			},
		}

	case "ss", "shadowsocks":
		outbound["type"] = "shadowsocks"
		decoded, decodeErr := base64.RawURLEncoding.DecodeString(parsed.User.Username())
		if decodeErr != nil {
			decoded, decodeErr = base64.StdEncoding.DecodeString(parsed.User.Username())
		}
		var method, password string
		if decodeErr == nil {
			var found bool
			method, password, found = strings.Cut(string(decoded), ":")
			if !found {
				method = ""
				password = ""
			}
		}
		if method == "" || password == "" {
			method = query.Get("cipher")
			password = parsed.User.Username()
			if p, ok := parsed.User.Password(); ok {
				method = parsed.User.Username()
				password = p
			}
		}
		if method == "" {
			method = "2022-blake3-aes-128-gcm"
		}
		outbound["method"] = method
		outbound["password"] = password

	case "tuic":
		outbound["type"] = "tuic"
		outbound["uuid"] = parsed.User.Username()
		password, _ := parsed.User.Password()
		outbound["password"] = password
		outbound["congestion_control"] = "bbr"
		outbound["udp_relay_mode"] = "native"
		tlsMap := map[string]any{
			"enabled":     true,
			"server_name": sni,
			"alpn":        []string{"h3"},
		}
		if insecure {
			tlsMap["insecure"] = true
		}
		outbound["tls"] = tlsMap

	case "trojan":
		outbound["type"] = "trojan"
		outbound["password"] = parsed.User.Username()
		tlsMap := map[string]any{
			"enabled":     true,
			"server_name": sni,
		}
		if insecure {
			tlsMap["insecure"] = true
		}
		outbound["tls"] = tlsMap

	case "anytls":
		outbound["type"] = "anytls"
		outbound["password"] = parsed.User.Username()
		tlsMap := map[string]any{
			"enabled":     true,
			"server_name": sni,
		}
		if insecure {
			tlsMap["insecure"] = true
		}
		outbound["tls"] = tlsMap

	default:
		return nil, fmt.Errorf("unsupported protocol %q", node.Protocol)
	}

	if len(dialerProxy) > 0 && dialerProxy[0] != "" {
		outbound["detour"] = dialerProxy[0]
	}

	return outbound, nil
}

func RenderSingboxSubscription(opts RenderSubscriptionOptions) (string, error) {
	items := make([]SubscriptionNode, len(opts.Items))
	copy(items, opts.Items)
	// Seed seenNames with reserved outbound tags to prevent collision
	seenNames := map[string]int{
		"proxy":   1,
		"auto":    1,
		"direct":  1,
		"block":   1,
		"dns-out": 1,
	}
	for i := range items {
		baseName := items[i].Node.Name
		count := seenNames[baseName]
		seenNames[baseName]++
		if count > 0 {
			items[i].Node.Name = fmt.Sprintf("%s (%d)", baseName, count+1)
		}
	}

	outbounds := make([]any, 0, len(items)+5)
	nodeTags := make([]string, 0, len(items))

	for _, item := range items {
		ob, err := singboxOutbound(item.Node, item.ShareURI, item.DialerProxy)
		if err != nil {
			continue
		}
		outbounds = append(outbounds, ob)
		nodeTags = append(nodeTags, item.Node.Name)
	}

	regionalGroups := GroupProxiesByRegion(nodeTags)

	selectorOutbounds := []string{"auto"}
	for _, rg := range regionalGroups {
		selectorOutbounds = append(selectorOutbounds, rg.GroupName)
	}
	selectorOutbounds = append(selectorOutbounds, nodeTags...)
	selectorOutbounds = append(selectorOutbounds, "direct")

	urltestOutbounds := nodeTags
	if len(urltestOutbounds) == 0 {
		urltestOutbounds = []string{"direct"}
	}

	allOutbounds := []any{
		map[string]any{
			"type":      "selector",
			"tag":       "proxy",
			"outbounds": selectorOutbounds,
			"default":   "auto",
		},
		map[string]any{
			"type":      "urltest",
			"tag":       "auto",
			"outbounds": urltestOutbounds,
			"url":       "http://cp.cloudflare.com/generate_204",
			"interval":  "5m",
			"tolerance": 50,
		},
	}

	for _, rg := range regionalGroups {
		allOutbounds = append(allOutbounds,
			map[string]any{
				"type":      "selector",
				"tag":       rg.GroupName,
				"outbounds": append([]string{rg.AutoName}, rg.Proxies...),
				"default":   rg.AutoName,
			},
			map[string]any{
				"type":      "urltest",
				"tag":       rg.AutoName,
				"outbounds": rg.Proxies,
				"url":       "http://cp.cloudflare.com/generate_204",
				"interval":  "5m",
				"tolerance": 50,
			},
		)
	}

	allOutbounds = append(allOutbounds, outbounds...)
	allOutbounds = append(allOutbounds,
		map[string]any{"type": "direct", "tag": "direct"},
		map[string]any{"type": "block", "tag": "block"},
		map[string]any{"type": "dns", "tag": "dns-out"},
	)

	config := map[string]any{
		"version": 1,
		"log": map[string]any{
			"level":     "info",
			"timestamp": true,
		},
		"dns": map[string]any{
			"servers": []any{
				map[string]any{"tag": "dns-remote", "address": "https://1.1.1.1/dns-query", "detour": "proxy"},
				map[string]any{"tag": "dns-direct", "address": "223.5.5.5", "detour": "direct"},
				map[string]any{"tag": "dns-block", "address": "rcode://success"},
			},
			"rules": []any{
				map[string]any{"geosite": "category-ads-all", "server": "dns-block"},
				map[string]any{"clash_mode": "Global", "server": "dns-remote"},
				map[string]any{"clash_mode": "Direct", "server": "dns-direct"},
				map[string]any{"geosite": "cn", "server": "dns-direct"},
				map[string]any{"outbound": "any", "server": "dns-direct"},
			},
			"strategy": "prefer_ipv4",
		},
		"inbounds": []any{
			map[string]any{
				"type":        "mixed",
				"tag":         "mixed-in",
				"listen":      "127.0.0.1",
				"listen_port": 2080,
			},
		},
		"outbounds": allOutbounds,
		"route": map[string]any{
			"rules": []any{
				map[string]any{"protocol": "dns", "outbound": "dns-out"},
				map[string]any{"clash_mode": "Global", "outbound": "proxy"},
				map[string]any{"clash_mode": "Direct", "outbound": "direct"},
				map[string]any{"ip_is_private": true, "outbound": "direct"},
				map[string]any{"geosite": "category-ads-all", "outbound": "block"},
				map[string]any{"geosite": "cn", "outbound": "direct"},
				map[string]any{"geoip": "cn", "outbound": "direct"},
			},
			"auto_detect_interface": true,
			"final":                 "proxy",
		},
	}

	payload, err := json.MarshalIndent(config, "", "  ")
	if err != nil {
		return "", err
	}
	return string(payload), nil
}

// RenderSubscription dispatches the generation based on the determined format
func RenderSubscription(format ClientFormat, opts RenderSubscriptionOptions) (content string, contentType string, err error) {
	switch format {
	case FormatBase64:
		content, err = RenderBase64Subscription(opts)
		contentType = "text/plain; charset=utf-8"
	case FormatSingbox:
		content, err = RenderSingboxSubscription(opts)
		contentType = "application/json; charset=utf-8"
	case FormatClash:
		fallthrough
	default:
		content, err = RenderClashSubscription(opts)
		contentType = "text/yaml; charset=utf-8"
	}
	return content, contentType, err
}
