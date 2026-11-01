package web

import (
	"encoding/base64"
	"encoding/json"
	"net/http/httptest"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestDetectClientFormat(t *testing.T) {
	tests := []struct {
		name       string
		url        string
		userAgent  string
		wantFormat ClientFormat
	}{
		{
			name:       "explicit format query clash",
			url:        "/sub/token?format=clash",
			userAgent:  "v2rayN",
			wantFormat: FormatClash,
		},
		{
			name:       "explicit format query base64",
			url:        "/sub/token?format=base64",
			userAgent:  "ClashMeta/1.18.0",
			wantFormat: FormatBase64,
		},
		{
			name:       "explicit format query v2ray",
			url:        "/sub/token?format=v2ray",
			userAgent:  "ClashMeta/1.18.0",
			wantFormat: FormatBase64,
		},
		{
			name:       "explicit format query singbox",
			url:        "/sub/token?format=singbox",
			userAgent:  "Shadowrocket/2.2.0",
			wantFormat: FormatSingbox,
		},
		{
			name:       "explicit format query sing-box",
			url:        "/sub/token?format=sing-box",
			userAgent:  "Mozilla/5.0",
			wantFormat: FormatSingbox,
		},
		{
			name:       "file extension yaml",
			url:        "/sub/token/clash.yaml",
			userAgent:  "",
			wantFormat: FormatClash,
		},
		{
			name:       "file extension txt",
			url:        "/sub/token/sub.txt",
			userAgent:  "",
			wantFormat: FormatBase64,
		},
		{
			name:       "file extension json",
			url:        "/sub/token/config.json",
			userAgent:  "",
			wantFormat: FormatSingbox,
		},
		{
			name:       "UA Shadowrocket",
			url:        "/sub/token",
			userAgent:  "Shadowrocket/2.2.0 (iOS; Version 16.0)",
			wantFormat: FormatBase64,
		},
		{
			name:       "UA v2rayN",
			url:        "/sub/token",
			userAgent:  "v2rayN/6.23",
			wantFormat: FormatBase64,
		},
		{
			name:       "UA Happ",
			url:        "/sub/token",
			userAgent:  "HappProxy/1.0",
			wantFormat: FormatBase64,
		},
		{
			name:       "UA sing-box",
			url:        "/sub/token",
			userAgent:  "sing-box/1.8.10",
			wantFormat: FormatSingbox,
		},
		{
			name:       "UA SFI iOS",
			url:        "/sub/token",
			userAgent:  "SFI/1.8.0 (iOS)",
			wantFormat: FormatSingbox,
		},
		{
			name:       "UA SFA Android",
			url:        "/sub/token",
			userAgent:  "SFA/1.8.0",
			wantFormat: FormatSingbox,
		},
		{
			name:       "UA Clash Verge",
			url:        "/sub/token",
			userAgent:  "clash-verge/v1.3.8",
			wantFormat: FormatClash,
		},
		{
			name:       "UA Mihomo",
			url:        "/sub/token",
			userAgent:  "Mihomo/1.18.0",
			wantFormat: FormatClash,
		},
		{
			name:       "UA Browser Chrome",
			url:        "/sub/token",
			userAgent:  "Mozilla/5.0 (Macintosh; Intel Mac OS X 10_15_7) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/120.0.0.0 Safari/537.36",
			wantFormat: FormatClash,
		},
		{
			name:       "generic client fallback",
			url:        "/sub/token",
			userAgent:  "curl/8.1.2",
			wantFormat: FormatBase64,
		},
	}

	for _, tt := range tests {
		t.Run(tt.name, func(t *testing.T) {
			req := httptest.NewRequest("GET", tt.url, nil)
			if tt.userAgent != "" {
				req.Header.Set("User-Agent", tt.userAgent)
			}
			got := DetectClientFormat(req)
			if got != tt.wantFormat {
				t.Fatalf("DetectClientFormat() = %v, want %v", got, tt.wantFormat)
			}
		})
	}
}

func TestRenderBase64Subscription(t *testing.T) {
	items := []SubscriptionNode{
		{
			Node:     model.Node{Name: "HK VLESS", Protocol: "vless"},
			ShareURI: "vless://uuid@hk.example.com:443?security=reality#HK%20VLESS",
		},
		{
			Node:     model.Node{Name: "US Hy2", Protocol: "hysteria2"},
			ShareURI: "hysteria2://pass@us.example.com:443/?sni=us.example.com#US%20Hy2",
		},
	}

	encoded, err := RenderBase64Subscription(RenderSubscriptionOptions{Items: items})
	if err != nil {
		t.Fatalf("RenderBase64Subscription error: %v", err)
	}

	decoded, err := base64.StdEncoding.DecodeString(encoded)
	if err != nil {
		t.Fatalf("base64 decode error: %v", err)
	}

	lines := strings.Split(strings.TrimSpace(string(decoded)), "\n")
	if len(lines) != 2 {
		t.Fatalf("expected 2 lines, got %d:\n%s", len(lines), string(decoded))
	}
	if lines[0] != items[0].ShareURI || lines[1] != items[1].ShareURI {
		t.Fatalf("unexpected content:\n%s", string(decoded))
	}
}

func TestRenderSingboxSubscription(t *testing.T) {
	items := []SubscriptionNode{
		{
			Node:     model.Node{Name: "HK VLESS", Protocol: "vless", Server: "hk.example.com", ListenPort: 443},
			ShareURI: "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@hk.example.com:443?security=reality&pbk=publickey123&sni=hk.example.com#HK%20VLESS",
		},
		{
			Node:     model.Node{Name: "US Hy2", Protocol: "hy2", Server: "us.example.com", ListenPort: 443},
			ShareURI: "hy2://password123@us.example.com:443/?sni=us.example.com#US%20Hy2",
		},
		{
			Node:     model.Node{Name: "JP SS", Protocol: "ss", Server: "jp.example.com", ListenPort: 8388},
			ShareURI: "ss://MjAyMi1ibGFrZTMtYWVzLTEyOC1nY206cGFzc3dvcmQxMjM@jp.example.com:8388#JP%20SS",
		},
		{
			Node:     model.Node{Name: "direct", Protocol: "vless", Server: "hk2.example.com", ListenPort: 443},
			ShareURI: "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@hk2.example.com:443?security=tls&sni=hk2.example.com#direct",
		},
	}

	jsonStr, err := RenderSingboxSubscription(RenderSubscriptionOptions{Items: items})
	if err != nil {
		t.Fatalf("RenderSingboxSubscription error: %v", err)
	}

	var parsed map[string]any
	if err := json.Unmarshal([]byte(jsonStr), &parsed); err != nil {
		t.Fatalf("invalid json generated: %v\n%s", err, jsonStr)
	}

	outbounds, ok := parsed["outbounds"].([]any)
	if !ok || len(outbounds) < 6 {
		t.Fatalf("expected at least 6 outbounds (selector, urltest, 4 nodes, direct, block, dns), got %d", len(outbounds))
	}

	// Verify selector
	selector, _ := outbounds[0].(map[string]any)
	if selector["type"] != "selector" || selector["tag"] != "proxy" {
		t.Fatalf("expected proxy selector, got %+v", selector)
	}

	// Check tags: ensure no duplicate tag for "direct"
	tagCounts := make(map[string]int)
	foundHy2 := false
	for _, ob := range outbounds {
		m, _ := ob.(map[string]any)
		tag, _ := m["tag"].(string)
		tagCounts[tag]++
		if m["type"] == "hysteria2" && tag == "US Hy2" {
			foundHy2 = true
		}
		// Verify reality without sid does not emit empty short_id
		if tag == "HK VLESS" {
			tls, _ := m["tls"].(map[string]any)
			reality, _ := tls["reality"].(map[string]any)
			if reality != nil && reality["short_id"] != nil {
				t.Fatalf("expected empty short_id to be omitted, got: %v", reality["short_id"])
			}
		}
	}
	for tag, count := range tagCounts {
		if count > 1 {
			t.Fatalf("duplicate outbound tag %q found %d times!", tag, count)
		}
	}
	if !foundHy2 {
		t.Fatal("expected hy2 protocol to be parsed as hysteria2 outbound in singbox config")
	}
	if tagCounts["direct (2)"] != 1 {
		t.Fatalf("expected node named 'direct' to be safely renamed to 'direct (2)', tagCounts: %+v", tagCounts)
	}

	// Verify DNS rule ordering: specific rules must precede outbound: any
	dns, _ := parsed["dns"].(map[string]any)
	rules, _ := dns["rules"].([]any)
	if len(rules) < 4 {
		t.Fatalf("expected at least 4 dns rules, got %d", len(rules))
	}
	firstRule, _ := rules[0].(map[string]any)
	if firstRule["outbound"] == "any" {
		t.Fatal("dns rules order error: outbound: any must not be the first rule!")
	}
}

func TestRenderSubscriptionDispatcher(t *testing.T) {
	items := []SubscriptionNode{
		{
			Node:     model.Node{Name: "HK VLESS", Protocol: "vless", Server: "hk.example.com", ListenPort: 443},
			ShareURI: "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@hk.example.com:443?security=reality&pbk=publickey123&sid=0123456789abcdef#HK%20VLESS",
		},
	}
	opts := RenderSubscriptionOptions{
		Title: "Test Sub",
		Items: items,
	}

	contentB64, ctB64, err := RenderSubscription(FormatBase64, opts)
	if err != nil || ctB64 != "text/plain; charset=utf-8" || contentB64 == "" {
		t.Fatalf("FormatBase64 render failed: %v, ct=%s", err, ctB64)
	}

	contentSB, ctSB, err := RenderSubscription(FormatSingbox, opts)
	if err != nil || ctSB != "application/json; charset=utf-8" || !strings.Contains(contentSB, `"tag": "proxy"`) {
		t.Fatalf("FormatSingbox render failed: %v, ct=%s", err, ctSB)
	}

	contentClash, ctClash, err := RenderSubscription(FormatClash, opts)
	if err != nil || ctClash != "text/yaml; charset=utf-8" || !strings.Contains(contentClash, "proxies:") {
		t.Fatalf("FormatClash render failed: %v, ct=%s", err, ctClash)
	}
}
