package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
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
		{"anytls", "anytls://secret@node.example.com:443/?sni=node.example.com", []string{"type: anytls", `password: "secret"`, "client-fingerprint: chrome", "udp: true", "idle-session-check-interval: 30"}},
		{"vmess", `vmess://eyJhZGQiOiJub2RlLmV4YW1wbGUuY29tIiwicG9ydCI6NDQzLCJpZCI6ImQzNDJkMTFlLWQ0MjQtNDU4My1iMzZlLTUyNGFiMWYwYWZhNCIsIm5ldCI6IndzIiwicGF0aCI6Ii92bWVzcyIsImhvc3QiOiJub2RlLmV4YW1wbGUuY29tIiwidGxzIjoidGxzIn0=`, []string{"type: vmess", `network: ws`, `path: "/vmess"`, `Host: "node.example.com"`}},
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

func TestClashProxyYAMLUsesIPv6LiteralFromShareURI(t *testing.T) {
	node := model.Node{
		Name:       "纯 V6",
		Protocol:   "hysteria2",
		Server:     "ac.252202.xyz",
		Domain:     "ac.252202.xyz",
		ListenPort: 39769,
	}
	share := "hysteria2://secret@[2602:faa8:502:5a::a]:39769/?sni=ac.252202.xyz"
	value, err := clashProxyYAML(node, share)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`server: "2602:faa8:502:5a::a"`, `port: 39769`, `sni: "ac.252202.xyz"`} {
		if !strings.Contains(value, want) {
			t.Fatalf("%q missing from YAML:\n%s", want, value)
		}
	}
	if strings.Contains(value, `server: "ac.252202.xyz"`) {
		t.Fatalf("YAML reverted to the mixed A/AAAA hostname:\n%s", value)
	}
}

func TestClashProxyYAMLUsesIPv4LiteralFromShareURI(t *testing.T) {
	node := model.Node{
		Name:       "纯 V4",
		Protocol:   "hysteria2",
		Mode:       "v4only",
		Server:     "ac.252202.xyz",
		Domain:     "ac.252202.xyz",
		ListenPort: 57280,
	}
	share := "hysteria2://secret@23.246.167.100:57280/?sni=ac.252202.xyz"
	value, err := clashProxyYAML(node, share)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{`server: "23.246.167.100"`, `port: 57280`, `sni: "ac.252202.xyz"`} {
		if !strings.Contains(value, want) {
			t.Fatalf("%q missing from YAML:\n%s", want, value)
		}
	}
	if strings.Contains(value, `server: "ac.252202.xyz"`) {
		t.Fatalf("YAML reverted to the mixed A/AAAA hostname:\n%s", value)
	}
}

func TestSubscriptionRenderTemplates(t *testing.T) {
	items := []SubscriptionNode{
		{
			Node:     model.Node{Name: "US-01", Protocol: "hysteria2", Server: "us01.example.com", ListenPort: 443},
			ShareURI: "hysteria2://pass1@us01.example.com:443/?sni=us01.example.com",
		},
		{
			Node:     model.Node{Name: "HK-01", Protocol: "hysteria2", Server: "hk01.example.com", ListenPort: 443},
			ShareURI: "hysteria2://pass2@hk01.example.com:443/?sni=hk01.example.com",
		},
	}

	t.Run("minimal template", func(t *testing.T) {
		out, err := RenderClashSubscription(RenderSubscriptionOptions{
			Title:     "Minimal Sub",
			GroupName: "Wukong Fleet",
			Template:  TemplateMinimal,
			Items:     items,
			Comments:  []string{"TEST COMMENT"},
		})
		if err != nil {
			t.Fatal(err)
		}
		if !strings.Contains(out, "# TEST COMMENT") {
			t.Errorf("missing comment in minimal output")
		}
		if !strings.Contains(out, `name: "US-01"`) || !strings.Contains(out, `name: "HK-01"`) {
			t.Errorf("missing proxies in minimal output")
		}
		if !strings.Contains(out, "proxy-groups:\n  - name: Wukong Fleet\n    type: select\n    proxies:\n      - \"US-01\"\n      - \"HK-01\"") {
			t.Errorf("incorrect proxy-groups for minimal: %s", out)
		}
		if !strings.Contains(out, "rules:\n  - MATCH,Wukong Fleet") {
			t.Errorf("missing MATCH rule for minimal: %s", out)
		}
		if strings.Contains(out, "dns:") {
			t.Errorf("minimal template must not include dns block:\n%s", out)
		}
		if strings.Contains(out, "🚀 节点选择") || strings.Contains(out, "🤖 AI 服务") {
			t.Errorf("minimal template must not include standard/smart groups")
		}
	})

	t.Run("standard template", func(t *testing.T) {
		out, err := RenderClashSubscription(RenderSubscriptionOptions{
			Template: TemplateStandard,
			Items:    items,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Proxy groups
		for _, want := range []string{
			"🚀 节点选择",
			"♻️ 自动选择",
			"type: url-test",
			"url: http://cp.cloudflare.com/generate_204",
			"interval: 300",
			"tolerance: 50",
			"🎯 全球直连",
			"🛑 广告拦截",
			"🐟 漏网之鱼",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("standard template missing %q:\n%s", want, out)
			}
		}
		// Rules
		for _, want := range []string{
			"GEOIP,private,DIRECT,no-resolve",
			"GEOSITE,category-ads-all,🛑 广告拦截",
			"GEOSITE,cn,🎯 全球直连",
			"GEOIP,CN,🎯 全球直连",
			"MATCH,🐟 漏网之鱼",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("standard template missing rule %q:\n%s", want, out)
			}
		}
		// DNS
		for _, want := range []string{
			"dns:",
			"enable: true",
			"enhanced-mode: fake-ip",
			"fake-ip-range: 198.18.0.1/16",
			"223.5.5.5",
			"119.29.29.29",
			"https://1.1.1.1/dns-query",
			"https://8.8.8.8/dns-query",
			"geoip: true",
			"geoip-code: CN",
			"geosite:\n      - gfw",
			"240.0.0.0/4",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("standard template missing DNS setting %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "🤖 AI 服务") || strings.Contains(out, "nameserver-policy:") {
			t.Errorf("standard template should not contain smart-only elements")
		}
	})

	t.Run("smart template", func(t *testing.T) {
		out, err := RenderClashSubscription(RenderSubscriptionOptions{
			Template: TemplateSmart,
			Items:    items,
		})
		if err != nil {
			t.Fatal(err)
		}
		// Proxy groups
		for _, want := range []string{
			"🚀 节点选择",
			"♻️ 自动选择",
			"🤖 AI 服务",
			"🎬 国际流媒体",
			"🎯 全球直连",
			"🛑 广告拦截",
			"🐟 漏网之鱼",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("smart template missing group %q:\n%s", want, out)
			}
		}
		// AI and streaming rules
		for _, want := range []string{
			"GEOSITE,openai,🤖 AI 服务",
			"GEOSITE,anthropic,🤖 AI 服务",
			"DOMAIN-SUFFIX,chatgpt.com,🤖 AI 服务",
			"GEOSITE,youtube,🎬 国际流媒体",
			"GEOSITE,netflix,🎬 国际流媒体",
			"GEOSITE,disney,🎬 国际流媒体",
			"GEOSITE,spotify,🎬 国际流媒体",
			"GEOSITE,cn,🎯 全球直连",
			"MATCH,🐟 漏网之鱼",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("smart template missing rule %q:\n%s", want, out)
			}
		}
		// Egress DNS via nameserver-policy
		for _, want := range []string{
			"nameserver-policy:",
			`"geosite:youtube,netflix,disney,spotify": "https://1.1.1.1/dns-query#🚀 节点选择"`,
			`"geosite:openai,claude": "https://1.1.1.1/dns-query#🚀 节点选择"`,
			`"+.openai.com,+.chatgpt.com,+.anthropic.com,+.claude.ai": "https://1.1.1.1/dns-query#🚀 节点选择"`,
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("smart template missing DNS policy %q:\n%s", want, out)
			}
		}
	})
}

func TestSubscriptionRenderEmptyNodes(t *testing.T) {
	for _, tpl := range []SubscriptionTemplate{TemplateMinimal, TemplateStandard, TemplateSmart} {
		out, err := RenderClashSubscription(RenderSubscriptionOptions{
			Template: tpl,
			Items:    nil,
		})
		if err != nil {
			t.Fatalf("failed for %s: %v", tpl, err)
		}
		if !strings.Contains(out, "DIRECT") {
			t.Fatalf("%s with empty nodes should contain DIRECT fallback: %s", tpl, out)
		}
	}
}

func TestSubscriptionRenderDuplicateNodeNames(t *testing.T) {
	items := []SubscriptionNode{
		{
			Node:     model.Node{Name: "Tokyo", Protocol: "hysteria2", Server: "tk1.example.com", ListenPort: 443},
			ShareURI: "hysteria2://pass1@tk1.example.com:443/?sni=tk1.example.com",
		},
		{
			Node:     model.Node{Name: "Tokyo", Protocol: "hysteria2", Server: "tk2.example.com", ListenPort: 443},
			ShareURI: "hysteria2://pass2@tk2.example.com:443/?sni=tk2.example.com",
		},
	}
	out, err := RenderClashSubscription(RenderSubscriptionOptions{
		Template: TemplateStandard,
		Items:    items,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(out, `name: "Tokyo"`) || !strings.Contains(out, `name: "Tokyo (2)"`) {
		t.Fatalf("expected Tokyo and Tokyo (2) in output:\n%s", out)
	}
}

type subMockAgent struct {
	fakeAgent
	shareURI string
}

func (a subMockAgent) Share(context.Context, string) (model.Share, error) {
	return model.Share{URI: a.shareURI}, nil
}

func TestSubscriptionSingleEndpointAndTemplateParam(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.SetSetting("subscription_token", "test-token-xyz"); err != nil {
		t.Fatal(err)
	}

	node := model.Node{
		ID:         "node-sub-1",
		Name:       "US-Proxy",
		Protocol:   "hysteria2",
		Server:     "us.example.com",
		ListenPort: 443,
		Status:     "active",
	}
	if err := db.UpsertNode(context.Background(), node, "secret"); err != nil {
		t.Fatal(err)
	}

	srv := New(config.Config{DataDir: dir, BasePath: "/", SecureCookie: false}, db, subMockAgent{shareURI: "hysteria2://pass@us.example.com:443/?sni=us.example.com"}, "1.0.0")

	// 1. Default request (no template query param) -> standard template (Fake-IP and 🚀 节点选择)
	req := httptest.NewRequest(http.MethodGet, "/sub/test-token-xyz/clash.yaml", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)
	if rec.Code != http.StatusOK {
		t.Fatalf("code=%d, want 200", rec.Code)
	}
	body := rec.Body.String()
	if !strings.Contains(body, "🚀 节点选择") || !strings.Contains(body, "enhanced-mode: fake-ip") {
		t.Fatalf("default should be standard template:\n%s", body)
	}
	if strings.Contains(body, "🤖 AI 服务") {
		t.Fatalf("standard template should not have AI group:\n%s", body)
	}

	// 2. Explicit template=smart override
	reqSmart := httptest.NewRequest(http.MethodGet, "/sub/test-token-xyz/clash.yaml?template=smart", nil)
	recSmart := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recSmart, reqSmart)
	if recSmart.Code != http.StatusOK {
		t.Fatalf("code=%d", recSmart.Code)
	}
	bodySmart := recSmart.Body.String()
	if !strings.Contains(bodySmart, "🤖 AI 服务") || !strings.Contains(bodySmart, "🎬 国际流媒体") || !strings.Contains(bodySmart, "nameserver-policy:") {
		t.Fatalf("expected smart template:\n%s", bodySmart)
	}

	// 3. Explicit template=minimal override
	reqMin := httptest.NewRequest(http.MethodGet, "/sub/test-token-xyz/clash.yaml?template=minimal", nil)
	recMin := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recMin, reqMin)
	if recMin.Code != http.StatusOK {
		t.Fatalf("code=%d", recMin.Code)
	}
	bodyMin := recMin.Body.String()
	if strings.Contains(bodyMin, "dns:") || !strings.Contains(bodyMin, "MATCH,Wukong") {
		t.Fatalf("expected minimal template without dns block:\n%s", bodyMin)
	}

	// 4. Update database setting subscription_template to minimal
	if err := db.SaveSettings(model.Settings{SubscriptionTemplate: "minimal", BillingResetDay: 1}); err != nil {
		t.Fatal(err)
	}

	// Request without query param should now use minimal
	reqDefMin := httptest.NewRequest(http.MethodGet, "/sub/test-token-xyz/clash.yaml", nil)
	recDefMin := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recDefMin, reqDefMin)
	if strings.Contains(recDefMin.Body.String(), "dns:") {
		t.Fatalf("expected minimal from DB setting:\n%s", recDefMin.Body.String())
	}

	// But query param ?template=smart still overrides to smart
	reqOverride := httptest.NewRequest(http.MethodGet, "/sub/test-token-xyz/clash.yaml?template=smart", nil)
	recOverride := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recOverride, reqOverride)
	if !strings.Contains(recOverride.Body.String(), "🤖 AI 服务") {
		t.Fatalf("expected smart override over DB minimal:\n%s", recOverride.Body.String())
	}
}
