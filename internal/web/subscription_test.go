package web

import (
	"context"
	"net/http"
	"net/http/httptest"
	"os"
	"os/exec"
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
			"default-nameserver:",
			"proxy-server-nameserver:",
			"ipv6: true",
			"use-hosts: true",
		} {
			if !strings.Contains(out, want) {
				t.Fatalf("standard template missing DNS setting %q:\n%s", want, out)
			}
		}
		if strings.Contains(out, "🤖 AI 服务") || strings.Contains(out, "nameserver-policy:") {
			t.Errorf("standard template should not contain smart-only elements")
		}
		if strings.Contains(out, "listen:") {
			t.Errorf("standard template should not force listen port in subscription profile:\n%s", out)
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
			"DOMAIN-SUFFIX,claude.ai,🤖 AI 服务",
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
		if strings.Contains(out, "GEOSITE,claude") {
			t.Fatalf("GEOSITE,claude is not a valid GeoSite tag in GeoSite.dat; claude must be covered via anthropic and domain rules:\n%s", out)
		}
		// Egress DNS via nameserver-policy
		for _, want := range []string{
			"nameserver-policy:",
			`"geosite:youtube,netflix,disney,spotify": "https://1.1.1.1/dns-query#🎬 国际流媒体"`,
			`"geosite:openai,anthropic": "https://1.1.1.1/dns-query#🤖 AI 服务"`,
			`"+.openai.com": "https://1.1.1.1/dns-query#🤖 AI 服务"`,
			`"+.chatgpt.com": "https://1.1.1.1/dns-query#🤖 AI 服务"`,
			`"+.claude.ai": "https://1.1.1.1/dns-query#🤖 AI 服务"`,
			`"+.youtube.com": "https://1.1.1.1/dns-query#🎬 国际流媒体"`,
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

func findMihomoBinary() string {
	if p, err := exec.LookPath("mihomo"); err == nil {
		return p
	}
	candidates := []string{
		"/Applications/Clash Party.app/Contents/Resources/sidecar/mihomo",
		"/usr/local/bin/mihomo",
		"/opt/homebrew/bin/mihomo",
	}
	for _, c := range candidates {
		if fi, err := os.Stat(c); err == nil && !fi.IsDir() && fi.Mode()&0111 != 0 {
			return c
		}
	}
	return ""
}

func TestSubscriptionMihomoCompatibility(t *testing.T) {
	mihomoPath := findMihomoBinary()
	if mihomoPath == "" {
		t.Skip("mihomo binary not found on host, skipping kernel test")
	}

	items := []SubscriptionNode{
		{
			Node:     model.Node{Name: "US-01", Protocol: "hysteria2", Server: "us01.example.com", ListenPort: 443},
			ShareURI: "hysteria2://pass1@us01.example.com:443/?sni=us01.example.com",
		},
		{
			Node:     model.Node{Name: "SG-01", Protocol: "vless", Server: "sg01.example.com", ListenPort: 443},
			ShareURI: "vless://00000000-0000-4000-8000-000000000001@sg01.example.com:443?security=tls&type=tcp",
		},
		{
			Node:     model.Node{Name: "US-Reality-Standard", Protocol: "vless", Server: "us02.example.com", ListenPort: 443},
			ShareURI: "vless://00000000-0000-4000-8000-000000000002@us02.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef&sni=us02.example.com&type=tcp#US-Reality-Standard",
		},
		{
			Node:     model.Node{Name: "US-Reality-LongHex32", Protocol: "vless", Server: "us03.example.com", ListenPort: 443},
			ShareURI: "vless://00000000-0000-4000-8000-000000000003@us03.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef0123456789abcdef&sni=us03.example.com&type=tcp#US-Reality-LongHex32",
		},
		{
			Node:     model.Node{Name: "US-Reality-InvalidNonHex", Protocol: "vless", Server: "us04.example.com", ListenPort: 443},
			ShareURI: "vless://00000000-0000-4000-8000-000000000004@us04.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=sid1&sni=us04.example.com&type=tcp#US-Reality-InvalidNonHex",
		},
		{
			Node:     model.Node{Name: "US-Reality-EmptySID", Protocol: "vless", Server: "us05.example.com", ListenPort: 443},
			ShareURI: "vless://00000000-0000-4000-8000-000000000005@us05.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=&sni=us05.example.com&type=tcp#US-Reality-EmptySID",
		},
	}

	for _, tpl := range []SubscriptionTemplate{TemplateMinimal, TemplateStandard, TemplateSmart} {
		t.Run(string(tpl), func(t *testing.T) {
			content, err := RenderClashSubscription(RenderSubscriptionOptions{
				Template: tpl,
				Items:    items,
			})
			if err != nil {
				t.Fatalf("render failed: %v", err)
			}

			tmpFile := filepath.Join(t.TempDir(), "config.yaml")
			if err := os.WriteFile(tmpFile, []byte(content), 0644); err != nil {
				t.Fatal(err)
			}

			cmd := exec.Command(mihomoPath, "-t", "-f", tmpFile)
			out, err := cmd.CombinedOutput()
			if err != nil {
				t.Fatalf("mihomo -t -f failed for template %s (exit: %v):\n%s\nConfig:\n%s", tpl, err, string(out), content)
			}
		})
	}
}

func TestSanitizeRealityShortID(t *testing.T) {
	cases := []struct {
		input string
		want  string
	}{
		{"0123456789abcdef", "0123456789abcdef"},
		{"6ba9633e", "6ba9633e"},
		{"6BA9633E", "6ba9633e"},
		{"0123456789abcdef0123456789abcdef", "0123456789abcdef"}, // Truncates 32 chars to 16
		{"6ba9633e-1234-5678-9abc-def012345678", "6ba9633e12345678"}, // Strips dashes and takes 16
		{"1234567", "01234567"},                                       // Pads odd length
		{"[ce7c5293131775d9]", "ce7c5293131775d9"},                   // Bracket-wrapped probe array
		{"%5Bce7c5293131775d9%5D", "ce7c5293131775d9"},               // URL-encoded bracket-wrapped probe array
		{"[\"ce7c5293131775d9\"]", "ce7c5293131775d9"},               // JSON array string representation
		{"sid1", ""},                                                  // Non-hex characters
		{"none", ""},                                                  // Non-hex
		{"undefined", ""},                                             // Non-hex
		{"null", ""},                                                  // Non-hex
		{"", ""},                                                      // Empty
		{"   ", ""},                                                   // Whitespace
	}
	for _, tc := range cases {
		got := SanitizeRealityShortID(tc.input)
		if got != tc.want {
			t.Errorf("SanitizeRealityShortID(%q) = %q, want %q", tc.input, got, tc.want)
		}
	}
}

func TestClashRealityShortIDFormatting(t *testing.T) {
	node := model.Node{
		Name:       "Test-Reality",
		Protocol:   "vless",
		Server:     "node.example.com",
		Domain:     "node.example.com",
		ListenPort: 443,
	}

	// 1. Valid short id should output quoted short-id
	validShare := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@node.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef"
	entry, err := clashProxyYAML(node, validShare)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entry, `short-id: "0123456789abcdef"`) {
		t.Fatalf("expected quoted short-id, got:\n%s", entry)
	}

	// 2. 32-char hex short id should be truncated to 16 chars
	longShare := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@node.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=0123456789abcdef0123456789abcdef"
	entry, err = clashProxyYAML(node, longShare)
	if err != nil {
		t.Fatal(err)
	}
	if !strings.Contains(entry, `short-id: "0123456789abcdef"`) {
		t.Fatalf("expected truncated 16-char short-id, got:\n%s", entry)
	}
	if strings.Contains(entry, "0123456789abcdef0123456789abcdef") {
		t.Fatalf("should not contain original 32-char short-id in:\n%s", entry)
	}

	// 3. Invalid non-hex short id should be omitted
	invalidShare := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@node.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid=sid1"
	entry, err = clashProxyYAML(node, invalidShare)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(entry, "short-id:") {
		t.Fatalf("short-id should be omitted for invalid non-hex sid, got:\n%s", entry)
	}
	if !strings.Contains(entry, `public-key: "AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA"`) {
		t.Fatalf("public-key should still be present, got:\n%s", entry)
	}

	// 4. Empty short id should be omitted
	emptyShare := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@node.example.com:443?security=reality&pbk=AAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAAA&sid="
	entry, err = clashProxyYAML(node, emptyShare)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(entry, "short-id:") {
		t.Fatalf("short-id should be omitted for empty sid, got:\n%s", entry)
	}
}

func TestClashProxyYAMLSpecificHardening(t *testing.T) {
	// 1. VLESS WS must emit udp: false and both servername and sni
	wsNode := model.Node{
		Name:       "FL-CF-V6",
		Protocol:   "vless",
		Server:     "cf.877774.xyz",
		Domain:     "qw.cnmd.xx.kg",
		ListenPort: 443,
	}
	wsShare := "vless://122fdfed-8397-450e-92a0-a29b5bc1afe9@cf.877774.xyz:443?security=tls&type=ws&path=%2Fwukong-test&host=qw.cnmd.xx.kg&sni=qw.cnmd.xx.kg"
	wsYAML, err := clashProxyYAML(wsNode, wsShare)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type: vless`,
		`network: ws`,
		`udp: false`,
		`servername: "qw.cnmd.xx.kg"`,
		`sni: "qw.cnmd.xx.kg"`,
	} {
		if !strings.Contains(wsYAML, want) {
			t.Fatalf("VLESS WS missing %q in YAML:\n%s", want, wsYAML)
		}
	}
	if strings.Contains(wsYAML, "udp: true") {
		t.Fatalf("VLESS WS must not emit udp: true (causes XUDP failure):\n%s", wsYAML)
	}

	// 2. REALITY must emit udp: false and both servername and sni
	realityNode := model.Node{
		Name:       "TW-REALITY-V6",
		Protocol:   "vless",
		Server:     "2001:b030:112d:711:1165::",
		Domain:     "d1.awsstatic.com",
		ListenPort: 57832,
	}
	realityShare := "vless://939fdd8d-dad1-488a-8639-199d2509717e@[2001:b030:112d:711:1165::]:57832?security=reality&pbk=BGcIcPCAu6Q3SwYNhKBAWlU0cPlDcZcVd01eJpvGSC0&sid=ce7c5293131775d9&sni=d1.awsstatic.com&type=tcp&flow=xtls-rprx-vision"
	realityYAML, err := clashProxyYAML(realityNode, realityShare)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`server: "2001:b030:112d:711:1165::"`,
		`port: 57832`,
		`udp: false`,
		`flow: xtls-rprx-vision`,
		`servername: "d1.awsstatic.com"`,
		`sni: "d1.awsstatic.com"`,
		`short-id: "ce7c5293131775d9"`,
	} {
		if !strings.Contains(realityYAML, want) {
			t.Fatalf("REALITY missing %q in YAML:\n%s", want, realityYAML)
		}
	}

	// 3. Hysteria 2 must emit both servername and sni and udp: true without forced alpn: [h3]
	hy2Node := model.Node{
		Name:       "US-旧金山-V6优先",
		Protocol:   "hysteria2",
		Server:     "ac.252202.xyz",
		Domain:     "ac.252202.xyz",
		ListenPort: 52246,
	}
	hy2Share := "hysteria2://password@ac.252202.xyz:52246/?sni=ac.252202.xyz"
	hy2YAML, err := clashProxyYAML(hy2Node, hy2Share)
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`type: hysteria2`,
		`server: "ac.252202.xyz"`,
		`port: 52246`,
		`servername: "ac.252202.xyz"`,
		`sni: "ac.252202.xyz"`,
		`udp: true`,
	} {
		if !strings.Contains(hy2YAML, want) {
			t.Fatalf("Hysteria 2 missing %q in YAML:\n%s", want, hy2YAML)
		}
	}
	if strings.Contains(hy2YAML, "alpn: [h3]") {
		t.Fatalf("Hysteria 2 should not force alpn: [h3], got:\n%s", hy2YAML)
	}
}
