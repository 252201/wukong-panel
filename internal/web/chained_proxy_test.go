package web

import (
	"bytes"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

func TestRegionalProxyGroupsAndChainedProxiesClash(t *testing.T) {
	items := []SubscriptionNode{
		{
			Node:        model.Node{Name: "🇭🇰 香港 01", Protocol: "hysteria2", Server: "hk01.example.com", ListenPort: 443},
			ShareURI:    "hysteria2://pass1@hk01.example.com:443/?sni=hk01.example.com#%F0%9F%87%AD%F0%9F%87%B0%20%E9%A6%99%E6%B8%AF%2001",
			DialerProxy: "",
		},
		{
			Node:        model.Node{Name: "🇺🇸 美国 01", Protocol: "hysteria2", Server: "us01.example.com", ListenPort: 443},
			ShareURI:    "hysteria2://pass2@us01.example.com:443/?sni=us01.example.com#%F0%9F%87%BA%F0%9F%87%B8%20%E7%BE%8E%E5%9B%BD%2001",
			DialerProxy: "",
		},
		{
			Node:        model.Node{Name: "🔗 香港 ➔ 土耳其落地", Protocol: "vless", Server: "tr01.example.com", ListenPort: 443},
			ShareURI:    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@tr01.example.com:443?security=reality&pbk=publickey123&sni=tr01.example.com#%F0%9F%94%97%20%E9%A6%99%E6%B8%AF%20%E2%9E%94%20%E5%9C%9F%E8%80%B3%E5%85%B6%E8%90%BD%E5%9C%B0",
			DialerProxy: "🇭🇰 香港 01",
		},
	}

	out, err := RenderClashSubscription(RenderSubscriptionOptions{
		Template: TemplateSmart,
		Items:    items,
	})
	if err != nil {
		t.Fatalf("RenderClashSubscription error: %v", err)
	}

	// 1. Verify regional groups generated
	for _, expectedGroup := range []string{
		"🇭🇰 香港节点",
		"♻️ 香港自动",
		"🇺🇸 美国节点",
		"♻️ 美国自动",
		"🇹🇷 土耳其节点",
		"♻️ 土耳其自动",
	} {
		if !strings.Contains(out, expectedGroup) {
			t.Fatalf("expected output to contain regional group %q, got:\n%s", expectedGroup, out)
		}
	}

	// 2. Verify chained proxy dialer-proxy field in YAML
	if !strings.Contains(out, `dialer-proxy: "🇭🇰 香港 01"`) {
		t.Fatalf("expected chained proxy to include dialer-proxy for Hong Kong, got:\n%s", out)
	}

	// 3. Verify AI service group prioritized US
	aiIdx := strings.Index(out, "name: 🤖 AI 服务")
	usIdx := strings.Index(out[aiIdx:], "🇺🇸 美国节点")
	if aiIdx == -1 || usIdx == -1 {
		t.Fatalf("AI 服务 group must prioritize 🇺🇸 美国节点:\n%s", out)
	}

	// 4. Verify Media group prioritized HK
	mediaIdx := strings.Index(out, "name: 🎬 国际流媒体")
	hkIdx := strings.Index(out[mediaIdx:], "🇭🇰 香港节点")
	if mediaIdx == -1 || hkIdx == -1 {
		t.Fatalf("国际流媒体 group must prioritize 🇭🇰 香港节点:\n%s", out)
	}
}

func TestRegionalProxyGroupsAndChainedProxiesSingbox(t *testing.T) {
	items := []SubscriptionNode{
		{
			Node:        model.Node{Name: "🇭🇰 香港 01", Protocol: "vless", Server: "hk01.example.com", ListenPort: 443},
			ShareURI:    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@hk01.example.com:443?security=reality&pbk=publickey123&sni=hk01.example.com#HK01",
			DialerProxy: "",
		},
		{
			Node:        model.Node{Name: "🔗 香港 ➔ 土耳其落地", Protocol: "vless", Server: "tr01.example.com", ListenPort: 443},
			ShareURI:    "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@tr01.example.com:443?security=reality&pbk=publickey123&sni=tr01.example.com#Chained",
			DialerProxy: "🇭🇰 香港 01",
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
	if !ok {
		t.Fatalf("expected outbounds array in sing-box config")
	}

	foundDetour := false
	foundHKGroup := false
	for _, ob := range outbounds {
		m, _ := ob.(map[string]any)
		tag, _ := m["tag"].(string)
		if tag == "🇭🇰 香港节点" {
			foundHKGroup = true
		}
		if tag == "🔗 香港 ➔ 土耳其落地" {
			detour, _ := m["detour"].(string)
			if detour == "🇭🇰 香港 01" {
				foundDetour = true
			}
		}
	}

	if !foundHKGroup {
		t.Fatalf("expected 🇭🇰 香港节点 selector in sing-box config")
	}
	if !foundDetour {
		t.Fatalf("expected detour: '🇭🇰 香港 01' on chained outbound in sing-box config")
	}
}

func TestChainedProxyAPIEndpoints(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "panel.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	server := New(config.Config{DataDir: dir, BasePath: "/", SecureCookie: false}, db, subMockAgent{}, "1.0.0")
	session := store.Session{Username: "admin"}

	// 1. Create chained proxy
	bodyJSON, _ := json.Marshal(map[string]any{
		"entryNodeName": "🇭🇰 香港 01",
		"exitNodeName":  "🇹🇷 土耳其 01",
		"name":          "🔗 香港中转 ➔ 土耳其落地",
	})
	req := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/chained-proxies", bytes.NewReader(bodyJSON))
	req.Header.Set("Content-Type", "application/json")
	rec := httptest.NewRecorder()

	server.saveChainedProxy(rec, req, session)
	if rec.Code != http.StatusOK {
		t.Fatalf("saveChainedProxy status=%d body=%s", rec.Code, rec.Body.String())
	}

	var created model.ChainedProxy
	if err := json.Unmarshal(rec.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal created: %v", err)
	}
	if created.ID == "" || !created.Enabled || created.Name != "🔗 香港中转 ➔ 土耳其落地" {
		t.Fatalf("unexpected created proxy: %+v", created)
	}

	// 2. List chained proxies
	reqList := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/chained-proxies", nil)
	recList := httptest.NewRecorder()
	server.listChainedProxies(recList, reqList, session)
	if recList.Code != http.StatusOK {
		t.Fatalf("listChainedProxies status=%d", recList.Code)
	}
	var list []model.ChainedProxy
	_ = json.Unmarshal(recList.Body.Bytes(), &list)
	if len(list) != 1 {
		t.Fatalf("expected 1 chained proxy in list, got %d", len(list))
	}

	// 3. Toggle chained proxy
	toggleJSON, _ := json.Marshal(map[string]any{"enabled": false})
	reqToggle := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/chained-proxies/"+created.ID+"/toggle", bytes.NewReader(toggleJSON))
	reqToggle.SetPathValue("id", created.ID)
	recToggle := httptest.NewRecorder()
	server.toggleChainedProxy(recToggle, reqToggle, session)
	if recToggle.Code != http.StatusOK {
		t.Fatalf("toggleChainedProxy status=%d body=%s", recToggle.Code, recToggle.Body.String())
	}

	// Verify disabled
	proxies, _ := server.store.ChainedProxies()
	if proxies[0].Enabled {
		t.Fatalf("expected chained proxy to be disabled")
	}

	// 4. Delete chained proxy
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/fleet/chained-proxies/"+created.ID, nil)
	reqDel.SetPathValue("id", created.ID)
	recDel := httptest.NewRecorder()
	server.deleteChainedProxy(recDel, reqDel, session)
	if recDel.Code != http.StatusOK {
		t.Fatalf("deleteChainedProxy status=%d", recDel.Code)
	}

	proxiesAfter, _ := server.store.ChainedProxies()
	if len(proxiesAfter) != 0 {
		t.Fatalf("expected 0 chained proxies after deletion, got %d", len(proxiesAfter))
	}
}
