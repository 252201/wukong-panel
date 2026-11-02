package web

import (
	"context"
	"encoding/base64"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

func TestExternalSubscriptionSSRFProtection(t *testing.T) {
	fetcher := &ExternalSubscriptionFetcher{
		AllowLoopback: false,
	}

	for _, badURL := range []string{
		"http://127.0.0.1:8080/sub",
		"http://localhost:8080/sub",
		"http://[::1]:8080/sub",
		"http://[::]:8080/sub",
		"http://0.0.0.0:8080/sub",
		"http://10.0.0.1/sub",
		"http://100.64.0.1/sub",
		"http://192.168.1.1/sub",
		"http://172.16.0.1/sub",
		"ftp://example.com/sub",
	} {
		sub := model.ExternalSubscription{
			URL: badURL,
		}
		_, _, err := fetcher.Fetch(context.Background(), sub)
		if err == nil {
			t.Fatalf("expected SSRF error for %s, got nil", badURL)
		}
		if !strings.Contains(err.Error(), "SSRF blocked") && !strings.Contains(err.Error(), "invalid subscription URL scheme") {
			t.Fatalf("unexpected error message for %s: %v", badURL, err)
		}
	}

	// Test redirect SSRF: public endpoint redirecting to private IP
	redirectServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		http.Redirect(w, r, "http://127.0.0.1:9999/pwn", http.StatusFound)
	}))
	defer redirectServer.Close()

	_, _, err := fetcher.Fetch(context.Background(), model.ExternalSubscription{URL: redirectServer.URL})
	if err == nil || !strings.Contains(err.Error(), "SSRF blocked") {
		t.Fatalf("expected redirect to 127.0.0.1 to be blocked by SSRF, got: %v", err)
	}
}

func TestParseExternalSubscriptionClashYAML(t *testing.T) {
	clashContent := `
proxies:
  - name: "🇭🇰 香港 01"
    type: ss
    server: "hk.example.com"
    port: 8388
    cipher: "aes-128-gcm"
    password: "secretpassword"
  - name: "🇺🇸 美国 Reality"
    type: vless
    server: "us.example.com"
    port: 443
    uuid: "d342d11e-d424-4583-b36e-524ab1f0afa4"
    network: tcp
    tls: true
    flow: xtls-rprx-vision
    servername: "us.example.com"
    reality-opts:
      public-key: "pubkey123"
      short-id: "abcdef"
  - name: "🇯🇵 日本 Hysteria2"
    type: hysteria2
    server: "jp.example.com"
    port: 443
    password: "hy2password"
    sni: "jp.example.com"
    skip-cert-verify: true
  - { name: "🇫🇷 法国 Flow", type: hy2, server: "fr.example.com", port: 443, password: "p1", sni: "fr.example.com" }
`
	header := http.Header{}
	header.Set("Subscription-Userinfo", "upload=1073741824; download=5368709120; total=107374182400; expire=1735689600")

	nodes, userinfo, err := ParseExternalSubscription([]byte(clashContent), header, "sub-test")
	if err != nil {
		t.Fatalf("ParseExternalSubscription error: %v", err)
	}

	if len(nodes) != 4 {
		t.Fatalf("expected 4 nodes, got %d", len(nodes))
	}
	if userinfo.UploadBytes != 1073741824 || userinfo.DownloadBytes != 5368709120 || userinfo.TotalBytes != 107374182400 {
		t.Fatalf("unexpected userinfo: %+v", userinfo)
	}

	// Verify SS
	ssNode := nodes[0]
	if ssNode.Name != "🇭🇰 香港 01" || ssNode.Protocol != "ss" || ssNode.Server != "hk.example.com" || ssNode.ListenPort != 8388 {
		t.Fatalf("unexpected ssNode: %+v", ssNode)
	}
	if !strings.HasPrefix(ssNode.ShareURI, "ss://") {
		t.Fatalf("expected ss:// share URI, got %s", ssNode.ShareURI)
	}

	// Verify VLESS
	vlessNode := nodes[1]
	if vlessNode.Name != "🇺🇸 美国 Reality" || vlessNode.Protocol != "vless" {
		t.Fatalf("unexpected vlessNode: %+v", vlessNode)
	}
	if !strings.Contains(vlessNode.ShareURI, "security=reality") || !strings.Contains(vlessNode.ShareURI, "pubkey123") {
		t.Fatalf("expected reality share URI, got %s", vlessNode.ShareURI)
	}

	// Verify Hysteria2
	hy2Node := nodes[2]
	if hy2Node.Name != "🇯🇵 日本 Hysteria2" || hy2Node.Protocol != "hysteria2" {
		t.Fatalf("unexpected hy2Node: %+v", hy2Node)
	}
	if !strings.HasPrefix(hy2Node.ShareURI, "hysteria2://") || !strings.Contains(hy2Node.ShareURI, "insecure=1") {
		t.Fatalf("expected hysteria2 share URI, got %s", hy2Node.ShareURI)
	}

	// Verify Flow-style hy2 Node
	flowNode := nodes[3]
	if flowNode.Name != "🇫🇷 法国 Flow" || flowNode.Protocol != "hysteria2" || flowNode.Server != "fr.example.com" {
		t.Fatalf("unexpected flowNode: %+v", flowNode)
	}
}

func TestParseExternalSubscriptionBase64(t *testing.T) {
	rawURIs := `vless://d342d11e-d424-4583-b36e-524ab1f0afa4@hk.example.com:443?security=reality&pbk=pubkey123#HK-Reality
hy2://pass123@us.example.com:443/?sni=us.example.com#US-Hy2
ss://YWVzLTEyOC1nY206c2VjcmV0cGFzc0BqcC5leGFtcGxlLmNvbTo4Mzg4#JP-Legacy-SS
`
	// Test multi-line base64 with line breaks (\r\n) as emitted by real-world airport panels
	encoded := base64.StdEncoding.EncodeToString([]byte(rawURIs))
	// Inject line breaks every 40 characters
	var wrapped strings.Builder
	for i := 0; i < len(encoded); i += 40 {
		end := i + 40
		if end > len(encoded) {
			end = len(encoded)
		}
		wrapped.WriteString(encoded[i:end] + "\r\n")
	}

	header := http.Header{}
	header.Set("Subscription-Userinfo", "upload=2000; download=3000; total=50000; expire=1735689600")

	nodes, userinfo, err := ParseExternalSubscription([]byte(wrapped.String()), header, "sub-b64")
	if err != nil {
		t.Fatalf("ParseExternalSubscription error: %v", err)
	}

	if len(nodes) != 3 {
		t.Fatalf("expected 3 nodes, got %d", len(nodes))
	}
	if userinfo.UploadBytes != 2000 || userinfo.DownloadBytes != 3000 || userinfo.TotalBytes != 50000 {
		t.Fatalf("unexpected userinfo: %+v", userinfo)
	}

	if nodes[0].Name != "HK-Reality" || nodes[0].Protocol != "vless" || nodes[0].Server != "hk.example.com" {
		t.Fatalf("unexpected node 0: %+v", nodes[0])
	}
	if nodes[1].Name != "US-Hy2" || nodes[1].Protocol != "hysteria2" || nodes[1].Server != "us.example.com" {
		t.Fatalf("unexpected node 1: %+v", nodes[1])
	}
	if nodes[2].Name != "JP-Legacy-SS" || nodes[2].Protocol != "ss" || nodes[2].Server != "jp.example.com" || nodes[2].ListenPort != 8388 {
		t.Fatalf("unexpected node 2: %+v", nodes[2])
	}
}

func TestExternalSubscriptionWebAPIsAndFleetMixing(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	if err := db.SetSetting("fleet_global_token", "fleet-secret-token"); err != nil {
		t.Fatal(err)
	}
	if err := db.SetSetting("fleet_controller_enabled", "true"); err != nil {
		t.Fatal(err)
	}

	// Create a dummy mock server that serves an airport subscription
	airportServer := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("Subscription-Userinfo", "upload=1000; download=2000; total=50000; expire=1735689600")
		w.Header().Set("Content-Type", "text/plain; charset=utf-8")
		uris := "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@ext.example.com:443?security=reality&pbk=publickey123#External-Node-01\n"
		b64 := base64.StdEncoding.EncodeToString([]byte(uris))
		fmt.Fprint(w, b64)
	}))
	defer airportServer.Close()

	srv := New(config.Config{DataDir: dir, BasePath: "/", SecureCookie: false}, db, subMockAgent{shareURI: "hysteria2://pass@local.example.com:443/?sni=local.example.com"}, "1.0.0")

	// 1. Add external subscription directly into store
	extSub := model.ExternalSubscription{
		ID:                "ext-sub-1",
		Name:              "Airport Alpha",
		URL:               airportServer.URL,
		Enabled:           true,
		AutoSync:          true,
		SyncIntervalHours: 12,
		UploadBytes:       1000,
		DownloadBytes:     2000,
		TotalBytes:        50000,
		Nodes: []model.Node{
			{
				ID:         "ext-node-1",
				Name:       "External-Node-01",
				Protocol:   "vless",
				Server:     "ext.example.com",
				ListenPort: 443,
				Status:     "active",
				ShareURI:   "vless://d342d11e-d424-4583-b36e-524ab1f0afa4@ext.example.com:443?security=reality&pbk=publickey123#External-Node-01",
			},
		},
	}
	if err := db.SaveExternalSubscription(extSub); err != nil {
		t.Fatal(err)
	}

	// 2. Add local node into DB
	localNode := model.Node{
		ID:         "local-node-1",
		Name:       "Local-Node-01",
		Protocol:   "hysteria2",
		Server:     "local.example.com",
		Domain:     "local.example.com",
		ListenPort: 443,
		Status:     "active",
	}
	if err := db.UpsertNode(context.Background(), localNode, "secret"); err != nil {
		t.Fatal(err)
	}

	// 3. Test Fleet subscription output format: Clash
	reqClash := httptest.NewRequest(http.MethodGet, "/fleet-sub/fleet-secret-token/clash.yaml", nil)
	recClash := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recClash, reqClash)
	if recClash.Code != http.StatusOK {
		t.Fatalf("clash sub code=%d, want 200", recClash.Code)
	}
	clashBody := recClash.Body.String()
	if !strings.Contains(clashBody, "External-Node-01") || !strings.Contains(clashBody, "Local-Node-01") {
		t.Fatalf("expected both local and external nodes in Clash YAML:\n%s", clashBody)
	}
	if recClash.Header().Get("Subscription-Userinfo") == "" {
		t.Fatal("expected Subscription-Userinfo header in fleet subscription")
	}

	// 4. Test Fleet subscription output format: Base64 via /fleet-sub/token/sub.txt
	reqB64 := httptest.NewRequest(http.MethodGet, "/fleet-sub/fleet-secret-token/sub.txt", nil)
	recB64 := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recB64, reqB64)
	if recB64.Code != http.StatusOK {
		t.Fatalf("base64 sub code=%d, want 200", recB64.Code)
	}
	b64Dec, err := base64.StdEncoding.DecodeString(recB64.Body.String())
	if err != nil {
		t.Fatalf("decode base64 failed: %v", err)
	}
	if !strings.Contains(string(b64Dec), "External-Node-01") || !strings.Contains(string(b64Dec), "local.example.com") {
		t.Fatalf("expected both nodes in base64 output:\n%s", string(b64Dec))
	}

	// 5. Test Fleet subscription output format: Sing-box via ?format=singbox
	reqSB := httptest.NewRequest(http.MethodGet, "/fleet-sub/fleet-secret-token?format=singbox", nil)
	recSB := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recSB, reqSB)
	if recSB.Code != http.StatusOK {
		t.Fatalf("singbox sub code=%d, want 200", recSB.Code)
	}
	var sbConfig map[string]any
	if err := json.Unmarshal(recSB.Body.Bytes(), &sbConfig); err != nil {
		t.Fatalf("invalid json from singbox sub: %v", err)
	}
	outbounds, _ := sbConfig["outbounds"].([]any)
	foundExt := false
	foundLocal := false
	for _, ob := range outbounds {
		m, _ := ob.(map[string]any)
		if m["tag"] == "External-Node-01" {
			foundExt = true
		}
		if m["tag"] == "Local-Node-01" {
			foundLocal = true
		}
	}
	if !foundExt || !foundLocal {
		t.Fatalf("expected both tags in singbox config outbounds: foundExt=%t, foundLocal=%t", foundExt, foundLocal)
	}

	// 7. Test /fleet/subscription/clash.yaml with query token
	reqPathQuery := httptest.NewRequest(http.MethodGet, "/fleet/subscription/clash.yaml?token=fleet-secret-token", nil)
	recPathQuery := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recPathQuery, reqPathQuery)
	if recPathQuery.Code != http.StatusOK {
		t.Fatalf("fleet sub with path filename and query token code=%d, want 200", recPathQuery.Code)
	}
	if !strings.Contains(recPathQuery.Body.String(), "External-Node-01") {
		t.Fatalf("expected External-Node-01 in path query fleet sub:\n%s", recPathQuery.Body.String())
	}

	// 8. Test /sub/clash.yaml with query token
	_ = db.SetSetting("subscription_token", "local-secret-token")
	reqSubPathQuery := httptest.NewRequest(http.MethodGet, "/sub/clash.yaml?token=local-secret-token", nil)
	recSubPathQuery := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recSubPathQuery, reqSubPathQuery)
	if recSubPathQuery.Code != http.StatusOK {
		t.Fatalf("sub with clash.yaml and query token code=%d, want 200", recSubPathQuery.Code)
	}
	if !strings.Contains(recSubPathQuery.Body.String(), "Local-Node-01") {
		t.Fatalf("expected Local-Node-01 in local sub:\n%s", recSubPathQuery.Body.String())
	}
}

func TestExternalSubscriptionWebAPIEndpoints(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := New(config.Config{DataDir: dir, BasePath: "/", SecureCookie: false}, db, subMockAgent{}, "1.0.0")
	if _, _, err := db.EnsureAdmin(); err != nil {
		t.Fatal(err)
	}
	db.DB.Exec("UPDATE users SET must_change=0")
	var id int64
	db.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&id)
	session, err := db.CreateSession(id)
	if err != nil {
		t.Fatal(err)
	}

	// 1. GET /api/v1/external-subscriptions (unauthenticated -> 401)
	reqUnauth := httptest.NewRequest(http.MethodGet, "/api/v1/external-subscriptions", nil)
	recUnauth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recUnauth, reqUnauth)
	if recUnauth.Code != http.StatusUnauthorized {
		t.Fatalf("expected 401, got %d", recUnauth.Code)
	}

	// 2. GET /api/v1/external-subscriptions (authenticated -> 200, empty list)
	reqAuth := httptest.NewRequest(http.MethodGet, "/api/v1/external-subscriptions", nil)
	reqAuth.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	recAuth := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recAuth, reqAuth)
	if recAuth.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d", recAuth.Code)
	}
	var list []model.ExternalSubscription
	if err := json.Unmarshal(recAuth.Body.Bytes(), &list); err != nil || len(list) != 0 {
		t.Fatalf("expected empty list, got %+v", list)
	}

	// 3. POST /api/v1/external-subscriptions (create)
	createBody := `{"name":"Test Airport","url":"https://example.com/test-sub","userAgent":"ClashMeta","syncIntervalHours":6}`
	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/external-subscriptions", strings.NewReader(createBody))
	reqCreate.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	reqCreate.Header.Set("X-CSRF-Token", session.CSRF)
	recCreate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recCreate, reqCreate)
	if recCreate.Code != http.StatusOK {
		t.Fatalf("create expected 200, got %d: %s", recCreate.Code, recCreate.Body.String())
	}
	var created model.ExternalSubscription
	if err := json.Unmarshal(recCreate.Body.Bytes(), &created); err != nil || created.ID == "" || created.Name != "Test Airport" {
		t.Fatalf("unexpected created response: %+v", created)
	}

	// 4. PUT /api/v1/external-subscriptions/{id} (update)
	updateBody := `{"name":"Updated Airport","syncIntervalHours":24}`
	reqUpdate := httptest.NewRequest(http.MethodPut, "/api/v1/external-subscriptions/"+created.ID, strings.NewReader(updateBody))
	reqUpdate.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	reqUpdate.Header.Set("X-CSRF-Token", session.CSRF)
	recUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recUpdate, reqUpdate)
	if recUpdate.Code != http.StatusOK {
		t.Fatalf("update expected 200, got %d: %s", recUpdate.Code, recUpdate.Body.String())
	}
	var updated model.ExternalSubscription
	if err := json.Unmarshal(recUpdate.Body.Bytes(), &updated); err != nil || updated.Name != "Updated Airport" || updated.SyncIntervalHours != 24 {
		t.Fatalf("unexpected updated response: %+v", updated)
	}

	// 5. DELETE /api/v1/external-subscriptions/{id}
	reqDel := httptest.NewRequest(http.MethodDelete, "/api/v1/external-subscriptions/"+created.ID, nil)
	reqDel.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	reqDel.Header.Set("X-CSRF-Token", session.CSRF)
	recDel := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recDel, reqDel)
	if recDel.Code != http.StatusOK {
		t.Fatalf("delete expected 200, got %d: %s", recDel.Code, recDel.Body.String())
	}

	// Verify it's gone
	reqListAfter := httptest.NewRequest(http.MethodGet, "/api/v1/external-subscriptions", nil)
	reqListAfter.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	recListAfter := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recListAfter, reqListAfter)
	var listAfter []model.ExternalSubscription
	_ = json.Unmarshal(recListAfter.Body.Bytes(), &listAfter)
	if len(listAfter) != 0 {
		t.Fatalf("expected 0 after delete, got %d", len(listAfter))
	}
}

func TestExternalSubscriptionDirectPasteAndProxyMode(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := New(config.Config{DataDir: dir, BasePath: "/", SecureCookie: false}, db, subMockAgent{}, "1.0.0")
	if _, _, err := db.EnsureAdmin(); err != nil {
		t.Fatal(err)
	}
	db.DB.Exec("UPDATE users SET must_change=0")
	var id int64
	db.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&id)
	session, err := db.CreateSession(id)
	if err != nil {
		t.Fatal(err)
	}

	// 1. Create a subscription with direct paste rawContent (Clash YAML format)
	clashYAML := `proxies:
  - name: "Direct Paste Trojan"
    type: trojan
    server: direct.example.com
    port: 443
    password: mypassword
    sni: direct.example.com`
	createBody, _ := json.Marshal(map[string]any{
		"name":       "Pasted Airport",
		"rawContent": clashYAML,
		"proxyUrl":   "http://127.0.0.1:2080",
	})

	reqCreate := httptest.NewRequest(http.MethodPost, "/api/v1/external-subscriptions", strings.NewReader(string(createBody)))
	reqCreate.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	reqCreate.Header.Set("X-CSRF-Token", session.CSRF)
	recCreate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recCreate, reqCreate)
	if recCreate.Code != http.StatusOK {
		t.Fatalf("create expected 200, got %d: %s", recCreate.Code, recCreate.Body.String())
	}

	var created model.ExternalSubscription
	if err := json.Unmarshal(recCreate.Body.Bytes(), &created); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if created.URL != "manual" || created.ProxyURL != "http://127.0.0.1:2080" {
		t.Fatalf("unexpected created sub: %+v", created)
	}
	if len(created.Nodes) != 1 || created.Nodes[0].Name != "Direct Paste Trojan" {
		t.Fatalf("expected 1 parsed node, got %+v", created.Nodes)
	}

	// 2. Sync again should re-parse successfully
	reqSync := httptest.NewRequest(http.MethodPost, "/api/v1/external-subscriptions/"+created.ID+"/sync", nil)
	reqSync.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	reqSync.Header.Set("X-CSRF-Token", session.CSRF)
	recSync := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recSync, reqSync)
	if recSync.Code != http.StatusOK {
		t.Fatalf("sync expected 200, got %d: %s", recSync.Code, recSync.Body.String())
	}

	var synced model.ExternalSubscription
	if err := json.Unmarshal(recSync.Body.Bytes(), &synced); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(synced.Nodes) != 1 || synced.LastError != "" {
		t.Fatalf("expected successful sync with 1 node, got nodes=%+v, err=%s", synced.Nodes, synced.LastError)
	}

	// 3. Update rawContent with multiple Trojan links
	linkList := "trojan://pass1@node1.example.com:443?sni=node1.example.com#Node01\ntrojan://pass2@node2.example.com:443?sni=node2.example.com#Node02"
	updateBody, _ := json.Marshal(map[string]any{
		"rawContent": linkList,
	})
	reqUpdate := httptest.NewRequest(http.MethodPut, "/api/v1/external-subscriptions/"+created.ID, strings.NewReader(string(updateBody)))
	reqUpdate.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
	reqUpdate.Header.Set("X-CSRF-Token", session.CSRF)
	recUpdate := httptest.NewRecorder()
	srv.Handler().ServeHTTP(recUpdate, reqUpdate)
	if recUpdate.Code != http.StatusOK {
		t.Fatalf("update expected 200, got %d: %s", recUpdate.Code, recUpdate.Body.String())
	}

	var updated model.ExternalSubscription
	if err := json.Unmarshal(recUpdate.Body.Bytes(), &updated); err != nil {
		t.Fatalf("unmarshal error: %v", err)
	}
	if len(updated.Nodes) != 2 {
		t.Fatalf("expected 2 parsed nodes from updated URI list, got %d: %+v", len(updated.Nodes), updated.Nodes)
	}
}

func TestFilterDummyAnnouncementNodesAndExtractUserinfo(t *testing.T) {
	// Sample Clash proxies YAML containing airport announcement dummy nodes
	clashWithDummy := `proxies:
  - {name: "Traffic: 11.72 GB / 200 GB", server: oss-guangzhou.example.com, port: 20004, type: trojan, password: pass}
  - {name: "Expire: 2027-02-18", server: oss-guangzhou.example.com, port: 20004, type: trojan, password: pass}
  - {name: "官网地址: https://example.com", server: 127.0.0.1, port: 1080, type: trojan, password: pass}
  - {name: "🇭🇰 Hong Kong | 01", server: hk1.example.com, port: 20001, type: trojan, password: pass}
  - {name: "🇭🇰 Hong Kong | 02", server: hk2.example.com, port: 20002, type: trojan, password: pass}
  - {name: "🇯🇵 Japan | 01", server: jp1.example.com, port: 20003, type: trojan, password: pass}`

	nodes, userinfo, err := ParseExternalSubscription([]byte(clashWithDummy), nil, "sub-dummy-test")
	if err != nil {
		t.Fatalf("ParseExternalSubscription failed: %v", err)
	}

	// 1. Verify dummy nodes were filtered out: only 3 real nodes remain
	if len(nodes) != 3 {
		t.Fatalf("expected exactly 3 real nodes, got %d: %+v", len(nodes), nodes)
	}
	for _, n := range nodes {
		if strings.Contains(n.Name, "Traffic") || strings.Contains(n.Name, "Expire") || strings.Contains(n.Name, "官网") {
			t.Fatalf("dummy node was not filtered: %s", n.Name)
		}
	}

	// 2. Verify traffic quota and expiry were extracted from dummy nodes
	expectedTotal := int64(200) * 1024 * 1024 * 1024
	if userinfo.TotalBytes != expectedTotal {
		t.Fatalf("expected total bytes %d, got %d", expectedTotal, userinfo.TotalBytes)
	}
	if userinfo.DownloadBytes <= 0 {
		t.Fatalf("expected positive download bytes, got %d", userinfo.DownloadBytes)
	}
	if userinfo.ExpiresAt != "2027-02-18" {
		t.Fatalf("expected expiresAt 2027-02-18, got %s", userinfo.ExpiresAt)
	}
}

func TestFleetSubscriptionSanitizationAndFlagInjection(t *testing.T) {
	dir := t.TempDir()
	db, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer db.Close()

	srv := New(config.Config{DataDir: dir, BasePath: "/", SecureCookie: false}, db, subMockAgent{}, "1.0.0")
	_ = db.SetSetting("fleet_global_token", "fleet-token-123")
	_ = db.SetSetting("fleet_controller_enabled", "true")

	extSub := model.ExternalSubscription{
		ID:      "sub-sanitize-test",
		Name:    "Test Airport",
		URL:     "manual",
		Enabled: true,
		Nodes: []model.Node{
			{
				ID:       "node-hk-noisy",
				Name:     "Hong Kong 01 | 剩余流量999G | 官网：https://airport.com",
				Protocol: "trojan",
				Server:   "hk1.example.com",
				ShareURI: "trojan://password@hk1.example.com:443#Hong%20Kong%2001%20%7C%20%E5%AE%98%E7%BD%91",
				Status:   "active",
			},
			{
				ID:       "node-tw-clean",
				Name:     "台湾 02 [1.5x] - 请勿测速",
				Protocol: "trojan",
				Server:   "tw1.example.com",
				ShareURI: "trojan://password@tw1.example.com:443#Taiwan",
				Status:   "active",
			},
		},
	}
	if err := db.SaveExternalSubscription(extSub); err != nil {
		t.Fatal(err)
	}

	req := httptest.NewRequest(http.MethodGet, "/fleet-sub/fleet-token-123/clash.yaml", nil)
	rec := httptest.NewRecorder()
	srv.Handler().ServeHTTP(rec, req)

	if rec.Code != http.StatusOK {
		t.Fatalf("fleet-sub failed with code %d: %s", rec.Code, rec.Body.String())
	}

	body := rec.Body.String()
	// Should have flag injected and ads removed
	if !strings.Contains(body, "🇭🇰 Hong Kong 01") {
		t.Errorf("expected '🇭🇰 Hong Kong 01' in Clash output, got:\n%s", body)
	}
	if strings.Contains(body, "剩余流量") || strings.Contains(body, "官网") {
		t.Errorf("expected ads to be stripped, got:\n%s", body)
	}
	if !strings.Contains(body, "🇹🇼 台湾 02") {
		t.Errorf("expected '🇹🇼 台湾 02' in Clash output, got:\n%s", body)
	}
	if strings.Contains(body, "请勿测速") || strings.Contains(body, "1.5x") {
		t.Errorf("expected rate/test warning to be stripped, got:\n%s", body)
	}
}


