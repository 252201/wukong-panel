package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/probe"
	"github.com/252201/wukong-panel/internal/store"
)

type fleetHealthAgent struct{ fakeAgent }

func (fleetHealthAgent) Health(context.Context) (map[string]any, error) {
	return map[string]any{"version": "1.13.14"}, nil
}

type networkTestAgent struct {
	fleetHealthAgent
	health model.NetworkHealth
}

func (a networkTestAgent) NetworkHealth(context.Context) (*model.NetworkHealth, error) {
	return &a.health, nil
}

func fleetWebTestServer(t *testing.T) (*Server, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	database, err := store.Open(filepath.Join(dir, "fleet.db"))
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = database.Close() })
	if err = database.SetSetting("fleet_controller_enabled", "true"); err != nil {
		t.Fatal(err)
	}
	if err = database.SetSetting("fleet_public_url", "https://controller.example/wukong/"); err != nil {
		t.Fatal(err)
	}
	return New(config.Config{DataDir: dir, BasePath: "/", SecureCookie: false}, database, fleetHealthAgent{}, "0.9.0"), database
}

func TestBuildFleetStatusIncludesLocalSingBoxVersion(t *testing.T) {
	server, _ := fleetWebTestServer(t)
	status, err := server.buildFleetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Hosts) == 0 {
		t.Fatal("fleet status has no hosts")
	}
	local := status.Hosts[0]
	if local.ID != localFleetHostID || local.SingBoxVersion != "1.13.14" {
		t.Fatalf("local host version=%q host=%q", local.SingBoxVersion, local.ID)
	}
	if local.OS == "" || local.Arch != runtime.GOARCH {
		t.Fatalf("local host platform=%q/%q", local.OS, local.Arch)
	}
	if local.Snapshot.Overview.SingBoxVersion != "1.13.14" {
		t.Fatalf("local snapshot version=%q", local.Snapshot.Overview.SingBoxVersion)
	}
	if local.Snapshot.Overview.BillingStart == "" || local.Snapshot.Overview.BillingEnd == "" {
		t.Fatalf("local snapshot billing period=%q..%q", local.Snapshot.Overview.BillingStart, local.Snapshot.Overview.BillingEnd)
	}
}

func TestOverviewAndFleetLocalExposeAgentNetworkHealth(t *testing.T) {
	server, _ := fleetWebTestServer(t)
	want := model.NetworkHealth{Status: "ok", LatencyMS: 42.5, PacketLossPct: 10, PacketsSent: 10, PacketsReceived: 9, Targets: []string{"1.1.1.1"}, CheckedAt: time.Now().UTC(), History: []model.NetworkSample{{Status: "ok", LatencyMS: 42.5, PacketLossPct: 10, PacketsSent: 10, PacketsReceived: 9, TargetResults: []model.NetworkTargetResult{{Target: "1.1.1.1", PacketsSent: 10, PacketsReceived: 9}}, CheckedAt: time.Now().UTC()}}, International: &model.NetworkGroupHealth{Status: "ok", LatencyMS: 42.5, Targets: []string{"1.1.1.1"}}, Domestic: &model.NetworkGroupHealth{Status: "ok", LatencyMS: 160, Targets: []string{"194.138.202.35"}, History: []model.NetworkSample{{Status: "ok", LatencyMS: 160, TargetResults: []model.NetworkTargetResult{{Target: "194.138.202.35", PacketsSent: 5, PacketsReceived: 4}}, CheckedAt: time.Now().UTC()}}}}
	server.agent = networkTestAgent{health: want}

	request := httptest.NewRequest(http.MethodGet, "/api/v1/overview", nil)
	recorder := httptest.NewRecorder()
	server.overview(recorder, request, store.Session{Username: "admin"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("overview status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var overview model.Overview
	if err := json.Unmarshal(recorder.Body.Bytes(), &overview); err != nil {
		t.Fatal(err)
	}
	if overview.Network == nil || overview.Network.LatencyMS != want.LatencyMS || overview.Network.PacketLossPct != want.PacketLossPct || len(overview.Network.History) != 1 || overview.Network.History[0].TargetResults[0].PacketsReceived != 9 || overview.Network.Domestic == nil || overview.Network.Domestic.LatencyMS != 160 || len(overview.Network.Domestic.History) != 1 || overview.Network.Domestic.History[0].TargetResults[0].PacketsReceived != 4 {
		t.Fatalf("overview network=%+v", overview.Network)
	}

	status, err := server.buildFleetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Hosts) == 0 || status.Hosts[0].Snapshot.Overview.Network == nil || status.Hosts[0].Snapshot.Overview.Network.PacketsReceived != want.PacketsReceived || len(status.Hosts[0].Snapshot.Overview.Network.History) != 1 || status.Hosts[0].Snapshot.Overview.Network.History[0].TargetResults[0].PacketsReceived != 9 || status.Hosts[0].Snapshot.Overview.Network.Domestic == nil || status.Hosts[0].Snapshot.Overview.Network.Domestic.LatencyMS != 160 || status.Hosts[0].Snapshot.Overview.Network.Domestic.History[0].TargetResults[0].PacketsReceived != 4 {
		t.Fatalf("fleet local network=%+v", status.Hosts)
	}
}

func TestFleetSubscriptionPublicURLFallbackAndOverride(t *testing.T) {
	server, database := fleetWebTestServer(t)
	if err := database.SetSetting("fleet_global_token", "global-secret"); err != nil {
		t.Fatal(err)
	}
	status, err := server.buildFleetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.GlobalSubscription != "https://controller.example/wukong/fleet-sub/global-secret/clash.yaml" {
		t.Fatalf("fallback subscription=%q", status.GlobalSubscription)
	}
	if err = database.SetSetting("fleet_subscription_public_url", "https://subscribe.example/"); err != nil {
		t.Fatal(err)
	}
	status, err = server.buildFleetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if status.SubscriptionPublicURL != "https://subscribe.example/" || status.GlobalSubscription != "https://subscribe.example/fleet-sub/global-secret/clash.yaml" {
		t.Fatalf("dedicated subscription status=%+v", status)
	}
}

func TestSaveFleetStatusPreservesDedicatedURLForLegacyClients(t *testing.T) {
	server, database := fleetWebTestServer(t)
	if err := database.SetSetting("fleet_subscription_public_url", "https://subscribe.example/"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/status", strings.NewReader(`{"enabled":true,"publicUrl":"https://new-controller.example/panel"}`))
	recorder := httptest.NewRecorder()
	server.saveFleetStatus(recorder, request, store.Session{Username: "admin"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("save status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := mustSetting(database, "fleet_subscription_public_url"); got != "https://subscribe.example/" {
		t.Fatalf("legacy save replaced dedicated URL: %q", got)
	}

	request = httptest.NewRequest(http.MethodPut, "/api/v1/fleet/status", strings.NewReader(`{"enabled":true,"publicUrl":"https://new-controller.example/panel","subscriptionPublicUrl":"https://sub.example/path"}`))
	recorder = httptest.NewRecorder()
	server.saveFleetStatus(recorder, request, store.Session{Username: "admin"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("dedicated save status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	if got := mustSetting(database, "fleet_subscription_public_url"); got != "https://sub.example/path/" {
		t.Fatalf("normalized dedicated URL=%q", got)
	}
}

func TestSaveFleetStatusRejectsInvalidSubscriptionURL(t *testing.T) {
	server, _ := fleetWebTestServer(t)
	request := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/status", strings.NewReader(`{"enabled":true,"publicUrl":"https://controller.example/","subscriptionPublicUrl":"http://subscribe.example"}`))
	recorder := httptest.NewRecorder()
	server.saveFleetStatus(recorder, request, store.Session{Username: "admin"})
	if recorder.Code != http.StatusBadRequest || !strings.Contains(recorder.Body.String(), "订阅公开地址") {
		t.Fatalf("invalid URL status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestProbeFleetSubscription(t *testing.T) {
	server, database := fleetWebTestServer(t)
	if err := database.SetSetting("fleet_global_token", "global-secret"); err != nil {
		t.Fatal(err)
	}
	endpoint := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/fleet-sub/global-secret/clash.yaml" {
			t.Errorf("probe path=%q", r.URL.Path)
		}
		_, _ = w.Write([]byte("proxies:\n  - name: edge-a\n  - name: edge-b\nproxy-groups:\n  - name: Wukong Fleet\n    type: select\n    proxies:\n      - edge-a\n      - edge-b\nrules:\n  - MATCH,Wukong Fleet\n"))
	}))
	defer endpoint.Close()
	server.fleetProbeClient = endpoint.Client()
	server.fleetProbeClient.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	request := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/subscription-probe", strings.NewReader(`{"subscriptionPublicUrl":"`+endpoint.URL+`"}`))
	recorder := httptest.NewRecorder()
	server.probeFleetSubscription(recorder, request, store.Session{Username: "admin"})
	if recorder.Code != http.StatusOK {
		t.Fatalf("probe status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result struct {
		OK        bool  `json:"ok"`
		NodeCount int   `json:"nodeCount"`
		LatencyMS int64 `json:"latencyMs"`
	}
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	if !result.OK || result.NodeCount != 2 || result.LatencyMS < 0 {
		t.Fatalf("probe result=%+v", result)
	}
}

func TestFleetSubscriptionNodeCountExcludesProxyGroup(t *testing.T) {
	content := "proxies:\n  - name: edge-a\n  - name: edge-b\nproxy-groups:\n  - name: Wukong Fleet\n    type: select\n    proxies:\n      - edge-a\n      - edge-b\nrules:\n  - MATCH,Wukong Fleet\n"
	if got := fleetSubscriptionNodeCount(content); got != 2 {
		t.Fatalf("node count=%d, want 2", got)
	}
}

func TestFleetSubscriptionNodeCountWithDNS(t *testing.T) {
	content := `# OFFLINE CACHE: Central Edge
proxies:
  - name: "HK-01"
    type: hysteria2
    server: "hk.example.com"
  - name: "SG-01"
    type: vless
    server: "sg.example.com"
proxy-groups:
  - name: 🚀 节点选择
    type: select
    proxies:
      - ♻️ 自动选择
      - "HK-01"
      - "SG-01"
  - name: ♻️ 自动选择
    type: url-test
    proxies:
      - "HK-01"
      - "SG-01"
rules:
  - MATCH,🐟 漏网之鱼
dns:
  enable: true
  enhanced-mode: fake-ip
  nameserver-policy:
    "geosite:openai,claude": "https://1.1.1.1/dns-query#🚀 节点选择"
`
	if got := fleetSubscriptionNodeCount(content); got != 2 {
		t.Fatalf("node count=%d, want 2", got)
	}
}

func TestFleetSubscriptionTemplateOverride(t *testing.T) {
	server, database := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, database, "edge-tpl", "Tpl Edge")
	selected, _ := json.Marshal([]string{enrolled.HostID})
	_ = database.SetSetting("fleet_subscription_hosts", string(selected))
	_ = database.SetSetting("fleet_global_token", "global-tpl")

	host, err := database.FleetHost(enrolled.HostID)
	if err != nil {
		t.Fatal(err)
	}
	entries := []fleetSubscriptionEntry{
		{
			Node:  model.Node{ID: "node-1", Name: "US-Node", Protocol: "vless", Status: "active"},
			Share: model.Share{URI: "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?security=tls&type=tcp#US-Node"},
		},
	}
	plain, _ := json.Marshal(entries)
	sealed, err := server.fleetVault.Encrypt(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	if err = database.SaveFleetSubscriptionCache(host.ID, fleetSubscriptionRevision(host), sealed); err != nil {
		t.Fatal(err)
	}

	// 1. Default -> standard (fake-ip + 🚀 节点选择)
	reqDef := httptest.NewRequest(http.MethodGet, "/fleet-sub/global-tpl/clash.yaml", nil)
	recDef := httptest.NewRecorder()
	server.Handler().ServeHTTP(recDef, reqDef)
	if recDef.Code != http.StatusOK {
		t.Fatalf("status=%d", recDef.Code)
	}
	bodyDef := recDef.Body.String()
	if !strings.Contains(bodyDef, "🚀 节点选择") || !strings.Contains(bodyDef, "enhanced-mode: fake-ip") {
		t.Fatalf("expected standard template:\n%s", bodyDef)
	}
	if strings.Contains(bodyDef, "🤖 AI 服务") {
		t.Fatalf("standard template should not have AI group")
	}

	// 2. URL param ?template=smart -> smart
	reqSmart := httptest.NewRequest(http.MethodGet, "/fleet-sub/global-tpl/clash.yaml?template=smart", nil)
	recSmart := httptest.NewRecorder()
	server.Handler().ServeHTTP(recSmart, reqSmart)
	if recSmart.Code != http.StatusOK {
		t.Fatalf("status=%d", recSmart.Code)
	}
	bodySmart := recSmart.Body.String()
	if !strings.Contains(bodySmart, "🤖 AI 服务") || !strings.Contains(bodySmart, "nameserver-policy:") {
		t.Fatalf("expected smart template:\n%s", bodySmart)
	}

	// 3. URL param ?template=minimal -> minimal
	reqMin := httptest.NewRequest(http.MethodGet, "/fleet-sub/global-tpl/clash.yaml?template=minimal", nil)
	recMin := httptest.NewRecorder()
	server.Handler().ServeHTTP(recMin, reqMin)
	if recMin.Code != http.StatusOK {
		t.Fatalf("status=%d", recMin.Code)
	}
	bodyMin := recMin.Body.String()
	if strings.Contains(bodyMin, "dns:") || !strings.Contains(bodyMin, "MATCH,Wukong Fleet") {
		t.Fatalf("expected minimal template:\n%s", bodyMin)
	}
}

func TestProbeFleetSubscriptionDoesNotFollowRedirects(t *testing.T) {
	server, database := fleetWebTestServer(t)
	if err := database.SetSetting("fleet_global_token", "global-secret"); err != nil {
		t.Fatal(err)
	}
	redirectReached := false
	destination := httptest.NewTLSServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		redirectReached = true
	}))
	defer destination.Close()
	origin := httptest.NewTLSServer(http.HandlerFunc(func(w http.ResponseWriter, _ *http.Request) {
		http.Redirect(w, &http.Request{}, destination.URL, http.StatusFound)
	}))
	defer origin.Close()
	client := origin.Client()
	client.CheckRedirect = func(_ *http.Request, _ []*http.Request) error { return http.ErrUseLastResponse }
	server.fleetProbeClient = client
	request := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/subscription-probe", strings.NewReader(`{"subscriptionPublicUrl":"`+origin.URL+`"}`))
	recorder := httptest.NewRecorder()
	server.probeFleetSubscription(recorder, request, store.Session{Username: "admin"})
	if recorder.Code != http.StatusBadGateway || redirectReached {
		t.Fatalf("redirect probe status=%d reached=%t body=%s", recorder.Code, redirectReached, recorder.Body.String())
	}
	if strings.Contains(recorder.Body.String(), "global-secret") {
		t.Fatal("probe error leaked subscription token")
	}
}

func enrollFleetAgent(t *testing.T, server *Server, database *store.Store, enrollment, name string) model.FleetEnrollmentResponse {
	t.Helper()
	if err := database.CreateFleetEnrollmentToken(enrollment, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	body, _ := json.Marshal(model.FleetEnrollmentRequest{Token: enrollment, Name: name, Hostname: strings.ToLower(name), OS: "debian", Arch: "amd64", PanelVersion: "0.9.0", ProtocolVersion: model.FleetProtocolVersion, Capabilities: []string{"overview", "nodes.write"}})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/enroll", bytes.NewReader(body))
	request.RemoteAddr = "192.0.2.10:1234"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("enroll status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	var result model.FleetEnrollmentResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &result); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestFleetAgentEnrollmentHeartbeatAndOneTimeToken(t *testing.T) {
	server, database := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, database, "one-time", "Edge A")
	if enrolled.HostID == "" || len(enrolled.AgentToken) < 40 {
		t.Fatalf("weak enrollment response: %+v", enrolled)
	}
	var rawTokenCount int
	if err := database.DB.QueryRow(`SELECT count(*) FROM fleet_hosts WHERE token_hash=?`, enrolled.AgentToken).Scan(&rawTokenCount); err != nil {
		t.Fatal(err)
	}
	if rawTokenCount != 0 {
		t.Fatal("controller stored raw agent token")
	}
	body, _ := json.Marshal(model.FleetEnrollmentRequest{Token: "one-time", Name: "Replay", ProtocolVersion: 1})
	replay := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/enroll", bytes.NewReader(body))
	replay.RemoteAddr = "192.0.2.11:1234"
	replayRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(replayRecorder, replay)
	if replayRecorder.Code != http.StatusUnauthorized {
		t.Fatalf("replay status=%d", replayRecorder.Code)
	}
	networkSample := model.NetworkSample{Status: "ok", LatencyMS: 42, PacketsSent: 10, PacketsReceived: 10, CheckedAt: time.Now().UTC()}
	heartbeatBody, _ := json.Marshal(model.FleetHeartbeat{ProtocolVersion: 1, PanelVersion: "0.9.0", Snapshot: model.FleetSnapshot{Full: true, Overview: model.Overview{Now: model.Metric{Timestamp: time.Now().Unix(), CPU: 18}, Network: &model.NetworkHealth{Status: "ok", LatencyMS: 42, History: []model.NetworkSample{networkSample}, Domestic: &model.NetworkGroupHealth{Status: "ok", LatencyMS: 160, History: []model.NetworkSample{{Status: "ok", LatencyMS: 160, CheckedAt: time.Now().UTC()}}}}}, Nodes: []model.Node{{ID: "node-a", Name: "A", Status: "active"}}}})
	heartbeat := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/heartbeat", bytes.NewReader(heartbeatBody))
	heartbeat.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	heartbeat.Header.Set("X-Wukong-Host-ID", enrolled.HostID)
	heartbeatRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(heartbeatRecorder, heartbeat)
	if heartbeatRecorder.Code != http.StatusNoContent {
		t.Fatalf("heartbeat status=%d body=%s", heartbeatRecorder.Code, heartbeatRecorder.Body.String())
	}
	host, err := database.FleetHost(enrolled.HostID)
	if err != nil || !host.Online || host.Snapshot.Nodes[0].ID != "node-a" || host.Snapshot.Overview.Network == nil || len(host.Snapshot.Overview.Network.History) != 1 || host.Snapshot.Overview.Network.History[0].LatencyMS != 42 || host.Snapshot.Overview.Network.Domestic == nil || len(host.Snapshot.Overview.Network.Domestic.History) != 1 || host.Snapshot.Overview.Network.Domestic.LatencyMS != 160 {
		t.Fatalf("host=%+v err=%v", host, err)
	}
}

func TestFleetCommandPayloadEncryptionLongPollAndHostIsolation(t *testing.T) {
	server, database := fleetWebTestServer(t)
	first := enrollFleetAgent(t, server, database, "first", "Edge A")
	second := enrollFleetAgent(t, server, database, "second", "Edge B")
	heartbeat := model.FleetHeartbeat{ProtocolVersion: 1, Snapshot: model.FleetSnapshot{Full: true, Overview: model.Overview{Now: model.Metric{Timestamp: time.Now().Unix()}}}}
	if err := database.SaveFleetHeartbeat(context.Background(), first.HostID, heartbeat); err != nil {
		t.Fatal(err)
	}
	host, err := database.FleetHost(first.HostID)
	if err != nil {
		t.Fatal(err)
	}
	command, _, err := server.queueFleetCommand(host, "node.rename", json.RawMessage(`{"id":"node-a","request":{"name":"secret-name"}}`), "admin", false)
	if err != nil {
		t.Fatal(err)
	}
	var storedCipher string
	if err = database.DB.QueryRow(`SELECT payload_cipher FROM fleet_commands WHERE id=?`, command.ID).Scan(&storedCipher); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(storedCipher, "secret-name") {
		t.Fatal("command payload was stored in plaintext")
	}
	next := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agent/commands/next?wait=1", nil)
	next.Header.Set("Authorization", "Bearer "+first.AgentToken)
	next.Header.Set("X-Wukong-Host-ID", first.HostID)
	nextRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(nextRecorder, next)
	if nextRecorder.Code != http.StatusOK || !strings.Contains(nextRecorder.Body.String(), "secret-name") {
		t.Fatalf("next=%d %s", nextRecorder.Code, nextRecorder.Body.String())
	}
	resultBody := []byte(`{"status":"success","result":{"ok":true}}`)
	cross := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/commands/"+command.ID+"/result", bytes.NewReader(resultBody))
	cross.Header.Set("Authorization", "Bearer "+second.AgentToken)
	cross.Header.Set("X-Wukong-Host-ID", second.HostID)
	crossRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(crossRecorder, cross)
	if crossRecorder.Code != http.StatusNotFound {
		t.Fatalf("cross-host result status=%d", crossRecorder.Code)
	}
	result := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/commands/"+command.ID+"/result", bytes.NewReader(resultBody))
	result.Header.Set("Authorization", "Bearer "+first.AgentToken)
	result.Header.Set("X-Wukong-Host-ID", first.HostID)
	resultRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(resultRecorder, result)
	if resultRecorder.Code != http.StatusNoContent {
		t.Fatalf("result status=%d body=%s", resultRecorder.Code, resultRecorder.Body.String())
	}
	raw, err := server.waitFleetCommand(context.Background(), command.ID, time.Second)
	if err != nil || !strings.Contains(string(raw), `"ok":true`) {
		t.Fatalf("raw=%s err=%v", raw, err)
	}
}

func TestFleetSubscriptionFailsWhenSelectedHostNeverCached(t *testing.T) {
	server, database := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, database, "offline", "Offline Edge")
	selected, _ := json.Marshal([]string{enrolled.HostID})
	if err := database.SetSetting("fleet_subscription_hosts", string(selected)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSetting("fleet_global_token", "global-secret"); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/fleet-sub/global-secret/clash.yaml", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusServiceUnavailable || !strings.Contains(recorder.Body.String(), "尚无可用订阅缓存") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestFleetSubscriptionUsesEncryptedOfflineCache(t *testing.T) {
	server, database := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, database, "cached", "Cached Edge")
	selected, _ := json.Marshal([]string{enrolled.HostID})
	if err := database.SetSetting("fleet_subscription_hosts", string(selected)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSetting("fleet_global_token", "global-secret"); err != nil {
		t.Fatal(err)
	}
	host, err := database.FleetHost(enrolled.HostID)
	if err != nil {
		t.Fatal(err)
	}
	entries := []fleetSubscriptionEntry{{
		Node:  model.Node{ID: "node-a", Name: "VLESS A", Protocol: "vless", Status: "active"},
		Share: model.Share{URI: "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?security=tls&type=tcp&sni=example.com#VLESS-A"},
	}}
	plain, _ := json.Marshal(entries)
	sealed, err := server.fleetVault.Encrypt(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	if err = database.SaveFleetSubscriptionCache(host.ID, fleetSubscriptionRevision(host), sealed); err != nil {
		t.Fatal(err)
	}
	var stored string
	if err = database.DB.QueryRow(`SELECT cipher FROM fleet_subscription_cache WHERE host_id=?`, host.ID).Scan(&stored); err != nil {
		t.Fatal(err)
	}
	if strings.Contains(stored, "00000000-0000-4000-8000-000000000001") {
		t.Fatal("subscription credential was stored in plaintext")
	}
	request := httptest.NewRequest(http.MethodGet, "/fleet-sub/global-secret/clash.yaml", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "OFFLINE CACHE: Cached Edge") || !strings.Contains(recorder.Body.String(), "name: \"VLESS A\"") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestFleetSubscriptionAcceptsSuccessfulEmptyCache(t *testing.T) {
	server, database := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, database, "empty-cache", "Empty Edge")
	selected, _ := json.Marshal([]string{enrolled.HostID})
	if err := database.SetSetting("fleet_subscription_hosts", string(selected)); err != nil {
		t.Fatal(err)
	}
	if err := database.SetSetting("fleet_global_token", "global-secret"); err != nil {
		t.Fatal(err)
	}
	host, err := database.FleetHost(enrolled.HostID)
	if err != nil {
		t.Fatal(err)
	}
	sealed, err := server.fleetVault.Encrypt(`[]`)
	if err != nil {
		t.Fatal(err)
	}
	if err = database.SaveFleetSubscriptionCache(host.ID, fleetSubscriptionRevision(host), sealed); err != nil {
		t.Fatal(err)
	}
	request := httptest.NewRequest(http.MethodGet, "/fleet-sub/global-secret/clash.yaml", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "proxies:") {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
}

func TestFleetSubscriptionCleanNodeNamesAndDeduplication(t *testing.T) {
	server, database := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, database, "edge-1", "JP-三网直连")
	selected, _ := json.Marshal([]string{enrolled.HostID})
	_ = database.SetSetting("fleet_subscription_hosts", string(selected))
	_ = database.SetSetting("fleet_global_token", "global-clean")

	host, err := database.FleetHost(enrolled.HostID)
	if err != nil {
		t.Fatal(err)
	}
	entries := []fleetSubscriptionEntry{
		{
			Node:  model.Node{ID: "node-1", Name: "JP-REALITY-V6优先", Protocol: "vless", Status: "active"},
			Share: model.Share{URI: "vless://00000000-0000-4000-8000-000000000001@203.0.113.10:443?security=tls&type=tcp#JP-REALITY-V6优先"},
		},
		{
			Node:  model.Node{ID: "node-2", Name: "JP-REALITY-V6优先", Protocol: "vless", Status: "active"},
			Share: model.Share{URI: "vless://00000000-0000-4000-8000-000000000002@203.0.113.11:443?security=tls&type=tcp#JP-REALITY-V6优先-2"},
		},
	}
	plain, _ := json.Marshal(entries)
	sealed, err := server.fleetVault.Encrypt(string(plain))
	if err != nil {
		t.Fatal(err)
	}
	if err = database.SaveFleetSubscriptionCache(host.ID, fleetSubscriptionRevision(host), sealed); err != nil {
		t.Fatal(err)
	}

	request := httptest.NewRequest(http.MethodGet, "/fleet-sub/global-clean/clash.yaml", nil)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)

	if recorder.Code != http.StatusOK {
		t.Fatalf("status=%d body=%s", recorder.Code, recorder.Body.String())
	}
	body := recorder.Body.String()
	if strings.Contains(body, "name: \"JP-三网直连 · ") {
		t.Fatalf("expected node name without VPS prefix, got: %s", body)
	}
	if !strings.Contains(body, "name: \"JP-REALITY-V6优先\"") {
		t.Fatalf("expected first node name JP-REALITY-V6优先, got: %s", body)
	}
	if !strings.Contains(body, "name: \"JP-REALITY-V6优先 (2)\"") {
		t.Fatalf("expected deduplicated second node name JP-REALITY-V6优先 (2), got: %s", body)
	}
}

func TestFleetAgentPayloadLimitAndControllerDisable(t *testing.T) {
	server, database := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, database, "limited", "Edge")
	oversized := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/heartbeat", strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	oversized.ContentLength = (1 << 20) + 1
	oversized.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	oversized.Header.Set("X-Wukong-Host-ID", enrolled.HostID)
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, oversized)
	if recorder.Code != http.StatusRequestEntityTooLarge {
		t.Fatalf("oversized status=%d", recorder.Code)
	}
	chunked := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/heartbeat", strings.NewReader(strings.Repeat("x", (1<<20)+1)))
	chunked.ContentLength = -1
	chunked.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	chunked.Header.Set("X-Wukong-Host-ID", enrolled.HostID)
	chunkedRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(chunkedRecorder, chunked)
	if chunkedRecorder.Code == http.StatusNoContent {
		t.Fatal("oversized chunked heartbeat was accepted")
	}
	if err := database.SetSetting("fleet_controller_enabled", "false"); err != nil {
		t.Fatal(err)
	}
	poll := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agent/commands/next?wait=1", nil)
	poll.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	poll.Header.Set("X-Wukong-Host-ID", enrolled.HostID)
	disabled := httptest.NewRecorder()
	server.Handler().ServeHTTP(disabled, poll)
	if disabled.Code != http.StatusNotFound {
		t.Fatalf("disabled controller accepted agent: %d", disabled.Code)
	}
}

func TestProbeEnrollmentCannotGainFleetCommands(t *testing.T) {
	server, database := fleetWebTestServer(t)
	const token = "probe_once"
	if err := database.CreateFleetEnrollmentToken(token, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	fullRequest := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/enroll", strings.NewReader(`{"token":"probe_once","name":"Full","capabilities":["nodes.write"]}`))
	fullRequest.RemoteAddr = "192.0.2.13:1234"
	fullRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(fullRecorder, fullRequest)
	if fullRecorder.Code != http.StatusBadRequest {
		t.Fatalf("probe token accepted full panel: %d", fullRecorder.Code)
	}
	enrollment, _ := json.Marshal(model.FleetEnrollmentRequest{Token: token, Name: "Probe", Hostname: "probe", OS: "linux", Arch: "amd64", ProtocolVersion: 1, Capabilities: []string{"overview", "probe"}})
	request := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/enroll", bytes.NewReader(enrollment))
	request.RemoteAddr = "192.0.2.12:1234"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, request)
	if recorder.Code != http.StatusCreated {
		t.Fatalf("enroll: %d %s", recorder.Code, recorder.Body.String())
	}
	var enrolled model.FleetEnrollmentResponse
	if err := json.Unmarshal(recorder.Body.Bytes(), &enrolled); err != nil {
		t.Fatal(err)
	}
	spoofed := model.FleetHeartbeat{ProtocolVersion: 1, Capabilities: []string{"overview", "nodes.write", "subscription-render"}, Snapshot: model.FleetSnapshot{Full: true, Overview: model.Overview{Now: model.Metric{Timestamp: time.Now().Unix(), CPU: 19}}}}
	if err := database.SaveFleetHeartbeat(context.Background(), enrolled.HostID, spoofed); err != nil {
		t.Fatal(err)
	}
	host, err := database.FleetHost(enrolled.HostID)
	if err != nil {
		t.Fatal(err)
	}
	if !fleetHasCapability(host, "probe") || fleetHasCapability(host, "nodes.write") {
		t.Fatalf("capabilities=%v", host.Capabilities)
	}
	if _, _, err = server.queueFleetCommand(host, "node.rename", json.RawMessage(`{}`), "admin", false); err == nil {
		t.Fatal("probe accepted command")
	}
	if _, _, err = server.queueFleetCommand(host, "probe.update", json.RawMessage(`{}`), "admin", true); err == nil {
		t.Fatal("probe without probe.update accepted probe.update command")
	}

	probeWithUpdate := host
	probeWithUpdate.Capabilities = []string{"overview", "probe", "probe.update"}
	cmd, job, err := server.queueFleetCommand(probeWithUpdate, "probe.update", json.RawMessage(`{"targetVersion":"2.0.0"}`), "admin", true)
	if err != nil {
		t.Fatalf("probe with probe.update failed to queue probe.update: %v", err)
	}
	if cmd.ID == "" || job.ID == "" {
		t.Fatalf("expected non-empty command and job, got cmd=%+v job=%+v", cmd, job)
	}
	storedJob, err := database.Job(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if storedJob.Message != "等待轻量探针接收更新指令" {
		t.Fatalf("expected probe waiting message, got %q", storedJob.Message)
	}

	jobReq := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/hosts/"+probeWithUpdate.ID+"/jobs/"+job.ID, nil)
	jobReq.SetPathValue("hostId", probeWithUpdate.ID)
	jobReq.SetPathValue("resource", "jobs/"+job.ID)
	jobRec := httptest.NewRecorder()
	server.fleetHostGateway(jobRec, jobReq, store.Session{Username: "admin"})
	if jobRec.Code != http.StatusOK {
		t.Fatalf("expected probe job query status 200, got %d: %s", jobRec.Code, jobRec.Body.String())
	}

	next := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/agent/commands/next?wait=1", nil)
	next.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	next.Header.Set("X-Wukong-Host-ID", enrolled.HostID)
	nextRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(nextRecorder, next)
	if nextRecorder.Code != http.StatusNoContent {
		t.Fatalf("probe command poll status=%d", nextRecorder.Code)
	}

	resultReq := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/commands/"+cmd.ID+"/result", strings.NewReader(`{"status":"success","result":{}}`))
	resultReq.SetPathValue("id", cmd.ID)
	resultReq.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	resultReq.Header.Set("X-Wukong-Host-ID", enrolled.HostID)
	resultRec := httptest.NewRecorder()
	server.fleetAgentCommandResult(resultRec, resultReq)
	if resultRec.Code != http.StatusNoContent {
		t.Fatalf("expected result status 204, got %d: %s", resultRec.Code, resultRec.Body.String())
	}
	finishedJob, err := database.Job(job.ID)
	if err != nil {
		t.Fatal(err)
	}
	if finishedJob.Status != "success" || finishedJob.Message != "轻量探针升级成功，已平滑重启" {
		t.Fatalf("expected probe upgrade success message, got status=%q message=%q", finishedJob.Status, finishedJob.Message)
	}
}

func TestProbeEnrollmentCommandUsesSeparateInstaller(t *testing.T) {
	server, _ := fleetWebTestServer(t)
	request := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/enrollments?type=probe", strings.NewReader(`{}`))
	recorder := httptest.NewRecorder()
	server.createFleetEnrollment(recorder, request, store.Session{Username: "admin"})
	if recorder.Code != http.StatusCreated || !strings.Contains(recorder.Body.String(), "probe-install.sh") || !strings.Contains(recorder.Body.String(), "probe_") || strings.Contains(recorder.Body.String(), "--join-controller") {
		t.Fatalf("probe command=%d %s", recorder.Code, recorder.Body.String())
	}
}

func TestLightweightProbeAppearsInControllerFleet(t *testing.T) {
	server, database := fleetWebTestServer(t)
	origin := httptest.NewTLSServer(server.Handler())
	defer origin.Close()
	const token = "probe_integration"
	if err := database.CreateFleetEnrollmentToken(token, time.Now().Add(time.Minute)); err != nil {
		t.Fatal(err)
	}
	directory := t.TempDir()
	joined, err := probe.Join(context.Background(), directory, origin.URL+"/", token, "Light VPS", origin.Client())
	if err != nil {
		t.Fatal(err)
	}
	client, err := probe.Load(directory)
	if err != nil {
		t.Fatal(err)
	}
	client.HTTP = origin.Client()
	client.Version = "1.7.0"
	if err = client.Heartbeat(context.Background()); err != nil {
		t.Fatal(err)
	}
	status, err := server.buildFleetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if len(status.Hosts) != 2 || status.Hosts[1].ID != joined.HostID || !status.Hosts[1].Online || !fleetHasCapability(status.Hosts[1], "probe") || status.Hosts[1].Snapshot.Overview.Now.Timestamp == 0 || status.Hosts[1].Snapshot.Overview.NodeCount != 0 {
		t.Fatalf("probe fleet status=%+v", status.Hosts)
	}

	// Test update fleet host settings
	settingsJSON := `{"billingResetDay":20,"trafficQuotaBytes":1000000000000,"trafficCalcMode":"both","expiresAt":"2027-10-01"}`
	setReq := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/hosts/"+joined.HostID+"/quota", strings.NewReader(settingsJSON))
	setReq.SetPathValue("hostId", joined.HostID)
	rec := httptest.NewRecorder()
	server.updateFleetHostSettings(rec, setReq, store.Session{Username: "admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("update settings status=%d %s", rec.Code, rec.Body.String())
	}

	// Test invalid date
	badDateReq := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/hosts/"+joined.HostID+"/quota", strings.NewReader(`{"expiresAt":"not-a-date"}`))
	badDateReq.SetPathValue("hostId", joined.HostID)
	badRec := httptest.NewRecorder()
	server.updateFleetHostSettings(badRec, badDateReq, store.Session{Username: "admin"})
	if badRec.Code != http.StatusBadRequest {
		t.Fatalf("expected 400 for bad date, got %d", badRec.Code)
	}

	// Verify status after update
	statusUpdated, err := server.buildFleetStatus(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if statusUpdated.Hosts[1].BillingResetDay != 20 || statusUpdated.Hosts[1].TrafficQuotaBytes != 1000000000000 || statusUpdated.Hosts[1].ExpiresAt != "2027-10-01" {
		t.Fatalf("updated host settings not reflected in fleet status: %+v", statusUpdated.Hosts[1])
	}
}

func TestRemotePanelUpdateCommandHandling(t *testing.T) {
	server, database := fleetWebTestServer(t)

	// 1. Host without panel.update capability
	legacyPanel := model.FleetHost{
		ID:              "panel-legacy",
		Name:            "Legacy Panel",
		Hostname:        "legacy.example.com",
		PanelVersion:    "2.0.2",
		ProtocolVersion: model.FleetProtocolVersion,
		Capabilities:    []string{"overview", "nodes.write"},
	}
	const tokenLegacy = "token_legacy"
	if err := database.CreateFleetEnrollmentToken(tokenLegacy, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := database.ConsumeFleetEnrollmentToken(tokenLegacy, legacyPanel, "agent_token_legacy"); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveFleetHeartbeat(context.Background(), legacyPanel.ID, model.FleetHeartbeat{
		ProtocolVersion: model.FleetProtocolVersion,
		Capabilities:    legacyPanel.Capabilities,
		PanelVersion:    legacyPanel.PanelVersion,
		Snapshot:        model.FleetSnapshot{Full: true},
	}); err != nil {
		t.Fatal(err)
	}

	reqLegacy := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/hosts/panel-legacy/system/panel/update", strings.NewReader(`{"targetVersion":"2.0.4"}`))
	reqLegacy.SetPathValue("hostId", "panel-legacy")
	reqLegacy.SetPathValue("resource", "system/panel/update")
	recLegacy := httptest.NewRecorder()
	server.fleetHostGateway(recLegacy, reqLegacy, store.Session{Username: "admin"})
	if recLegacy.Code != http.StatusConflict {
		t.Fatalf("expected 409 for legacy panel update, got %d: %s", recLegacy.Code, recLegacy.Body.String())
	}

	// 2. Host with panel.update capability
	modernPanel := model.FleetHost{
		ID:              "panel-modern",
		Name:            "Modern Panel",
		Hostname:        "modern.example.com",
		PanelVersion:    "2.0.3",
		ProtocolVersion: model.FleetProtocolVersion,
		Capabilities:    []string{"overview", "nodes.write", "panel.update"},
	}
	const tokenModern = "token_modern"
	if err := database.CreateFleetEnrollmentToken(tokenModern, time.Now().Add(time.Hour)); err != nil {
		t.Fatal(err)
	}
	if err := database.ConsumeFleetEnrollmentToken(tokenModern, modernPanel, "agent_token_modern"); err != nil {
		t.Fatal(err)
	}
	if err := database.SaveFleetHeartbeat(context.Background(), modernPanel.ID, model.FleetHeartbeat{
		ProtocolVersion: model.FleetProtocolVersion,
		Capabilities:    modernPanel.Capabilities,
		PanelVersion:    modernPanel.PanelVersion,
		Snapshot:        model.FleetSnapshot{Full: true},
	}); err != nil {
		t.Fatal(err)
	}

	// Query status on system/panel
	reqStatus := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/hosts/panel-modern/system/panel", nil)
	reqStatus.SetPathValue("hostId", "panel-modern")
	reqStatus.SetPathValue("resource", "system/panel")
	recStatus := httptest.NewRecorder()
	server.fleetHostGateway(recStatus, reqStatus, store.Session{Username: "admin"})
	if recStatus.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel status query, got %d: %s", recStatus.Code, recStatus.Body.String())
	}
	var state model.ComponentUpdateState
	if err := json.Unmarshal(recStatus.Body.Bytes(), &state); err != nil || !state.Writable || state.CurrentVersion != "2.0.3" {
		t.Fatalf("unexpected panel component update state: %+v (err: %v)", state, err)
	}

	// Post update on system/panel/update
	reqUpdate := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/hosts/panel-modern/system/panel/update", strings.NewReader(`{"targetVersion":"2.0.4"}`))
	reqUpdate.SetPathValue("hostId", "panel-modern")
	reqUpdate.SetPathValue("resource", "system/panel/update")
	recUpdate := httptest.NewRecorder()
	server.fleetHostGateway(recUpdate, reqUpdate, store.Session{Username: "admin"})
	if recUpdate.Code != http.StatusAccepted {
		t.Fatalf("expected 202 for panel update queue, got %d: %s", recUpdate.Code, recUpdate.Body.String())
	}
	var res map[string]string
	if err := json.Unmarshal(recUpdate.Body.Bytes(), &res); err != nil || res["jobId"] == "" {
		t.Fatalf("expected jobId in response, got %s", recUpdate.Body.String())
	}

	// Verify job created
	jobID := res["jobId"]
	job, err := database.Job(jobID)
	if err != nil {
		t.Fatal(err)
	}
	if job.Kind != "fleet.panel.update" || job.Message != "等待远端面板接收更新指令" {
		t.Fatalf("unexpected job attributes: %+v", job)
	}

	// Query job via gateway
	reqJob := httptest.NewRequest(http.MethodGet, "/api/v1/fleet/hosts/panel-modern/jobs/"+jobID, nil)
	reqJob.SetPathValue("hostId", "panel-modern")
	reqJob.SetPathValue("resource", "jobs/"+jobID)
	recJob := httptest.NewRecorder()
	server.fleetHostGateway(recJob, reqJob, store.Session{Username: "admin"})
	if recJob.Code != http.StatusOK {
		t.Fatalf("expected 200 for panel update job query, got %d: %s", recJob.Code, recJob.Body.String())
	}
}

func TestFleetHostCustomOrder(t *testing.T) {
	hosts := []model.FleetHost{
		{ID: "host-c", Name: "Host C"},
		{ID: "host-a", Name: "Host A"},
		{ID: "host-b", Name: "Host B"},
		{ID: "host-d", Name: "Host D"},
	}
	order := []string{"host-b", "host-d", "host-a"}
	sorted := sortFleetHostsByOrder(hosts, order)
	if len(sorted) != 4 {
		t.Fatalf("expected 4 hosts, got %d", len(sorted))
	}
	if sorted[0].ID != "host-b" || sorted[1].ID != "host-d" || sorted[2].ID != "host-a" || sorted[3].ID != "host-c" {
		t.Fatalf("unexpected order: %v, %v, %v, %v", sorted[0].ID, sorted[1].ID, sorted[2].ID, sorted[3].ID)
	}

	server, db := fleetWebTestServer(t)
	defer db.Close()

	req := httptest.NewRequest(http.MethodPut, "/api/v1/fleet/host-order", strings.NewReader(`{"order":["local", "host-2", "host-1", "host-2"]}`))
	rec := httptest.NewRecorder()
	server.saveFleetHostOrder(rec, req, store.Session{Username: "admin"})
	if rec.Code != http.StatusOK {
		t.Fatalf("expected 200, got %d: %s", rec.Code, rec.Body.String())
	}
	var res struct {
		OK    bool     `json:"ok"`
		Order []string `json:"order"`
	}
	if err := json.Unmarshal(rec.Body.Bytes(), &res); err != nil {
		t.Fatal(err)
	}
	if !res.OK || len(res.Order) != 2 || res.Order[0] != "host-2" || res.Order[1] != "host-1" {
		t.Fatalf("unexpected response: %+v", res)
	}
	saved, _ := db.Setting("fleet_host_order")
	if saved != `["host-2","host-1"]` {
		t.Fatalf("unexpected saved setting: %s", saved)
	}
}
