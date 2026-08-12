package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

type fleetHealthAgent struct{ fakeAgent }

func (fleetHealthAgent) Health(context.Context) (map[string]any, error) {
	return map[string]any{"version": "1.13.14"}, nil
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
	if local.Snapshot.Overview.SingBoxVersion != "1.13.14" {
		t.Fatalf("local snapshot version=%q", local.Snapshot.Overview.SingBoxVersion)
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
	heartbeatBody, _ := json.Marshal(model.FleetHeartbeat{ProtocolVersion: 1, PanelVersion: "0.9.0", Snapshot: model.FleetSnapshot{Full: true, Overview: model.Overview{Now: model.Metric{Timestamp: time.Now().Unix(), CPU: 18}}, Nodes: []model.Node{{ID: "node-a", Name: "A", Status: "active"}}}})
	heartbeat := httptest.NewRequest(http.MethodPost, "/api/v1/fleet/agent/heartbeat", bytes.NewReader(heartbeatBody))
	heartbeat.Header.Set("Authorization", "Bearer "+enrolled.AgentToken)
	heartbeat.Header.Set("X-Wukong-Host-ID", enrolled.HostID)
	heartbeatRecorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(heartbeatRecorder, heartbeat)
	if heartbeatRecorder.Code != http.StatusNoContent {
		t.Fatalf("heartbeat status=%d body=%s", heartbeatRecorder.Code, heartbeatRecorder.Body.String())
	}
	host, err := database.FleetHost(enrolled.HostID)
	if err != nil || !host.Online || host.Snapshot.Nodes[0].ID != "node-a" {
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
	if recorder.Code != http.StatusOK || !strings.Contains(recorder.Body.String(), "OFFLINE CACHE: Cached Edge") || !strings.Contains(recorder.Body.String(), "Cached Edge · VLESS A") {
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
