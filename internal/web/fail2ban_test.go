package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

type fail2banTestAgent struct {
	fakeAgent
	calls      int
	configured model.Fail2banConfig
	unbanned   string
}

func (a *fail2banTestAgent) Fail2ban(context.Context) (model.Fail2banStatus, error) {
	a.calls++
	return model.Fail2banStatus{Installed: true, Writable: true}, nil
}
func (a *fail2banTestAgent) ConfigureFail2ban(_ context.Context, r model.Fail2banConfig) (model.Fail2banStatus, error) {
	a.calls++
	a.configured = r
	return model.Fail2banStatus{}, nil
}
func (a *fail2banTestAgent) UnbanFail2ban(_ context.Context, r model.Fail2banUnbanRequest) (model.Fail2banStatus, error) {
	a.calls++
	a.unbanned = r.IP
	return model.Fail2banStatus{}, nil
}

func TestFail2banHTTPRequiresSessionAndCSRF(t *testing.T) {
	server, db := fleetWebTestServer(t)
	a := &fail2banTestAgent{}
	server.agent = a
	password, _, err := db.EnsureAdmin()
	if err != nil {
		t.Fatal(err)
	}
	id, _, err := db.Authenticate("admin", password)
	if err != nil {
		t.Fatal(err)
	}
	if err = db.ChangePassword(id, "firewall-test-password"); err != nil {
		t.Fatal(err)
	}
	session, err := db.CreateSession(id)
	if err != nil {
		t.Fatal(err)
	}
	handler := server.Handler()
	call := func(method, path, body string, cookie, csrf bool) *httptest.ResponseRecorder {
		request := httptest.NewRequest(method, path, strings.NewReader(body))
		if cookie {
			request.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
		}
		if csrf {
			request.Header.Set("X-CSRF-Token", session.CSRF)
		}
		recorder := httptest.NewRecorder()
		handler.ServeHTTP(recorder, request)
		return recorder
	}

	for _, r := range []struct{ method, path, body string }{{"GET", "/api/v1/system/fail2ban", ""}, {"POST", "/api/v1/system/fail2ban", `{"enabled":true,"maxRetry":5}`}, {"POST", "/api/v1/system/fail2ban/unban", `{"ip":"192.0.2.47"}`}} {
		if got := call(r.method, r.path, r.body, false, false); got.Code != 401 {
			t.Fatalf("unauth=%d", got.Code)
		}
		if r.method != "GET" {
			if got := call(r.method, r.path, r.body, true, false); got.Code != 403 {
				t.Fatalf("csrf=%d", got.Code)
			}
		}
	}
	if a.calls != 0 {
		t.Fatal("denied request reached Agent")
	}
	if got := call("GET", "/api/v1/system/fail2ban", "", true, false); got.Code != 200 {
		t.Fatal(got.Code)
	}
	if got := call("POST", "/api/v1/system/fail2ban", `{"enabled":true,"maxRetry":5}`, true, true); got.Code != 200 || !a.configured.Enabled {
		t.Fatal(got.Code)
	}
	if got := call("POST", "/api/v1/system/fail2ban/unban", `{"ip":"192.0.2.47"}`, true, true); got.Code != 200 || a.unbanned != "192.0.2.47" {
		t.Fatal(got.Code)
	}
	if got := call("POST", "/api/v1/system/fail2ban", `{"enabled":true,"command":"stop"}`, true, true); got.Code != 400 {
		t.Fatal("accepted unknown field")
	}
	if got := call("POST", "/api/v1/system/fail2ban/unban", `{"ip":"192.0.2.47","jail":"nginx"}`, true, true); got.Code != 400 {
		t.Fatal("accepted arbitrary jail")
	}
	var count int
	if err = db.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor='admin' AND action LIKE 'fail2ban.%'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit=%d err=%v", count, err)
	}
}

func TestFleetFail2banMappings(t *testing.T) {
	for _, tc := range []struct{ method, path, body, kind string }{{"GET", "system/fail2ban", "{}", "fail2ban.status"}, {"POST", "system/fail2ban", `{"enabled":true}`, "fail2ban.configure"}, {"POST", "system/fail2ban/unban", `{"ip":"192.0.2.47"}`, "fail2ban.unban"}} {
		req := httptest.NewRequest(tc.method, "/"+tc.path, strings.NewReader(tc.body))
		kind, body, async, err := fleetCommandForRequest(req, tc.path)
		if err != nil || kind != tc.kind || async || string(body) != tc.body {
			t.Fatalf("%s %s %s %v", tc.path, kind, body, err)
		}
	}
}

func TestFleetFail2banRejectsOldAgentsAndOfflineSnapshotIsReadOnly(t *testing.T) {
	server, db := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, db, "firewall-test", "Edge FW")
	call := func(method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/unused", strings.NewReader(`{"port":80,"protocol":"tcp"}`))
		req.SetPathValue("hostId", enrolled.HostID)
		resource := "system/fail2ban"
		if method != "GET" {
			resource += "/unban"
		}
		req.SetPathValue("resource", resource)
		recorder := httptest.NewRecorder()
		server.fleetHostGateway(recorder, req, store.Session{Username: "admin"})
		return recorder
	}
	if got := call("POST"); got.Code != 501 {
		t.Fatalf("old agent=%d %s", got.Code, got.Body.String())
	}
	heartbeat := model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, Capabilities: []string{"fail2ban-ssh"}, Snapshot: model.FleetSnapshot{Full: true, Fail2ban: &model.Fail2banStatus{Installed: true, Writable: true, CheckedAt: time.Now()}}}
	if err := db.SaveFleetHeartbeat(context.Background(), enrolled.HostID, heartbeat); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE fleet_hosts SET last_seen_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), enrolled.HostID); err != nil {
		t.Fatal(err)
	}
	got := call("GET")
	var status model.Fail2banStatus
	if err := json.Unmarshal(got.Body.Bytes(), &status); err != nil || got.Code != 200 || status.Writable || !status.Installed {
		t.Fatalf("offline=%d %s err=%v", got.Code, got.Body.String(), err)
	}
	if got := call("POST"); got.Code != 409 {
		t.Fatalf("offline write=%d", got.Code)
	}
	// A probe remains read only even if it claims the firewall capability.
	caps, _ := json.Marshal([]string{"probe", "fail2ban-ssh"})
	if _, err := db.DB.Exec(`UPDATE fleet_hosts SET capabilities_json=? WHERE id=?`, string(caps), enrolled.HostID); err != nil {
		t.Fatal(err)
	}
	if got := call("POST"); got.Code != 403 {
		t.Fatalf("probe write=%d", got.Code)
	}
}
