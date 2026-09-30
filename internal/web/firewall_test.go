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

type firewallTestAgent struct {
	fakeAgent
	calls         int
	zone, deleted string
	added         model.FirewallPortRequest
}

func (a *firewallTestAgent) Firewall(_ context.Context, zone string) (model.FirewallStatus, error) {
	a.calls++
	a.zone = zone
	return model.FirewallStatus{Backend: "firewalld", Writable: true}, nil
}
func (a *firewallTestAgent) AddFirewallPort(_ context.Context, r model.FirewallPortRequest) (model.FirewallStatus, error) {
	a.calls++
	a.added = r
	return model.FirewallStatus{Backend: "firewalld"}, nil
}
func (a *firewallTestAgent) RemoveFirewallPort(_ context.Context, r model.FirewallDeleteRequest) (model.FirewallStatus, error) {
	a.calls++
	a.deleted = r.ID
	return model.FirewallStatus{Backend: "firewalld"}, nil
}

func TestFirewallHTTPRequiresSessionAndCSRF(t *testing.T) {
	server, db := fleetWebTestServer(t)
	a := &firewallTestAgent{}
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
	for _, r := range []struct{ method, path, body string }{{"GET", "/api/v1/system/firewall", ""}, {"POST", "/api/v1/system/firewall/ports", `{"port":8443,"protocol":"tcp"}`}, {"DELETE", "/api/v1/system/firewall/ports/00112233445566778899aabb", ""}} {
		if got := call(r.method, r.path, r.body, false, false); got.Code != 401 {
			t.Fatalf("unauthenticated %s=%d", r.method, got.Code)
		}
		if r.method != "GET" {
			if got := call(r.method, r.path, r.body, true, false); got.Code != 403 {
				t.Fatalf("CSRF %s=%d", r.method, got.Code)
			}
		}
	}
	if a.calls != 0 {
		t.Fatal("denied requests reached Agent")
	}
	if got := call("GET", "/api/v1/system/firewall?zone=trusted", "", true, false); got.Code != 200 || a.zone != "trusted" {
		t.Fatalf("GET=%d %s", got.Code, got.Body.String())
	}
	if got := call("POST", "/api/v1/system/firewall/ports", `{"port":8443,"protocol":"udp","zone":"trusted"}`, true, true); got.Code != 200 || a.added.Port != 8443 || a.added.Protocol != "udp" {
		t.Fatalf("POST=%d %s", got.Code, got.Body.String())
	}
	if got := call("DELETE", "/api/v1/system/firewall/ports/00112233445566778899aabb", "", true, true); got.Code != 200 || a.deleted != "00112233445566778899aabb" {
		t.Fatalf("DELETE=%d", got.Code)
	}
	if got := call("POST", "/api/v1/system/firewall/ports", `{"port":8443,"protocol":"udp","enable":true}`, true, true); got.Code != 400 {
		t.Fatalf("unknown field=%d", got.Code)
	}
	var count int
	if err = db.DB.QueryRow(`SELECT count(*) FROM audit_logs WHERE actor='admin' AND action LIKE 'firewall.port.%'`).Scan(&count); err != nil || count != 2 {
		t.Fatalf("audit=%d err=%v", count, err)
	}
}

func TestFleetFirewallMappings(t *testing.T) {
	for _, tc := range []struct{ method, path, body, kind, expected string }{
		{"GET", "system/firewall?zone=trusted", "", "firewall.status", `{"zone":"trusted"}`},
		{"POST", "system/firewall/ports", `{"port":8443,"protocol":"tcp"}`, "firewall.add", `{"port":8443,"protocol":"tcp"}`},
		{"DELETE", "system/firewall/ports/00112233445566778899aabb", "", "firewall.remove", `{"id":"00112233445566778899aabb"}`},
	} {
		req := httptest.NewRequest(tc.method, "/"+tc.path, strings.NewReader(tc.body))
		kind, body, async, err := fleetCommandForRequest(req, strings.Trim(req.URL.Path, "/"))
		if err != nil || kind != tc.kind || async || string(body) != tc.expected {
			t.Fatalf("%s: %s %s async=%v err=%v", tc.path, kind, body, async, err)
		}
	}
}

func TestFleetFirewallRejectsOldAgentsAndOfflineSnapshotIsReadOnly(t *testing.T) {
	server, db := fleetWebTestServer(t)
	enrolled := enrollFleetAgent(t, server, db, "firewall-test", "Edge FW")
	call := func(method string) *httptest.ResponseRecorder {
		req := httptest.NewRequest(method, "/unused", strings.NewReader(`{"port":80,"protocol":"tcp"}`))
		req.SetPathValue("hostId", enrolled.HostID)
		resource := "system/firewall"
		if method != "GET" {
			resource += "/ports"
		}
		req.SetPathValue("resource", resource)
		recorder := httptest.NewRecorder()
		server.fleetHostGateway(recorder, req, store.Session{Username: "admin"})
		return recorder
	}
	if got := call("POST"); got.Code != 501 {
		t.Fatalf("old agent=%d %s", got.Code, got.Body.String())
	}
	heartbeat := model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, Capabilities: []string{"firewall-ports"}, Snapshot: model.FleetSnapshot{Full: true, Firewall: &model.FirewallStatus{Backend: "ufw", Writable: true, CheckedAt: time.Now()}}}
	if err := db.SaveFleetHeartbeat(context.Background(), enrolled.HostID, heartbeat); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec(`UPDATE fleet_hosts SET last_seen_at=? WHERE id=?`, time.Now().Add(-time.Minute).Unix(), enrolled.HostID); err != nil {
		t.Fatal(err)
	}
	got := call("GET")
	var status model.FirewallStatus
	if err := json.Unmarshal(got.Body.Bytes(), &status); err != nil || got.Code != 200 || status.Writable || status.Backend != "ufw" {
		t.Fatalf("offline=%d %s err=%v", got.Code, got.Body.String(), err)
	}
	if got := call("POST"); got.Code != 409 {
		t.Fatalf("offline write=%d", got.Code)
	}
	// A probe remains read only even if it claims the firewall capability.
	caps, _ := json.Marshal([]string{"probe", "firewall-ports"})
	if _, err := db.DB.Exec(`UPDATE fleet_hosts SET capabilities_json=? WHERE id=?`, string(caps), enrolled.HostID); err != nil {
		t.Fatal(err)
	}
	if got := call("POST"); got.Code != 403 {
		t.Fatalf("probe write=%d", got.Code)
	}
}
