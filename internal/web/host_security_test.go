package web

import (
	"context"
	"encoding/json"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
	"net/http"
	"net/http/httptest"
	"strings"
	"testing"
	"time"
)

type securityFakeAgent struct {
	fakeAgent
	applied int
}

func (a *securityFakeAgent) Firewall(context.Context, string) (model.FirewallState, error) {
	return model.FirewallState{Backend: "nftables", CheckedAt: time.Now(), Revision: "r"}, nil
}
func (a *securityFakeAgent) Fail2ban(context.Context) (model.Fail2banState, error) {
	return model.Fail2banState{CheckedAt: time.Now(), Revision: "r"}, nil
}
func (a *securityFakeAgent) SecurityPreview(context.Context, string, model.SecurityRequest) (model.SecurityPreview, error) {
	return model.SecurityPreview{Revision: "r"}, nil
}
func (a *securityFakeAgent) SecurityApply(context.Context, string, model.SecurityRequest) (model.SecurityResult, error) {
	a.applied++
	return model.SecurityResult{}, nil
}
func (a *securityFakeAgent) SecurityConfirm(context.Context, string) (model.SecurityTransaction, error) {
	return model.SecurityTransaction{Status: "confirmed"}, nil
}
func (a *securityFakeAgent) SecurityTransaction(context.Context, string) (model.SecurityTransaction, error) {
	return model.SecurityTransaction{Status: "awaiting-confirmation"}, nil
}
func TestHostSecurityAuthAndCSRF(t *testing.T) {
	s, db := fleetWebTestServer(t)
	agent := &securityFakeAgent{}
	s.agent = agent
	if _, _, e := db.EnsureAdmin(); e != nil {
		t.Fatal(e)
	}
	if _, e := db.DB.Exec("UPDATE users SET must_change=0"); e != nil {
		t.Fatal(e)
	}
	var userID int64
	if e := db.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&userID); e != nil {
		t.Fatal(e)
	}
	session, e := db.CreateSession(userID)
	if e != nil {
		t.Fatal(e)
	}
	for _, kind := range []string{"firewall", "fail2ban"} {
		for _, test := range []struct {
			cookie, csrf bool
			want         int
		}{{false, false, 401}, {true, false, 403}, {true, true, 200}} {
			req := httptest.NewRequest("POST", "/api/v1/system/"+kind+"/apply", strings.NewReader(`{"operation":"disable","revision":"r"}`))
			if test.cookie {
				req.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
			}
			if test.csrf {
				req.Header.Set("X-CSRF-Token", session.CSRF)
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			if rec.Code != test.want {
				t.Fatalf("%s cookie=%t csrf=%t: %d %s", kind, test.cookie, test.csrf, rec.Code, rec.Body.String())
			}
		}
	}
	if agent.applied != 2 {
		t.Fatalf("unauthorized mutation calls %d", agent.applied)
	}
}
func TestFleetSecurityRequiresCapabilityAndProbeCannotSpoof(t *testing.T) {
	s, db := fleetWebTestServer(t)
	for _, test := range []struct {
		name string
		cap  []string
	}{{"old", []string{"overview", "nodes.write"}}, {"probe", []string{"probe", "security.firewall", "security.fail2ban"}}} {
		token := test.name + "-enroll"
		if e := db.CreateFleetEnrollmentToken(token, time.Now().Add(time.Minute)); e != nil {
			t.Fatal(e)
		}
		host := model.FleetHost{ID: test.name, Name: test.name, Capabilities: test.cap, ProtocolVersion: model.FleetProtocolVersion}
		if e := db.ConsumeFleetEnrollmentToken(token, host, "token-"+test.name); e != nil {
			t.Fatal(e)
		}
		for _, resource := range []string{"system/firewall", "system/firewall/apply", "system/fail2ban/preview", "system/security-transactions/abcd/confirm"} {
			req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
			req.SetPathValue("hostId", host.ID)
			req.SetPathValue("resource", resource)
			rec := httptest.NewRecorder()
			s.fleetHostGateway(rec, req, store.Session{Username: "admin"})
			if rec.Code != 409 && rec.Code != 403 {
				t.Fatalf("%s %s: %d %s", test.name, resource, rec.Code, rec.Body.String())
			}
		}
		var count int
		if e := db.DB.QueryRow("SELECT count(*) FROM fleet_commands WHERE host_id=?", host.ID).Scan(&count); e != nil || count != 0 {
			t.Fatalf("unsafe queued commands %d %v", count, e)
		}
	}
}
func TestSecurityFleetCommandMapping(t *testing.T) {
	for _, test := range []struct {
		method, path, body, kind string
		async                    bool
	}{{"GET", "system/firewall", "", "security.firewall.status", false}, {"POST", "system/firewall/preview", `{"operation":"enable"}`, "security.firewall.preview", false}, {"POST", "system/fail2ban/apply", `{"operation":"install"}`, "security.fail2ban.apply", true}, {"POST", "system/security-transactions/abc/confirm", "{}", "security.transaction.confirm", false}} {
		req := httptest.NewRequest(test.method, "/?zone=public", strings.NewReader(test.body))
		kind, payload, async, e := fleetCommandForRequest(req, test.path)
		if e != nil || kind != test.kind || async != test.async || !json.Valid(payload) {
			t.Fatalf("%s %s: %s %t %s %v", test.method, test.path, kind, async, payload, e)
		}
	}
	for _, path := range []string{"system/firewall/execute", "system/security-transactions/abc/execute", "system/fail2ban/command"} {
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
		if _, _, _, e := fleetCommandForRequest(req, path); e == nil {
			t.Fatal("arbitrary security command accepted")
		}
	}
}
