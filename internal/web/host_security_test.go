package web

import (
	"context"
	"encoding/json"
	"fmt"
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
	}{{"GET", "system/firewall", "", "security.firewall.status", false}, {"POST", "system/firewall/preview", `{"operation":"enable"}`, "security.firewall.preview", false}, {"POST", "system/fail2ban/apply", `{"operation":"install"}`, "security.fail2ban.apply", true}, {"POST", "system/fail2ban/apply", `{"operation":"reinstall","confirmation":"RESET FAIL2BAN"}`, "security.fail2ban.apply", true}, {"POST", "system/security-transactions/abc/confirm", "{}", "security.transaction.confirm", false}} {
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

func TestFleetFail2banResetRequiresIndependentCapability(t *testing.T) {
	s, db := fleetWebTestServer(t)
	for _, test := range []struct {
		name string
		caps []string
		want int
	}{
		{"old-security", []string{"security.fail2ban"}, 409},
		{"new-reset", []string{"security.fail2ban", "security.fail2ban.reset"}, 202},
		{"reset-probe", []string{"probe", "security.fail2ban", "security.fail2ban.reset"}, 409},
	} {
		token := test.name + "-token"
		if err := db.CreateFleetEnrollmentToken(token, time.Now().Add(time.Minute)); err != nil {
			t.Fatal(err)
		}
		host := model.FleetHost{ID: test.name, Name: test.name, Capabilities: test.caps, ProtocolVersion: model.FleetProtocolVersion}
		if err := db.ConsumeFleetEnrollmentToken(token, host, "credential-"+test.name); err != nil {
			t.Fatal(err)
		}
		if err := db.SaveFleetHeartbeat(context.Background(), host.ID, model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, Capabilities: test.caps, Snapshot: model.FleetSnapshot{Full: true}}); err != nil {
			t.Fatal(err)
		}
		req := httptest.NewRequest("POST", "/", strings.NewReader(`{"operation":"reinstall","revision":"r","confirmation":"RESET FAIL2BAN"}`))
		req.SetPathValue("hostId", host.ID)
		req.SetPathValue("resource", "system/fail2ban/apply")
		rec := httptest.NewRecorder()
		s.fleetHostGateway(rec, req, store.Session{Username: "admin"})
		if rec.Code != test.want {
			t.Fatalf("%s: %d %s", test.name, rec.Code, rec.Body.String())
		}
		var count int
		if err := db.DB.QueryRow("SELECT count(*) FROM fleet_commands WHERE host_id=?", host.ID).Scan(&count); err != nil {
			t.Fatal(err)
		}
		if test.want != 202 && count != 0 || test.want == 202 && count != 1 {
			t.Fatalf("%s commands=%d", test.name, count)
		}
	}
}

func TestFleetFirewallBatchCapabilityAndHostIsolation(t *testing.T) {
	for _, action := range []string{"preview", "apply"} {
		for _, tc := range []struct {
			name   string
			caps   []string
			online bool
			want   int
		}{
			{"old", []string{"security.firewall"}, true, 409},
			{"probe", []string{"probe", "security.firewall", "security.firewall.batch"}, true, 409},
			{"offline", []string{"security.firewall", "security.firewall.batch"}, false, 409},
			{"new", []string{"security.firewall", "security.firewall.batch"}, true, 200},
		} {
			t.Run(action+"/"+tc.name, func(t *testing.T) {
				s, db := fleetWebTestServer(t)
				if e := db.CreateFleetEnrollmentToken("batch-token", time.Now().Add(time.Minute)); e != nil {
					t.Fatal(e)
				}
				host := model.FleetHost{ID: "target", Name: tc.name, Capabilities: tc.caps, ProtocolVersion: model.FleetProtocolVersion}
				if e := db.ConsumeFleetEnrollmentToken("batch-token", host, "credential"); e != nil {
					t.Fatal(e)
				}
				if tc.online {
					if e := db.SaveFleetHeartbeat(context.Background(), host.ID, model.FleetHeartbeat{ProtocolVersion: model.FleetProtocolVersion, Capabilities: tc.caps, Snapshot: model.FleetSnapshot{Full: true}}); e != nil {
						t.Fatal(e)
					}
				}
				ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
				defer cancel()
				done := make(chan error, 1)
				if tc.want == 200 {
					go func() {
						for {
							record, e := db.NextFleetCommand("target")
							if e == nil {
								raw, e := s.fleetVault.Decrypt(record.PayloadCipher)
								if e != nil {
									done <- e
									return
								}
								var req model.SecurityRequest
								if e = json.Unmarshal([]byte(raw), &req); e != nil {
									done <- e
									return
								}
								if req.Operation != "batch-delete" || len(req.RuleIDs) != 2 {
									done <- fmt.Errorf("lost batch payload: %s", raw)
									return
								}
								cipher, e := s.fleetVault.Encrypt(`{"revision":"r","changes":[]}`)
								if e == nil {
									_, e = db.CompleteFleetCommand(record.Command.ID, "success", cipher, "")
								}
								done <- e
								return
							}
							select {
							case <-ctx.Done():
								done <- ctx.Err()
								return
							case <-time.After(10 * time.Millisecond):
							}
						}
					}()
				}
				req := httptest.NewRequest("POST", "/", strings.NewReader(`{"operation":"batch-delete","ruleIds":["aaaaaaaaaaaaaaaaaaaaaaaaaaaaaaaa","bbbbbbbbbbbbbbbbbbbbbbbbbbbbbbbb"],"revision":"r"}`)).WithContext(ctx)
				req.SetPathValue("hostId", "target")
				req.SetPathValue("resource", "system/firewall/"+action)
				rec := httptest.NewRecorder()
				s.fleetHostGateway(rec, req, store.Session{Username: "admin"})
				if rec.Code != tc.want {
					t.Fatalf("%d %s", rec.Code, rec.Body.String())
				}
				if tc.want == 200 {
					if e := <-done; e != nil {
						t.Fatal(e)
					}
				}
				var count int
				if e := db.DB.QueryRow("SELECT count(*) FROM fleet_commands").Scan(&count); e != nil {
					t.Fatal(e)
				}
				if tc.want == 200 && count != 1 || tc.want != 200 && count != 0 {
					t.Fatal("unexpected commands", count)
				}
				if _, e := db.NextFleetCommand("other-host"); e == nil {
					t.Fatal("batch delivered to another host")
				}
			})
		}
	}
}

func TestSecurityIPLocationRequiresLoginAndValidIP(t *testing.T) {
	s, db := fleetWebTestServer(t)
	if _, _, err := db.EnsureAdmin(); err != nil {
		t.Fatal(err)
	}
	if _, err := db.DB.Exec("UPDATE users SET must_change=0"); err != nil {
		t.Fatal(err)
	}
	var userID int64
	if err := db.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&userID); err != nil {
		t.Fatal(err)
	}
	session, err := db.CreateSession(userID)
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		ip    string
		login bool
		want  int
	}{
		{"127.0.0.1", false, http.StatusUnauthorized},
		{"127.0.0.1", true, http.StatusOK},
		{"10.0.0.1", true, http.StatusOK},
		{"8.8.8.8%3Btouch", true, http.StatusBadRequest},
		{"https://example.com", true, http.StatusBadRequest},
	} {
		req := httptest.NewRequest("GET", "/api/v1/system/ip-location?ip="+test.ip, nil)
		if test.login {
			req.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
		}
		rec := httptest.NewRecorder()
		s.Handler().ServeHTTP(rec, req)
		if rec.Code != test.want {
			t.Fatalf("%s login=%v: %d %s", test.ip, test.login, rec.Code, rec.Body.String())
		}
		if test.want == http.StatusOK && !strings.Contains(rec.Body.String(), `"status":"private"`) {
			t.Fatalf("unexpected location %s", rec.Body.String())
		}
	}
}
