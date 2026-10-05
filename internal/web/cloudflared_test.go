package web

import (
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"strings"
	"sync/atomic"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

type cloudflaredFake struct {
	fakeAgent
	calls atomic.Int32
}

func (a *cloudflaredFake) Cloudflared(_ context.Context, r model.CloudflaredRequest) (model.CloudflaredState, error) {
	a.calls.Add(1)
	return model.CloudflaredState{Installed: true, CurrentVersion: "2026.8.2", LatestVersion: "2026.9.3", Writable: true}, nil
}

func TestCloudflaredAuthAndJob(t *testing.T) {
	s, db := fleetWebTestServer(t)
	a := &cloudflaredFake{}
	s.agent = a
	if _, _, e := db.EnsureAdmin(); e != nil {
		t.Fatal(e)
	}
	db.DB.Exec("UPDATE users SET must_change=0")
	var id int64
	db.DB.QueryRow("SELECT id FROM users WHERE username='admin'").Scan(&id)
	session, e := db.CreateSession(id)
	if e != nil {
		t.Fatal(e)
	}
	for _, action := range []string{"check", "settings", "update"} {
		for _, auth := range []struct {
			cookie, csrf bool
			want         int
		}{{false, false, 401}, {true, false, 403}, {true, true, 200}} {
			req := httptest.NewRequest("POST", "/api/v1/system/cloudflared/"+action, strings.NewReader(`{"autoUpdate":true,"currentVersion":"2026.8.2","targetVersion":"2026.9.3"}`))
			if auth.cookie {
				req.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
			}
			if auth.csrf {
				req.Header.Set("X-CSRF-Token", session.CSRF)
			}
			rec := httptest.NewRecorder()
			s.Handler().ServeHTTP(rec, req)
			want := auth.want
			if action == "update" && want == 200 {
				want = 202
			}
			if rec.Code != want {
				t.Fatalf("%s %v: %d %s", action, auth, rec.Code, rec.Body.String())
			}
			if want == 202 {
				var result struct {
					JobID string `json:"jobId"`
				}
				json.Unmarshal(rec.Body.Bytes(), &result)
				deadline := time.Now().Add(time.Second)
				for {
					job, e := db.Job(result.JobID)
					if e != nil {
						t.Fatal(e)
					}
					if job.Status == "success" {
						break
					}
					if time.Now().After(deadline) {
						t.Fatal("job did not complete", job)
					}
					time.Sleep(time.Millisecond)
				}
			}
		}
	}
	if a.calls.Load() != 3 {
		t.Fatal("unauthorized requests reached Agent", a.calls.Load())
	}
}
func TestCloudflaredFleetMappingAndLegacyRestriction(t *testing.T) {
	for _, action := range []string{"status", "check", "settings", "update"} {
		path := "system/cloudflared"
		method := "GET"
		if action != "status" {
			path += "/" + action
			method = "POST"
		}
		req := httptest.NewRequest(method, "/", strings.NewReader(`{"operation":"malicious","autoUpdate":true}`))
		kind, payload, async, e := fleetCommandForRequest(req, path)
		if e != nil || kind != "cloudflared."+action || async != (action == "update") {
			t.Fatal(kind, async, e)
		}
		var r model.CloudflaredRequest
		json.Unmarshal(payload, &r)
		if r.Operation != action {
			t.Fatal("untrusted operation reached Agent", r)
		}
	}
	s, db := fleetWebTestServer(t)
	h := model.FleetHost{ID: "legacy", Name: "legacy", Online: true, Compatible: true, Capabilities: []string{"overview"}}
	if e := db.CreateFleetEnrollmentToken("test-enroll", time.Now().Add(time.Minute)); e != nil {
		t.Fatal(e)
	}
	if e := db.ConsumeFleetEnrollmentToken("test-enroll", h, "testhash"); e != nil {
		t.Fatal(e)
	}
	r := httptest.NewRequest("POST", "/", strings.NewReader(`{}`))
	r.SetPathValue("hostId", h.ID)
	r.SetPathValue("resource", "system/cloudflared/update")
	w := httptest.NewRecorder()
	s.fleetHostGateway(w, r, store.Session{Username: "admin"})
	if w.Code != 409 {
		t.Fatal(w.Code, w.Body.String())
	}
	var count int
	db.DB.QueryRow("SELECT COUNT(*) FROM fleet_commands").Scan(&count)
	if count != 0 {
		t.Fatal("legacy Agent received update command")
	}
}
