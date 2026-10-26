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
)

type panelUpdateFakeAgent struct {
	fakeAgent
	calls atomic.Int32
}

func (a *panelUpdateFakeAgent) PanelUpdate(_ context.Context, _ string) error {
	a.calls.Add(1)
	return nil
}

func TestPanelUpdateAuthAndJob(t *testing.T) {
	s, db := fleetWebTestServer(t)
	agent := &panelUpdateFakeAgent{}
	s.agent = agent

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

	for _, auth := range []struct {
		cookie, csrf bool
		want         int
	}{
		{false, false, 401},
		{true, false, 403},
		{true, true, 202},
	} {
		req := httptest.NewRequest("POST", "/api/v1/system/panel/update", strings.NewReader(`{"currentVersion":"1.7.29","targetVersion":"1.7.30"}`))
		if auth.cookie {
			req.AddCookie(&http.Cookie{Name: "wukong_session", Value: session.Token})
		}
		if auth.csrf {
			req.Header.Set("X-CSRF-Token", session.CSRF)
		}
		req.Header.Set("Content-Type", "application/json")
		rr := httptest.NewRecorder()
		s.Handler().ServeHTTP(rr, req)

		if rr.Code != auth.want {
			t.Fatalf("auth=%+v code=%d want=%d body=%s", auth, rr.Code, auth.want, rr.Body.String())
		}
		if auth.want == 202 {
			var resp map[string]string
			if err := json.Unmarshal(rr.Body.Bytes(), &resp); err != nil || resp["jobId"] == "" {
				t.Fatalf("invalid job response: %s", rr.Body.String())
			}
			// Wait for agent call
			deadline := time.Now().Add(3 * time.Second)
			for time.Now().Before(deadline) && agent.calls.Load() < 1 {
				time.Sleep(10 * time.Millisecond)
			}
			if agent.calls.Load() != 1 {
				t.Fatalf("expected agent to be called once, got %d", agent.calls.Load())
			}
		}
	}
}
