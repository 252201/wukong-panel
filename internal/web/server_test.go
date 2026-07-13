package web

import (
	"bytes"
	"context"
	"encoding/json"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/singboxconfig"
	"github.com/252201/wukong-panel/internal/store"
)

type fakeAgent struct{}

func (fakeAgent) Scan(context.Context) ([]model.NodeCandidate, error) { return nil, nil }
func (fakeAgent) DeploymentDefaults(context.Context) (model.NodeDeploymentDefaults, error) {
	return model.NodeDeploymentDefaults{PanelDomain: "panel.example.com"}, nil
}
func (fakeAgent) Import(context.Context, []string) error { return nil }
func (fakeAgent) Create(context.Context, model.NodeCreateRequest) (model.Node, error) {
	return model.Node{}, nil
}
func (fakeAgent) Action(context.Context, string, model.NodeActionRequest) error { return nil }
func (fakeAgent) Share(context.Context, string) (model.Share, error)            { return model.Share{}, nil }
func (fakeAgent) MigrationPlan(context.Context, string) (singboxconfig.Plan, error) {
	return singboxconfig.Plan{Compatible: true}, nil
}

func TestBillingPeriodBeforeAndAfterResetDay(t *testing.T) {
	tz := "Asia/Shanghai"
	before := time.Date(2026, 7, 3, 10, 0, 0, 0, time.UTC)
	start, end := billingPeriod(before, 5, tz)
	if start.Format("2006-01-02") != "2026-06-05" || end.Format("2006-01-02") != "2026-07-04" {
		t.Fatalf("unexpected early-month period: %s %s", start, end)
	}
	after := time.Date(2026, 7, 10, 10, 0, 0, 0, time.UTC)
	start, end = billingPeriod(after, 5, tz)
	if start.Format("2006-01-02") != "2026-07-05" || end.Format("2006-01-02") != "2026-08-04" {
		t.Fatalf("unexpected current period: %s %s", start, end)
	}
}

func TestMaskToken(t *testing.T) {
	if got := maskToken("abcdefghijklmnop"); got != "abcd••••mnop" {
		t.Fatalf("unexpected masked token %q", got)
	}
}

func TestAuthCookieAndCSRF(t *testing.T) {
	dir := t.TempDir()
	database, err := store.Open(filepath.Join(dir, "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	password, _, err := database.EnsureAdmin()
	if err != nil {
		t.Fatal(err)
	}
	server := New(config.Config{BasePath: "/", SecureCookie: false}, database, fakeAgent{}, "test")
	loginBody, _ := json.Marshal(map[string]string{"username": "admin", "password": password})
	login := httptest.NewRequest(http.MethodPost, "/api/v1/auth/login", bytes.NewReader(loginBody))
	login.RemoteAddr = "192.0.2.1:1234"
	recorder := httptest.NewRecorder()
	server.Handler().ServeHTTP(recorder, login)
	if recorder.Code != http.StatusOK {
		t.Fatalf("login status %d: %s", recorder.Code, recorder.Body.String())
	}
	var payload map[string]any
	if err := json.Unmarshal(recorder.Body.Bytes(), &payload); err != nil {
		t.Fatal(err)
	}
	csrf, _ := payload["csrf"].(string)
	if csrf == "" {
		t.Fatal("missing csrf token")
	}
	cookies := recorder.Result().Cookies()
	if len(cookies) != 1 || !cookies[0].HttpOnly {
		t.Fatal("secure session cookie missing")
	}
	request := httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader([]byte("{}")))
	request.AddCookie(cookies[0])
	denied := httptest.NewRecorder()
	server.Handler().ServeHTTP(denied, request)
	if denied.Code != http.StatusForbidden {
		t.Fatalf("missing CSRF status = %d", denied.Code)
	}
	request = httptest.NewRequest(http.MethodPost, "/api/v1/auth/logout", bytes.NewReader([]byte("{}")))
	request.AddCookie(cookies[0])
	request.Header.Set("X-CSRF-Token", csrf)
	allowed := httptest.NewRecorder()
	server.Handler().ServeHTTP(allowed, request)
	if allowed.Code != http.StatusOK {
		t.Fatalf("valid CSRF status = %d", allowed.Code)
	}
}

func TestBuildTrafficTimeline(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	location, err := time.LoadLocation("Asia/Shanghai")
	if err != nil {
		t.Fatal(err)
	}
	now := time.Date(2026, 7, 10, 12, 30, 0, 0, location)
	start := time.Date(2026, 7, 10, 0, 0, 0, 0, location)
	metrics := []model.Metric{
		{Timestamp: start.Add(-10 * time.Second).Unix(), Interface: "eth0", RXBytes: 1_000, TXBytes: 2_000},
		{Timestamp: start.Add(10 * time.Second).Unix(), Interface: "eth0", RXBytes: 4_000, TXBytes: 6_000},
		{Timestamp: start.Add(12*time.Hour + 10*time.Second).Unix(), Interface: "eth0", RXBytes: 9_000, TXBytes: 12_000},
	}
	for _, metric := range metrics {
		if err := database.AddMetric(metric); err != nil {
			t.Fatal(err)
		}
	}
	if err := database.AddDailyTraffic("2026-07-05", 100, 200, "test"); err != nil {
		t.Fatal(err)
	}
	if err := database.AddDailyTraffic("2026-07-10", 300, 400, "test"); err != nil {
		t.Fatal(err)
	}
	result, err := buildTrafficTimeline(database, now, model.Settings{Timezone: "Asia/Shanghai", BillingResetDay: 5})
	if err != nil {
		t.Fatal(err)
	}
	if len(result.Today) != 24 || result.Today[0].RXBytes != 3_000 || result.Today[0].TXBytes != 4_000 {
		t.Fatalf("unexpected today buckets: %#v", result.Today[:1])
	}
	if result.Today[12].RXBytes != 5_000 || result.Today[12].TXBytes != 6_000 || result.TodayRX != 8_000 || result.TodayTX != 10_000 {
		t.Fatalf("unexpected today totals: rx=%d tx=%d bucket=%#v", result.TodayRX, result.TodayTX, result.Today[12])
	}
	if len(result.Billing) != 31 || result.BillingStart != "2026-07-05" || result.BillingEnd != "2026-08-04" || result.BillingRX != 400 || result.BillingTX != 600 {
		t.Fatalf("unexpected billing timeline: %#v", result)
	}
}
