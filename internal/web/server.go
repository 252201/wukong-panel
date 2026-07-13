package web

import (
	"context"
	"database/sql"
	"embed"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"io/fs"
	"log"
	"net"
	"net/http"
	"net/url"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/singboxconfig"
	"github.com/252201/wukong-panel/internal/store"
)

//go:embed dist/*
var staticFiles embed.FS

type AgentAPI interface {
	Scan(context.Context) ([]model.NodeCandidate, error)
	DeploymentDefaults(context.Context) (model.NodeDeploymentDefaults, error)
	Import(context.Context, []string) error
	Create(context.Context, model.NodeCreateRequest) (model.Node, error)
	Action(context.Context, string, model.NodeActionRequest) error
	Share(context.Context, string) (model.Share, error)
	MigrationPlan(context.Context, string) (singboxconfig.Plan, error)
}

type Server struct {
	cfg           config.Config
	store         *store.Store
	agent         AgentAPI
	version       string
	limiterMu     sync.Mutex
	loginAttempts map[string][]time.Time
}

func New(cfg config.Config, s *store.Store, agent AgentAPI, version string) *Server {
	return &Server{cfg: cfg, store: s, agent: agent, version: version, loginAttempts: map[string][]time.Time{}}
}

func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	mux.HandleFunc("POST /api/v1/auth/login", s.login)
	mux.HandleFunc("GET /api/v1/auth/me", s.auth(s.me, false))
	mux.HandleFunc("POST /api/v1/auth/logout", s.auth(s.logout, true))
	mux.HandleFunc("POST /api/v1/auth/password", s.auth(s.changePassword, true))
	mux.HandleFunc("GET /api/v1/overview", s.auth(s.overview, false))
	mux.HandleFunc("GET /api/v1/metrics", s.auth(s.metrics, false))
	mux.HandleFunc("GET /api/v1/metrics/endpoints", s.auth(s.endpoints, false))
	mux.HandleFunc("GET /api/v1/metrics/timeline", s.auth(s.timeline, false))
	mux.HandleFunc("GET /api/v1/nodes", s.auth(s.nodes, false))
	mux.HandleFunc("GET /api/v1/nodes/deployment-defaults", s.auth(s.nodeDeploymentDefaults, false))
	mux.HandleFunc("POST /api/v1/nodes", s.auth(s.createNode, true))
	mux.HandleFunc("POST /api/v1/nodes/{id}/actions", s.auth(s.nodeAction, true))
	mux.HandleFunc("GET /api/v1/nodes/{id}/share", s.auth(s.share, false))
	mux.HandleFunc("GET /api/v1/imports/scan", s.auth(s.scan, false))
	mux.HandleFunc("GET /api/v1/system/sing-box/migration", s.auth(s.singBoxMigration, false))
	mux.HandleFunc("POST /api/v1/imports/confirm", s.auth(s.confirmImport, true))
	mux.HandleFunc("GET /api/v1/jobs", s.auth(s.jobs, false))
	mux.HandleFunc("GET /api/v1/jobs/{id}", s.auth(s.job, false))
	mux.HandleFunc("GET /api/v1/jobs/{id}/events", s.auth(s.jobEvents, false))
	mux.HandleFunc("GET /api/v1/settings", s.auth(s.settings, false))
	mux.HandleFunc("PUT /api/v1/settings", s.auth(s.saveSettings, true))
	mux.HandleFunc("POST /api/v1/settings/subscription-token", s.auth(s.rotateSubscriptionToken, true))
	mux.HandleFunc("GET /sub/{token}/clash.yaml", s.subscription)
	mux.HandleFunc("GET /healthz", func(w http.ResponseWriter, r *http.Request) {
		writeJSON(w, 200, map[string]any{"ok": true, "version": s.version})
	})
	mux.Handle("/", s.static())
	return s.securityHeaders(mux)
}

func (s *Server) ListenAndServe(ctx context.Context) error {
	server := &http.Server{Addr: s.cfg.Listen, Handler: s.Handler(), ReadHeaderTimeout: 5 * time.Second, ReadTimeout: 20 * time.Second, WriteTimeout: 70 * time.Second, IdleTimeout: 90 * time.Second}
	go func() {
		<-ctx.Done()
		shutdown, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		_ = server.Shutdown(shutdown)
	}()
	log.Printf("wukong web listening on %s", s.cfg.Listen)
	return server.ListenAndServe()
}

func (s *Server) login(w http.ResponseWriter, r *http.Request) {
	ip := clientIP(r)
	if !s.allowLogin(ip) {
		writeError(w, 429, "登录尝试过多，请稍后再试")
		return
	}
	var request struct {
		Username string `json:"username"`
		Password string `json:"password"`
	}
	if !decode(w, r, &request) {
		return
	}
	userID, mustChange, err := s.store.Authenticate(request.Username, request.Password)
	if err != nil {
		writeError(w, 500, "登录服务不可用")
		return
	}
	if userID == 0 {
		_ = s.store.Audit(request.Username, "login_failed", ip, "invalid credentials")
		writeError(w, 401, "用户名或密码错误")
		return
	}
	session, err := s.store.CreateSession(userID)
	if err != nil {
		writeError(w, 500, "无法创建会话")
		return
	}
	http.SetCookie(w, &http.Cookie{Name: "wukong_session", Value: session.Token, Path: s.cfg.BasePath, Expires: session.ExpiresAt, MaxAge: int((12 * time.Hour).Seconds()), HttpOnly: true, Secure: s.cfg.SecureCookie, SameSite: http.SameSiteStrictMode})
	_ = s.store.Audit(request.Username, "login", ip, "success")
	writeJSON(w, 200, map[string]any{"username": request.Username, "csrf": session.CSRF, "mustChange": mustChange})
}

func (s *Server) me(w http.ResponseWriter, r *http.Request, session store.Session) {
	writeJSON(w, 200, map[string]any{"username": session.Username, "csrf": session.CSRF, "mustChange": session.MustChange, "version": s.version, "basePath": s.cfg.BasePath})
}
func (s *Server) logout(w http.ResponseWriter, r *http.Request, session store.Session) {
	cookie, _ := r.Cookie("wukong_session")
	if cookie != nil {
		_ = s.store.DeleteSession(cookie.Value)
	}
	http.SetCookie(w, &http.Cookie{Name: "wukong_session", Value: "", Path: s.cfg.BasePath, MaxAge: -1, HttpOnly: true, Secure: s.cfg.SecureCookie, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) changePassword(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request struct {
		Password string `json:"password"`
	}
	if !decode(w, r, &request) {
		return
	}
	if err := s.store.ChangePassword(session.UserID, request.Password); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "change_password", "admin", "session revoked")
	http.SetCookie(w, &http.Cookie{Name: "wukong_session", Value: "", Path: s.cfg.BasePath, MaxAge: -1, HttpOnly: true, Secure: s.cfg.SecureCookie, SameSite: http.SameSiteStrictMode})
	writeJSON(w, 200, map[string]bool{"ok": true})
}

func (s *Server) overview(w http.ResponseWriter, r *http.Request, session store.Session) {
	metrics, _ := s.store.Metrics(80)
	devices, _ := s.store.ActiveDevices(25*time.Second, 12)
	processes, processCount, _ := s.store.Processes(100)
	nodes, _ := s.store.Nodes(r.Context())
	settings, _ := s.store.Settings()
	var now model.Metric
	if len(metrics) > 0 {
		now = metrics[len(metrics)-1]
	}
	online := 0
	for _, n := range nodes {
		if n.Status == "active" {
			online++
		}
	}
	start, end := billingPeriod(time.Now(), settings.BillingResetDay, settings.Timezone)
	used := int64(0)
	if rx, tx, err := s.store.TrafficBetween(start.Format("2006-01-02"), end.Format("2006-01-02")); err == nil {
		used = rx + tx
	}
	version := "unknown"
	if healthAgent, ok := s.agent.(interface {
		Health(context.Context) (map[string]any, error)
	}); ok {
		if result, err := healthAgent.Health(r.Context()); err == nil {
			version = fmt.Sprint(result["version"])
		}
	}
	writeJSON(w, 200, model.Overview{Now: now, History: metrics, Devices: devices, Processes: processes, ProcessCount: processCount, NodeCount: len(nodes), OnlineNodes: online, TrafficUsed: used, TrafficQuota: settings.TrafficQuotaBytes, BillingStart: start.Format("2006-01-02"), BillingEnd: end.Format("2006-01-02"), SingBoxVersion: version, PanelVersion: s.version})
}
func (s *Server) metrics(w http.ResponseWriter, r *http.Request, session store.Session) {
	limit, _ := strconv.Atoi(r.URL.Query().Get("limit"))
	items, err := s.store.Metrics(limit)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) endpoints(w http.ResponseWriter, r *http.Request, session store.Session) {
	items, err := s.store.TopEndpoints(10)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	for i := range items {
		items[i].Endpoint = maskEndpoint(items[i].Endpoint)
	}
	writeJSON(w, 200, items)
}

func (s *Server) timeline(w http.ResponseWriter, r *http.Request, session store.Session) {
	settings, err := s.store.Settings()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	result, err := buildTrafficTimeline(s.store, time.Now(), settings)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, result)
}

func buildTrafficTimeline(s *store.Store, now time.Time, settings model.Settings) (model.TrafficTimeline, error) {
	location, err := time.LoadLocation(settings.Timezone)
	if err != nil {
		location = time.Local
	}
	localNow := now.In(location)
	todayStart := time.Date(localNow.Year(), localNow.Month(), localNow.Day(), 0, 0, 0, 0, location)
	result := model.TrafficTimeline{Today: make([]model.TrafficBucket, 24), Timezone: location.String()}
	for hour := range 24 {
		started := todayStart.Add(time.Duration(hour) * time.Hour)
		result.Today[hour] = model.TrafficBucket{Label: fmt.Sprintf("%02d", hour), StartedAt: started.Unix()}
	}
	metrics, err := s.MetricsBetween(todayStart.Add(-time.Minute).Unix(), now.Unix())
	if err != nil {
		return result, err
	}
	for index := 1; index < len(metrics); index++ {
		current, previous := metrics[index], metrics[index-1]
		if current.Timestamp < todayStart.Unix() {
			continue
		}
		hour := time.Unix(current.Timestamp, 0).In(location).Hour()
		rx := current.RXBytes - previous.RXBytes
		tx := current.TXBytes - previous.TXBytes
		if rx > 0 {
			result.Today[hour].RXBytes += rx
			result.TodayRX += rx
		}
		if tx > 0 {
			result.Today[hour].TXBytes += tx
			result.TodayTX += tx
		}
	}
	billingStart, billingEnd := billingPeriod(now, settings.BillingResetDay, location.String())
	result.BillingStart = billingStart.Format("2006-01-02")
	result.BillingEnd = billingEnd.Format("2006-01-02")
	daily, err := s.TrafficBuckets(result.BillingStart, result.BillingEnd)
	if err != nil {
		return result, err
	}
	byDay := make(map[string]model.TrafficBucket, len(daily))
	for _, item := range daily {
		byDay[item.Label] = item
	}
	for day := billingStart; !day.After(billingEnd); day = day.AddDate(0, 0, 1) {
		key := day.Format("2006-01-02")
		item := byDay[key]
		item.Label = day.Format("01-02")
		item.StartedAt = day.Unix()
		result.Billing = append(result.Billing, item)
		result.BillingRX += item.RXBytes
		result.BillingTX += item.TXBytes
	}
	return result, nil
}
func (s *Server) nodes(w http.ResponseWriter, r *http.Request, session store.Session) {
	items, err := s.store.Nodes(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}

func (s *Server) nodeDeploymentDefaults(w http.ResponseWriter, r *http.Request, session store.Session) {
	defaults, err := s.agent.DeploymentDefaults(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, defaults)
}

func (s *Server) createNode(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request model.NodeCreateRequest
	if !decode(w, r, &request) {
		return
	}
	job, err := s.store.CreateJob("node.create", request.Name)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	go s.runJob(job, func(ctx context.Context) error { _, err := s.agent.Create(ctx, request); return err })
	writeJSON(w, 202, map[string]string{"jobId": job.ID})
}
func (s *Server) nodeAction(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request model.NodeActionRequest
	if !decode(w, r, &request) {
		return
	}
	id := r.PathValue("id")
	job, err := s.store.CreateJob("node."+request.Action, id)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	go s.runJob(job, func(ctx context.Context) error { return s.agent.Action(ctx, id, request) })
	writeJSON(w, 202, map[string]string{"jobId": job.ID})
}
func (s *Server) share(w http.ResponseWriter, r *http.Request, session store.Session) {
	share, err := s.agent.Share(r.Context(), r.PathValue("id"))
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "reveal_share", r.PathValue("id"), "expires in 30 seconds")
	writeJSON(w, 200, share)
}
func (s *Server) scan(w http.ResponseWriter, r *http.Request, session store.Session) {
	items, err := s.agent.Scan(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) singBoxMigration(w http.ResponseWriter, r *http.Request, session store.Session) {
	target := r.URL.Query().Get("target")
	if target == "" {
		target = "1.13.14"
	}
	plan, err := s.agent.MigrationPlan(r.Context(), target)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, plan)
}
func (s *Server) confirmImport(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request struct {
		Fingerprints []string `json:"fingerprints"`
	}
	if !decode(w, r, &request) {
		return
	}
	job, err := s.store.CreateJob("nodes.import", fmt.Sprintf("%d nodes", len(request.Fingerprints)))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	go s.runJob(job, func(ctx context.Context) error { return s.agent.Import(ctx, request.Fingerprints) })
	writeJSON(w, 202, map[string]string{"jobId": job.ID})
}

func (s *Server) jobs(w http.ResponseWriter, r *http.Request, session store.Session) {
	items, err := s.store.Jobs(80)
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, items)
}
func (s *Server) job(w http.ResponseWriter, r *http.Request, session store.Session) {
	job, err := s.store.Job(r.PathValue("id"))
	if err != nil {
		writeError(w, 404, "任务不存在")
		return
	}
	writeJSON(w, 200, job)
}
func (s *Server) jobEvents(w http.ResponseWriter, r *http.Request, session store.Session) {
	flusher, ok := w.(http.Flusher)
	if !ok {
		writeError(w, 500, "streaming unsupported")
		return
	}
	w.Header().Set("Content-Type", "text/event-stream")
	w.Header().Set("Cache-Control", "no-cache")
	ticker := time.NewTicker(time.Second)
	defer ticker.Stop()
	for {
		job, err := s.store.Job(r.PathValue("id"))
		if err != nil {
			return
		}
		data, _ := json.Marshal(job)
		fmt.Fprintf(w, "event: progress\ndata: %s\n\n", data)
		flusher.Flush()
		if job.Status == "success" || job.Status == "failed" {
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) settings(w http.ResponseWriter, r *http.Request, session store.Session) {
	settings, err := s.store.Settings()
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	settings.SubscriptionToken = maskToken(settings.SubscriptionToken)
	writeJSON(w, 200, settings)
}
func (s *Server) saveSettings(w http.ResponseWriter, r *http.Request, session store.Session) {
	var settings model.Settings
	if !decode(w, r, &settings) {
		return
	}
	if err := s.store.SaveSettings(settings); err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "save_settings", "panel", "updated")
	writeJSON(w, 200, map[string]bool{"ok": true})
}
func (s *Server) rotateSubscriptionToken(w http.ResponseWriter, r *http.Request, session store.Session) {
	token, err := security.RandomToken(24)
	if err == nil {
		err = s.store.SetSetting("subscription_token", token)
	}
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "rotate_subscription_token", "subscription", "rotated")
	writeJSON(w, 200, map[string]string{"token": token})
}

func (s *Server) subscription(w http.ResponseWriter, r *http.Request) {
	token, err := s.store.Setting("subscription_token")
	if err != nil || token == "" || r.PathValue("token") != token {
		http.NotFound(w, r)
		return
	}
	nodes, err := s.store.Nodes(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	settings, _ := s.store.Settings()
	metrics, _ := s.store.Metrics(2)
	var used int64
	if len(metrics) > 1 {
		used = max64(0, metrics[len(metrics)-1].RXBytes-metrics[0].RXBytes) + max64(0, metrics[len(metrics)-1].TXBytes-metrics[0].TXBytes)
	}
	expire := time.Now().AddDate(0, 1, 0).Unix()
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Subscription-Userinfo", fmt.Sprintf("upload=%d; download=%d; total=%d; expire=%d", used/2, used-used/2, settings.TrafficQuotaBytes, expire))
	w.Header().Set("Profile-Update-Interval", "10")
	w.Header().Set("Profile-Title", "Wukong Panel")
	fmt.Fprintln(w, "proxies:")
	for _, node := range nodes {
		share, err := s.agent.Share(r.Context(), node.ID)
		if err != nil {
			continue
		}
		parsed, _ := url.Parse(share.URI)
		password := ""
		if parsed != nil && parsed.User != nil {
			password, _ = url.QueryUnescape(parsed.User.Username())
		}
		server := node.Server
		if server == "" {
			server = node.Domain
		}
		fmt.Fprintf(w, "  - name: %q\n    type: hysteria2\n    server: %q\n    port: %d\n    password: %q\n    sni: %q\n    alpn: [h3]\n", node.Name, server, node.ListenPort, password, node.Domain)
	}
	fmt.Fprintln(w, "proxy-groups:\n  - name: Wukong\n    type: select\n    proxies:")
	for _, node := range nodes {
		fmt.Fprintf(w, "      - %q\n", node.Name)
	}
	fmt.Fprintln(w, "rules:\n  - MATCH,Wukong")
}

func (s *Server) runJob(job model.Job, operation func(context.Context) error) {
	_ = s.store.UpdateJob(job.ID, "running", 20, "正在执行", "")
	ctx, cancel := context.WithTimeout(context.Background(), 2*time.Minute)
	defer cancel()
	err := operation(ctx)
	if err != nil {
		_ = s.store.UpdateJob(job.ID, "failed", 100, "执行失败", err.Error())
		return
	}
	_ = s.store.UpdateJob(job.ID, "success", 100, "执行完成", "")
}

type authHandler func(http.ResponseWriter, *http.Request, store.Session)

func (s *Server) auth(next authHandler, csrf bool) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("wukong_session")
		if err != nil {
			writeError(w, 401, "未登录")
			return
		}
		session, err := s.store.Session(cookie.Value)
		if err != nil {
			writeError(w, 401, "会话已失效")
			return
		}
		if csrf && r.Header.Get("X-CSRF-Token") != session.CSRF {
			writeError(w, 403, "CSRF 校验失败")
			return
		}
		if session.MustChange && r.URL.Path != "/api/v1/auth/password" && r.URL.Path != "/api/v1/auth/logout" {
			writeError(w, 428, "首次登录必须修改密码")
			return
		}
		next(w, r, session)
	}
}

func (s *Server) static() http.Handler {
	assets, _ := fs.Sub(staticFiles, "dist")
	fileServer := http.FileServer(http.FS(assets))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		path := strings.TrimPrefix(r.URL.Path, "/")
		if path == "" || path == "index.html" {
			s.serveIndex(w, r, assets)
			return
		}
		if _, err := fs.Stat(assets, path); err != nil {
			s.serveIndex(w, r, assets)
			return
		}
		r.URL.Path = "/" + path
		fileServer.ServeHTTP(w, r)
	})
}

func (s *Server) serveIndex(w http.ResponseWriter, r *http.Request, assets fs.FS) {
	data, err := fs.ReadFile(assets, "index.html")
	if err != nil {
		http.Error(w, "embedded frontend unavailable", http.StatusInternalServerError)
		return
	}
	w.Header().Set("Content-Type", "text/html; charset=utf-8")
	w.Header().Set("Cache-Control", "no-cache")
	http.ServeContent(w, r, "index.html", time.Time{}, strings.NewReader(string(data)))
}
func (s *Server) securityHeaders(next http.Handler) http.Handler {
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		w.Header().Set("X-Content-Type-Options", "nosniff")
		w.Header().Set("X-Frame-Options", "DENY")
		w.Header().Set("Referrer-Policy", "no-referrer")
		w.Header().Set("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
		w.Header().Set("Content-Security-Policy", "default-src 'self'; img-src 'self' data:; style-src 'self' 'unsafe-inline'; script-src 'self'; connect-src 'self'")
		next.ServeHTTP(w, r)
	})
}
func (s *Server) allowLogin(ip string) bool {
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	attempts := s.loginAttempts[ip][:0]
	for _, stamp := range s.loginAttempts[ip] {
		if stamp.After(cutoff) {
			attempts = append(attempts, stamp)
		}
	}
	if len(attempts) >= 5 {
		s.loginAttempts[ip] = attempts
		return false
	}
	s.loginAttempts[ip] = append(attempts, time.Now())
	return true
}
func clientIP(r *http.Request) string {
	host, _, err := net.SplitHostPort(r.RemoteAddr)
	if err == nil {
		return host
	}
	return r.RemoteAddr
}

func billingPeriod(now time.Time, day int, tz string) (time.Time, time.Time) {
	if day < 1 || day > 28 {
		day = 1
	}
	location, err := time.LoadLocation(tz)
	if err != nil {
		location = time.Local
	}
	local := now.In(location)
	year, month := local.Year(), local.Month()
	if local.Day() < day {
		month--
		if month == 0 {
			month = 12
			year--
		}
	}
	start := time.Date(year, month, day, 0, 0, 0, 0, location)
	return start, start.AddDate(0, 1, 0).Add(-time.Second)
}
func maskToken(token string) string {
	if len(token) < 8 {
		return ""
	}
	return token[:4] + "••••" + token[len(token)-4:]
}
func maskEndpoint(value string) string {
	if strings.HasPrefix(value, "[") {
		if index := strings.LastIndex(value, "]:"); index >= 0 {
			return "[****:****]" + value[index+1:]
		}
		return "[****:****]"
	}
	host, port, err := net.SplitHostPort(value)
	if err != nil {
		return "***"
	}
	parts := strings.Split(host, ".")
	if len(parts) == 4 {
		return parts[0] + ".***.***." + parts[3] + ":" + port
	}
	return "***:" + port
}
func max64(a, b int64) int64 {
	if a > b {
		return a
	}
	return b
}
func decode(w http.ResponseWriter, r *http.Request, target any) bool {
	decoder := json.NewDecoder(io.LimitReader(r.Body, 1<<20))
	decoder.DisallowUnknownFields()
	if err := decoder.Decode(target); err != nil {
		writeError(w, 400, "请求格式错误: "+err.Error())
		return false
	}
	return true
}
func writeJSON(w http.ResponseWriter, status int, value any) {
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(status)
	_ = json.NewEncoder(w).Encode(value)
}
func writeError(w http.ResponseWriter, status int, message string) {
	writeJSON(w, status, map[string]string{"error": message})
}

var _ = errors.Is
var _ = sql.ErrNoRows
