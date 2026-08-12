package web

import (
	"context"
	"crypto/subtle"
	"database/sql"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/store"
)

const localFleetHostID = "local"

const maxFleetProbeBody = 2 << 20

type fleetSubscriptionEntry struct {
	Node  model.Node  `json:"node"`
	Share model.Share `json:"share"`
}

func (s *Server) fleetAuth(next authHandler) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		cookie, err := r.Cookie("wukong_session")
		if err != nil {
			writeError(w, http.StatusUnauthorized, "未登录")
			return
		}
		session, err := s.store.Session(cookie.Value)
		if err != nil {
			writeError(w, http.StatusUnauthorized, "会话已失效")
			return
		}
		if r.Method != http.MethodGet && r.Method != http.MethodHead && r.Header.Get("X-CSRF-Token") != session.CSRF {
			writeError(w, http.StatusForbidden, "CSRF 校验失败")
			return
		}
		if session.MustChange {
			writeError(w, http.StatusPreconditionRequired, "首次登录必须修改密码")
			return
		}
		next(w, r, session)
	}
}

func (s *Server) fleetEnabled() bool {
	value, _ := s.store.Setting("fleet_controller_enabled")
	return value == "true"
}

func validControllerURL(value string) (string, error) {
	return validHTTPSBaseURL(value, "主控地址")
}

func validSubscriptionPublicURL(value string) (string, error) {
	return validHTTPSBaseURL(value, "订阅公开地址")
}

func validHTTPSBaseURL(value, label string) (string, error) {
	value = strings.TrimRight(strings.TrimSpace(value), "/") + "/"
	parsed, err := url.Parse(value)
	if err != nil || parsed.Scheme != "https" || parsed.Host == "" || parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", fmt.Errorf("%s必须是证书可信的 HTTPS URL", label)
	}
	return value, nil
}

func (s *Server) fleetStatus(w http.ResponseWriter, r *http.Request, _ store.Session) {
	status, err := s.buildFleetStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) buildFleetStatus(ctx context.Context) (model.FleetStatus, error) {
	_ = s.store.PurgeExpiredFleetArchives(time.Now().Add(-30 * 24 * time.Hour))
	allHosts, err := s.store.FleetHosts(true)
	if err != nil {
		return model.FleetStatus{}, err
	}
	hosts := []model.FleetHost{}
	archivedHosts := []model.FleetHost{}
	for _, host := range allHosts {
		if _, _, cachedAt, cacheErr := s.store.FleetSubscriptionCache(host.ID); cacheErr == nil {
			host.SubscriptionCachedAt = cachedAt
		}
		if host.Archived {
			archivedHosts = append(archivedHosts, host)
		} else {
			hosts = append(hosts, host)
		}
	}
	publicURL, _ := s.store.Setting("fleet_public_url")
	subscriptionPublicURL, _ := s.store.Setting("fleet_subscription_public_url")
	status := model.FleetStatus{Enabled: s.fleetEnabled(), PublicURL: publicURL, SubscriptionPublicURL: subscriptionPublicURL, LocalHostID: localFleetHostID}
	_ = json.Unmarshal([]byte(mustSetting(s.store, "fleet_subscription_hosts")), &status.SelectedHostIDs)
	_ = json.Unmarshal([]byte(mustSetting(s.store, "fleet_subscription_nodes")), &status.SelectedNodeIDs)
	singBoxVersion := s.singBoxVersion(ctx)
	local := model.FleetHost{ID: localFleetHostID, Name: "本机", Hostname: "localhost", PanelVersion: s.version, SingBoxVersion: singBoxVersion, ProtocolVersion: model.FleetProtocolVersion, Compatible: true, Online: true, CreatedAt: time.Now()}
	metrics, _ := s.store.Metrics(80)
	nodes, _ := s.store.Nodes(ctx)
	jobs, _ := s.store.Jobs(30)
	settings, _ := s.store.Settings()
	var now model.Metric
	if len(metrics) > 0 {
		now = metrics[len(metrics)-1]
	}
	online := 0
	for _, node := range nodes {
		if node.Status == "active" {
			online++
		}
	}
	local.Snapshot = model.FleetSnapshot{Overview: model.Overview{Now: now, History: metrics, NodeCount: len(nodes), OnlineNodes: online, SingBoxVersion: singBoxVersion, PanelVersion: s.version}, Nodes: nodes, Jobs: jobs, Settings: settings}
	status.Hosts = append([]model.FleetHost{local}, hosts...)
	status.ArchivedHosts = archivedHosts
	subscriptionBaseURL := subscriptionPublicURL
	if subscriptionBaseURL == "" {
		subscriptionBaseURL = publicURL
	}
	if token, _ := s.store.Setting("fleet_global_token"); token != "" && subscriptionBaseURL != "" {
		status.GlobalSubscription = subscriptionBaseURL + "fleet-sub/" + token + "/clash.yaml"
	}
	return status, nil
}

func (s *Server) saveFleetStatus(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request struct {
		Enabled               bool                `json:"enabled"`
		PublicURL             string              `json:"publicUrl"`
		SubscriptionPublicURL *string             `json:"subscriptionPublicUrl"`
		SelectedHostIDs       []string            `json:"selectedHostIds"`
		SelectedNodeIDs       map[string][]string `json:"selectedNodeIds"`
		RotateGlobalToken     bool                `json:"rotateGlobalToken"`
	}
	if !decode(w, r, &request) {
		return
	}
	publicURL := ""
	subscriptionPublicURL := mustSetting(s.store, "fleet_subscription_public_url")
	var err error
	if request.Enabled {
		publicURL, err = validControllerURL(request.PublicURL)
		if err != nil {
			writeError(w, http.StatusBadRequest, err.Error())
			return
		}
		if request.SubscriptionPublicURL != nil {
			subscriptionPublicURL = strings.TrimSpace(*request.SubscriptionPublicURL)
			if subscriptionPublicURL != "" {
				subscriptionPublicURL, err = validSubscriptionPublicURL(subscriptionPublicURL)
				if err != nil {
					writeError(w, http.StatusBadRequest, err.Error())
					return
				}
			}
		}
	} else {
		subscriptionPublicURL = ""
	}
	if request.SelectedHostIDs != nil && len(request.SelectedHostIDs) == 0 {
		writeError(w, http.StatusBadRequest, "全局订阅至少需要选择一台主机")
		return
	}
	if err = s.store.SetSetting("fleet_controller_enabled", strconv.FormatBool(request.Enabled)); err == nil {
		err = s.store.SetSetting("fleet_public_url", publicURL)
	}
	if err == nil {
		err = s.store.SetSetting("fleet_subscription_public_url", subscriptionPublicURL)
	}
	if err == nil && request.SelectedHostIDs != nil {
		encoded, _ := json.Marshal(uniqueStrings(request.SelectedHostIDs))
		err = s.store.SetSetting("fleet_subscription_hosts", string(encoded))
		if err == nil {
			err = s.store.ClearFleetSubscriptionCaches()
		}
	}
	if err == nil && request.SelectedNodeIDs != nil {
		clean := make(map[string][]string, len(request.SelectedNodeIDs))
		for hostID, nodeIDs := range request.SelectedNodeIDs {
			clean[hostID] = uniqueStrings(nodeIDs)
		}
		encoded, _ := json.Marshal(clean)
		err = s.store.SetSetting("fleet_subscription_nodes", string(encoded))
		if err == nil {
			err = s.store.ClearFleetSubscriptionCaches()
		}
	}
	if err == nil {
		token, _ := s.store.Setting("fleet_global_token")
		if token == "" || request.RotateGlobalToken {
			token, err = security.RandomToken(24)
			if err == nil {
				err = s.store.SetSetting("fleet_global_token", token)
				if err == nil && request.RotateGlobalToken {
					err = s.store.ClearFleetSubscriptionCaches()
				}
			}
		}
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "fleet.controller.configure", localFleetHostID, fmt.Sprintf("enabled=%t", request.Enabled))
	status, err := s.buildFleetStatus(r.Context())
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, status)
}

func (s *Server) probeFleetSubscription(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request struct {
		SubscriptionPublicURL string `json:"subscriptionPublicUrl"`
	}
	if !decode(w, r, &request) {
		return
	}
	baseURL := strings.TrimSpace(request.SubscriptionPublicURL)
	if baseURL == "" {
		baseURL = mustSetting(s.store, "fleet_public_url")
	}
	baseURL, err := validSubscriptionPublicURL(baseURL)
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token := mustSetting(s.store, "fleet_global_token")
	if token == "" {
		writeError(w, http.StatusConflict, "请先保存中央控制设置并生成全局订阅令牌")
		return
	}
	target := baseURL + "fleet-sub/" + url.PathEscape(token) + "/clash.yaml"
	probeRequest, err := http.NewRequestWithContext(r.Context(), http.MethodGet, target, nil)
	if err != nil {
		writeError(w, http.StatusBadRequest, "无法创建订阅检测请求")
		return
	}
	probeRequest.Header.Set("User-Agent", "Wukong-Panel-Subscription-Probe/1")
	startedAt := time.Now()
	response, err := s.fleetProbeClient.Do(probeRequest)
	latency := time.Since(startedAt).Milliseconds()
	if err != nil {
		var urlError *url.Error
		if errors.As(err, &urlError) {
			err = urlError.Err
		}
		writeError(w, http.StatusBadGateway, "订阅入口访问失败："+err.Error())
		return
	}
	defer response.Body.Close()
	if response.StatusCode != http.StatusOK {
		writeError(w, http.StatusBadGateway, fmt.Sprintf("订阅入口返回 HTTP %d", response.StatusCode))
		return
	}
	body, err := io.ReadAll(io.LimitReader(response.Body, maxFleetProbeBody+1))
	if err != nil {
		writeError(w, http.StatusBadGateway, "无法读取订阅响应")
		return
	}
	if len(body) > maxFleetProbeBody {
		writeError(w, http.StatusBadGateway, "订阅响应超过 2 MiB")
		return
	}
	content := string(body)
	if !strings.Contains(content, "proxies:") {
		writeError(w, http.StatusBadGateway, "响应不是有效的 Clash 订阅")
		return
	}
	nodeCount := fleetSubscriptionNodeCount(content)
	_ = s.store.Audit(session.Username, "fleet.subscription.probe", baseURL, fmt.Sprintf("status=200 nodes=%d latency_ms=%d", nodeCount, latency))
	writeJSON(w, http.StatusOK, map[string]any{"ok": true, "status": response.StatusCode, "nodeCount": nodeCount, "latencyMs": latency})
}

func fleetSubscriptionNodeCount(content string) int {
	inProxies := false
	nodeCount := 0
	for _, line := range strings.Split(content, "\n") {
		trimmed := strings.TrimSpace(line)
		switch trimmed {
		case "proxies:":
			inProxies = true
			continue
		case "proxy-groups:", "rules:":
			inProxies = false
		}
		if inProxies && strings.HasPrefix(line, "  - name:") {
			nodeCount++
		}
	}
	return nodeCount
}

func uniqueStrings(values []string) []string {
	seen := map[string]bool{}
	result := make([]string, 0, len(values))
	for _, value := range values {
		value = strings.TrimSpace(value)
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	sort.Strings(result)
	return result
}

func (s *Server) createFleetEnrollment(w http.ResponseWriter, r *http.Request, session store.Session) {
	if !s.fleetEnabled() {
		writeError(w, http.StatusConflict, "请先启用中央控制")
		return
	}
	hosts, err := s.store.FleetHosts(false)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if len(hosts) >= 10 {
		writeError(w, http.StatusConflict, "首版最多接入 10 台远端 VPS")
		return
	}
	publicURL, err := validControllerURL(mustSetting(s.store, "fleet_public_url"))
	if err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	token, err := security.RandomToken(24)
	if err == nil {
		err = s.store.CreateFleetEnrollmentToken(token, time.Now().Add(10*time.Minute))
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	command := fmt.Sprintf("curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- --join-controller %s --enrollment-token %s", shellQuote(publicURL), shellQuote(token))
	_ = s.store.Audit(session.Username, "fleet.enrollment.create", "fleet", "expires in 10 minutes")
	writeJSON(w, http.StatusCreated, map[string]any{"token": token, "expiresAt": time.Now().Add(10 * time.Minute), "command": command})
}

func shellQuote(value string) string { return "'" + strings.ReplaceAll(value, "'", "'\\''") + "'" }

func mustSetting(s *store.Store, key string) string {
	value, _ := s.Setting(key)
	return value
}

func (s *Server) fleetAgentEnroll(w http.ResponseWriter, r *http.Request) {
	if !s.fleetEnabled() {
		http.NotFound(w, r)
		return
	}
	if !s.allowLogin("fleet:" + clientIP(r)) {
		writeError(w, http.StatusTooManyRequests, "接入尝试过多")
		return
	}
	if !fleetPayloadAllowed(w, r) {
		return
	}
	var request model.FleetEnrollmentRequest
	if !decode(w, r, &request) {
		return
	}
	if len(request.Name) > 80 || len(request.Hostname) > 255 || request.Token == "" {
		writeError(w, http.StatusBadRequest, "接入信息无效")
		return
	}
	hosts, err := s.store.FleetHosts(false)
	if err != nil || len(hosts) >= 10 {
		writeError(w, http.StatusConflict, "远端主机数量已达到上限")
		return
	}
	hostID, err := security.RandomToken(12)
	var token string
	if err == nil {
		token, err = security.RandomToken(32)
	}
	if err != nil {
		writeError(w, http.StatusInternalServerError, "无法签发主机凭据")
		return
	}
	host := model.FleetHost{ID: hostID, Name: strings.TrimSpace(request.Name), Hostname: request.Hostname, OS: request.OS, Arch: request.Arch, ServiceManager: request.ServiceManager, PanelVersion: request.PanelVersion, ProtocolVersion: request.ProtocolVersion, Capabilities: uniqueStrings(request.Capabilities)}
	if host.Name == "" {
		host.Name = request.Hostname
	}
	if err = s.store.ConsumeFleetEnrollmentToken(request.Token, host, token); err != nil {
		writeError(w, http.StatusUnauthorized, err.Error())
		return
	}
	_ = s.store.Audit("fleet-agent", "fleet.host.enroll", hostID, host.Name)
	writeJSON(w, http.StatusCreated, model.FleetEnrollmentResponse{HostID: hostID, AgentToken: token, ProtocolVersion: model.FleetProtocolVersion, HeartbeatSeconds: 10, EnrolledAt: time.Now()})
}

func bearerToken(r *http.Request) string {
	value := r.Header.Get("Authorization")
	if !strings.HasPrefix(value, "Bearer ") {
		return ""
	}
	return strings.TrimSpace(strings.TrimPrefix(value, "Bearer "))
}

func (s *Server) authenticateFleetAgent(w http.ResponseWriter, r *http.Request) (string, bool) {
	if !s.fleetEnabled() {
		http.NotFound(w, r)
		return "", false
	}
	hostID := strings.TrimSpace(r.Header.Get("X-Wukong-Host-ID"))
	if hostID == "" || !s.store.AuthenticateFleetHost(hostID, bearerToken(r)) {
		writeError(w, http.StatusUnauthorized, "Agent 凭据无效或已撤销")
		return "", false
	}
	if !s.allowFleetRequest(hostID) {
		writeError(w, http.StatusTooManyRequests, "Agent 请求过于频繁")
		return "", false
	}
	return hostID, true
}

func (s *Server) allowFleetRequest(hostID string) bool {
	s.limiterMu.Lock()
	defer s.limiterMu.Unlock()
	cutoff := time.Now().Add(-time.Minute)
	requests := s.fleetRequests[hostID][:0]
	for _, stamp := range s.fleetRequests[hostID] {
		if stamp.After(cutoff) {
			requests = append(requests, stamp)
		}
	}
	if len(requests) >= 60 {
		s.fleetRequests[hostID] = requests
		return false
	}
	s.fleetRequests[hostID] = append(requests, time.Now())
	return true
}

func fleetPayloadAllowed(w http.ResponseWriter, r *http.Request) bool {
	if r.ContentLength > 1<<20 {
		writeError(w, http.StatusRequestEntityTooLarge, "Agent 负载超过 1 MiB")
		return false
	}
	r.Body = http.MaxBytesReader(w, r.Body, 1<<20)
	return true
}

func (s *Server) fleetAgentHeartbeat(w http.ResponseWriter, r *http.Request) {
	hostID, ok := s.authenticateFleetAgent(w, r)
	if !ok {
		return
	}
	if !fleetPayloadAllowed(w, r) {
		return
	}
	var heartbeat model.FleetHeartbeat
	if !decode(w, r, &heartbeat) {
		return
	}
	if err := s.store.SaveFleetHeartbeat(r.Context(), hostID, heartbeat); err != nil {
		writeError(w, http.StatusBadRequest, "心跳无法保存")
		return
	}
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) fleetAgentNextCommand(w http.ResponseWriter, r *http.Request) {
	hostID, ok := s.authenticateFleetAgent(w, r)
	if !ok {
		return
	}
	host, err := s.store.FleetHost(hostID)
	if err != nil || !host.Compatible {
		w.WriteHeader(http.StatusNoContent)
		return
	}
	waitSeconds, _ := strconv.Atoi(r.URL.Query().Get("wait"))
	if waitSeconds < 1 || waitSeconds > 25 {
		waitSeconds = 25
	}
	deadline := time.NewTimer(time.Duration(waitSeconds) * time.Second)
	defer deadline.Stop()
	ticker := time.NewTicker(350 * time.Millisecond)
	defer ticker.Stop()
	for {
		record, nextErr := s.store.NextFleetCommand(hostID)
		if nextErr == nil {
			if s.fleetVaultErr != nil {
				writeError(w, http.StatusInternalServerError, "中央密钥不可用")
				return
			}
			plain, decryptErr := s.fleetVault.Decrypt(record.PayloadCipher)
			if decryptErr != nil {
				_, _ = s.store.CompleteFleetCommand(record.Command.ID, "failed", "", "命令载荷无法解密")
				continue
			}
			record.Command.Payload = json.RawMessage(plain)
			writeJSON(w, http.StatusOK, record.Command)
			return
		}
		if !errors.Is(nextErr, sql.ErrNoRows) {
			writeError(w, http.StatusInternalServerError, "命令队列不可用")
			return
		}
		select {
		case <-r.Context().Done():
			return
		case <-deadline.C:
			w.WriteHeader(http.StatusNoContent)
			return
		case <-ticker.C:
		}
	}
}

func (s *Server) fleetAgentCommandResult(w http.ResponseWriter, r *http.Request) {
	hostID, ok := s.authenticateFleetAgent(w, r)
	if !ok {
		return
	}
	if !fleetPayloadAllowed(w, r) {
		return
	}
	var result model.FleetCommandResult
	if !decode(w, r, &result) {
		return
	}
	if result.Status != "success" && result.Status != "failed" {
		writeError(w, http.StatusBadRequest, "回执状态无效")
		return
	}
	if len(result.Result) > 1<<20 {
		writeError(w, http.StatusRequestEntityTooLarge, "回执过大")
		return
	}
	commandHostID, err := s.store.FleetCommandHost(r.PathValue("id"))
	if err != nil || commandHostID != hostID {
		writeError(w, http.StatusNotFound, "命令不存在")
		return
	}
	cipher := ""
	if len(result.Result) > 0 {
		if s.fleetVaultErr != nil {
			writeError(w, http.StatusInternalServerError, "中央密钥不可用")
			return
		}
		cipher, err = s.fleetVault.Encrypt(string(result.Result))
		if err != nil {
			writeError(w, http.StatusInternalServerError, "回执无法加密")
			return
		}
	}
	jobID, err := s.store.CompleteFleetCommand(r.PathValue("id"), result.Status, cipher, result.Error)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "回执无法保存")
		return
	}
	if jobID != "" {
		if result.Status == "success" {
			_ = s.store.UpdateJob(jobID, "success", 100, "远端执行完成", "")
		} else {
			_ = s.store.UpdateJob(jobID, "failed", 100, "远端执行失败", result.Error)
		}
	}
	_ = s.store.Audit("fleet-agent", "fleet.command.result", hostID, r.PathValue("id")+" "+result.Status)
	w.WriteHeader(http.StatusNoContent)
}

func (s *Server) renameFleetHost(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request struct {
		Name string `json:"name"`
	}
	if !decode(w, r, &request) {
		return
	}
	if len(strings.TrimSpace(request.Name)) > 80 {
		writeError(w, http.StatusBadRequest, "主机名过长")
		return
	}
	if err := s.store.RenameFleetHost(r.PathValue("hostId"), strings.TrimSpace(request.Name)); err != nil {
		writeError(w, http.StatusBadRequest, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "fleet.host.rename", r.PathValue("hostId"), request.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) archiveFleetHost(w http.ResponseWriter, r *http.Request, session store.Session) {
	host, err := s.store.FleetHost(r.PathValue("hostId"))
	if err != nil {
		writeError(w, http.StatusNotFound, "主机不存在")
		return
	}
	var request struct {
		ConfirmName string `json:"confirmName"`
	}
	if !decode(w, r, &request) {
		return
	}
	if request.ConfirmName != host.Name {
		writeError(w, http.StatusBadRequest, "请输入完整主机名确认移除")
		return
	}
	if err = s.store.ArchiveFleetHost(host.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.ClearFleetSubscriptionCaches()
	_ = s.store.Audit(session.Username, "fleet.host.archive", host.ID, host.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) purgeFleetHost(w http.ResponseWriter, r *http.Request, session store.Session) {
	host, err := s.store.FleetHost(r.PathValue("hostId"))
	if err != nil || !host.Archived {
		writeError(w, http.StatusConflict, "只能永久清除已移除的主机")
		return
	}
	var request struct {
		ConfirmName string `json:"confirmName"`
	}
	if !decode(w, r, &request) {
		return
	}
	if request.ConfirmName != host.Name {
		writeError(w, http.StatusBadRequest, "请输入完整主机名确认永久清除")
		return
	}
	if err = s.store.PurgeFleetHost(host.ID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "fleet.host.purge", host.ID, host.Name)
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}

func (s *Server) fleetHostGateway(w http.ResponseWriter, r *http.Request, session store.Session) {
	host, err := s.store.FleetHost(r.PathValue("hostId"))
	if err != nil || host.Archived {
		writeError(w, http.StatusNotFound, "远端主机不存在")
		return
	}
	resource := strings.Trim(r.PathValue("resource"), "/")
	if r.Method == http.MethodGet {
		if s.writeFleetSnapshotResource(w, host, resource) {
			return
		}
	}
	if !host.Online {
		writeError(w, http.StatusConflict, "主机离线，只能查看最后快照")
		return
	}
	if !host.Compatible {
		writeError(w, http.StatusConflict, "舰队协议版本不兼容，已禁用操作")
		return
	}
	kind, payload, async, mapErr := fleetCommandForRequest(r, resource)
	if mapErr != nil {
		writeError(w, http.StatusNotFound, mapErr.Error())
		return
	}
	command, job, err := s.queueFleetCommand(host, kind, payload, session.Username, async)
	if err != nil {
		writeError(w, http.StatusConflict, err.Error())
		return
	}
	if async {
		writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID})
		return
	}
	result, err := s.waitFleetCommand(r.Context(), command.ID, 70*time.Second)
	if err != nil {
		writeError(w, http.StatusBadGateway, err.Error())
		return
	}
	if len(result) == 0 || string(result) == "null" {
		writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
		return
	}
	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(result)
}

func (s *Server) writeFleetSnapshotResource(w http.ResponseWriter, host model.FleetHost, resource string) bool {
	snapshot := host.Snapshot
	switch {
	case resource == "overview":
		snapshot.Overview.History, _ = s.store.FleetMetrics(host.ID, 80)
		writeJSON(w, http.StatusOK, snapshot.Overview)
	case resource == "metrics":
		items, _ := s.store.FleetMetrics(host.ID, 120)
		writeJSON(w, http.StatusOK, items)
	case resource == "metrics/endpoints":
		writeJSON(w, http.StatusOK, snapshot.Endpoints)
	case resource == "metrics/timeline":
		writeJSON(w, http.StatusOK, snapshot.Timeline)
	case resource == "nodes":
		writeJSON(w, http.StatusOK, snapshot.Nodes)
	case resource == "nodes/deployment-defaults":
		writeJSON(w, http.StatusOK, snapshot.DeploymentDefaults)
	case strings.HasPrefix(resource, "nodes/") && strings.HasSuffix(resource, "/edit"):
		id := strings.TrimSuffix(strings.TrimPrefix(resource, "nodes/"), "/edit")
		value, ok := snapshot.NodeDetails[id]
		if !ok {
			writeError(w, http.StatusNotFound, "节点编辑快照不存在")
		} else {
			writeJSON(w, http.StatusOK, value)
		}
	case resource == "jobs":
		items := append([]model.Job{}, snapshot.Jobs...)
		centralJobs, _ := s.store.Jobs(80)
		for _, job := range centralJobs {
			if strings.HasPrefix(job.Kind, "fleet.") && job.Target == host.Name {
				items = append(items, job)
			}
		}
		sort.Slice(items, func(i, j int) bool { return items[i].CreatedAt.After(items[j].CreatedAt) })
		writeJSON(w, http.StatusOK, items)
	case strings.HasPrefix(resource, "jobs/"):
		id := strings.TrimPrefix(resource, "jobs/")
		for _, job := range snapshot.Jobs {
			if job.ID == id {
				writeJSON(w, http.StatusOK, job)
				return true
			}
		}
		if job, err := s.store.Job(id); err == nil && strings.HasPrefix(job.Kind, "fleet.") && job.Target == host.Name {
			writeJSON(w, http.StatusOK, job)
			return true
		}
		writeError(w, http.StatusNotFound, "任务不存在")
	case resource == "settings":
		snapshot.Settings.SubscriptionToken = maskToken(snapshot.Settings.SubscriptionToken)
		writeJSON(w, http.StatusOK, snapshot.Settings)
	case resource == "system/residential-exit":
		writeJSON(w, http.StatusOK, snapshot.ResidentialExit)
	case resource == "system/socks-exit":
		writeJSON(w, http.StatusOK, snapshot.SOCKSExit)
	default:
		return false
	}
	return true
}

func fleetCommandForRequest(r *http.Request, resource string) (string, json.RawMessage, bool, error) {
	body, err := io.ReadAll(io.LimitReader(r.Body, 1<<20))
	if err != nil {
		return "", nil, false, err
	}
	if len(body) == 0 {
		body = []byte("{}")
	}
	wrap := func(id string) json.RawMessage {
		return json.RawMessage(fmt.Sprintf(`{"id":%q,"request":%s}`, id, body))
	}
	parts := strings.Split(resource, "/")
	switch {
	case r.Method == http.MethodGet && resource == "imports/scan":
		return "imports.scan", body, false, nil
	case r.Method == http.MethodGet && resource == "system/sing-box/migration":
		target := r.URL.Query().Get("target")
		if target == "" {
			target = "1.13.14"
		}
		payload, _ := json.Marshal(map[string]string{"target": target})
		return "migration.plan", payload, false, nil
	case r.Method == http.MethodGet && len(parts) == 3 && parts[0] == "nodes" && parts[2] == "share":
		payload, _ := json.Marshal(map[string]string{"id": parts[1]})
		return "node.share", payload, false, nil
	case r.Method == http.MethodPost && resource == "nodes":
		return "node.create", body, true, nil
	case r.Method == http.MethodPost && resource == "nodes/batch":
		return "node.create_batch", body, true, nil
	case len(parts) == 2 && parts[0] == "nodes" && r.Method == http.MethodPut:
		return "node.edit", wrap(parts[1]), true, nil
	case len(parts) == 2 && parts[0] == "nodes" && r.Method == http.MethodPatch:
		return "node.rename", wrap(parts[1]), true, nil
	case len(parts) == 3 && parts[0] == "nodes" && parts[2] == "actions" && r.Method == http.MethodPost:
		return "node.action", wrap(parts[1]), true, nil
	case r.Method == http.MethodPost && resource == "imports/confirm":
		return "imports.confirm", body, true, nil
	case len(parts) == 3 && parts[0] == "imports" && parts[2] == "delete" && r.Method == http.MethodPost:
		return "candidate.delete", wrap(parts[1]), true, nil
	case r.Method == http.MethodPut && resource == "system/residential-exit":
		return "residential.configure", body, false, nil
	case r.Method == http.MethodDelete && resource == "system/residential-exit":
		return "residential.remove", body, false, nil
	case r.Method == http.MethodPut && resource == "system/socks-exit":
		return "socks.configure", body, false, nil
	case r.Method == http.MethodDelete && resource == "system/socks-exit":
		return "socks.remove", body, false, nil
	case r.Method == http.MethodPut && resource == "settings":
		return "settings.save", body, false, nil
	case r.Method == http.MethodPost && resource == "settings/subscription-token":
		return "settings.rotate-subscription", body, false, nil
	default:
		return "", nil, false, errors.New("远端接口未实现")
	}
}

func (s *Server) queueFleetCommand(host model.FleetHost, kind string, payload json.RawMessage, actor string, createJob bool) (model.FleetCommand, model.Job, error) {
	if s.fleetVaultErr != nil {
		return model.FleetCommand{}, model.Job{}, s.fleetVaultErr
	}
	cipher, err := s.fleetVault.Encrypt(string(payload))
	if err != nil {
		return model.FleetCommand{}, model.Job{}, err
	}
	var job model.Job
	if createJob {
		job, err = s.store.CreateJob("fleet."+kind, host.Name)
		if err != nil {
			return model.FleetCommand{}, job, err
		}
	}
	ttl := 2 * time.Minute
	if !createJob {
		ttl = 60 * time.Second
	}
	command, err := s.store.QueueFleetCommand(host.ID, job.ID, kind, actor, cipher, time.Now().Add(ttl))
	if err != nil {
		return command, job, err
	}
	if job.ID != "" {
		_ = s.store.UpdateJob(job.ID, "running", 10, "等待远端 Agent", "")
	}
	_ = s.store.Audit(actor, "fleet.command.queue", host.ID, kind+" "+command.ID)
	return command, job, nil
}

func (s *Server) waitFleetCommand(ctx context.Context, id string, timeout time.Duration) (json.RawMessage, error) {
	deadline := time.NewTimer(timeout)
	defer deadline.Stop()
	ticker := time.NewTicker(300 * time.Millisecond)
	defer ticker.Stop()
	for {
		status, cipher, commandErr, err := s.store.FleetCommand(id)
		if err != nil {
			return nil, err
		}
		switch status {
		case "success":
			if cipher == "" {
				return nil, nil
			}
			plain, err := s.fleetVault.Decrypt(cipher)
			return json.RawMessage(plain), err
		case "failed", "expired":
			if commandErr == "" {
				commandErr = "远端命令执行失败"
			}
			return nil, errors.New(commandErr)
		}
		select {
		case <-ctx.Done():
			return nil, ctx.Err()
		case <-deadline.C:
			return nil, errors.New("等待远端 Agent 超时")
		case <-ticker.C:
		}
	}
}

func (s *Server) fleetSubscription(w http.ResponseWriter, r *http.Request) {
	providedToken := r.PathValue("token")
	wantedToken := mustSetting(s.store, "fleet_global_token")
	providedHash := []byte(security.HashToken(providedToken))
	wantedHash := []byte(security.HashToken(wantedToken))
	if !s.fleetEnabled() || providedToken == "" || wantedToken == "" || subtle.ConstantTimeCompare(providedHash, wantedHash) != 1 {
		http.NotFound(w, r)
		return
	}
	selected := []string{}
	_ = json.Unmarshal([]byte(mustSetting(s.store, "fleet_subscription_hosts")), &selected)
	selectedNodes := map[string][]string{}
	_ = json.Unmarshal([]byte(mustSetting(s.store, "fleet_subscription_nodes")), &selectedNodes)
	if len(selected) == 0 {
		selected = []string{localFleetHostID}
		hosts, _ := s.store.FleetHosts(false)
		for _, host := range hosts {
			selected = append(selected, host.ID)
		}
	}
	entries := []fleetSubscriptionEntry{}
	comments := []string{}
	for _, hostID := range uniqueStrings(selected) {
		selectedNodeIDs, hasNodeSelection := selectedNodes[hostID]
		wantedNodes := map[string]bool{}
		for _, nodeID := range selectedNodeIDs {
			wantedNodes[nodeID] = true
		}
		if hostID == localFleetHostID {
			nodes, _ := s.store.Nodes(r.Context())
			for _, node := range nodes {
				if node.Status != "active" || (hasNodeSelection && !wantedNodes[node.ID]) {
					continue
				}
				share, err := s.agent.Share(r.Context(), node.ID)
				if err == nil {
					entries = append(entries, fleetSubscriptionEntry{Node: node, Share: share})
				}
			}
			continue
		}
		host, err := s.store.FleetHost(hostID)
		if err != nil || host.Archived {
			continue
		}
		var cached []fleetSubscriptionEntry
		cacheAvailable := false
		revision, cipher, updated, cacheErr := s.store.FleetSubscriptionCache(host.ID)
		currentRevision := fleetSubscriptionRevision(host)
		if host.Online && host.Compatible && (cacheErr != nil || revision != currentRevision || time.Since(updated) > time.Minute) {
			command, _, queueErr := s.queueFleetCommand(host, "subscription.render", json.RawMessage(`{}`), "global-subscription", false)
			if queueErr == nil {
				if raw, waitErr := s.waitFleetCommand(r.Context(), command.ID, 35*time.Second); waitErr == nil {
					if json.Unmarshal(raw, &cached) == nil {
						sealed, _ := s.fleetVault.Encrypt(string(raw))
						_ = s.store.SaveFleetSubscriptionCache(host.ID, currentRevision, sealed)
						revision, cipher, updated, cacheErr = currentRevision, sealed, time.Now(), nil
						cacheAvailable = true
					}
				}
			}
		}
		if !cacheAvailable && cacheErr == nil {
			plain, decryptErr := s.fleetVault.Decrypt(cipher)
			if decryptErr == nil {
				cacheAvailable = json.Unmarshal([]byte(plain), &cached) == nil
			}
		}
		if !cacheAvailable {
			writeError(w, http.StatusServiceUnavailable, "主机 "+host.Name+" 尚无可用订阅缓存")
			return
		}
		if !host.Online {
			comments = append(comments, fmt.Sprintf("# OFFLINE CACHE: %s · %s", host.Name, updated.Format(time.RFC3339)))
		}
		for index := range cached {
			if hasNodeSelection && !wantedNodes[cached[index].Node.ID] {
				continue
			}
			cached[index].Node.Name = host.Name + " · " + cached[index].Node.Name
			entries = append(entries, cached[index])
		}
	}
	w.Header().Set("Content-Type", "text/yaml; charset=utf-8")
	w.Header().Set("Profile-Update-Interval", "10")
	w.Header().Set("Profile-Title", "Wukong Fleet")
	for _, comment := range comments {
		fmt.Fprintln(w, comment)
	}
	fmt.Fprintln(w, "proxies:")
	names := []string{}
	for _, item := range entries {
		entry, err := clashProxyYAML(item.Node, item.Share.URI)
		if err != nil {
			continue
		}
		fmt.Fprint(w, entry)
		names = append(names, item.Node.Name)
	}
	fmt.Fprintln(w, "proxy-groups:\n  - name: Wukong Fleet\n    type: select\n    proxies:")
	for _, name := range names {
		fmt.Fprintf(w, "      - %q\n", name)
	}
	fmt.Fprintln(w, "rules:\n  - MATCH,Wukong Fleet")
}

func fleetSubscriptionRevision(host model.FleetHost) string {
	parts := make([]string, 0, len(host.Snapshot.Nodes))
	for _, node := range host.Snapshot.Nodes {
		if node.Status == "active" {
			parts = append(parts, node.ID+":"+node.UpdatedAt.UTC().Format(time.RFC3339Nano))
		}
	}
	sort.Strings(parts)
	return security.HashToken(strings.Join(parts, "|"))
}
