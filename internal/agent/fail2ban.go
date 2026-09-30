package agent

import (
	"context"
	"fmt"
	"net/http"

	"github.com/252201/wukong-panel/internal/fail2ban"
	"github.com/252201/wukong-panel/internal/model"
)

func (m *Manager) fail2banController() *fail2ban.Controller {
	return fail2ban.New(m.cfg.SecretDir, m.cfg.Demo)
}
func (m *Manager) Fail2ban(ctx context.Context) (model.Fail2banStatus, error) {
	return m.fail2banController().Status(ctx)
}
func (m *Manager) ConfigureFail2ban(ctx context.Context, r model.Fail2banConfig) (model.Fail2banStatus, error) {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	result, err := m.fail2banController().Configure(ctx, r)
	if err == nil {
		_ = m.store.Audit("agent", "fail2ban.configure", "wukong-sshd", fmt.Sprintf("enabled=%t maxretry=%d findtime=%d bantime=%d mode=%s trusted=%d", r.Enabled, r.MaxRetry, r.FindTime, r.BanTime, r.Mode, len(r.IgnoreIPs)))
	}
	return result, err
}
func (m *Manager) UnbanFail2ban(ctx context.Context, r model.Fail2banUnbanRequest) (model.Fail2banStatus, error) {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	result, err := m.fail2banController().Unban(ctx, r.IP)
	if err == nil {
		_ = m.store.Audit("agent", "fail2ban.unban", "wukong-sshd", r.IP)
	}
	return result, err
}
func (s *Server) fail2ban(w http.ResponseWriter, r *http.Request) {
	result, err := s.manager.Fail2ban(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) configureFail2ban(w http.ResponseWriter, r *http.Request) {
	var request model.Fail2banConfig
	if !decode(w, r, &request) {
		return
	}
	result, err := s.manager.ConfigureFail2ban(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) unbanFail2ban(w http.ResponseWriter, r *http.Request) {
	var request model.Fail2banUnbanRequest
	if !decode(w, r, &request) {
		return
	}
	result, err := s.manager.UnbanFail2ban(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (c *Client) Fail2ban(ctx context.Context) (model.Fail2banStatus, error) {
	var result model.Fail2banStatus
	err := c.request(ctx, "GET", "/fail2ban", nil, &result)
	return result, err
}
func (c *Client) ConfigureFail2ban(ctx context.Context, r model.Fail2banConfig) (model.Fail2banStatus, error) {
	var result model.Fail2banStatus
	err := c.request(ctx, "POST", "/fail2ban", r, &result)
	return result, err
}
func (c *Client) UnbanFail2ban(ctx context.Context, r model.Fail2banUnbanRequest) (model.Fail2banStatus, error) {
	var result model.Fail2banStatus
	err := c.request(ctx, "POST", "/fail2ban/unban", r, &result)
	return result, err
}
