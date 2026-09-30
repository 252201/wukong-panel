package web

import (
	"context"
	"fmt"
	"net/http"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

type fail2banAgent interface {
	Fail2ban(context.Context) (model.Fail2banStatus, error)
	ConfigureFail2ban(context.Context, model.Fail2banConfig) (model.Fail2banStatus, error)
	UnbanFail2ban(context.Context, model.Fail2banUnbanRequest) (model.Fail2banStatus, error)
}

func (s *Server) fail2ban(w http.ResponseWriter, r *http.Request, _ store.Session) {
	agent, ok := s.agent.(fail2banAgent)
	if !ok {
		writeError(w, 501, "此 Agent 尚不支持 Fail2ban 管理")
		return
	}
	result, err := agent.Fail2ban(r.Context())
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) configureFail2ban(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request model.Fail2banConfig
	if !decode(w, r, &request) {
		return
	}
	agent, ok := s.agent.(fail2banAgent)
	if !ok {
		writeError(w, 501, "此 Agent 尚不支持 Fail2ban 管理")
		return
	}
	result, err := agent.ConfigureFail2ban(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "fail2ban.configure", "wukong-sshd", fmt.Sprintf("enabled=%t maxretry=%d findtime=%d bantime=%d mode=%s trusted=%d", request.Enabled, request.MaxRetry, request.FindTime, request.BanTime, request.Mode, len(request.IgnoreIPs)))
	writeJSON(w, 200, result)
}
func (s *Server) unbanFail2ban(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request model.Fail2banUnbanRequest
	if !decode(w, r, &request) {
		return
	}
	agent, ok := s.agent.(fail2banAgent)
	if !ok {
		writeError(w, 501, "此 Agent 尚不支持 Fail2ban 管理")
		return
	}
	result, err := agent.UnbanFail2ban(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "fail2ban.unban", "wukong-sshd", request.IP)
	writeJSON(w, 200, result)
}
