package web

import (
	"context"
	"fmt"
	"net/http"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

type firewallAgent interface {
	Firewall(context.Context, string) (model.FirewallStatus, error)
	AddFirewallPort(context.Context, model.FirewallPortRequest) (model.FirewallStatus, error)
	RemoveFirewallPort(context.Context, model.FirewallDeleteRequest) (model.FirewallStatus, error)
}

func (s *Server) firewall(w http.ResponseWriter, r *http.Request, _ store.Session) {
	agent, ok := s.agent.(firewallAgent)
	if !ok {
		writeError(w, 501, "此 Agent 尚不支持防火墙端口管理")
		return
	}
	result, err := agent.Firewall(r.Context(), r.URL.Query().Get("zone"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) addFirewallPort(w http.ResponseWriter, r *http.Request, session store.Session) {
	var request model.FirewallPortRequest
	if !decode(w, r, &request) {
		return
	}
	agent, ok := s.agent.(firewallAgent)
	if !ok {
		writeError(w, 501, "此 Agent 尚不支持防火墙端口管理")
		return
	}
	result, err := agent.AddFirewallPort(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "firewall.port.add", result.Backend, fmt.Sprintf("%d/%s zone=%s", request.Port, request.Protocol, result.Zone))
	writeJSON(w, 200, result)
}
func (s *Server) removeFirewallPort(w http.ResponseWriter, r *http.Request, session store.Session) {
	agent, ok := s.agent.(firewallAgent)
	if !ok {
		writeError(w, 501, "此 Agent 尚不支持防火墙端口管理")
		return
	}
	request := model.FirewallDeleteRequest{ID: r.PathValue("id")}
	result, err := agent.RemoveFirewallPort(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	_ = s.store.Audit(session.Username, "firewall.port.remove", result.Backend, request.ID)
	writeJSON(w, 200, result)
}
