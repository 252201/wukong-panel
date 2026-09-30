package agent

import (
	"context"
	"fmt"
	"net/http"
	"net/url"

	"github.com/252201/wukong-panel/internal/firewall"
	"github.com/252201/wukong-panel/internal/model"
)

func (m *Manager) firewallController() *firewall.Controller {
	return firewall.New(m.cfg.SecretDir, m.cfg.Demo)
}
func (m *Manager) RecoverFirewall(ctx context.Context) error {
	return m.firewallController().Recover(ctx)
}
func (m *Manager) Firewall(ctx context.Context, zone string) (model.FirewallStatus, error) {
	return m.firewallController().Status(ctx, zone)
}
func (m *Manager) AddFirewallPort(ctx context.Context, r model.FirewallPortRequest) (model.FirewallStatus, error) {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	result, err := m.firewallController().Add(ctx, r)
	if err == nil {
		_ = m.store.Audit("agent", "firewall.port.add", result.Backend, fmt.Sprintf("%d/%s zone=%s", r.Port, r.Protocol, result.Zone))
	}
	return result, err
}
func (m *Manager) RemoveFirewallPort(ctx context.Context, r model.FirewallDeleteRequest) (model.FirewallStatus, error) {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	result, err := m.firewallController().Remove(ctx, r.ID)
	if err == nil {
		_ = m.store.Audit("agent", "firewall.port.remove", result.Backend, r.ID)
	}
	return result, err
}

func (s *Server) firewall(w http.ResponseWriter, r *http.Request) {
	result, err := s.manager.Firewall(r.Context(), r.URL.Query().Get("zone"))
	if err != nil {
		writeError(w, 500, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) addFirewallPort(w http.ResponseWriter, r *http.Request) {
	var request model.FirewallPortRequest
	if !decode(w, r, &request) {
		return
	}
	result, err := s.manager.AddFirewallPort(r.Context(), request)
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (s *Server) removeFirewallPort(w http.ResponseWriter, r *http.Request) {
	result, err := s.manager.RemoveFirewallPort(r.Context(), model.FirewallDeleteRequest{ID: r.PathValue("id")})
	if err != nil {
		writeError(w, 400, err.Error())
		return
	}
	writeJSON(w, 200, result)
}
func (c *Client) Firewall(ctx context.Context, zone string) (model.FirewallStatus, error) {
	var result model.FirewallStatus
	err := c.request(ctx, "GET", "/firewall?zone="+url.QueryEscape(zone), nil, &result)
	return result, err
}
func (c *Client) AddFirewallPort(ctx context.Context, r model.FirewallPortRequest) (model.FirewallStatus, error) {
	var result model.FirewallStatus
	err := c.request(ctx, "POST", "/firewall/ports", r, &result)
	return result, err
}
func (c *Client) RemoveFirewallPort(ctx context.Context, r model.FirewallDeleteRequest) (model.FirewallStatus, error) {
	var result model.FirewallStatus
	err := c.request(ctx, "DELETE", "/firewall/ports/"+url.PathEscape(r.ID), nil, &result)
	return result, err
}
