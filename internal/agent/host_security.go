package agent

import (
	"context"
	"github.com/252201/wukong-panel/internal/hostsecurity"
	"github.com/252201/wukong-panel/internal/model"
	"net/http"
	"net/url"
	"time"
)

func (m *Manager) securityController() *hostsecurity.Controller {
	c := hostsecurity.New(m.cfg.SecretDir, m.cfg.Demo)
	if m.securityFactory != nil {
		c = m.securityFactory()
	}
	if m.store != nil {
		c.Nodes, _ = m.store.Nodes(context.Background())
	}
	return c
}
func (m *Manager) Firewall(ctx context.Context, zone string) (model.FirewallState, error) {
	return m.securityController().Firewall(ctx, zone)
}
func (m *Manager) Fail2ban(ctx context.Context) (model.Fail2banState, error) {
	return m.securityController().Fail2ban(ctx)
}
func (m *Manager) SecurityPreview(ctx context.Context, kind string, r model.SecurityRequest) (model.SecurityPreview, error) {
	return m.securityController().Preview(ctx, kind, r)
}
func (m *Manager) SecurityApply(ctx context.Context, kind string, r model.SecurityRequest) (model.SecurityResult, error) {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	result, e := m.securityController().Apply(ctx, kind, r)
	if m.store != nil {
		detail := r.Operation
		if kind == "fail2ban" && (r.Operation == "ban" || r.Operation == "unban") {
			detail += " jail=" + r.Jail + " ip=" + r.IP
		}
		if e != nil {
			detail += " failed: " + e.Error()
		}
		_ = m.store.Audit("agent", "security."+kind, "system", detail)
	}
	return result, e
}
func (m *Manager) SecurityConfirm(ctx context.Context, id string) (model.SecurityTransaction, error) {
	return m.securityController().Confirm(ctx, id)
}
func (m *Manager) SecurityTransaction(ctx context.Context, id string) (model.SecurityTransaction, error) {
	return m.securityController().Transaction(id)
}
func (s *Server) hostSecurity(w http.ResponseWriter, r *http.Request) {
	kind := r.PathValue("kind")
	if r.Method == http.MethodGet {
		if kind == "firewall" {
			v, e := s.manager.Firewall(r.Context(), r.URL.Query().Get("zone"))
			if e != nil {
				writeError(w, 500, e.Error())
				return
			}
			writeJSON(w, 200, v)
		} else if kind == "fail2ban" {
			v, e := s.manager.Fail2ban(r.Context())
			if e != nil {
				writeError(w, 500, e.Error())
				return
			}
			writeJSON(w, 200, v)
		} else {
			writeError(w, 404, "unknown security resource")
		}
		return
	}
	var req model.SecurityRequest
	if !decode(w, r, &req) {
		return
	}
	if r.PathValue("action") == "preview" {
		v, e := s.manager.SecurityPreview(r.Context(), kind, req)
		if e != nil {
			writeError(w, 400, e.Error())
			return
		}
		writeJSON(w, 200, v)
	} else if r.PathValue("action") == "apply" {
		v, e := s.manager.SecurityApply(r.Context(), kind, req)
		if e != nil {
			writeError(w, 400, e.Error())
			return
		}
		writeJSON(w, 200, v)
	} else {
		writeError(w, 404, "unknown security action")
	}
}
func (s *Server) securityTransaction(w http.ResponseWriter, r *http.Request) {
	var v model.SecurityTransaction
	var e error
	if r.Method == http.MethodGet {
		v, e = s.manager.SecurityTransaction(r.Context(), r.PathValue("id"))
	} else {
		v, e = s.manager.SecurityConfirm(r.Context(), r.PathValue("id"))
	}
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (c *Client) Firewall(ctx context.Context, zone string) (model.FirewallState, error) {
	var v model.FirewallState
	e := c.request(ctx, "GET", "/host-security/firewall?zone="+url.QueryEscape(zone), nil, &v)
	return v, e
}
func (c *Client) Fail2ban(ctx context.Context) (model.Fail2banState, error) {
	var v model.Fail2banState
	e := c.request(ctx, "GET", "/host-security/fail2ban", nil, &v)
	return v, e
}
func (c *Client) SecurityPreview(ctx context.Context, kind string, r model.SecurityRequest) (model.SecurityPreview, error) {
	var v model.SecurityPreview
	e := c.request(ctx, "POST", "/host-security/"+kind+"/preview", r, &v)
	return v, e
}
func (c *Client) SecurityApply(ctx context.Context, kind string, r model.SecurityRequest) (model.SecurityResult, error) {
	copyHTTP := *c.http
	copyHTTP.Timeout = 9 * time.Minute
	copyClient := *c
	copyClient.http = &copyHTTP
	var v model.SecurityResult
	e := copyClient.request(ctx, "POST", "/host-security/"+kind+"/apply", r, &v)
	return v, e
}
func (c *Client) SecurityConfirm(ctx context.Context, id string) (model.SecurityTransaction, error) {
	var v model.SecurityTransaction
	e := c.request(ctx, "POST", "/security-transactions/"+id+"/confirm", map[string]string{}, &v)
	return v, e
}
func (c *Client) SecurityTransaction(ctx context.Context, id string) (model.SecurityTransaction, error) {
	var v model.SecurityTransaction
	e := c.request(ctx, "GET", "/security-transactions/"+id, nil, &v)
	return v, e
}
