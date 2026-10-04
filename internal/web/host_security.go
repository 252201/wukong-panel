package web

import (
	"context"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
	"net/http"
	"net/netip"
	"time"
)

type hostSecurityAgent interface {
	Firewall(context.Context, string) (model.FirewallState, error)
	Fail2ban(context.Context) (model.Fail2banState, error)
	SecurityPreview(context.Context, string, model.SecurityRequest) (model.SecurityPreview, error)
	SecurityApply(context.Context, string, model.SecurityRequest) (model.SecurityResult, error)
	SecurityConfirm(context.Context, string) (model.SecurityTransaction, error)
	SecurityTransaction(context.Context, string) (model.SecurityTransaction, error)
}

func (s *Server) hostSecurity(w http.ResponseWriter, r *http.Request, session store.Session) {
	agent, ok := s.agent.(hostSecurityAgent)
	if !ok {
		writeError(w, 501, "Agent 不支持安全管理，请更新完整面板")
		return
	}
	kind := r.PathValue("kind")
	if kind != "firewall" && kind != "fail2ban" {
		writeError(w, 404, "unknown security resource")
		return
	}
	if r.Method == http.MethodGet {
		if kind == "firewall" {
			v, e := agent.Firewall(r.Context(), r.URL.Query().Get("zone"))
			if e != nil {
				writeError(w, 500, e.Error())
				return
			}
			writeJSON(w, 200, v)
		} else {
			v, e := agent.Fail2ban(r.Context())
			if e != nil {
				writeError(w, 500, e.Error())
				return
			}
			writeJSON(w, 200, v)
		}
		return
	}
	var req model.SecurityRequest
	if !decode(w, r, &req) {
		return
	}
	if r.PathValue("action") == "preview" {
		v, e := agent.SecurityPreview(r.Context(), kind, req)
		if e != nil {
			writeError(w, 400, e.Error())
			return
		}
		writeJSON(w, 200, v)
		return
	}
	if r.PathValue("action") != "apply" {
		writeError(w, 404, "unknown security action")
		return
	}
	detail := "requested through web"
	if kind == "fail2ban" && (req.Operation == "ban" || req.Operation == "unban") {
		detail += " jail=" + req.Jail + " ip=" + req.IP
	}
	_ = s.store.Audit(session.Username, "security."+kind+"."+req.Operation, "local", detail)
	if req.Operation == "install" || kind == "fail2ban" && req.Operation == "reinstall" {
		job, e := s.store.CreateJob("security."+kind+"."+req.Operation, "local")
		if e != nil {
			writeError(w, 500, e.Error())
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 9*time.Minute)
			defer cancel()
			_ = s.store.UpdateJob(job.ID, "running", 10, "正在备份、清理或安装安全组件", "")
			_, e := agent.SecurityApply(ctx, kind, req)
			if e != nil {
				_ = s.store.UpdateJob(job.ID, "failed", 100, "安装失败", e.Error())
			} else {
				_ = s.store.UpdateJob(job.ID, "success", 100, "安装完成", "")
			}
		}()
		writeJSON(w, 202, map[string]string{"jobId": job.ID})
		return
	}
	job, e := s.store.CreateJob("security."+kind+"."+req.Operation, "local")
	if e != nil {
		writeError(w, 500, e.Error())
		return
	}
	_ = s.store.UpdateJob(job.ID, "running", 10, "执行安全变更"+securityIPOperationDetail(req), "")
	v, e := agent.SecurityApply(r.Context(), kind, req)
	if e != nil {
		_ = s.store.UpdateJob(job.ID, "failed", 100, "安全变更失败"+securityIPOperationDetail(req), e.Error())
	} else {
		_ = s.store.UpdateJob(job.ID, "success", 100, "安全变更完成"+securityIPOperationDetail(req), "")
	}
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func (s *Server) hostSecurityTransaction(w http.ResponseWriter, r *http.Request, session store.Session) {
	agent, ok := s.agent.(hostSecurityAgent)
	if !ok {
		writeError(w, 501, "Agent 不支持安全管理")
		return
	}
	var v model.SecurityTransaction
	var e error
	if r.Method == http.MethodGet {
		v, e = agent.SecurityTransaction(r.Context(), r.PathValue("id"))
	} else {
		job, je := s.store.CreateJob("security.confirm", "local")
		if je != nil {
			writeError(w, 500, je.Error())
			return
		}
		v, e = agent.SecurityConfirm(r.Context(), r.PathValue("id"))
		if e != nil {
			_ = s.store.UpdateJob(job.ID, "failed", 100, "安全确认失败", e.Error())
		} else {
			_ = s.store.UpdateJob(job.ID, "success", 100, "安全变更已确认", "")
		}
		_ = s.store.Audit(session.Username, "security.confirm", "local", r.PathValue("id"))
	}
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
func requiredSecurityCapability(resource string) string {
	if resource == "system/firewall" || len(resource) > 16 && resource[:16] == "system/firewall/" {
		return "security.firewall"
	}
	if resource == "system/fail2ban" || len(resource) > 16 && resource[:16] == "system/fail2ban/" {
		return "security.fail2ban"
	}
	if len(resource) >= 28 && resource[:28] == "system/security-transactions" {
		return "security.firewall"
	}
	return ""
}

func securityIPOperationDetail(req model.SecurityRequest) string {
	if req.Operation != "ban" && req.Operation != "unban" {
		return ""
	}
	addr, err := netip.ParseAddr(req.IP)
	if err != nil || addr.Zone() != "" {
		return ""
	}
	operation := "手动封禁"
	if req.Operation == "unban" {
		operation = "解除封禁"
	}
	return "：" + operation + " " + addr.Unmap().String() + "（SSH）"
}
