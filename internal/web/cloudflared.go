package web

import (
	"context"
	"net/http"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/store"
)

type cloudflaredAgent interface {
	Cloudflared(context.Context, model.CloudflaredRequest) (model.CloudflaredState, error)
}

func (s *Server) cloudflared(w http.ResponseWriter, r *http.Request, session store.Session) {
	a, ok := s.agent.(cloudflaredAgent)
	if !ok {
		writeError(w, 501, "Agent does not support cloudflared updates")
		return
	}
	s.componentUpdate(w, r, session, "cloudflared", a.Cloudflared)
}

type singBoxUpdateAgent interface {
	SingBoxUpdate(context.Context, model.ComponentUpdateRequest) (model.ComponentUpdateState, error)
}

func (s *Server) singBoxUpdate(w http.ResponseWriter, r *http.Request, session store.Session) {
	a, ok := s.agent.(singBoxUpdateAgent)
	if !ok {
		writeError(w, 501, "Agent does not support sing-box updates")
		return
	}
	s.componentUpdate(w, r, session, "sing-box", a.SingBoxUpdate)
}
func (s *Server) componentUpdate(w http.ResponseWriter, r *http.Request, session store.Session, name string, run func(context.Context, model.ComponentUpdateRequest) (model.ComponentUpdateState, error)) {
	req := model.ComponentUpdateRequest{Operation: "status"}
	if r.Method != http.MethodGet {
		if !decode(w, r, &req) {
			return
		}
		req.Operation = r.PathValue("action")
		if name == "sing-box" && req.Operation == "settings" {
			writeError(w, 404, "sing-box automatic updates are not enabled")
			return
		}
		if req.Operation != "check" && req.Operation != "settings" && req.Operation != "update" {
			writeError(w, 404, "unknown component update operation")
			return
		}
		_ = s.store.Audit(session.Username, name+"."+req.Operation, "local", "requested through web")
	}
	if req.Operation == "update" {
		job, e := s.store.CreateJob(name+".update", "local")
		if e != nil {
			writeError(w, 500, e.Error())
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			_ = s.store.UpdateJob(job.ID, "running", 10, "正在校验、备份并更新 "+name, "")
			_, e := run(ctx, req)
			if e != nil {
				_ = s.store.UpdateJob(job.ID, "failed", 100, name+" 更新失败", e.Error())
			} else {
				_ = s.store.UpdateJob(job.ID, "success", 100, name+" 更新完成", "")
			}
		}()
		writeJSON(w, 202, map[string]string{"jobId": job.ID})
		return
	}
	v, e := run(r.Context(), req)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
