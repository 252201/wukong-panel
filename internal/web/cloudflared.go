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
	req := model.CloudflaredRequest{Operation: "status"}
	if r.Method != http.MethodGet {
		if !decode(w, r, &req) {
			return
		}
		req.Operation = r.PathValue("action")
		if req.Operation != "check" && req.Operation != "settings" && req.Operation != "update" {
			writeError(w, 404, "unknown cloudflared operation")
			return
		}
		_ = s.store.Audit(session.Username, "cloudflared."+req.Operation, "local", "requested through web")
	}
	if req.Operation == "update" {
		job, e := s.store.CreateJob("cloudflared.update", "local")
		if e != nil {
			writeError(w, 500, e.Error())
			return
		}
		go func() {
			ctx, cancel := context.WithTimeout(context.Background(), 5*time.Minute)
			defer cancel()
			_ = s.store.UpdateJob(job.ID, "running", 10, "正在校验、备份并更新 cloudflared", "")
			_, e := a.Cloudflared(ctx, req)
			if e != nil {
				_ = s.store.UpdateJob(job.ID, "failed", 100, "cloudflared 更新失败", e.Error())
			} else {
				_ = s.store.UpdateJob(job.ID, "success", 100, "cloudflared 更新完成", "")
			}
		}()
		writeJSON(w, 202, map[string]string{"jobId": job.ID})
		return
	}
	v, e := a.Cloudflared(r.Context(), req)
	if e != nil {
		writeError(w, 400, e.Error())
		return
	}
	writeJSON(w, 200, v)
}
