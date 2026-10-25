package web

import (
	"context"
	"net/http"
	"time"

	"github.com/252201/wukong-panel/internal/store"
)

type panelUpdateAgent interface {
	PanelUpdate(context.Context, string) error
}

func (s *Server) panelUpdate(w http.ResponseWriter, r *http.Request, session store.Session) {
	a, ok := s.agent.(panelUpdateAgent)
	if !ok {
		writeError(w, http.StatusNotImplemented, "Agent 不支持面板在线更新")
		return
	}
	var req struct {
		TargetVersion string `json:"targetVersion"`
	}
	if r.ContentLength > 0 && !decode(w, r, &req) {
		return
	}
	_ = s.store.Audit(session.Username, "panel.update", "local", req.TargetVersion)
	job, err := s.store.CreateJob("panel.update", "local")
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	go func() {
		ctx, cancel := context.WithTimeout(context.Background(), 10*time.Minute)
		defer cancel()
		_ = s.store.UpdateJob(job.ID, "running", 20, "正在获取发布清单与下载新版面板程序...", "")
		if err := a.PanelUpdate(ctx, req.TargetVersion); err != nil {
			_ = s.store.UpdateJob(job.ID, "failed", 100, "面板更新失败", err.Error())
			return
		}
		_ = s.store.UpdateJob(job.ID, "success", 100, "更新已完成，面板服务正在平滑重启...", "")
	}()
	writeJSON(w, http.StatusAccepted, map[string]string{"jobId": job.ID})
}
