package web

import (
	"net/http"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/store"
)

func (s *Server) listChainedProxies(w http.ResponseWriter, r *http.Request, session store.Session) {
	list, err := s.store.ChainedProxies()
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	writeJSON(w, http.StatusOK, list)
}

func (s *Server) saveChainedProxy(w http.ResponseWriter, r *http.Request, session store.Session) {
	var input model.ChainedProxy
	if !decode(w, r, &input) {
		return
	}

	input.EntryNodeName = strings.TrimSpace(input.EntryNodeName)
	input.ExitNodeName = strings.TrimSpace(input.ExitNodeName)
	input.Name = strings.TrimSpace(input.Name)

	if input.EntryNodeName == "" || input.ExitNodeName == "" {
		writeError(w, http.StatusBadRequest, "前置入口节点与落地出口节点均不能为空")
		return
	}
	if input.EntryNodeName == input.ExitNodeName {
		writeError(w, http.StatusBadRequest, "前置入口节点与落地出口节点不能相同")
		return
	}
	if input.ID == "" {
		token, _ := security.RandomToken(8)
		input.ID = "chain-" + token
		input.Enabled = true
	}
	if input.Name == "" {
		input.Name = "🔗 " + input.EntryNodeName + " ➔ " + input.ExitNodeName
	}

	if err := s.store.SaveChainedProxy(input); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.ClearFleetSubscriptionCaches()
	writeJSON(w, http.StatusOK, input)
}

func (s *Server) deleteChainedProxy(w http.ResponseWriter, r *http.Request, session store.Session) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	if err := s.store.DeleteChainedProxy(id); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.ClearFleetSubscriptionCaches()
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}

func (s *Server) toggleChainedProxy(w http.ResponseWriter, r *http.Request, session store.Session) {
	id := r.PathValue("id")
	if id == "" {
		writeError(w, http.StatusBadRequest, "id 不能为空")
		return
	}
	var body struct {
		Enabled bool `json:"enabled"`
	}
	if !decode(w, r, &body) {
		return
	}
	if err := s.store.ToggleChainedProxy(id, body.Enabled); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	_ = s.store.ClearFleetSubscriptionCaches()
	writeJSON(w, http.StatusOK, map[string]any{"success": true})
}
