package web

import (
	"github.com/252201/wukong-panel/internal/store"
	"net/http"
)

func (s *Server) securityIPLocation(w http.ResponseWriter, r *http.Request, _ store.Session) {
	location, err := s.ipLocations.Lookup(r.URL.Query().Get("ip"))
	if err != nil {
		writeError(w, http.StatusBadRequest, "IP 地址无效")
		return
	}
	writeJSON(w, http.StatusOK, location)
}
