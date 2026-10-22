package web

import (
	"context"
	"fmt"
	"io"
	"net/http"
	"net/netip"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/store"
)

func (s *Server) ipReputation(w http.ResponseWriter, r *http.Request, _ store.Session) {
	rawIP := strings.TrimSpace(r.URL.Query().Get("ip"))
	if rawIP == "" {
		writeError(w, http.StatusBadRequest, "缺少 ip 参数")
		return
	}
	addr, err := netip.ParseAddr(rawIP)
	if err != nil {
		writeError(w, http.StatusBadRequest, "无效的 IP 地址")
		return
	}
	ctx, cancel := context.WithTimeout(r.Context(), 8*time.Second)
	defer cancel()

	targetURL := fmt.Sprintf("https://ip.net.coffee/api/ip/lookup/%s", addr.String())
	req, err := http.NewRequestWithContext(ctx, http.MethodGet, targetURL, nil)
	if err != nil {
		writeError(w, http.StatusInternalServerError, "创建请求失败")
		return
	}
	req.Header.Set("User-Agent", "Wukong-Panel/1.7")

	client := s.fleetProbeClient
	if client == nil {
		client = http.DefaultClient
	}
	resp, err := client.Do(req)
	if err != nil {
		writeError(w, http.StatusBadGateway, "请求 Net.Coffee 接口失败: "+err.Error())
		return
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		writeError(w, resp.StatusCode, fmt.Sprintf("Net.Coffee 返回 HTTP %d", resp.StatusCode))
		return
	}

	body, err := io.ReadAll(io.LimitReader(resp.Body, 64*1024))
	if err != nil {
		writeError(w, http.StatusInternalServerError, "读取响应失败")
		return
	}

	w.Header().Set("Content-Type", "application/json; charset=utf-8")
	w.WriteHeader(http.StatusOK)
	_, _ = w.Write(body)
}
