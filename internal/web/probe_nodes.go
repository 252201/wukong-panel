package web

import (
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net/http"
	"net/url"
	"strconv"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/store"
)

func parseShareURI(raw string) (model.FleetProbeNode, error) {
	raw = strings.TrimSpace(raw)
	if raw == "" {
		return model.FleetProbeNode{}, errors.New("节点链接不能为空")
	}

	// VMess base64 JSON format: vmess://eyJhZGQiOi...
	if strings.HasPrefix(strings.ToLower(raw), "vmess://") {
		encoded := strings.TrimPrefix(raw, "vmess://")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(encoded)
		}
		if err != nil {
			return model.FleetProbeNode{}, errors.New("无法解析 VMess 链接")
		}
		var vmessMap map[string]any
		if err := json.Unmarshal(decoded, &vmessMap); err != nil {
			return model.FleetProbeNode{}, errors.New("VMess 数据格式无效")
		}
		name, _ := vmessMap["ps"].(string)
		server, _ := vmessMap["add"].(string)
		portVal := fmt.Sprintf("%v", vmessMap["port"])
		port, _ := strconv.Atoi(portVal)
		if port < 1 || port > 65535 {
			port = 443
		}
		if name == "" {
			name = fmt.Sprintf("VMess-%s-%d", server, port)
		}
		id, _ := security.RandomToken(12)
		return model.FleetProbeNode{
			ID:       "probe_node_" + id,
			Name:     name,
			Protocol: "vmess",
			Server:   server,
			Port:     port,
			Domain:   server,
			ShareURI: raw,
			Source:   "manual",
			RawName:  name,
		}, nil
	}

	parsed, err := url.Parse(raw)
	if err != nil {
		return model.FleetProbeNode{}, fmt.Errorf("节点链接格式无效: %w", err)
	}

	scheme := strings.ToLower(parsed.Scheme)
	var protocol string
	switch scheme {
	case "hysteria2", "hy2":
		protocol = "hysteria2"
	case "vless":
		if strings.EqualFold(parsed.Query().Get("type"), "ws") {
			protocol = "vless-ws-tunnel"
		} else {
			protocol = "vless"
		}
	case "ss":
		protocol = "shadowsocks"
	case "tuic":
		protocol = "tuic"
	case "trojan":
		protocol = "trojan"
	case "anytls":
		protocol = "anytls"
	default:
		return model.FleetProbeNode{}, fmt.Errorf("不支持的协议: %s", scheme)
	}

	server := parsed.Hostname()
	portStr := parsed.Port()
	port := 0
	if portStr != "" {
		port, _ = strconv.Atoi(portStr)
	}
	if port < 1 || port > 65535 {
		if protocol == "vless-ws-tunnel" {
			port = 443
		} else {
			port = 443
		}
	}

	name := parsed.Fragment
	if unescaped, err := url.QueryUnescape(name); err == nil && unescaped != "" {
		name = unescaped
	}
	if strings.TrimSpace(name) == "" {
		name = fmt.Sprintf("%s-%s-%d", strings.ToUpper(protocol), server, port)
	}

	domain := parsed.Query().Get("sni")
	if domain == "" {
		domain = parsed.Query().Get("host")
	}
	if domain == "" {
		domain = server
	}

	id, _ := security.RandomToken(12)
	return model.FleetProbeNode{
		ID:       "probe_node_" + id,
		Name:     name,
		Protocol: protocol,
		Server:   server,
		Port:     port,
		Domain:   domain,
		ShareURI: raw,
		Source:   "manual",
		RawName:  name,
	}, nil
}

func (s *Server) getFleetProbeNodes(w http.ResponseWriter, r *http.Request, _ store.Session) {
	hostID := r.PathValue("hostId")
	host, err := s.store.FleetHost(hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "主机不存在")
		return
	}
	if !fleetHasCapability(host, "probe") {
		writeError(w, http.StatusBadRequest, "仅轻量探针支持节点托管")
		return
	}
	nodes, err := s.store.FleetProbeNodes(r.Context(), hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	if nodes == nil {
		nodes = []model.FleetProbeNode{}
	}
	writeJSON(w, http.StatusOK, nodes)
}

func (s *Server) createFleetProbeNode(w http.ResponseWriter, r *http.Request, session store.Session) {
	hostID := r.PathValue("hostId")
	host, err := s.store.FleetHost(hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "主机不存在")
		return
	}
	if !fleetHasCapability(host, "probe") {
		writeError(w, http.StatusBadRequest, "仅轻量探针支持节点托管")
		return
	}

	var req struct {
		Name     string `json:"name"`
		ShareURI string `json:"shareUri"`
		Links    string `json:"links"`
	}
	if !decode(w, r, &req) {
		return
	}

	var inputLinks []string
	if strings.TrimSpace(req.Links) != "" {
		for _, line := range strings.Split(req.Links, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				inputLinks = append(inputLinks, line)
			}
		}
	} else if strings.TrimSpace(req.ShareURI) != "" {
		for _, line := range strings.Split(req.ShareURI, "\n") {
			line = strings.TrimSpace(line)
			if line != "" {
				inputLinks = append(inputLinks, line)
			}
		}
	}

	if len(inputLinks) == 0 {
		writeError(w, http.StatusBadRequest, "请输入至少一个有效的节点链接")
		return
	}

	var createdNodes []model.FleetProbeNode
	for _, link := range inputLinks {
		node, err := parseShareURI(link)
		if err != nil {
			writeError(w, http.StatusBadRequest, fmt.Sprintf("链接解析失败 (%s): %v", link, err))
			return
		}
		node.HostID = hostID
		if len(inputLinks) == 1 && strings.TrimSpace(req.Name) != "" {
			node.Name = strings.TrimSpace(req.Name)
		}
		if err := s.store.SaveFleetProbeNode(r.Context(), node); err != nil {
			writeError(w, http.StatusInternalServerError, "保存节点失败: "+err.Error())
			return
		}
		createdNodes = append(createdNodes, node)
	}

	_ = s.store.Audit(session.Username, "fleet.probe.node.create", hostID, fmt.Sprintf("created %d nodes for host %s", len(createdNodes), host.Name))
	_ = s.store.ClearFleetSubscriptionCaches()
	writeJSON(w, http.StatusCreated, createdNodes)
}

func (s *Server) updateFleetProbeNode(w http.ResponseWriter, r *http.Request, session store.Session) {
	hostID := r.PathValue("hostId")
	nodeID := r.PathValue("nodeId")
	host, err := s.store.FleetHost(hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "主机不存在")
		return
	}
	if !fleetHasCapability(host, "probe") {
		writeError(w, http.StatusBadRequest, "仅轻量探针支持节点托管")
		return
	}

	var req struct {
		Name     string `json:"name"`
		Server   string `json:"server,omitempty"`
		Port     int    `json:"port,omitempty"`
		ShareURI string `json:"shareUri,omitempty"`
	}
	if !decode(w, r, &req) {
		return
	}

	req.Name = strings.TrimSpace(req.Name)
	if req.Name == "" {
		writeError(w, http.StatusBadRequest, "节点名称不能为空")
		return
	}

	nodes, err := s.store.FleetProbeNodes(r.Context(), hostID)
	if err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}
	var target *model.FleetProbeNode
	for i := range nodes {
		if nodes[i].ID == nodeID {
			target = &nodes[i]
			break
		}
	}
	if target == nil {
		writeError(w, http.StatusNotFound, "节点不存在")
		return
	}

	target.Name = req.Name
	if req.Server != "" {
		target.Server = strings.TrimSpace(req.Server)
	}
	if req.Port > 0 && req.Port <= 65535 {
		target.Port = req.Port
	}
	if strings.TrimSpace(req.ShareURI) != "" {
		target.ShareURI = strings.TrimSpace(req.ShareURI)
	}

	if err := s.store.SaveFleetProbeNode(r.Context(), *target); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.Audit(session.Username, "fleet.probe.node.update", hostID, fmt.Sprintf("updated node %s (%s) for host %s", nodeID, target.Name, host.Name))
	_ = s.store.ClearFleetSubscriptionCaches()
	writeJSON(w, http.StatusOK, target)
}

func (s *Server) deleteFleetProbeNode(w http.ResponseWriter, r *http.Request, session store.Session) {
	hostID := r.PathValue("hostId")
	nodeID := r.PathValue("nodeId")
	host, err := s.store.FleetHost(hostID)
	if err != nil {
		writeError(w, http.StatusNotFound, "主机不存在")
		return
	}
	if !fleetHasCapability(host, "probe") {
		writeError(w, http.StatusBadRequest, "仅轻量探针支持节点托管")
		return
	}

	if err := s.store.DeleteFleetProbeNode(r.Context(), hostID, nodeID); err != nil {
		writeError(w, http.StatusInternalServerError, err.Error())
		return
	}

	_ = s.store.Audit(session.Username, "fleet.probe.node.delete", hostID, fmt.Sprintf("deleted node %s for host %s", nodeID, host.Name))
	_ = s.store.ClearFleetSubscriptionCaches()
	writeJSON(w, http.StatusOK, map[string]bool{"ok": true})
}
