package monitor

import (
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
)

type tunnelProcessService struct {
	manager string
	nodes   []string
}

// Associate only known managed connectors; never inspect Tunnel tokens or infer
// a node from its hostname, port, or a cloudflared command-line argument.
func cloudflaredNodeServices(nodes []model.Node) map[string]tunnelProcessService {
	services := map[string]tunnelProcessService{}
	for _, node := range nodes {
		if node.Protocol != "vless-ws-tunnel" || node.Ownership != "managed" {
			continue
		}
		key := node.ID
		if strings.TrimSpace(node.SharedGroup) != "" {
			key = node.SharedGroup
		}
		if key == "" || strings.Trim(key, "abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789-_") != "" {
			continue
		}
		name := "cloudflared-wukong-" + key
		service, exists := services[name]
		if exists && service.manager != node.ServiceManager {
			service.manager = "" // Inconsistent ownership: retain only the generic label.
		} else if !exists {
			service.manager = node.ServiceManager
		}
		service.nodes = append(service.nodes, node.Name)
		services[name] = service
	}
	for name, service := range services {
		sort.Strings(service.nodes)
		services[name] = service
	}
	return services
}

func cloudflaredProcessNodes(pid int, cgroup []byte, services map[string]tunnelProcessService, runDir string) []string {
	for _, line := range strings.Split(string(cgroup), "\n") {
		parts := strings.SplitN(line, ":", 3)
		if len(parts) != 3 || (parts[1] != "" && parts[1] != "name=systemd") {
			continue
		}
		unit := filepath.Base(parts[2])
		if !strings.HasSuffix(unit, ".service") {
			continue
		}
		if service, ok := services[strings.TrimSuffix(unit, ".service")]; ok && service.manager == "systemd" {
			return append([]string(nil), service.nodes...)
		}
	}
	// OpenRC writes this PID file for the connector itself, not its supervisor.
	var matched []string
	for name, service := range services {
		if service.manager != "openrc" {
			continue
		}
		data, err := os.ReadFile(filepath.Join(runDir, name+".pid"))
		if err != nil {
			continue
		}
		servicePID, err := strconv.Atoi(strings.TrimSpace(string(data)))
		if err != nil || servicePID != pid || pid <= 0 {
			continue
		}
		if matched != nil {
			return nil // Conflicting PID files cannot establish connector ownership.
		}
		matched = append([]string(nil), service.nodes...)
	}
	return matched
}
