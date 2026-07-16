package agent

import (
	"bytes"
	"context"
	"crypto/ecdsa"
	"crypto/elliptic"
	"crypto/rand"
	"crypto/sha256"
	"crypto/tls"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/hex"
	"encoding/json"
	"encoding/pem"
	"errors"
	"fmt"
	"math/big"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
	"unicode/utf8"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/singboxconfig"
	"github.com/252201/wukong-panel/internal/store"
)

type Manager struct {
	cfg   config.Config
	store *store.Store
	vault *security.Vault
}

func (m *Manager) RunReconciler(ctx context.Context) {
	_ = m.ReconcileDeviceGroups(ctx)
	_ = m.ReconcileRuntimeVersion(ctx)
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = m.ReconcileDeviceGroups(ctx)
			_ = m.ReconcileRuntimeVersion(ctx)
			_ = m.ReconcileBindings(ctx)
		}
	}
}

func (m *Manager) ReconcileDeviceGroups(ctx context.Context) error {
	if m.cfg.Demo {
		return nil
	}
	nodes, err := m.store.Nodes(ctx)
	if err != nil {
		return err
	}
	groups := map[string][]model.Node{}
	for _, node := range nodes {
		if node.Ownership == "managed" && strings.TrimSpace(node.SharedGroup) != "" {
			groups[node.SharedGroup] = append(groups[node.SharedGroup], node)
		}
	}
	errorsByGroup := []string{}
	for group, groupNodes := range groups {
		if len(groupNodes) < 2 || deviceGroupAlreadyShared(groupNodes) {
			continue
		}
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(group) {
			errorsByGroup = append(errorsByGroup, fmt.Sprintf("%s: invalid group identifier", group))
			continue
		}
		if err := m.consolidateDeviceGroup(ctx, group, groupNodes); err != nil {
			errorsByGroup = append(errorsByGroup, fmt.Sprintf("%s: %v", group, err))
			_ = m.store.Audit("agent", "device_group_consolidation_failed", group, err.Error())
		}
	}
	if len(errorsByGroup) > 0 {
		return errors.New(strings.Join(errorsByGroup, "; "))
	}
	return nil
}

func deviceGroupAlreadyShared(nodes []model.Node) bool {
	if len(nodes) < 2 {
		return false
	}
	first := nodes[0]
	for _, node := range nodes[1:] {
		if node.ServiceName != first.ServiceName || node.ServiceManager != first.ServiceManager || node.ConfigPath != first.ConfigPath {
			return false
		}
	}
	return true
}

func (m *Manager) consolidateDeviceGroup(ctx context.Context, group string, nodes []model.Node) error {
	first := nodes[0]
	payload, err := mergeDeviceGroupConfigs(nodes)
	if err != nil {
		return err
	}
	manager := first.ServiceManager
	service := "sing-box-wukong-" + group
	configPath := filepath.Join(m.cfg.ConfigDir, "wukong-"+group+".json")
	checkPath := configPath + ".consolidate.tmp"
	if err = os.WriteFile(checkPath, payload, 0o600); err != nil {
		return err
	}
	if err = command(ctx, m.cfg.SingBoxBin, "check", "-c", checkPath); err != nil {
		_ = os.Remove(checkPath)
		return fmt.Errorf("merged configuration check failed: %w", err)
	}
	_ = os.Remove(checkPath)
	for _, node := range nodes {
		if err = m.backup(node); err != nil {
			return fmt.Errorf("backup legacy device %s: %w", node.Name, err)
		}
	}
	oldServices := map[string]model.Node{}
	wasActive := false
	for _, node := range nodes {
		key := node.ServiceManager + "\x00" + node.ServiceName
		oldServices[key] = node
		if m.serviceStatus(ctx, node.ServiceManager, node.ServiceName) == "active" {
			wasActive = true
		}
	}
	stopped := []model.Node{}
	for _, node := range oldServices {
		if m.serviceStatus(ctx, node.ServiceManager, node.ServiceName) != "active" {
			continue
		}
		if err = m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName); err != nil {
			for _, previous := range stopped {
				_ = m.serviceCommand(ctx, previous.ServiceManager, "start", previous.ServiceName)
			}
			return fmt.Errorf("stop legacy service %s: %w", node.ServiceName, err)
		}
		stopped = append(stopped, node)
	}
	target := model.Node{ID: group, Protocol: first.Protocol, ServiceName: service, ServiceManager: manager, ConfigPath: configPath, Ownership: "managed", SharedGroup: group}
	if err = m.installConfig(ctx, configPath, service, manager, payload); err != nil {
		_ = m.cleanupFailedCreate(ctx, target, false)
		for _, node := range stopped {
			_ = m.serviceCommand(ctx, node.ServiceManager, "start", node.ServiceName)
		}
		return fmt.Errorf("start consolidated service: %w", err)
	}
	status := "active"
	if !wasActive {
		status = "inactive"
		if err = m.serviceCommand(ctx, manager, "stop", service); err != nil {
			_ = m.cleanupFailedCreate(ctx, target, false)
			return fmt.Errorf("preserve inactive group state: %w", err)
		}
	}
	version := m.Version(ctx)
	if err = m.store.UpdateNodeGroupRuntime(ctx, group, service, manager, configPath, version, status); err != nil {
		_ = m.cleanupFailedCreate(ctx, target, false)
		for _, node := range stopped {
			_ = m.serviceCommand(ctx, node.ServiceManager, "start", node.ServiceName)
		}
		return fmt.Errorf("persist consolidated runtime: %w", err)
	}
	for _, node := range oldServices {
		if node.ServiceName == service && node.ServiceManager == manager {
			continue
		}
		_ = m.disableService(ctx, node)
		_ = m.removeService(node)
		if node.ConfigPath != configPath {
			_ = os.Remove(node.ConfigPath)
		}
	}
	_ = m.store.Audit("agent", "device_group_consolidated", group, fmt.Sprintf("nodes=%d service=%s", len(nodes), service))
	return nil
}

func mergeDeviceGroupConfigs(nodes []model.Node) ([]byte, error) {
	if len(nodes) < 2 {
		return nil, errors.New("at least two device nodes are required for consolidation")
	}
	var root map[string]any
	inbounds := make([]any, 0, len(nodes))
	for index, node := range nodes {
		data, err := os.ReadFile(node.ConfigPath)
		if err != nil {
			return nil, fmt.Errorf("read %s: %w", node.ConfigPath, err)
		}
		var current map[string]any
		if err = json.Unmarshal(data, &current); err != nil {
			return nil, fmt.Errorf("parse %s: %w", node.ConfigPath, err)
		}
		if index == 0 {
			root = current
		}
		currentInbounds, _ := current["inbounds"].([]any)
		found := false
		for _, item := range currentInbounds {
			inbound, _ := item.(map[string]any)
			if int(numberValue(inbound["listen_port"])) == node.ListenPort {
				inbounds = append(inbounds, item)
				found = true
				break
			}
		}
		if !found {
			return nil, fmt.Errorf("inbound port %d for %s was not found", node.ListenPort, node.Name)
		}
	}
	root["inbounds"] = inbounds
	return json.MarshalIndent(root, "", "  ")
}

func (m *Manager) ReconcileRuntimeVersion(ctx context.Context) error {
	if m.cfg.Demo {
		return nil
	}
	version := m.Version(ctx)
	if version == "" || version == "not-installed" {
		return errors.New("sing-box version is unavailable")
	}
	return m.store.UpdateNodeConfigVersions(version)
}

func (m *Manager) DeploymentDefaults(context.Context) (model.NodeDeploymentDefaults, error) {
	v4, v6 := bindAddressOptions()
	return model.NodeDeploymentDefaults{PanelDomain: strings.TrimSpace(m.cfg.PanelDomain), IPv4: v4, IPv6: v6}, nil
}

func (m *Manager) ReconcileBindings(ctx context.Context) error {
	if m.cfg.Demo {
		return nil
	}
	v4s, v6s := globalAddresses()
	nodes, err := m.store.Nodes(ctx)
	if err != nil {
		return err
	}
	updatedConfigs := map[string]bool{}
	for _, node := range nodes {
		if !node.AutoBind || node.Ownership == "unmanaged" {
			continue
		}
		newV4, newV6 := node.IPv4Bind, node.IPv6Bind
		if node.IPv4Bind != "" && !contains(v4s, node.IPv4Bind) && len(v4s) == 1 {
			newV4 = v4s[0]
		}
		if node.IPv6Bind != "" && !contains(v6s, node.IPv6Bind) && len(v6s) == 1 {
			newV6 = v6s[0]
		}
		if newV4 == node.IPv4Bind && newV6 == node.IPv6Bind {
			continue
		}
		if !updatedConfigs[node.ConfigPath] {
			if err := m.rewriteBindings(ctx, node, newV4, newV6); err != nil {
				_ = m.store.Audit("agent", "reconcile_failed", node.ID, err.Error())
				continue
			}
			updatedConfigs[node.ConfigPath] = true
		}
		_ = m.store.UpdateNodeBinds(node.ID, newV4, newV6)
		_ = m.store.Audit("agent", "reconcile_bindings", node.ID, fmt.Sprintf("ipv4=%s ipv6=%s", newV4, newV6))
	}
	return nil
}

func (m *Manager) rewriteBindings(ctx context.Context, node model.Node, newV4, newV6 string) error {
	if err := m.validateManagedNode(node); err != nil {
		return err
	}
	if err := m.backup(node); err != nil {
		return err
	}
	data, err := os.ReadFile(node.ConfigPath)
	if err != nil {
		return err
	}
	text := string(data)
	if node.IPv4Bind != "" && newV4 != "" {
		text = strings.ReplaceAll(text, `"`+node.IPv4Bind+`"`, `"`+newV4+`"`)
	}
	if node.IPv6Bind != "" && newV6 != "" {
		text = strings.ReplaceAll(text, `"`+node.IPv6Bind+`"`, `"`+newV6+`"`)
	}
	tmp := node.ConfigPath + ".reconcile.tmp"
	if err = os.WriteFile(tmp, []byte(text), 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err = command(ctx, m.cfg.SingBoxBin, "check", "-c", tmp); err != nil {
		return err
	}
	if err = os.Rename(tmp, node.ConfigPath); err != nil {
		return err
	}
	return m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName)
}

func NewManager(cfg config.Config, s *store.Store, vault *security.Vault) *Manager {
	return &Manager{cfg: cfg, store: s, vault: vault}
}

func (m *Manager) Version(ctx context.Context) string {
	if m.cfg.Demo {
		return "1.14.0-demo"
	}
	out, err := exec.CommandContext(ctx, m.cfg.SingBoxBin, "version").Output()
	if err != nil {
		return "not-installed"
	}
	re := regexp.MustCompile(`(?m)sing-box version ([^\s]+)`)
	match := re.FindStringSubmatch(string(out))
	if len(match) > 1 {
		return match[1]
	}
	return strings.TrimSpace(string(out))
}

func (m *Manager) MigrationPlan(_ context.Context, target string) (singboxconfig.Plan, error) {
	if m.cfg.Demo {
		return singboxconfig.Plan{Target: target, Compatible: true, Files: []singboxconfig.FilePlan{}}, nil
	}
	return singboxconfig.PlanDirectory(m.cfg.ConfigDir, target)
}

func (m *Manager) Scan(ctx context.Context) ([]model.NodeCandidate, error) {
	files, err := filepath.Glob(filepath.Join(m.cfg.ConfigDir, "*.json"))
	if err != nil {
		return nil, err
	}
	version := m.Version(ctx)
	knownNodes, err := m.store.Nodes(ctx)
	if err != nil {
		return nil, fmt.Errorf("list registered nodes: %w", err)
	}
	registered := make(map[string]struct{}, len(knownNodes))
	for _, node := range knownNodes {
		registered[candidateKey(node.ConfigPath, node.ListenPort)] = struct{}{}
	}
	result := []model.NodeCandidate{}
	for _, path := range files {
		data, err := os.ReadFile(path)
		if err != nil {
			continue
		}
		var root map[string]any
		if json.Unmarshal(data, &root) != nil {
			continue
		}
		inbounds, _ := root["inbounds"].([]any)
		mode, v4, v6 := detectMode(root)
		service, manager := m.findService(path)
		for index, item := range inbounds {
			inbound, _ := item.(map[string]any)
			protocol := normalizeProtocol(stringValue(inbound["type"]))
			if !supportedProtocols[protocol] {
				continue
			}
			// A managed VLESS + WebSocket node also needs its Cloudflare Tunnel
			// token and companion service metadata. Neither exists in sing-box's
			// inbound, so importing an arbitrary WS inbound would create a node
			// that cannot be operated safely.
			if protocol == protocolVLESS {
				transport, _ := inbound["transport"].(map[string]any)
				if strings.EqualFold(stringValue(transport["type"]), "ws") {
					continue
				}
			}
			port := int(numberValue(inbound["listen_port"]))
			if port < 1 {
				continue
			}
			if _, exists := registered[candidateKey(path, port)]; exists {
				continue
			}
			name := candidateInboundName(path, inbound)
			credentials, credentialErr := credentialsFromInbound(protocol, inbound)
			if credentialErr != nil {
				continue
			}
			secret, credentialErr := encodeProtocolCredentials(credentials)
			if credentialErr != nil {
				continue
			}
			domain := inboundDomain(protocol, inbound)
			fingerprint := fingerprint(path, port, name)
			shared := ""
			if len(inbounds) > 1 {
				shared = path
			}
			candidateName := preferredCandidateName(name, path, index, port, protocol)
			result = append(result, model.NodeCandidate{Fingerprint: fingerprint, Name: candidateName, Protocol: protocol, Mode: mode, ListenPort: port, Domain: domain, IPv4Bind: v4, IPv6Bind: v6, ServiceName: service, ServiceManager: manager, ConfigPath: path, ConfigVersion: version, SharedGroup: shared, Secret: secret})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ListenPort < result[j].ListenPort })
	return result, nil
}

func (m *Manager) DeleteCandidate(ctx context.Context, id, confirmName string) error {
	candidates, err := m.Scan(ctx)
	if err != nil {
		return err
	}
	var candidate model.NodeCandidate
	found := false
	for _, item := range candidates {
		if item.Fingerprint == id {
			candidate = item
			found = true
			break
		}
	}
	if !found {
		return errors.New("candidate node was not found or is already registered")
	}
	if confirmName != candidate.Name {
		return errors.New("confirmation name does not match")
	}
	if err = m.validateCandidate(candidate); err != nil {
		return err
	}
	node := model.Node{
		ID: candidate.Fingerprint, Name: candidate.Name, Protocol: candidate.Protocol,
		ListenPort: candidate.ListenPort, ServiceName: candidate.ServiceName,
		ServiceManager: candidate.ServiceManager, ConfigPath: candidate.ConfigPath,
		Ownership: "unmanaged", SharedGroup: candidate.SharedGroup,
	}
	if err = m.backup(node); err != nil {
		return fmt.Errorf("backup candidate configuration: %w", err)
	}
	original, err := os.ReadFile(candidate.ConfigPath)
	if err != nil {
		return err
	}
	info, err := os.Stat(candidate.ConfigPath)
	if err != nil {
		return err
	}
	var root map[string]any
	if err = json.Unmarshal(original, &root); err != nil {
		return fmt.Errorf("parse candidate configuration: %w", err)
	}
	inbounds, _ := root["inbounds"].([]any)
	remaining := make([]any, 0, len(inbounds))
	removed := false
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		port := int(numberValue(inbound["listen_port"]))
		name := candidateInboundName(candidate.ConfigPath, inbound)
		if !removed && fingerprint(candidate.ConfigPath, port, name) == candidate.Fingerprint {
			removed = true
			continue
		}
		remaining = append(remaining, item)
	}
	if !removed {
		return errors.New("candidate inbound changed before deletion; scan again")
	}
	if len(remaining) > 0 {
		root["inbounds"] = remaining
		payload, marshalErr := json.MarshalIndent(root, "", "  ")
		if marshalErr != nil {
			return marshalErr
		}
		if err = m.replaceCandidateConfig(ctx, node, original, payload, info.Mode().Perm()); err != nil {
			return err
		}
	} else if err = m.deleteCandidateRuntime(ctx, node, original, info.Mode().Perm()); err != nil {
		return err
	}
	_ = m.store.Audit("admin", "candidate_delete", candidate.Fingerprint, fmt.Sprintf("%s port=%d config=%s", candidate.Name, candidate.ListenPort, candidate.ConfigPath))
	return nil
}

func candidateInboundName(path string, inbound map[string]any) string {
	name := stringValue(inbound["tag"])
	if name == "" {
		name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
	}
	return name
}

func (m *Manager) validateCandidate(candidate model.NodeCandidate) error {
	root := filepath.Clean(m.cfg.ConfigDir)
	clean := filepath.Clean(candidate.ConfigPath)
	relative, err := filepath.Rel(root, clean)
	if err != nil || relative == "." || relative == ".." || strings.HasPrefix(relative, ".."+string(os.PathSeparator)) {
		return errors.New("candidate config path is outside the managed configuration directory")
	}
	if candidate.ServiceName == "unknown" && candidate.ServiceManager == "unknown" {
		return nil
	}
	if candidate.ServiceManager != "systemd" && candidate.ServiceManager != "openrc" {
		return errors.New("candidate service manager is unsupported")
	}
	matched, _ := regexp.MatchString(`^[A-Za-z0-9_.@-]+$`, candidate.ServiceName)
	if !matched || candidate.ServiceName == "" || candidate.ServiceName == "unknown" {
		return errors.New("candidate service name is invalid")
	}
	return nil
}

func (m *Manager) replaceCandidateConfig(ctx context.Context, node model.Node, original, updated []byte, mode os.FileMode) error {
	tmp := node.ConfigPath + ".candidate-delete.tmp"
	if err := os.WriteFile(tmp, updated, mode); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if !m.cfg.Demo {
		if err := command(ctx, m.cfg.SingBoxBin, "check", "-c", tmp); err != nil {
			return fmt.Errorf("candidate configuration check failed: %w", err)
		}
	}
	wasActive := m.candidateServiceKnown(node) && m.serviceStatus(ctx, node.ServiceManager, node.ServiceName) == "active"
	if err := os.Rename(tmp, node.ConfigPath); err != nil {
		return err
	}
	if !wasActive {
		return nil
	}
	if err := m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName); err != nil {
		rollbackErr := m.restoreCandidateConfig(ctx, node, original, mode, true)
		if rollbackErr != nil {
			return fmt.Errorf("candidate service restart failed: %w (configuration rollback failed: %v)", err, rollbackErr)
		}
		return fmt.Errorf("candidate service restart failed and the previous configuration was restored: %w", err)
	}
	return nil
}

func (m *Manager) restoreCandidateConfig(ctx context.Context, node model.Node, payload []byte, mode os.FileMode, restart bool) error {
	tmp := node.ConfigPath + ".candidate-delete.rollback"
	if err := os.WriteFile(tmp, payload, mode); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := os.Rename(tmp, node.ConfigPath); err != nil {
		return err
	}
	if restart {
		return m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName)
	}
	return nil
}

func (m *Manager) deleteCandidateRuntime(ctx context.Context, node model.Node, original []byte, mode os.FileMode) error {
	if !m.candidateServiceKnown(node) {
		return os.Remove(node.ConfigPath)
	}
	wasActive := m.serviceStatus(ctx, node.ServiceManager, node.ServiceName) == "active"
	wasEnabled := m.serviceEnabled(ctx, node.ServiceManager, node.ServiceName)
	if wasActive {
		if err := m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName); err != nil {
			return err
		}
	}
	if wasEnabled {
		if err := m.disableService(ctx, node); err != nil {
			if wasActive {
				_ = m.serviceCommand(ctx, node.ServiceManager, "start", node.ServiceName)
			}
			return err
		}
	}
	restoreState := func() error {
		if wasEnabled {
			if err := m.enableService(ctx, node); err != nil {
				return err
			}
		}
		if wasActive {
			return m.serviceCommand(ctx, node.ServiceManager, "start", node.ServiceName)
		}
		return nil
	}
	if err := os.Remove(node.ConfigPath); err != nil {
		if stateErr := restoreState(); stateErr != nil {
			return fmt.Errorf("remove candidate config: %w (service state rollback failed: %v)", err, stateErr)
		}
		return err
	}
	if err := m.removeService(node); err != nil {
		restoreErr := os.WriteFile(node.ConfigPath, original, mode)
		stateErr := restoreState()
		if restoreErr != nil || stateErr != nil {
			return fmt.Errorf("remove candidate service: %w (config rollback: %v; service rollback: %v)", err, restoreErr, stateErr)
		}
		return fmt.Errorf("remove candidate service failed and the previous runtime was restored: %w", err)
	}
	return nil
}

func (m *Manager) candidateServiceKnown(node model.Node) bool {
	return !m.cfg.Demo && node.ServiceName != "" && node.ServiceName != "unknown" && (node.ServiceManager == "systemd" || node.ServiceManager == "openrc")
}

func (m *Manager) serviceEnabled(ctx context.Context, manager, name string) bool {
	if manager == "openrc" {
		output, err := exec.CommandContext(ctx, "rc-update", "show", "default").CombinedOutput()
		if err != nil {
			return false
		}
		for _, line := range strings.Split(string(output), "\n") {
			fields := strings.Fields(line)
			if len(fields) > 0 && fields[0] == name {
				return true
			}
		}
		return false
	}
	return command(ctx, "systemctl", "is-enabled", "--quiet", name+".service") == nil
}

func (m *Manager) enableService(ctx context.Context, node model.Node) error {
	if node.ServiceManager == "openrc" {
		return command(ctx, "rc-update", "add", node.ServiceName, "default")
	}
	return command(ctx, "systemctl", "enable", node.ServiceName+".service")
}

func (m *Manager) Import(ctx context.Context, fingerprints []string) (int, error) {
	candidates, err := m.Scan(ctx)
	if err != nil {
		return 0, err
	}
	wanted := map[string]bool{}
	for _, id := range fingerprints {
		wanted[id] = true
	}
	count := 0
	for _, candidate := range candidates {
		if !wanted[candidate.Fingerprint] {
			continue
		}
		cipher, err := m.vault.Encrypt(candidate.Secret)
		if err != nil {
			return count, err
		}
		status := m.serviceStatus(ctx, candidate.ServiceManager, candidate.ServiceName)
		server := strings.TrimSpace(m.cfg.PanelDomain)
		if server == "" {
			server = candidate.Domain
		}
		node := model.Node{ID: candidate.Fingerprint, Name: candidate.Name, Protocol: candidate.Protocol, Mode: candidate.Mode, ListenPort: candidate.ListenPort, Server: server, Domain: candidate.Domain, IPv4Bind: candidate.IPv4Bind, IPv6Bind: candidate.IPv6Bind, AutoBind: true, ServiceName: candidate.ServiceName, ServiceManager: candidate.ServiceManager, ConfigPath: candidate.ConfigPath, ConfigVersion: candidate.ConfigVersion, Ownership: "imported", SharedGroup: candidate.SharedGroup, Status: status}
		if err = m.store.UpsertNode(ctx, node, cipher); err != nil {
			return count, err
		}
		count++
	}
	_ = m.store.Audit("admin", "import_nodes", "sing-box", fmt.Sprintf("imported=%d", count))
	return count, nil
}

func (m *Manager) Create(ctx context.Context, request model.NodeCreateRequest) (model.Node, error) {
	request, err := prepareCreateRequest(request)
	if err != nil {
		return model.Node{}, err
	}
	return m.createPrepared(ctx, request, "", true)
}

func (m *Manager) CreateBatch(ctx context.Context, request model.NodeBatchCreateRequest) ([]model.Node, error) {
	if len(request.Nodes) < 2 || len(request.Nodes) > 20 {
		return nil, errors.New("device batch must contain between 2 and 20 nodes")
	}
	prepared := make([]model.NodeCreateRequest, 0, len(request.Nodes))
	names := map[string]bool{}
	ports := map[int]bool{}
	tunnelHostnames := map[string]bool{}
	tunnelToken := ""
	protocol := ""
	var sharedRequest model.NodeCreateRequest
	for index, item := range request.Nodes {
		value, err := prepareCreateRequest(item)
		if err != nil {
			return nil, fmt.Errorf("device %d: %w", index+1, err)
		}
		if protocol == "" {
			protocol = value.Protocol
			sharedRequest = value
		} else if value.Protocol != protocol {
			return nil, errors.New("all device nodes in a batch must use the same protocol")
		} else if !sameBatchRuntimeSettings(sharedRequest, value) {
			return nil, errors.New("all device nodes in a batch must use the same outbound mode, bind addresses and IPv6 domain policy")
		}
		nameKey := strings.ToLower(strings.TrimSpace(value.Name))
		if names[nameKey] {
			return nil, fmt.Errorf("device %d: duplicate node name %q", index+1, value.Name)
		}
		names[nameKey] = true
		if value.ListenPort != 0 {
			if ports[value.ListenPort] {
				return nil, fmt.Errorf("device %d: duplicate listen port %d", index+1, value.ListenPort)
			}
			ports[value.ListenPort] = true
		}
		if value.Protocol == protocolVLESSWSTunnel {
			hostnameKey := strings.ToLower(strings.TrimSpace(value.Server))
			if tunnelHostnames[hostnameKey] {
				return nil, fmt.Errorf("device %d: duplicate Cloudflare hostname %q", index+1, value.Server)
			}
			tunnelHostnames[hostnameKey] = true
			if tunnelToken == "" {
				tunnelToken = value.TunnelToken
			} else if value.TunnelToken != tunnelToken {
				return nil, errors.New("all Tunnel device nodes must use the same Tunnel token")
			}
		}
		prepared = append(prepared, value)
	}
	group, err := security.RandomToken(8)
	if err != nil {
		return nil, err
	}
	group = "devices-" + strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(group))
	created, err := m.createDeviceGroup(ctx, prepared, group)
	if err != nil {
		return nil, err
	}
	_ = m.store.Audit("admin", "create_device_batch", group, fmt.Sprintf("protocol=%s nodes=%d", protocol, len(created)))
	return created, nil
}

func sameBatchRuntimeSettings(a, b model.NodeCreateRequest) bool {
	if a.Mode != b.Mode || a.IPv4Bind != b.IPv4Bind || a.IPv6Bind != b.IPv6Bind || a.AutoBind != b.AutoBind || len(a.V6OnlyDomains) != len(b.V6OnlyDomains) {
		return false
	}
	for index := range a.V6OnlyDomains {
		if a.V6OnlyDomains[index] != b.V6OnlyDomains[index] {
			return false
		}
	}
	return true
}

type preparedDeviceNode struct {
	node         model.Node
	request      model.NodeCreateRequest
	credentials  protocolCredentials
	cipher       string
	certPath     string
	keyPath      string
	generateCert bool
}

func (m *Manager) createDeviceGroup(ctx context.Context, requests []model.NodeCreateRequest, group string) ([]model.Node, error) {
	manager := detectServiceManager()
	service := "sing-box-wukong-" + group
	configPath := filepath.Join(m.cfg.ConfigDir, "wukong-"+group+".json")
	version := m.Version(ctx)
	if m.cfg.Demo {
		version = "1.14-demo"
	}
	usedPorts := map[int]bool{}
	prepared := make([]preparedDeviceNode, 0, len(requests))
	for index, request := range requests {
		port := request.ListenPort
		if port == 0 {
			var err error
			port, err = freeUnusedProtocolPort(request.Protocol, usedPorts)
			if err != nil {
				return nil, fmt.Errorf("device %d: %w", index+1, err)
			}
		}
		if usedPorts[port] {
			return nil, fmt.Errorf("device %d: duplicate listen port %d", index+1, port)
		}
		usedPorts[port] = true
		id, err := security.RandomToken(8)
		if err != nil {
			return nil, err
		}
		id = strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(id))
		credentials, err := generateProtocolCredentials(request.Protocol, request.Password)
		if err != nil {
			return nil, fmt.Errorf("device %d: %w", index+1, err)
		}
		if request.Protocol == protocolVLESSWSTunnel {
			credentials.WebSocketPath = request.WebSocketPath
			credentials.TunnelToken = request.TunnelToken
		}
		secret, err := encodeProtocolCredentials(credentials)
		if err != nil {
			return nil, err
		}
		cipher, err := m.vault.Encrypt(secret)
		if err != nil {
			return nil, err
		}
		certPath, keyPath, generateCertificate := "", "", false
		if protocolUsesCertificate(request.Protocol) {
			certPath, keyPath, generateCertificate, err = m.certificatePaths(request, id)
			if err != nil {
				return nil, fmt.Errorf("device %d: %w", index+1, err)
			}
		}
		node := model.Node{ID: id, Name: request.Name, Protocol: request.Protocol, Mode: request.Mode, ListenPort: port, Server: request.Server, Domain: request.Domain, PreferredServer: request.PreferredServer, WebSocketPath: request.WebSocketPath, IPv4Bind: request.IPv4Bind, IPv6Bind: request.IPv6Bind, AutoBind: request.AutoBind, ServiceName: service, ServiceManager: manager, ConfigPath: configPath, ConfigVersion: version, Ownership: "managed", SharedGroup: group, Status: "active"}
		prepared = append(prepared, preparedDeviceNode{node: node, request: request, credentials: credentials, cipher: cipher, certPath: certPath, keyPath: keyPath, generateCert: generateCertificate})
	}
	identity := prepared[0].node
	installedRuntime := false
	installedTunnel := false
	cleanup := func() {
		if installedTunnel {
			_ = m.removeCloudflaredService(ctx, identity)
		}
		if installedRuntime {
			_ = m.cleanupFailedCreate(ctx, identity, false)
		}
	}
	if !m.cfg.Demo {
		if err := os.MkdirAll(m.cfg.ConfigDir, 0o700); err != nil {
			return nil, err
		}
		inbounds := make([]any, 0, len(prepared))
		for index := range prepared {
			item := &prepared[index]
			if item.generateCert {
				sni := item.request.Domain
				if sni == "" {
					sni = "www.bing.com"
				}
				if err := generateSelfSigned(item.keyPath, item.certPath, sni); err != nil {
					return nil, fmt.Errorf("device %d: %w", index+1, err)
				}
			}
			inbound, err := buildProtocolInbound(item.request, item.node.ListenPort, item.credentials, item.certPath, item.keyPath)
			if err != nil {
				return nil, fmt.Errorf("device %d: %w", index+1, err)
			}
			inbounds = append(inbounds, inbound)
		}
		payload, err := buildConfigWithInbounds(requests[0], inbounds, version)
		if err != nil {
			return nil, err
		}
		installedRuntime = true
		if err = m.installConfig(ctx, configPath, service, manager, payload); err != nil {
			cleanup()
			return nil, err
		}
		for index, item := range prepared {
			if item.request.Protocol != protocolVLESS && item.request.Protocol != protocolVLESSWSTunnel {
				continue
			}
			if _, probeErr := singboxconfig.ProbeConfigInbound(ctx, m.cfg.SingBoxBin, configPath, item.request.Protocol, item.node.ListenPort); probeErr != nil {
				cleanup()
				return nil, fmt.Errorf("device %d local preflight failed: %w", index+1, probeErr)
			}
		}
		if requests[0].Protocol == protocolVLESSWSTunnel {
			cloudflaredBinary, ensureErr := m.ensureCloudflared(ctx)
			if ensureErr != nil {
				cleanup()
				return nil, ensureErr
			}
			installedTunnel = true
			if err = m.installCloudflaredService(ctx, group, manager, cloudflaredBinary, prepared[0].credentials.TunnelToken); err != nil {
				cleanup()
				return nil, fmt.Errorf("Cloudflare Tunnel service installation failed: %w", err)
			}
		}
	}
	created := make([]model.Node, 0, len(prepared))
	for index, item := range prepared {
		if err := m.store.UpsertNode(ctx, item.node, item.cipher); err != nil {
			for _, node := range created {
				_ = m.store.DeleteNode(node.ID)
			}
			cleanup()
			return nil, fmt.Errorf("device %d persistence failed: %w", index+1, err)
		}
		created = append(created, item.node)
		_ = m.store.Audit("admin", "create_node", item.node.ID, item.node.Name)
	}
	return created, nil
}

func freeUnusedProtocolPort(protocol string, used map[int]bool) (int, error) {
	for attempt := 0; attempt < 64; attempt++ {
		port, err := freeProtocolPort(protocol)
		if err != nil {
			return 0, err
		}
		if !used[port] {
			return port, nil
		}
	}
	return 0, errors.New("failed to allocate a unique device port")
}

func prepareCreateRequest(request model.NodeCreateRequest) (model.NodeCreateRequest, error) {
	request.Protocol = normalizeProtocol(request.Protocol)
	request = normalizeModeBindings(request)
	if request.Protocol == protocolVLESS && strings.TrimSpace(request.Domain) == "" {
		request.Domain = realityDefaultSNI
	}
	if request.Protocol == protocolVLESSWSTunnel {
		request.Server = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(request.Server)), ".")
		request.Domain = request.Server
		request.PreferredServer = normalizePreferredServer(request.PreferredServer)
		request.TunnelToken = strings.TrimSpace(request.TunnelToken)
		request.WebSocketPath = strings.TrimSpace(request.WebSocketPath)
		if request.WebSocketPath == "" {
			randomPath, randomErr := security.RandomToken(12)
			if randomErr != nil {
				return model.NodeCreateRequest{}, randomErr
			}
			request.WebSocketPath = "/wukong-" + strings.ToLower(randomPath)
		}
	} else {
		request.PreferredServer = ""
	}
	if err := validateCreate(request); err != nil {
		return model.NodeCreateRequest{}, err
	}
	return request, nil
}

func (m *Manager) createPrepared(ctx context.Context, request model.NodeCreateRequest, group string, installTunnelConnector bool) (model.Node, error) {
	port := request.ListenPort
	if port == 0 {
		var err error
		port, err = freeProtocolPort(request.Protocol)
		if err != nil {
			return model.Node{}, err
		}
	}
	id, err := security.RandomToken(8)
	if err != nil {
		return model.Node{}, err
	}
	id = strings.ToLower(strings.NewReplacer("-", "", "_", "").Replace(id))
	credentials, err := generateProtocolCredentials(request.Protocol, request.Password)
	if err != nil {
		return model.Node{}, err
	}
	if request.Protocol == protocolVLESSWSTunnel {
		credentials.WebSocketPath = request.WebSocketPath
		credentials.TunnelToken = request.TunnelToken
	}
	service := "sing-box-wukong-" + id
	configPath := filepath.Join(m.cfg.ConfigDir, "wukong-"+id+".json")
	manager := detectServiceManager()
	identity := model.Node{ID: id, Protocol: request.Protocol, ServiceName: service, ServiceManager: manager, ConfigPath: configPath, Ownership: "managed", SharedGroup: group}
	tunnelServiceKey := id
	if group != "" {
		tunnelServiceKey = group
	}
	cloudflaredBinary := ""
	if request.Protocol == protocolVLESSWSTunnel && installTunnelConnector && !m.cfg.Demo {
		cloudflaredBinary, err = m.ensureCloudflared(ctx)
		if err != nil {
			return model.Node{}, err
		}
	}
	certPath, keyPath, generateCertificate := "", "", false
	if protocolUsesCertificate(request.Protocol) {
		certPath, keyPath, generateCertificate, err = m.certificatePaths(request, id)
		if err != nil {
			return model.Node{}, err
		}
	}
	if !m.cfg.Demo {
		if err := os.MkdirAll(m.cfg.ConfigDir, 0o700); err != nil {
			return model.Node{}, err
		}
		if generateCertificate {
			sni := request.Domain
			if sni == "" {
				sni = "www.bing.com"
			}
			if err := generateSelfSigned(keyPath, certPath, sni); err != nil {
				return model.Node{}, err
			}
		}
		version := m.Version(ctx)
		payload, err := buildConfig(request, port, credentials, certPath, keyPath, version)
		if err != nil {
			return model.Node{}, err
		}
		if err = m.installConfig(ctx, configPath, service, manager, payload); err != nil {
			return model.Node{}, err
		}
		if request.Protocol == protocolVLESS {
			if _, probeErr := singboxconfig.ProbeConfigInbound(ctx, m.cfg.SingBoxBin, configPath, request.Protocol, port); probeErr != nil {
				cleanupErr := m.cleanupFailedCreate(ctx, identity, false)
				if cleanupErr != nil {
					return model.Node{}, fmt.Errorf("VLESS REALITY preflight failed: %w (cleanup failed: %v)", probeErr, cleanupErr)
				}
				return model.Node{}, fmt.Errorf("VLESS REALITY preflight failed; choose another handshake server: %w", probeErr)
			}
		}
		if request.Protocol == protocolVLESSWSTunnel {
			if _, probeErr := singboxconfig.ProbeConfigInbound(ctx, m.cfg.SingBoxBin, configPath, request.Protocol, port); probeErr != nil {
				cleanupErr := m.cleanupFailedCreate(ctx, identity, false)
				if cleanupErr != nil {
					return model.Node{}, fmt.Errorf("VLESS WebSocket local preflight failed: %w (cleanup failed: %v)", probeErr, cleanupErr)
				}
				return model.Node{}, fmt.Errorf("VLESS WebSocket local preflight failed: %w", probeErr)
			}
			if installTunnelConnector {
				if err = m.installCloudflaredService(ctx, tunnelServiceKey, manager, cloudflaredBinary, credentials.TunnelToken); err != nil {
					cleanupErr := m.cleanupFailedCreate(ctx, identity, true)
					if cleanupErr != nil {
						return model.Node{}, fmt.Errorf("Cloudflare Tunnel service installation failed: %w (cleanup failed: %v)", err, cleanupErr)
					}
					return model.Node{}, fmt.Errorf("Cloudflare Tunnel service installation failed: %w", err)
				}
			}
		}
	}
	secret, err := encodeProtocolCredentials(credentials)
	if err != nil {
		return model.Node{}, err
	}
	cipher, err := m.vault.Encrypt(secret)
	if err != nil {
		return model.Node{}, err
	}
	version := m.Version(ctx)
	if m.cfg.Demo {
		version = "1.14-demo"
	}
	node := model.Node{ID: id, Name: request.Name, Protocol: request.Protocol, Mode: request.Mode, ListenPort: port, Server: request.Server, Domain: request.Domain, PreferredServer: request.PreferredServer, WebSocketPath: request.WebSocketPath, IPv4Bind: request.IPv4Bind, IPv6Bind: request.IPv6Bind, AutoBind: request.AutoBind, ServiceName: service, ServiceManager: manager, ConfigPath: configPath, ConfigVersion: version, Ownership: "managed", SharedGroup: group, Status: "active"}
	if err = m.store.UpsertNode(ctx, node, cipher); err != nil {
		if !m.cfg.Demo {
			_ = m.cleanupFailedCreate(ctx, node, request.Protocol == protocolVLESSWSTunnel && installTunnelConnector)
		}
		return model.Node{}, err
	}
	_ = m.store.Audit("admin", "create_node", node.ID, node.Name)
	return node, nil
}

func normalizeModeBindings(request model.NodeCreateRequest) model.NodeCreateRequest {
	switch request.Mode {
	case "v4only":
		request.IPv6Bind = ""
	case "v6only":
		request.IPv4Bind = ""
	}
	return request
}

func (m *Manager) certificatePaths(request model.NodeCreateRequest, id string) (certPath, keyPath string, generate bool, err error) {
	if request.CertificatePath != "" || request.KeyPath != "" {
		if request.CertificatePath == "" || request.KeyPath == "" {
			return "", "", false, errors.New("certificate and private key paths must be provided together")
		}
		if !regularFile(request.CertificatePath) || !regularFile(request.KeyPath) {
			return "", "", false, errors.New("certificate or private key file is not readable")
		}
		if !certificatePairCoversDomain(request.CertificatePath, request.KeyPath, request.Domain) {
			return "", "", false, fmt.Errorf("certificate and private key do not form a valid pair for TLS domain %s", request.Domain)
		}
		return request.CertificatePath, request.KeyPath, false, nil
	}
	if request.Domain != "" && certificatePairCoversDomain(m.cfg.TLSCertFile, m.cfg.TLSKeyFile, request.Domain) {
		return m.cfg.TLSCertFile, m.cfg.TLSKeyFile, false, nil
	}
	return filepath.Join(m.cfg.ConfigDir, "wukong-"+id+".cer"), filepath.Join(m.cfg.ConfigDir, "wukong-"+id+".key"), true, nil
}

func regularFile(path string) bool {
	info, err := os.Stat(path)
	return err == nil && info.Mode().IsRegular()
}

func certificateCoversDomain(path, domain string) bool {
	certificate, err := loadCertificate(path)
	return err == nil && certificate.VerifyHostname(domain) == nil
}

func loadCertificate(path string) (*x509.Certificate, error) {
	data, err := os.ReadFile(path)
	if err != nil {
		return nil, err
	}
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, errors.New("certificate PEM block not found")
	}
	return x509.ParseCertificate(block.Bytes)
}

func certificatePairCoversDomain(certPath, keyPath, domain string) bool {
	if !regularFile(certPath) || !regularFile(keyPath) {
		return false
	}
	if _, err := tls.LoadX509KeyPair(certPath, keyPath); err != nil {
		return false
	}
	return domain == "" || certificateCoversDomain(certPath, domain)
}

func configUsesSelfSignedCertificate(configPath string) bool {
	data, err := os.ReadFile(configPath)
	if err != nil {
		return false
	}
	var root map[string]any
	if json.Unmarshal(data, &root) != nil {
		return false
	}
	inbounds, _ := root["inbounds"].([]any)
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		tlsConfig, _ := inbound["tls"].(map[string]any)
		certificatePath := stringValue(tlsConfig["certificate_path"])
		if certificatePath == "" {
			continue
		}
		certificate, err := loadCertificate(certificatePath)
		if err != nil {
			return false
		}
		return bytes.Equal(certificate.RawIssuer, certificate.RawSubject) && certificate.CheckSignature(certificate.SignatureAlgorithm, certificate.RawTBSCertificate, certificate.Signature) == nil
	}
	return false
}

func (m *Manager) Action(ctx context.Context, id, action, confirmName string) error {
	node, err := m.store.Node(ctx, id, true)
	if err != nil {
		return err
	}
	if !m.cfg.Demo {
		if err = m.validateManagedNode(node); err != nil {
			return err
		}
	}
	allowed := map[string]bool{"start": true, "stop": true, "restart": true, "check": true, "probe": true, "delete": true}
	if !allowed[action] {
		return errors.New("unsupported node action")
	}
	if action == "delete" && confirmName != node.Name {
		return errors.New("confirmation name does not match")
	}
	if m.cfg.Demo {
		if action == "delete" {
			return m.store.DeleteNode(id)
		}
		if action == "probe" {
			return m.store.SetNodeProbeResult(id, "success", 42, "203.0.113.18", "www.cloudflare.com", "", time.Now())
		}
		status := "active"
		if action == "stop" {
			status = "inactive"
		}
		if shared, _, _ := m.managedSharedRuntime(ctx, node); shared {
			return m.store.SetNodeGroupStatus(node.SharedGroup, status)
		}
		return m.store.SetNodeStatus(id, status)
	}
	if action == "check" {
		if err = command(ctx, m.cfg.SingBoxBin, "check", "-c", node.ConfigPath); err != nil {
			return err
		}
		if normalizeProtocol(node.Protocol) == protocolVLESSWSTunnel {
			return m.checkCloudflaredNode(ctx, node)
		}
		return nil
	}
	if action == "probe" {
		return m.probeNode(ctx, node)
	}
	if action == "delete" {
		sharedRuntime, groupNodes, groupErr := m.managedSharedRuntime(ctx, node)
		if groupErr != nil {
			return groupErr
		}
		if sharedRuntime && len(groupNodes) > 1 {
			if err = m.removeNodeFromSharedConfig(ctx, node); err != nil {
				return err
			}
			_ = m.store.Audit("admin", "node_delete", node.ID, node.Name)
			return nil
		}
		if err = m.backup(node); err != nil {
			return err
		}
		removeTunnelConnector, connectorErr := m.shouldRemoveTunnelConnector(ctx, node)
		if connectorErr != nil {
			return connectorErr
		}
		if removeTunnelConnector {
			tunnelNode := node
			tunnelNode.ServiceName = cloudflaredServiceName(cloudflaredNodeKey(node))
			if err = m.serviceCommand(ctx, tunnelNode.ServiceManager, "stop", tunnelNode.ServiceName); err != nil {
				return err
			}
		}
		if err = m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName); err != nil {
			return err
		}
		_ = m.disableService(ctx, node)
		if node.SharedGroup == "" || node.Ownership == "managed" {
			_ = os.Remove(node.ConfigPath)
			_ = m.removeService(node)
		}
		if removeTunnelConnector {
			if err = m.removeCloudflaredService(ctx, node); err != nil {
				return err
			}
		}
		err = m.store.DeleteNode(id)
	} else {
		err = m.actionNodeServices(ctx, node, action)
		if err == nil {
			status := "active"
			if action == "stop" {
				status = "inactive"
			}
			if shared, _, groupErr := m.managedSharedRuntime(ctx, node); groupErr == nil && shared {
				_ = m.store.SetNodeGroupStatus(node.SharedGroup, status)
			} else {
				_ = m.store.SetNodeStatus(id, status)
			}
		}
	}
	if err == nil {
		_ = m.store.Audit("admin", "node_"+action, node.ID, node.Name)
	}
	return err
}

func (m *Manager) managedSharedRuntime(ctx context.Context, node model.Node) (bool, []model.Node, error) {
	if node.Ownership != "managed" || strings.TrimSpace(node.SharedGroup) == "" {
		return false, nil, nil
	}
	nodes, err := m.store.NodesByGroup(ctx, node.SharedGroup)
	if err != nil {
		return false, nil, err
	}
	if len(nodes) < 2 {
		return false, nodes, nil
	}
	for _, item := range nodes {
		if item.Ownership != "managed" || item.ServiceName != node.ServiceName || item.ServiceManager != node.ServiceManager || item.ConfigPath != node.ConfigPath {
			return false, nodes, nil
		}
	}
	return true, nodes, nil
}

func (m *Manager) removeNodeFromSharedConfig(ctx context.Context, node model.Node) error {
	if err := m.backup(node); err != nil {
		return err
	}
	original, err := os.ReadFile(node.ConfigPath)
	if err != nil {
		return err
	}
	var root map[string]any
	if err = json.Unmarshal(original, &root); err != nil {
		return err
	}
	inbounds, _ := root["inbounds"].([]any)
	remaining := make([]any, 0, len(inbounds))
	removed := false
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		if !removed && int(numberValue(inbound["listen_port"])) == node.ListenPort {
			removed = true
			continue
		}
		remaining = append(remaining, item)
	}
	if !removed {
		return fmt.Errorf("device inbound on port %d was not found in shared configuration", node.ListenPort)
	}
	if len(remaining) == 0 {
		return errors.New("refusing to leave a shared sing-box configuration without inbounds")
	}
	root["inbounds"] = remaining
	payload, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		return err
	}
	tmp := node.ConfigPath + ".device-delete.tmp"
	if err = os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err = command(ctx, m.cfg.SingBoxBin, "check", "-c", tmp); err != nil {
		return fmt.Errorf("shared configuration check failed: %w", err)
	}
	if err = os.Rename(tmp, node.ConfigPath); err != nil {
		return err
	}
	if err = m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName); err != nil {
		restoreErr := m.restoreSharedConfig(ctx, node, original)
		if restoreErr != nil {
			return fmt.Errorf("shared service restart failed: %w (configuration rollback failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("shared service restart failed and the previous configuration was restored: %w", err)
	}
	if err = m.store.DeleteNode(node.ID); err != nil {
		if restoreErr := m.restoreSharedConfig(ctx, node, original); restoreErr != nil {
			return fmt.Errorf("delete device metadata failed: %w (configuration rollback failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("delete device metadata failed and the previous configuration was restored: %w", err)
	}
	return nil
}

func (m *Manager) restoreSharedConfig(ctx context.Context, node model.Node, payload []byte) error {
	if err := os.WriteFile(node.ConfigPath, payload, 0o600); err != nil {
		return err
	}
	return m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName)
}

func (m *Manager) shouldRemoveTunnelConnector(ctx context.Context, node model.Node) (bool, error) {
	if normalizeProtocol(node.Protocol) != protocolVLESSWSTunnel {
		return false, nil
	}
	if node.Ownership != "managed" || node.SharedGroup == "" {
		return true, nil
	}
	count, err := m.store.NodeGroupCount(ctx, node.SharedGroup)
	if err != nil {
		return false, err
	}
	return count <= 1, nil
}

func (m *Manager) probeNode(ctx context.Context, node model.Node) error {
	if err := m.store.SetNodeProbeResult(node.ID, "running", 0, "", "", "", time.Time{}); err != nil {
		return err
	}
	fail := func(result singboxconfig.ProbeResult, err error) error {
		message := compactProbeError(err)
		_ = m.store.SetNodeProbeResult(node.ID, "failed", result.LatencyMS, result.ExitIP, result.Target, message, time.Now())
		_ = m.store.Audit("admin", "node_probe_failed", node.ID, message)
		return err
	}
	if m.serviceStatus(ctx, node.ServiceManager, node.ServiceName) != "active" {
		return fail(singboxconfig.ProbeResult{}, errors.New("node service is not active"))
	}
	if normalizeProtocol(node.Protocol) == protocolVLESSWSTunnel && m.cloudflaredStatus(ctx, node) != "active" {
		return fail(singboxconfig.ProbeResult{}, errors.New("Cloudflare Tunnel service is not active"))
	}
	if err := command(ctx, m.cfg.SingBoxBin, "check", "-c", node.ConfigPath); err != nil {
		return fail(singboxconfig.ProbeResult{}, fmt.Errorf("configuration check failed: %w", err))
	}
	var result singboxconfig.ProbeResult
	var err error
	if normalizeProtocol(node.Protocol) == protocolVLESSWSTunnel {
		secret, decryptErr := m.vault.Decrypt(node.Secret)
		if decryptErr != nil {
			return fail(result, decryptErr)
		}
		credentials, decodeErr := decodeProtocolCredentials(node.Protocol, secret)
		if decodeErr != nil {
			return fail(result, decodeErr)
		}
		result, err = singboxconfig.ProbeVLESSWebSocketEndpoint(ctx, m.cfg.SingBoxBin, node.PreferredServer, node.Server, credentials.UUID, credentials.WebSocketPath)
	} else {
		result, err = singboxconfig.ProbeConfigInbound(ctx, m.cfg.SingBoxBin, node.ConfigPath, node.Protocol, node.ListenPort)
	}
	if err != nil {
		return fail(result, fmt.Errorf("full proxy round trip failed: %w", err))
	}
	if err = m.store.SetNodeProbeResult(node.ID, "success", result.LatencyMS, result.ExitIP, result.Target, "", time.Now()); err != nil {
		return err
	}
	_ = m.store.Audit("admin", "node_probe", node.ID, fmt.Sprintf("latency_ms=%d exit_ip=%s target=%s", result.LatencyMS, result.ExitIP, result.Target))
	return nil
}

func compactProbeError(err error) string {
	if err == nil {
		return ""
	}
	message := strings.Join(strings.Fields(err.Error()), " ")
	if len(message) > 600 {
		message = message[len(message)-600:]
	}
	return message
}

func (m *Manager) Rename(ctx context.Context, id string, request model.NodeRenameRequest) error {
	name := strings.TrimSpace(request.Name)
	if name == "" || utf8.RuneCountInString(name) > 80 {
		return errors.New("node name is required and must be at most 80 characters")
	}
	node, err := m.store.Node(ctx, id, false)
	if err != nil {
		return err
	}
	if name == node.Name {
		return nil
	}
	if err = m.store.RenameNode(ctx, id, name); err != nil {
		return err
	}
	_ = m.store.Audit("admin", "node_rename", id, fmt.Sprintf("%s -> %s", node.Name, name))
	return nil
}

func (m *Manager) EditDetails(ctx context.Context, id string) (model.NodeEditDetails, error) {
	node, err := m.store.Node(ctx, id, false)
	if err != nil {
		return model.NodeEditDetails{}, err
	}
	if node.Ownership != "managed" {
		return model.NodeEditDetails{}, errors.New("only Wukong-managed nodes can be edited")
	}
	domains := []string{}
	if !m.cfg.Demo {
		data, readErr := os.ReadFile(node.ConfigPath)
		if readErr != nil {
			return model.NodeEditDetails{}, readErr
		}
		var root map[string]any
		if json.Unmarshal(data, &root) != nil {
			return model.NodeEditDetails{}, errors.New("managed node configuration is invalid")
		}
		domains = v6OnlyDomainsFromConfig(root)
	}
	return model.NodeEditDetails{Node: node, V6OnlyDomains: domains}, nil
}

func (m *Manager) Edit(ctx context.Context, id string, edit model.NodeEditRequest) error {
	node, err := m.store.Node(ctx, id, true)
	if err != nil {
		return err
	}
	if node.Ownership != "managed" {
		return errors.New("only Wukong-managed nodes can be edited")
	}
	if !m.cfg.Demo {
		if err = m.validateManagedNode(node); err != nil {
			return err
		}
	}
	secret, err := m.vault.Decrypt(node.Secret)
	if err != nil {
		return err
	}
	credentials, err := decodeProtocolCredentials(node.Protocol, secret)
	if err != nil {
		return err
	}
	request := model.NodeCreateRequest{
		Protocol: node.Protocol, Name: edit.Name, Mode: edit.Mode, ListenPort: edit.ListenPort,
		Server: edit.Server, Domain: edit.Domain, PreferredServer: edit.PreferredServer,
		WebSocketPath: edit.WebSocketPath, IPv4Bind: edit.IPv4Bind, IPv6Bind: edit.IPv6Bind,
		AutoBind: edit.AutoBind, V6OnlyDomains: normalizeDomainList(edit.V6OnlyDomains),
		TunnelToken: credentials.TunnelToken,
	}
	request, err = prepareCreateRequest(request)
	if err != nil {
		return err
	}
	if request.ListenPort == 0 {
		request.ListenPort, err = freeProtocolPort(node.Protocol)
		if err != nil {
			return err
		}
	}
	allNodes, err := m.store.Nodes(ctx)
	if err != nil {
		return err
	}
	for _, other := range allNodes {
		if other.ID == node.ID {
			continue
		}
		if request.ListenPort != node.ListenPort && other.ListenPort == request.ListenPort {
			return fmt.Errorf("listen port %d is already assigned to %s", request.ListenPort, other.Name)
		}
		if node.Protocol == protocolVLESSWSTunnel && other.Protocol == protocolVLESSWSTunnel && strings.EqualFold(strings.TrimSpace(other.Server), request.Server) {
			return fmt.Errorf("Cloudflare hostname %s is already assigned to %s", request.Server, other.Name)
		}
	}
	if request.ListenPort != node.ListenPort && !protocolPortAvailable(node.Protocol, request.ListenPort) {
		return fmt.Errorf("listen port %d is already in use", request.ListenPort)
	}

	sharedRuntime, runtimeNodes, err := m.managedSharedRuntime(ctx, node)
	if err != nil {
		return err
	}
	if !sharedRuntime {
		runtimeNodes = []model.Node{node}
	}
	if m.cfg.Demo {
		credentials.WebSocketPath = request.WebSocketPath
		encoded, encodeErr := encodeProtocolCredentials(credentials)
		if encodeErr != nil {
			return encodeErr
		}
		cipher, encryptErr := m.vault.Encrypt(encoded)
		if encryptErr != nil {
			return encryptErr
		}
		updated := editedNode(node, request)
		return m.store.UpdateManagedNodeEdit(ctx, updated, cipher, sharedRuntime)
	}

	original, err := os.ReadFile(node.ConfigPath)
	if err != nil {
		return err
	}
	var root map[string]any
	if err = json.Unmarshal(original, &root); err != nil {
		return err
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) == 0 {
		return errors.New("managed configuration has no inbounds")
	}
	newInbounds := make([]any, 0, len(runtimeNodes))
	var targetCipher string
	for _, runtimeNode := range runtimeNodes {
		stored, nodeErr := m.store.Node(ctx, runtimeNode.ID, true)
		if nodeErr != nil {
			return nodeErr
		}
		storedSecret, decryptErr := m.vault.Decrypt(stored.Secret)
		if decryptErr != nil {
			return decryptErr
		}
		storedCredentials, decodeErr := decodeProtocolCredentials(stored.Protocol, storedSecret)
		if decodeErr != nil {
			return decodeErr
		}
		runtimeRequest := requestFromNode(stored, request.V6OnlyDomains)
		runtimeRequest.Mode = request.Mode
		runtimeRequest.IPv4Bind = request.IPv4Bind
		runtimeRequest.IPv6Bind = request.IPv6Bind
		runtimeRequest.AutoBind = request.AutoBind
		if stored.ID == node.ID {
			runtimeRequest = request
			storedCredentials.WebSocketPath = request.WebSocketPath
			encoded, encodeErr := encodeProtocolCredentials(storedCredentials)
			if encodeErr != nil {
				return encodeErr
			}
			targetCipher, err = m.vault.Encrypt(encoded)
			if err != nil {
				return err
			}
		}
		oldInbound := inboundByPort(inbounds, stored.ListenPort)
		if oldInbound == nil {
			return fmt.Errorf("inbound on port %d was not found", stored.ListenPort)
		}
		certPath, keyPath := certificatePathsFromInbound(oldInbound)
		if protocolUsesCertificate(stored.Protocol) && !certificatePairCoversDomain(certPath, keyPath, runtimeRequest.Domain) {
			if certificatePairCoversDomain(m.cfg.TLSCertFile, m.cfg.TLSKeyFile, runtimeRequest.Domain) {
				certPath, keyPath = m.cfg.TLSCertFile, m.cfg.TLSKeyFile
			} else {
				return fmt.Errorf("current certificate does not cover TLS domain %s; issue or install a matching certificate before editing", runtimeRequest.Domain)
			}
		}
		inbound, buildErr := buildProtocolInbound(runtimeRequest, runtimeRequest.ListenPort, storedCredentials, certPath, keyPath)
		if buildErr != nil {
			return buildErr
		}
		newInbounds = append(newInbounds, inbound)
	}
	payload, err := buildConfigWithInbounds(request, newInbounds, m.Version(ctx))
	if err != nil {
		return err
	}
	if err = m.backup(node); err != nil {
		return err
	}
	tmp := node.ConfigPath + ".edit.tmp"
	if err = os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err = command(ctx, m.cfg.SingBoxBin, "check", "-c", tmp); err != nil {
		return fmt.Errorf("edited configuration check failed: %w", err)
	}
	wasActive := m.serviceStatus(ctx, node.ServiceManager, node.ServiceName) == "active"
	if err = os.Rename(tmp, node.ConfigPath); err != nil {
		return err
	}
	rollback := func() error {
		if restoreErr := os.WriteFile(node.ConfigPath, original, 0o600); restoreErr != nil {
			return restoreErr
		}
		if wasActive {
			return m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName)
		}
		return nil
	}
	if wasActive {
		if err = m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName); err != nil {
			if restoreErr := rollback(); restoreErr != nil {
				return fmt.Errorf("edited service restart failed: %w (rollback failed: %v)", err, restoreErr)
			}
			return fmt.Errorf("edited service restart failed; previous configuration restored: %w", err)
		}
	}
	updated := editedNode(node, request)
	if err = m.store.UpdateManagedNodeEdit(ctx, updated, targetCipher, sharedRuntime); err != nil {
		if restoreErr := rollback(); restoreErr != nil {
			return fmt.Errorf("persist edited node failed: %w (configuration rollback failed: %v)", err, restoreErr)
		}
		return fmt.Errorf("persist edited node failed; previous configuration restored: %w", err)
	}
	_ = m.store.Audit("admin", "node_edit", node.ID, fmt.Sprintf("%s port=%d mode=%s", updated.Name, updated.ListenPort, updated.Mode))
	return nil
}

func editedNode(node model.Node, request model.NodeCreateRequest) model.Node {
	node.Name, node.Mode, node.ListenPort = strings.TrimSpace(request.Name), request.Mode, request.ListenPort
	node.Server, node.Domain = request.Server, request.Domain
	node.PreferredServer, node.WebSocketPath = request.PreferredServer, request.WebSocketPath
	node.IPv4Bind, node.IPv6Bind, node.AutoBind = request.IPv4Bind, request.IPv6Bind, request.AutoBind
	return node
}

func requestFromNode(node model.Node, domains []string) model.NodeCreateRequest {
	return model.NodeCreateRequest{Protocol: node.Protocol, Name: node.Name, Mode: node.Mode, ListenPort: node.ListenPort, Server: node.Server, Domain: node.Domain, PreferredServer: node.PreferredServer, WebSocketPath: node.WebSocketPath, IPv4Bind: node.IPv4Bind, IPv6Bind: node.IPv6Bind, AutoBind: node.AutoBind, V6OnlyDomains: domains}
}

func normalizeDomainList(values []string) []string {
	result, seen := []string{}, map[string]bool{}
	for _, value := range values {
		value = strings.Trim(strings.ToLower(strings.TrimSpace(value)), ".")
		if value != "" && !seen[value] {
			seen[value] = true
			result = append(result, value)
		}
	}
	return result
}

func v6OnlyDomainsFromConfig(root map[string]any) []string {
	route, _ := root["route"].(map[string]any)
	rules, _ := route["rules"].([]any)
	for _, item := range rules {
		rule, _ := item.(map[string]any)
		if stringValue(rule["outbound"]) != "out-v6only" {
			continue
		}
		values, _ := rule["domain_suffix"].([]any)
		result := make([]string, 0, len(values))
		for _, value := range values {
			if domain := stringValue(value); domain != "" {
				result = append(result, domain)
			}
		}
		return result
	}
	return nil
}

func inboundByPort(inbounds []any, port int) map[string]any {
	for _, item := range inbounds {
		inbound, _ := item.(map[string]any)
		if int(numberValue(inbound["listen_port"])) == port {
			return inbound
		}
	}
	return nil
}

func certificatePathsFromInbound(inbound map[string]any) (string, string) {
	tlsConfig, _ := inbound["tls"].(map[string]any)
	return stringValue(tlsConfig["certificate_path"]), stringValue(tlsConfig["key_path"])
}

func protocolPortAvailable(protocol string, port int) bool {
	if protocolUsesTCP(protocol) {
		listener, err := net.Listen("tcp", fmt.Sprintf("[::]:%d", port))
		if err != nil {
			return false
		}
		_ = listener.Close()
	}
	if protocolUsesUDP(protocol) {
		packet, err := net.ListenPacket("udp", fmt.Sprintf("[::]:%d", port))
		if err != nil {
			return false
		}
		_ = packet.Close()
	}
	return true
}

func (m *Manager) Share(ctx context.Context, id string) (model.Share, error) {
	node, err := m.store.Node(ctx, id, true)
	if err != nil {
		return model.Share{}, err
	}
	secret, err := m.vault.Decrypt(node.Secret)
	if err != nil {
		return model.Share{}, err
	}
	credentials, err := decodeProtocolCredentials(node.Protocol, secret)
	if err != nil {
		return model.Share{}, err
	}
	uri, err := buildShareURI(node, credentials, configUsesSelfSignedCertificate(node.ConfigPath))
	if err != nil {
		return model.Share{}, err
	}
	return model.Share{URI: uri, ExpiresAt: time.Now().Add(30 * time.Second).UTC().Format(time.RFC3339)}, nil
}

func (m *Manager) RefreshStatuses(ctx context.Context) {
	nodes, _ := m.store.Nodes(ctx)
	for _, node := range nodes {
		status := m.serviceStatus(ctx, node.ServiceManager, node.ServiceName)
		if normalizeProtocol(node.Protocol) == protocolVLESSWSTunnel && m.cloudflaredStatus(ctx, node) != "active" {
			status = "inactive"
		}
		_ = m.store.SetNodeStatus(node.ID, status)
	}
}

func (m *Manager) installConfig(ctx context.Context, path, service, manager string, payload []byte) error {
	tmp := path + ".tmp"
	if err := os.WriteFile(tmp, payload, 0o600); err != nil {
		return err
	}
	defer os.Remove(tmp)
	if err := command(ctx, m.cfg.SingBoxBin, "check", "-c", tmp); err != nil {
		return fmt.Errorf("sing-box check failed: %w", err)
	}
	if err := os.Rename(tmp, path); err != nil {
		return err
	}
	if manager == "systemd" {
		unit := fmt.Sprintf("[Unit]\nDescription=Wukong managed sing-box node %s\nAfter=network-online.target\nWants=network-online.target\n\n[Service]\nType=simple\nUser=root\nExecStart=%s run -c %s\nRestart=on-failure\nRestartSec=5s\nLimitNOFILE=1048576\n\n[Install]\nWantedBy=multi-user.target\n", service, m.cfg.SingBoxBin, path)
		unitPath := filepath.Join("/etc/systemd/system", service+".service")
		if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
			return err
		}
		if err := command(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		return command(ctx, "systemctl", "enable", "--now", service+".service")
	}
	script := fmt.Sprintf("#!/sbin/openrc-run\nname=\"%s\"\ncommand=\"%s\"\ncommand_args=\"run -c %s\"\ncommand_background=true\npidfile=\"/run/%s.pid\"\noutput_log=\"/var/log/%s.log\"\nerror_log=\"/var/log/%s.log\"\ndepend(){ need net; after firewall; }\n", service, m.cfg.SingBoxBin, path, service, service, service)
	initPath := filepath.Join("/etc/init.d", service)
	if err := os.WriteFile(initPath, []byte(script), 0o755); err != nil {
		return err
	}
	if err := command(ctx, "rc-update", "add", service, "default"); err != nil {
		return err
	}
	return command(ctx, "rc-service", service, "start")
}

func (m *Manager) cleanupFailedCreate(ctx context.Context, node model.Node, removeTunnelConnector bool) error {
	if removeTunnelConnector && normalizeProtocol(node.Protocol) == protocolVLESSWSTunnel && node.ID != "" {
		_ = m.removeCloudflaredService(ctx, node)
	}
	_ = m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName)
	_ = m.disableService(ctx, node)
	serviceErr := m.removeService(node)
	configErr := os.Remove(node.ConfigPath)
	if errors.Is(serviceErr, os.ErrNotExist) {
		serviceErr = nil
	}
	if errors.Is(configErr, os.ErrNotExist) {
		configErr = nil
	}
	if serviceErr != nil {
		return serviceErr
	}
	return configErr
}

func buildConfig(request model.NodeCreateRequest, port int, credentials protocolCredentials, certPath, keyPath, version string) ([]byte, error) {
	inbound, err := buildProtocolInbound(request, port, credentials, certPath, keyPath)
	if err != nil {
		return nil, err
	}
	return buildConfigWithInbounds(request, []any{inbound}, version)
}

func buildConfigWithInbounds(request model.NodeCreateRequest, inbounds []any, version string) ([]byte, error) {
	if len(inbounds) == 0 {
		return nil, errors.New("at least one inbound is required")
	}
	capabilities := singboxconfig.CapabilitiesFor(version)
	outbounds := []any{}
	rules := []any{}
	direct := func(tag, strategy string) map[string]any {
		o := map[string]any{"type": "direct", "tag": tag}
		if request.IPv4Bind != "" {
			o["inet4_bind_address"] = request.IPv4Bind
		}
		if request.IPv6Bind != "" {
			o["inet6_bind_address"] = request.IPv6Bind
		}
		if capabilities.NewDNSServers {
			o["domain_resolver"] = map[string]any{"server": "local", "strategy": strategy}
		} else {
			o["domain_strategy"] = strategy
		}
		return o
	}
	final := "out-direct"
	strategy := "prefer_ipv6"
	if request.Mode == "v4only" {
		strategy = "ipv4_only"
	}
	if request.Mode == "v6only" {
		strategy = "ipv6_only"
	}
	outbounds = append(outbounds, direct(final, strategy))
	if request.Mode == "prefer_v6" && len(request.V6OnlyDomains) > 0 {
		outbounds = append(outbounds, direct("out-v6only", "ipv6_only"))
		rule := map[string]any{"domain_suffix": request.V6OnlyDomains, "outbound": "out-v6only"}
		if capabilities.RuleActions {
			rule["action"] = "route"
		}
		rules = append(rules, rule)
	}
	root := map[string]any{"log": map[string]any{"level": "warn", "timestamp": true}, "inbounds": inbounds, "outbounds": outbounds, "route": map[string]any{"rules": rules, "final": final}}
	if capabilities.NewDNSServers {
		root["dns"] = map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}}
	}
	if capabilities.RuleActions {
		root["route"].(map[string]any)["rules"] = append([]any{map[string]any{"action": "sniff"}}, rules...)
	}
	return json.MarshalIndent(root, "", "  ")
}

func detectMode(root map[string]any) (mode, v4, v6 string) {
	mode = "v4only"
	outbounds, _ := root["outbounds"].([]any)
	for _, item := range outbounds {
		o, _ := item.(map[string]any)
		if v := stringValue(o["inet4_bind_address"]); v != "" {
			v4 = v
		}
		if v := stringValue(o["inet6_bind_address"]); v != "" {
			v6 = v
		}
		strategy := stringValue(o["domain_strategy"])
		if resolver, ok := o["domain_resolver"].(map[string]any); ok {
			strategy = stringValue(resolver["strategy"])
		}
		if strategy == "prefer_ipv6" {
			mode = "prefer_v6"
		} else if strategy == "ipv6_only" && v4 == "" {
			mode = "v6only"
		}
	}
	if v4 != "" && v6 != "" {
		mode = "prefer_v6"
	} else if v6 != "" && v4 == "" {
		mode = "v6only"
	}
	return
}
func (m *Manager) findService(configPath string) (string, string) {
	if units, _ := filepath.Glob("/etc/systemd/system/sing-box*.service"); len(units) > 0 {
		for _, unit := range units {
			if data, err := os.ReadFile(unit); err == nil && strings.Contains(string(data), configPath) {
				return strings.TrimSuffix(filepath.Base(unit), ".service"), "systemd"
			}
		}
	}
	if scripts, _ := filepath.Glob("/etc/init.d/sing-box*"); len(scripts) > 0 {
		for _, script := range scripts {
			if data, err := os.ReadFile(script); err == nil && strings.Contains(string(data), configPath) {
				return filepath.Base(script), "openrc"
			}
		}
	}
	return "unknown", "unknown"
}
func detectServiceManager() string {
	if _, err := os.Stat("/run/systemd/system"); err == nil {
		return "systemd"
	}
	if _, err := os.Stat("/sbin/openrc-run"); err == nil {
		return "openrc"
	}
	return "systemd"
}
func (m *Manager) serviceStatus(ctx context.Context, manager, name string) string {
	if m.cfg.Demo {
		return "active"
	}
	if name == "" || name == "unknown" {
		return "unknown"
	}
	if manager == "openrc" {
		if command(ctx, "rc-service", name, "status") == nil {
			return "active"
		}
		return "inactive"
	}
	if command(ctx, "systemctl", "is-active", "--quiet", name+".service") == nil {
		return "active"
	}
	return "inactive"
}
func (m *Manager) serviceCommand(ctx context.Context, manager, action, name string) error {
	if manager == "openrc" {
		return command(ctx, "rc-service", name, action)
	}
	return command(ctx, "systemctl", action, name+".service")
}
func (m *Manager) disableService(ctx context.Context, node model.Node) error {
	if node.ServiceManager == "openrc" {
		return command(ctx, "rc-update", "del", node.ServiceName, "default")
	}
	return command(ctx, "systemctl", "disable", node.ServiceName+".service")
}
func (m *Manager) removeService(node model.Node) error {
	if node.ServiceManager == "openrc" {
		return os.Remove(filepath.Join("/etc/init.d", node.ServiceName))
	}
	err := os.Remove(filepath.Join("/etc/systemd/system", node.ServiceName+".service"))
	_ = exec.Command("systemctl", "daemon-reload").Run()
	return err
}
func (m *Manager) backup(node model.Node) error {
	dir := filepath.Join(m.cfg.DataDir, "backups", time.Now().Format("20060102-150405")+"-"+node.ID)
	if err := os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	data, err := os.ReadFile(node.ConfigPath)
	if err != nil {
		return err
	}
	sum := sha256.Sum256(data)
	if err = os.WriteFile(filepath.Join(dir, filepath.Base(node.ConfigPath)), data, 0o600); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(dir, "SHA256SUMS"), []byte(hex.EncodeToString(sum[:])+"  "+filepath.Base(node.ConfigPath)+"\n"), 0o600)
}

func validateCreate(r model.NodeCreateRequest) error {
	if strings.TrimSpace(r.Name) == "" || utf8.RuneCountInString(r.Name) > 80 {
		return errors.New("node name is required and must be at most 80 characters")
	}
	if r.Mode != "prefer_v6" && r.Mode != "v4only" && r.Mode != "v6only" {
		return errors.New("invalid outbound mode")
	}
	protocol := normalizeProtocol(r.Protocol)
	if !supportedProtocols[protocol] {
		return errors.New("unsupported node protocol")
	}
	if r.ListenPort < 0 || r.ListenPort > 65535 {
		return errors.New("invalid listen port")
	}
	if r.IPv4Bind != "" && net.ParseIP(r.IPv4Bind) == nil {
		return errors.New("invalid IPv4 bind address")
	}
	if r.IPv6Bind != "" && net.ParseIP(r.IPv6Bind) == nil {
		return errors.New("invalid IPv6 bind address")
	}
	if r.Mode == "v6only" && r.IPv6Bind == "" {
		return errors.New("IPv6-only mode requires an IPv6 bind address")
	}
	if protocol == protocolVLESS && strings.TrimSpace(r.Domain) == "" {
		return errors.New("VLESS REALITY requires a handshake server name")
	}
	if strings.TrimSpace(r.Server) == "" {
		return errors.New("public server domain or IP is required")
	}
	if protocolUsesCertificate(protocol) && strings.TrimSpace(r.Domain) == "" {
		return errors.New("TLS domain is required for this protocol")
	}
	if protocol == protocolVLESSWSTunnel {
		if !validTunnelHostname(r.Server) {
			return errors.New("Cloudflare Tunnel hostname must be a valid DNS hostname")
		}
		if !validPreferredServer(r.PreferredServer) {
			return errors.New("Cloudflare preferred endpoint must be a DNS hostname or IP address without a scheme or port")
		}
		if !validWebSocketPath(r.WebSocketPath) {
			return errors.New("WebSocket path must start with /, contain no whitespace, ? or #, and be at most 128 characters")
		}
		if !validTunnelToken(r.TunnelToken) {
			return errors.New("a valid Cloudflare Tunnel token is required")
		}
	}
	return nil
}

func (m *Manager) actionNodeServices(ctx context.Context, node model.Node, action string) error {
	if normalizeProtocol(node.Protocol) != protocolVLESSWSTunnel {
		return m.serviceCommand(ctx, node.ServiceManager, action, node.ServiceName)
	}
	tunnelNode := node
	tunnelNode.ServiceName = cloudflaredServiceName(cloudflaredNodeKey(node))
	sharedConnector := node.Ownership == "managed" && node.SharedGroup != ""
	switch action {
	case "start":
		if sharedConnector && m.cloudflaredStatus(ctx, node) != "active" {
			if err := m.serviceCommand(ctx, tunnelNode.ServiceManager, "start", tunnelNode.ServiceName); err != nil {
				return err
			}
		}
		if err := m.serviceCommand(ctx, node.ServiceManager, "start", node.ServiceName); err != nil {
			return err
		}
		if sharedConnector {
			return nil
		}
		if err := m.serviceCommand(ctx, tunnelNode.ServiceManager, "start", tunnelNode.ServiceName); err != nil {
			_ = m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName)
			return err
		}
		return nil
	case "stop":
		if sharedConnector {
			return m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName)
		}
		if err := m.serviceCommand(ctx, tunnelNode.ServiceManager, "stop", tunnelNode.ServiceName); err != nil {
			return err
		}
		return m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName)
	case "restart":
		if sharedConnector {
			if m.cloudflaredStatus(ctx, node) != "active" {
				if err := m.serviceCommand(ctx, tunnelNode.ServiceManager, "start", tunnelNode.ServiceName); err != nil {
					return err
				}
			}
			return m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName)
		}
		if err := m.serviceCommand(ctx, node.ServiceManager, "restart", node.ServiceName); err != nil {
			return err
		}
		return m.serviceCommand(ctx, tunnelNode.ServiceManager, "restart", tunnelNode.ServiceName)
	default:
		return errors.New("unsupported service action")
	}
}

func validTunnelHostname(value string) bool {
	value = strings.TrimSuffix(strings.ToLower(strings.TrimSpace(value)), ".")
	if value == "" || len(value) > 253 || net.ParseIP(value) != nil || !strings.Contains(value, ".") {
		return false
	}
	for _, label := range strings.Split(value, ".") {
		if label == "" || len(label) > 63 || label[0] == '-' || label[len(label)-1] == '-' {
			return false
		}
		for _, char := range label {
			if (char < 'a' || char > 'z') && (char < '0' || char > '9') && char != '-' {
				return false
			}
		}
	}
	return true
}

func normalizePreferredServer(value string) string {
	value = strings.TrimSpace(value)
	if strings.HasPrefix(value, "[") && strings.HasSuffix(value, "]") {
		value = strings.TrimSuffix(strings.TrimPrefix(value, "["), "]")
	}
	if ip := net.ParseIP(value); ip != nil {
		return ip.String()
	}
	return strings.TrimSuffix(strings.ToLower(value), ".")
}

func validPreferredServer(value string) bool {
	value = strings.TrimSpace(value)
	return value == "" || net.ParseIP(value) != nil || validTunnelHostname(value)
}

func validWebSocketPath(value string) bool {
	if len(value) < 2 || len(value) > 128 || !strings.HasPrefix(value, "/") || strings.ContainsAny(value, "?#") {
		return false
	}
	for _, char := range value {
		if char <= ' ' || char == 0x7f {
			return false
		}
	}
	return true
}

func validTunnelToken(value string) bool {
	value = strings.TrimSpace(value)
	if len(value) < 80 || len(value) > 4096 {
		return false
	}
	withoutPadding := strings.TrimRight(value, "=")
	if len(value)-len(withoutPadding) > 2 || strings.ContainsRune(withoutPadding, '=') {
		return false
	}
	for _, char := range value {
		if (char < 'A' || char > 'Z') && (char < 'a' || char > 'z') && (char < '0' || char > '9') && !strings.ContainsRune("-_.=+/", char) {
			return false
		}
	}
	return strings.Contains(value, ".") || strings.HasPrefix(value, "eyJ")
}
func generateSelfSigned(keyPath, certPath, domain string) error {
	privateKey, err := ecdsa.GenerateKey(elliptic.P256(), rand.Reader)
	if err != nil {
		return err
	}
	serialLimit := new(big.Int).Lsh(big.NewInt(1), 128)
	serial, err := rand.Int(rand.Reader, serialLimit)
	if err != nil {
		return err
	}
	now := time.Now()
	template := &x509.Certificate{
		SerialNumber: serial,
		Subject:      pkix.Name{CommonName: domain},
		NotBefore:    now.Add(-5 * time.Minute),
		NotAfter:     now.AddDate(10, 0, 0),
		KeyUsage:     x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:  []x509.ExtKeyUsage{x509.ExtKeyUsageServerAuth},
	}
	if ip := net.ParseIP(domain); ip != nil {
		template.IPAddresses = []net.IP{ip}
	} else {
		template.DNSNames = []string{domain}
	}
	der, err := x509.CreateCertificate(rand.Reader, template, template, &privateKey.PublicKey, privateKey)
	if err != nil {
		return err
	}
	keyDER, err := x509.MarshalECPrivateKey(privateKey)
	if err != nil {
		return err
	}
	if err = os.WriteFile(keyPath, pem.EncodeToMemory(&pem.Block{Type: "EC PRIVATE KEY", Bytes: keyDER}), 0o600); err != nil {
		return err
	}
	if err = os.WriteFile(certPath, pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: der}), 0o644); err != nil {
		_ = os.Remove(keyPath)
		return err
	}
	return nil
}
func command(ctx context.Context, name string, args ...string) error {
	cmd := exec.CommandContext(ctx, name, args...)
	output, err := cmd.CombinedOutput()
	if err != nil {
		return fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(output)))
	}
	return nil
}
func freeUDPPort() (int, error) {
	listener, err := net.ListenPacket("udp", ":0")
	if err != nil {
		return 0, err
	}
	defer listener.Close()
	return listener.LocalAddr().(*net.UDPAddr).Port, nil
}
func freeProtocolPort(protocol string) (int, error) {
	if protocolUsesTCP(protocol) && protocolUsesUDP(protocol) {
		for range 32 {
			listener, err := net.Listen("tcp", "[::]:0")
			if err != nil {
				return 0, err
			}
			port := listener.Addr().(*net.TCPAddr).Port
			packet, packetErr := net.ListenPacket("udp", fmt.Sprintf("[::]:%d", port))
			_ = listener.Close()
			if packetErr == nil {
				_ = packet.Close()
				return port, nil
			}
		}
		return 0, errors.New("unable to find a free TCP/UDP port")
	}
	if protocolUsesTCP(protocol) {
		listener, err := net.Listen("tcp", "[::]:0")
		if err != nil {
			return 0, err
		}
		defer listener.Close()
		return listener.Addr().(*net.TCPAddr).Port, nil
	}
	return freeUDPPort()
}
func fingerprint(path string, port int, name string) string {
	sum := sha256.Sum256([]byte(fmt.Sprintf("%s:%d:%s", path, port, name)))
	return hex.EncodeToString(sum[:8])
}
func displayName(tag string, index int, protocol string) string {
	tag = strings.TrimSpace(tag)
	if tag == "" {
		return fmt.Sprintf("%s 节点 %d", strings.ToUpper(protocolTagPrefix(protocol)), index+1)
	}
	tag = strings.TrimPrefix(tag, protocolTagPrefix(protocol)+"-")
	tag = strings.TrimSuffix(tag, "-in")
	return tag
}
func candidateKey(path string, port int) string {
	return filepath.Clean(path) + "\x00" + strconv.Itoa(port)
}
func preferredCandidateName(tag, path string, index, port int, protocol string) string {
	name := displayName(tag, index, protocol)
	if genericNodeName(name) {
		base := strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
		if strings.HasPrefix(base, "wukong-") {
			return fmt.Sprintf("悟空节点 · %d", port)
		}
		return base
	}
	return name
}
func genericNodeName(name string) bool {
	switch strings.ToLower(strings.TrimSpace(name)) {
	case "in", "inbound", "hy2", "hy2-in", "hysteria2-in", "vless", "vless-in", "ss", "ss-in", "shadowsocks", "shadowsocks-in", "tuic", "tuic-in", "trojan", "trojan-in":
		return true
	default:
		return false
	}
}
func stringValue(v any) string {
	if value, ok := v.(string); ok {
		return value
	}
	return ""
}
func numberValue(v any) float64 {
	switch value := v.(type) {
	case float64:
		return value
	case json.Number:
		n, _ := value.Float64()
		return n
	case string:
		n, _ := strconv.ParseFloat(value, 64)
		return n
	}
	return 0
}
func hostForURI(host string) string {
	if strings.Contains(host, ":") && !strings.HasPrefix(host, "[") {
		return "[" + host + "]"
	}
	return host
}
func urlEncode(value string) string {
	return strings.NewReplacer("%", "%25", " ", "%20", "#", "%23", "@", "%40", ":", "%3A", "/", "%2F").Replace(value)
}

func globalAddresses() (v4s, v6s []string) {
	interfaces, _ := net.Interfaces()
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ipText := strings.Split(address.String(), "/")[0]
			ip := net.ParseIP(ipText)
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() {
				continue
			}
			if ip.To4() != nil {
				v4s = append(v4s, ip.String())
			} else if ip.IsGlobalUnicast() {
				v6s = append(v6s, ip.String())
			}
		}
	}
	sort.Strings(v4s)
	sort.Strings(v6s)
	return unique(v4s), unique(v6s)
}

func bindAddressOptions() (v4, v6 []model.BindAddress) {
	v4 = make([]model.BindAddress, 0)
	v6 = make([]model.BindAddress, 0)
	interfaces, _ := net.Interfaces()
	var fallback4, fallback6 []model.BindAddress
	for _, iface := range interfaces {
		if iface.Flags&net.FlagUp == 0 || iface.Flags&net.FlagLoopback != 0 {
			continue
		}
		addresses, _ := iface.Addrs()
		for _, address := range addresses {
			ip := net.ParseIP(strings.Split(address.String(), "/")[0])
			if ip == nil || ip.IsLoopback() || ip.IsLinkLocalUnicast() || !ip.IsGlobalUnicast() {
				continue
			}
			option := model.BindAddress{Address: ip.String(), Interface: iface.Name}
			if ip.To4() != nil {
				fallback4 = append(fallback4, option)
				if !virtualBindInterface(iface.Name) {
					v4 = append(v4, option)
				}
			} else {
				fallback6 = append(fallback6, option)
				if !virtualBindInterface(iface.Name) {
					v6 = append(v6, option)
				}
			}
		}
	}
	if len(v4) == 0 {
		v4 = fallback4
	}
	if len(v6) == 0 {
		v6 = fallback6
	}
	sortBindAddresses(v4)
	sortBindAddresses(v6)
	return uniqueBindAddresses(v4), uniqueBindAddresses(v6)
}

func virtualBindInterface(name string) bool {
	name = strings.ToLower(strings.TrimSpace(name))
	for _, prefix := range []string{"br-", "docker", "veth", "virbr", "tun", "utun", "tap", "wg", "tailscale", "zt"} {
		if strings.HasPrefix(name, prefix) {
			return true
		}
	}
	return false
}

func sortBindAddresses(addresses []model.BindAddress) {
	sort.Slice(addresses, func(i, j int) bool {
		if addresses[i].Interface == addresses[j].Interface {
			return addresses[i].Address < addresses[j].Address
		}
		return addresses[i].Interface < addresses[j].Interface
	})
}

func uniqueBindAddresses(addresses []model.BindAddress) []model.BindAddress {
	result := make([]model.BindAddress, 0, len(addresses))
	seen := make(map[string]bool, len(addresses))
	for _, address := range addresses {
		if seen[address.Address] {
			continue
		}
		seen[address.Address] = true
		result = append(result, address)
	}
	return result
}

func unique(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
func contains(values []string, needle string) bool {
	for _, value := range values {
		if value == needle {
			return true
		}
	}
	return false
}

func (m *Manager) validateManagedNode(node model.Node) error {
	clean := filepath.Clean(node.ConfigPath)
	root := filepath.Clean(m.cfg.ConfigDir) + string(os.PathSeparator)
	if !strings.HasPrefix(clean, root) {
		return errors.New("node config path is outside the managed directory")
	}
	matched, _ := regexp.MatchString(`^[A-Za-z0-9_.@-]+$`, node.ServiceName)
	if !matched {
		return errors.New("invalid managed service name")
	}
	return nil
}
