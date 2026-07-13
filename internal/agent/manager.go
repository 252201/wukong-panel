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
	_ = m.ReconcileRuntimeVersion(ctx)
	ticker := time.NewTicker(2 * time.Minute)
	defer ticker.Stop()
	for {
		select {
		case <-ctx.Done():
			return
		case <-ticker.C:
			_ = m.ReconcileRuntimeVersion(ctx)
			_ = m.ReconcileBindings(ctx)
		}
	}
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
	knownNames := map[string]string{}
	if knownNodes, knownErr := m.store.Nodes(ctx); knownErr == nil {
		for _, node := range knownNodes {
			knownNames[candidateKey(node.ConfigPath, node.ListenPort)] = node.Name
		}
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
			port := int(numberValue(inbound["listen_port"]))
			if port < 1 {
				continue
			}
			name := stringValue(inbound["tag"])
			if name == "" {
				name = strings.TrimSuffix(filepath.Base(path), filepath.Ext(path))
			}
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
			candidateName := preferredCandidateName(name, path, index, port, protocol, knownNames[candidateKey(path, port)])
			result = append(result, model.NodeCandidate{Fingerprint: fingerprint, Name: candidateName, Protocol: protocol, Mode: mode, ListenPort: port, Domain: domain, IPv4Bind: v4, IPv6Bind: v6, ServiceName: service, ServiceManager: manager, ConfigPath: path, ConfigVersion: version, SharedGroup: shared, Secret: secret})
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].ListenPort < result[j].ListenPort })
	return result, nil
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
	request.Protocol = normalizeProtocol(request.Protocol)
	request = normalizeModeBindings(request)
	if request.Protocol == protocolVLESS && strings.TrimSpace(request.Domain) == "" {
		request.Domain = realityDefaultSNI
	}
	if err := validateCreate(request); err != nil {
		return model.Node{}, err
	}
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
	service := "sing-box-wukong-" + id
	configPath := filepath.Join(m.cfg.ConfigDir, "wukong-"+id+".json")
	manager := detectServiceManager()
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
				cleanupErr := m.cleanupFailedCreate(ctx, model.Node{ServiceName: service, ServiceManager: manager, ConfigPath: configPath})
				if cleanupErr != nil {
					return model.Node{}, fmt.Errorf("VLESS REALITY preflight failed: %w (cleanup failed: %v)", probeErr, cleanupErr)
				}
				return model.Node{}, fmt.Errorf("VLESS REALITY preflight failed; choose another handshake server: %w", probeErr)
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
	node := model.Node{ID: id, Name: request.Name, Protocol: request.Protocol, Mode: request.Mode, ListenPort: port, Server: request.Server, Domain: request.Domain, IPv4Bind: request.IPv4Bind, IPv6Bind: request.IPv6Bind, AutoBind: request.AutoBind, ServiceName: service, ServiceManager: manager, ConfigPath: configPath, ConfigVersion: version, Ownership: "managed", Status: "active"}
	if err = m.store.UpsertNode(ctx, node, cipher); err != nil {
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
		return m.store.SetNodeStatus(id, status)
	}
	if action == "check" {
		return command(ctx, m.cfg.SingBoxBin, "check", "-c", node.ConfigPath)
	}
	if action == "probe" {
		return m.probeNode(ctx, node)
	}
	if action == "delete" {
		if err = m.backup(node); err != nil {
			return err
		}
		if err = m.serviceCommand(ctx, node.ServiceManager, "stop", node.ServiceName); err != nil {
			return err
		}
		_ = m.disableService(ctx, node)
		if node.SharedGroup == "" {
			_ = os.Remove(node.ConfigPath)
			_ = m.removeService(node)
		}
		err = m.store.DeleteNode(id)
	} else {
		err = m.serviceCommand(ctx, node.ServiceManager, action, node.ServiceName)
		if err == nil {
			status := "active"
			if action == "stop" {
				status = "inactive"
			}
			_ = m.store.SetNodeStatus(id, status)
		}
	}
	if err == nil {
		_ = m.store.Audit("admin", "node_"+action, node.ID, node.Name)
	}
	return err
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
	if err := command(ctx, m.cfg.SingBoxBin, "check", "-c", node.ConfigPath); err != nil {
		return fail(singboxconfig.ProbeResult{}, fmt.Errorf("configuration check failed: %w", err))
	}
	result, err := singboxconfig.ProbeConfigInbound(ctx, m.cfg.SingBoxBin, node.ConfigPath, node.Protocol, node.ListenPort)
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
		_ = m.store.SetNodeStatus(node.ID, m.serviceStatus(ctx, node.ServiceManager, node.ServiceName))
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

func (m *Manager) cleanupFailedCreate(ctx context.Context, node model.Node) error {
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
	root := map[string]any{"log": map[string]any{"level": "warn", "timestamp": true}, "inbounds": []any{inbound}, "outbounds": outbounds, "route": map[string]any{"rules": rules, "final": final}}
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
	return nil
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
func preferredCandidateName(tag, path string, index, port int, protocol, known string) string {
	if strings.TrimSpace(known) != "" && !genericNodeName(known) {
		return known
	}
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
