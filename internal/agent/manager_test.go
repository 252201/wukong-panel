package agent

import (
	"context"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/config"
	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/security"
	"github.com/252201/wukong-panel/internal/store"
)

func newDemoManager(t *testing.T) (*Manager, *store.Store) {
	t.Helper()
	dir := t.TempDir()
	database, err := store.Open(filepath.Join(dir, "wukong.db"))
	if err != nil {
		t.Fatal(err)
	}
	vault, err := security.OpenVault(dir)
	if err != nil {
		database.Close()
		t.Fatal(err)
	}
	manager := NewManager(config.Config{ConfigDir: filepath.Join(dir, "configs"), DataDir: dir, SecretDir: filepath.Join(dir, "secrets"), Demo: true}, database, vault)
	t.Cleanup(func() { database.Close() })
	return manager, database
}

func baseRequest() model.NodeCreateRequest {
	return model.NodeCreateRequest{Protocol: protocolHysteria2, Name: "Test", Mode: "prefer_v6", IPv4Bind: "192.0.2.5", IPv6Bind: "2001:db8::5", V6OnlyDomains: []string{"chatgpt.com"}}
}

func TestBuildLegacyConfig(t *testing.T) {
	payload, err := buildConfig(baseRequest(), 45080, protocolCredentials{Password: "secret"}, "/tmp/cert", "/tmp/key", "1.10.7")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	if !strings.Contains(text, `"domain_strategy": "prefer_ipv6"`) {
		t.Fatal("legacy domain strategy missing")
	}
	if strings.Contains(text, `"domain_resolver"`) {
		t.Fatal("legacy config contains modern resolver")
	}
}

func TestBuildModernConfig(t *testing.T) {
	payload, err := buildConfig(baseRequest(), 45080, protocolCredentials{Password: "secret"}, "/tmp/cert", "/tmp/key", "1.13.14")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err := json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	if root["dns"] == nil {
		t.Fatal("modern DNS configuration missing")
	}
	inbound := root["inbounds"].([]any)[0].(map[string]any)
	if inbound["tag"] != "hy2-Test-in" {
		t.Fatalf("node name not preserved in inbound tag: %v", inbound["tag"])
	}
	text := string(payload)
	if !strings.Contains(text, `"domain_resolver"`) || !strings.Contains(text, `"action": "sniff"`) {
		t.Fatal("modern migration fields missing")
	}
	if strings.Contains(text, `"domain_strategy"`) {
		t.Fatal("modern config contains removed domain_strategy")
	}
}

func TestBuildDeviceGroupConfigContainsMultipleInbounds(t *testing.T) {
	request := baseRequest()
	first, err := buildProtocolInbound(request, 45115, protocolCredentials{Password: "first-secret"}, "/tmp/device.cer", "/tmp/device.key")
	if err != nil {
		t.Fatal(err)
	}
	secondRequest := request
	secondRequest.Name = "Second"
	second, err := buildProtocolInbound(secondRequest, 45116, protocolCredentials{Password: "second-secret"}, "/tmp/device.cer", "/tmp/device.key")
	if err != nil {
		t.Fatal(err)
	}
	payload, err := buildConfigWithInbounds(request, []any{first, second}, "1.13.14")
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) != 2 {
		t.Fatalf("device group config has %d inbounds, want 2", len(inbounds))
	}
}

func TestMergeLegacyDeviceConfigsSelectsEachNodeInbound(t *testing.T) {
	dir := t.TempDir()
	paths := []string{filepath.Join(dir, "first.json"), filepath.Join(dir, "second.json")}
	for index, path := range paths {
		payload := fmt.Sprintf(`{"inbounds":[{"type":"hysteria2","tag":"device-%d","listen_port":%d}],"outbounds":[{"type":"direct","tag":"direct"}]}`, index+1, 45115+index)
		if err := os.WriteFile(path, []byte(payload), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	nodes := []model.Node{
		{Name: "one", ListenPort: 45115, ConfigPath: paths[0]},
		{Name: "two", ListenPort: 45116, ConfigPath: paths[1]},
	}
	payload, err := mergeDeviceGroupConfigs(nodes)
	if err != nil {
		t.Fatal(err)
	}
	var root map[string]any
	if err = json.Unmarshal(payload, &root); err != nil {
		t.Fatal(err)
	}
	inbounds, _ := root["inbounds"].([]any)
	if len(inbounds) != 2 || int(numberValue(inbounds[0].(map[string]any)["listen_port"])) != 45115 || int(numberValue(inbounds[1].(map[string]any)["listen_port"])) != 45116 {
		t.Fatalf("legacy device inbounds were not merged correctly: %#v", inbounds)
	}
}

func TestPreferredCandidateName(t *testing.T) {
	if got := preferredCandidateName("hy2-in", "/etc/s-box/wukong-random.json", 0, 59904, protocolHysteria2); got != "悟空节点 · 59904" {
		t.Fatalf("generic inbound tag not replaced: %q", got)
	}
	if got := preferredCandidateName("hy2-Mac mini-in", "/etc/s-box/node.json", 0, 45116, protocolHysteria2); got != "Mac mini" {
		t.Fatalf("descriptive inbound tag changed: %q", got)
	}
}

func TestVirtualBindInterfaceFiltering(t *testing.T) {
	for _, name := range []string{"tun0", "utun4", "wg0", "docker0", "br-abcd", "veth123", "tailscale0"} {
		if !virtualBindInterface(name) {
			t.Fatalf("virtual interface %q was not filtered", name)
		}
	}
	for _, name := range []string{"eth0", "ens3", "enp1s0"} {
		if virtualBindInterface(name) {
			t.Fatalf("host interface %q was filtered", name)
		}
	}
}

func TestDeploymentDefaultsUsesPanelDomain(t *testing.T) {
	manager := &Manager{cfg: config.Config{PanelDomain: " panel.example.com "}}
	defaults, err := manager.DeploymentDefaults(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	if defaults.PanelDomain != "panel.example.com" || defaults.IPv4 == nil || defaults.IPv6 == nil {
		t.Fatalf("unexpected deployment defaults: %#v", defaults)
	}
}

func TestRenameUpdatesOnlyNodeMetadata(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	node := model.Node{ID: "node-1", Name: "旧名称", Protocol: "hysteria2", Mode: "v6only", ListenPort: 45119, ServiceName: "sing-box-node-1", ServiceManager: "openrc", ConfigPath: "/etc/s-box/node-1.json", ConfigVersion: "1.13.14", Ownership: "managed", Status: "active"}
	if err := database.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{store: database}
	if err := manager.Rename(t.Context(), node.ID, model.NodeRenameRequest{Name: "  新名称  "}); err != nil {
		t.Fatal(err)
	}
	renamed, err := database.Node(t.Context(), node.ID, false)
	if err != nil || renamed.Name != "新名称" || renamed.ConfigPath != node.ConfigPath || renamed.ServiceName != node.ServiceName {
		t.Fatalf("unexpected renamed node: %#v, %v", renamed, err)
	}
	if err := manager.Rename(t.Context(), node.ID, model.NodeRenameRequest{Name: "   "}); err == nil {
		t.Fatal("blank node name accepted")
	}
	if err := manager.Rename(t.Context(), node.ID, model.NodeRenameRequest{Name: strings.Repeat("名", 81)}); err == nil {
		t.Fatal("overlong Unicode node name accepted")
	}
}

func TestEditDeviceNodePreservesCredentialAndUpdatesSharedRuntime(t *testing.T) {
	manager, database := newDemoManager(t)
	requests := []model.NodeCreateRequest{
		{Protocol: protocolHysteria2, Name: "iPhone", Mode: "prefer_v6", ListenPort: 45115, Server: "node.example.com", Domain: "node.example.com", IPv4Bind: "192.0.2.5", IPv6Bind: "2001:db8::5", AutoBind: true, V6OnlyDomains: []string{"chatgpt.com"}},
		{Protocol: protocolHysteria2, Name: "Mac", Mode: "prefer_v6", ListenPort: 45116, Server: "node.example.com", Domain: "node.example.com", IPv4Bind: "192.0.2.5", IPv6Bind: "2001:db8::5", AutoBind: true, V6OnlyDomains: []string{"chatgpt.com"}},
	}
	nodes, err := manager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: requests})
	if err != nil {
		t.Fatal(err)
	}
	before, err := database.Node(t.Context(), nodes[0].ID, true)
	if err != nil {
		t.Fatal(err)
	}
	beforeSecret, err := manager.vault.Decrypt(before.Secret)
	if err != nil {
		t.Fatal(err)
	}
	edit := model.NodeEditRequest{Name: "iPhone18", Mode: "v4only", ListenPort: 45125, Server: "new.example.com", Domain: "new.example.com", IPv4Bind: "192.0.2.8", AutoBind: false}
	if err = manager.Edit(t.Context(), nodes[0].ID, edit); err != nil {
		t.Fatal(err)
	}
	first, err := database.Node(t.Context(), nodes[0].ID, true)
	if err != nil {
		t.Fatal(err)
	}
	second, err := database.Node(t.Context(), nodes[1].ID, false)
	if err != nil {
		t.Fatal(err)
	}
	afterSecret, err := manager.vault.Decrypt(first.Secret)
	if err != nil {
		t.Fatal(err)
	}
	if first.Name != "iPhone18" || first.ListenPort != 45125 || first.Server != "new.example.com" || first.Mode != "v4only" || first.IPv4Bind != "192.0.2.8" || first.IPv6Bind != "" {
		t.Fatalf("unexpected edited node: %#v", first)
	}
	if second.Name != "Mac" || second.ListenPort != 45116 || second.Mode != "v4only" || second.IPv4Bind != "192.0.2.8" || second.IPv6Bind != "" {
		t.Fatalf("shared runtime settings not propagated: %#v", second)
	}
	if beforeSecret != afterSecret {
		t.Fatal("editing changed the node credential")
	}
}

func TestDemoProbeActionStoresSuccessfulRoundTrip(t *testing.T) {
	database, err := store.Open(filepath.Join(t.TempDir(), "test.db"))
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	node := model.Node{ID: "probe-demo", Name: "检测节点", Protocol: "vless", Mode: "v6only", ListenPort: 28441, ServiceName: "sing-box-probe", ServiceManager: "openrc", ConfigPath: "/etc/s-box/probe.json", ConfigVersion: "1.13.14", Ownership: "managed", Status: "active"}
	if err = database.UpsertNode(t.Context(), node, "encrypted"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: config.Config{Demo: true}, store: database}
	if err = manager.Action(t.Context(), node.ID, "probe", ""); err != nil {
		t.Fatal(err)
	}
	stored, err := database.Node(t.Context(), node.ID, false)
	if err != nil || stored.ProbeStatus != "success" || stored.ProbeLatencyMS != 42 || stored.ProbeExitIP == "" {
		t.Fatalf("unexpected demo probe result: %#v err=%v", stored, err)
	}
}

func TestBuildRuleActionConfig(t *testing.T) {
	payload, err := buildConfig(baseRequest(), 45080, protocolCredentials{Password: "secret"}, "/tmp/cert", "/tmp/key", "1.11.15")
	if err != nil {
		t.Fatal(err)
	}
	text := string(payload)
	if !strings.Contains(text, `"action": "sniff"`) || !strings.Contains(text, `"domain_strategy"`) || strings.Contains(text, `"domain_resolver"`) {
		t.Fatalf("1.11 capability split is incorrect: %s", text)
	}
}

func TestValidateCreateRejectsUnsafeValues(t *testing.T) {
	request := baseRequest()
	request.Mode = "unknown"
	if validateCreate(request) == nil {
		t.Fatal("invalid mode accepted")
	}
	request = baseRequest()
	request.IPv4Bind = "$(touch /tmp/nope)"
	if validateCreate(request) == nil {
		t.Fatal("invalid IP accepted")
	}
}

func TestNormalizeModeBindingsDropsUnusedAddressFamily(t *testing.T) {
	v6 := baseRequest()
	v6.Mode = "v6only"
	v6 = normalizeModeBindings(v6)
	if v6.IPv4Bind != "" || v6.IPv6Bind == "" {
		t.Fatalf("IPv6-only bindings were not normalized: %#v", v6)
	}
	v4 := baseRequest()
	v4.Mode = "v4only"
	v4 = normalizeModeBindings(v4)
	if v4.IPv6Bind != "" || v4.IPv4Bind == "" {
		t.Fatalf("IPv4-only bindings were not normalized: %#v", v4)
	}
}

func TestCreateBatchSupportsEveryProtocol(t *testing.T) {
	for _, protocol := range []string{protocolHysteria2, protocolVLESS, protocolVLESSWSTunnel, protocolShadowsocks, protocolTUIC, protocolTrojan} {
		t.Run(protocol, func(t *testing.T) {
			manager, database := newDemoManager(t)
			requests := make([]model.NodeCreateRequest, 2)
			for index := range requests {
				requests[index] = model.NodeCreateRequest{Protocol: protocol, Name: fmt.Sprintf("%s-device-%d", protocol, index+1), Mode: "prefer_v6", Server: "node.example.com", Domain: "node.example.com", IPv4Bind: "192.0.2.5", IPv6Bind: "2001:db8::5", AutoBind: true}
				if protocol == protocolVLESS {
					requests[index].Domain = realityDefaultSNI
				}
				if protocol == protocolVLESSWSTunnel {
					requests[index].Server = fmt.Sprintf("device-%d.example.com", index+1)
					requests[index].Domain = requests[index].Server
					requests[index].TunnelToken = "eyJ" + strings.Repeat("a", 90) + ".signature"
				}
			}
			nodes, err := manager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: requests})
			if err != nil {
				t.Fatal(err)
			}
			if len(nodes) != 2 || nodes[0].SharedGroup == "" || nodes[0].SharedGroup != nodes[1].SharedGroup || nodes[0].ListenPort == nodes[1].ListenPort {
				t.Fatalf("invalid device batch: %#v", nodes)
			}
			if nodes[0].ServiceName != nodes[1].ServiceName || nodes[0].ConfigPath != nodes[1].ConfigPath {
				t.Fatalf("device batch does not share one sing-box runtime: %#v", nodes)
			}
			if protocol == protocolVLESSWSTunnel && cloudflaredNodeKey(nodes[0]) != cloudflaredNodeKey(nodes[1]) {
				t.Fatalf("Tunnel devices did not share one connector: %#v", nodes)
			}
			stored, err := database.Nodes(context.Background())
			if err != nil || len(stored) != 2 {
				t.Fatalf("batch was not persisted: %#v err=%v", stored, err)
			}
		})
	}
}

func TestDeviceGroupLifecycleUpdatesEveryNode(t *testing.T) {
	manager, database := newDemoManager(t)
	requests := []model.NodeCreateRequest{
		{Protocol: protocolHysteria2, Name: "one", Mode: "prefer_v6", Server: "node.example.com", Domain: "node.example.com", IPv6Bind: "2001:db8::5"},
		{Protocol: protocolHysteria2, Name: "two", Mode: "prefer_v6", Server: "node.example.com", Domain: "node.example.com", IPv6Bind: "2001:db8::5"},
	}
	nodes, err := manager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: requests})
	if err != nil {
		t.Fatal(err)
	}
	if err = manager.Action(t.Context(), nodes[0].ID, "stop", ""); err != nil {
		t.Fatal(err)
	}
	stored, err := database.Nodes(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	for _, node := range stored {
		if node.Status != "inactive" {
			t.Fatalf("group member %s remained %s", node.Name, node.Status)
		}
	}
}

func TestCreateBatchRejectsInvalidWholeBatchBeforeCreatingNodes(t *testing.T) {
	manager, database := newDemoManager(t)
	request := model.NodeCreateRequest{Protocol: protocolHysteria2, Name: "same", Mode: "prefer_v6", Server: "node.example.com", Domain: "node.example.com", IPv6Bind: "2001:db8::5"}
	_, err := manager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: []model.NodeCreateRequest{request, request}})
	if err == nil {
		t.Fatal("duplicate device batch accepted")
	}
	nodes, listErr := database.Nodes(t.Context())
	if listErr != nil || len(nodes) != 0 {
		t.Fatalf("invalid batch created partial nodes: %#v err=%v", nodes, listErr)
	}
}

func TestTunnelBatchRequiresOneSharedTokenAndDistinctHostnames(t *testing.T) {
	manager, _ := newDemoManager(t)
	base := model.NodeCreateRequest{Protocol: protocolVLESSWSTunnel, Name: "one", Mode: "prefer_v6", Server: "one.example.com", WebSocketPath: "/device-one", IPv6Bind: "2001:db8::5", TunnelToken: "eyJ" + strings.Repeat("a", 90) + ".signature"}
	second := base
	second.Name = "two"
	second.Server = "two.example.com"
	second.WebSocketPath = "/device-two"
	second.TunnelToken = "eyJ" + strings.Repeat("b", 90) + ".signature"
	if _, err := manager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: []model.NodeCreateRequest{base, second}}); err == nil || !strings.Contains(err.Error(), "same Tunnel token") {
		t.Fatalf("different Tunnel tokens were not rejected: %v", err)
	}
	second.TunnelToken = base.TunnelToken
	if nodes, err := manager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: []model.NodeCreateRequest{base, second}}); err != nil || len(nodes) != 2 {
		t.Fatalf("distinct Tunnel hostnames were rejected: nodes=%#v err=%v", nodes, err)
	}

	duplicateManager, _ := newDemoManager(t)
	second.Server = base.Server
	if _, err := duplicateManager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: []model.NodeCreateRequest{base, second}}); err == nil || !strings.Contains(err.Error(), "duplicate Cloudflare hostname") {
		t.Fatalf("duplicate Tunnel hostnames were not rejected: %v", err)
	}
}

func TestSharedTunnelConnectorIsRemovedOnlyWithLastDevice(t *testing.T) {
	manager, database := newDemoManager(t)
	token := "eyJ" + strings.Repeat("a", 90) + ".signature"
	requests := []model.NodeCreateRequest{
		{Protocol: protocolVLESSWSTunnel, Name: "one", Mode: "prefer_v6", Server: "one.example.com", IPv6Bind: "2001:db8::5", TunnelToken: token},
		{Protocol: protocolVLESSWSTunnel, Name: "two", Mode: "prefer_v6", Server: "two.example.com", IPv6Bind: "2001:db8::5", TunnelToken: token},
	}
	nodes, err := manager.CreateBatch(t.Context(), model.NodeBatchCreateRequest{Nodes: requests})
	if err != nil {
		t.Fatal(err)
	}
	remove, err := manager.shouldRemoveTunnelConnector(t.Context(), nodes[0])
	if err != nil || remove {
		t.Fatalf("shared connector would be removed while two devices remain: remove=%v err=%v", remove, err)
	}
	if err = database.DeleteNode(nodes[0].ID); err != nil {
		t.Fatal(err)
	}
	remove, err = manager.shouldRemoveTunnelConnector(t.Context(), nodes[1])
	if err != nil || !remove {
		t.Fatalf("last device would leave shared connector behind: remove=%v err=%v", remove, err)
	}
}

func TestCertificatePathsReuseTrustedPanelCertificate(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "panel.cer")
	keyPath := filepath.Join(dir, "panel.key")
	if err := generateSelfSigned(keyPath, certPath, "node.example.com"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: config.Config{ConfigDir: dir, TLSCertFile: certPath, TLSKeyFile: keyPath}}
	request := baseRequest()
	request.Domain = "node.example.com"
	cert, key, generate, err := manager.certificatePaths(request, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cert != certPath || key != keyPath || generate {
		t.Fatalf("trusted certificate not reused: cert=%s key=%s generate=%v", cert, key, generate)
	}
}

func TestCertificatePathsFallBackWhenDomainDoesNotMatch(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "panel.cer")
	keyPath := filepath.Join(dir, "panel.key")
	if err := generateSelfSigned(keyPath, certPath, "panel.example.com"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: config.Config{ConfigDir: dir, TLSCertFile: certPath, TLSKeyFile: keyPath}}
	request := baseRequest()
	request.Domain = "node.example.com"
	cert, key, generate, err := manager.certificatePaths(request, "test")
	if err != nil {
		t.Fatal(err)
	}
	if cert != filepath.Join(dir, "wukong-test.cer") || key != filepath.Join(dir, "wukong-test.key") || !generate {
		t.Fatalf("expected self-signed fallback: cert=%s key=%s generate=%v", cert, key, generate)
	}
}

func TestGeneratedSelfSignedCertificateHasSAN(t *testing.T) {
	dir := t.TempDir()
	for _, domain := range []string{"node.example.com", "2001:db8::10"} {
		certPath := filepath.Join(dir, strings.NewReplacer(":", "-", ".", "-").Replace(domain)+".cer")
		keyPath := certPath + ".key"
		if err := generateSelfSigned(keyPath, certPath, domain); err != nil {
			t.Fatal(err)
		}
		if !certificateCoversDomain(certPath, domain) {
			t.Fatalf("generated certificate does not cover %s", domain)
		}
	}
}

func TestExplicitCertificateMustCoverTLSDomain(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "panel.cer")
	keyPath := filepath.Join(dir, "panel.key")
	if err := generateSelfSigned(keyPath, certPath, "panel.example.com"); err != nil {
		t.Fatal(err)
	}
	manager := &Manager{cfg: config.Config{ConfigDir: dir}}
	request := baseRequest()
	request.Domain = "node.example.com"
	request.CertificatePath = certPath
	request.KeyPath = keyPath
	if _, _, _, err := manager.certificatePaths(request, "test"); err == nil {
		t.Fatal("mismatched explicit certificate accepted")
	}
}

func TestSelfSignedNodeConfigIsDetectedForShareLink(t *testing.T) {
	dir := t.TempDir()
	certPath := filepath.Join(dir, "node.cer")
	keyPath := filepath.Join(dir, "node.key")
	if err := generateSelfSigned(keyPath, certPath, "node.example.com"); err != nil {
		t.Fatal(err)
	}
	payload, err := buildConfig(baseRequest(), 45080, protocolCredentials{Password: "secret"}, certPath, keyPath, "1.10.7")
	if err != nil {
		t.Fatal(err)
	}
	configPath := filepath.Join(dir, "node.json")
	if err = os.WriteFile(configPath, payload, 0o600); err != nil {
		t.Fatal(err)
	}
	if !configUsesSelfSignedCertificate(configPath) {
		t.Fatal("self-signed node certificate was not detected")
	}
}
