package agent

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"path/filepath"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"github.com/252201/wukong-panel/internal/singboxconfig"
)

const socksExitStateFile = "socks-exit.json"

type socksExitState struct {
	Server         string `json:"server"`
	Port           int    `json:"port"`
	Version        string `json:"version"`
	Username       string `json:"username,omitempty"`
	PasswordCipher string `json:"passwordCipher,omitempty"`
	Network        string `json:"network"`
	ExpectedExitIP string `json:"expectedExitIp,omitempty"`
	ProbeExitIP    string `json:"probeExitIp,omitempty"`
	ProbeLatencyMS int64  `json:"probeLatencyMs,omitempty"`
	ProbeCheckedAt int64  `json:"probeCheckedAt,omitempty"`
}

func (m *Manager) socksStatePath() string {
	return filepath.Join(m.cfg.SecretDir, socksExitStateFile)
}

func (m *Manager) loadSOCKSExit() (socksExitState, error) {
	data, err := os.ReadFile(m.socksStatePath())
	if err != nil {
		return socksExitState{}, err
	}
	var state socksExitState
	if err = json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	return state, nil
}

func (m *Manager) saveSOCKSExit(state socksExitState) error {
	if err := os.MkdirAll(m.cfg.SecretDir, 0o700); err != nil {
		return err
	}
	if err := os.Chmod(m.cfg.SecretDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	if err = m.backupSOCKSExit(); err != nil {
		return err
	}
	file, err := os.CreateTemp(m.cfg.SecretDir, ".socks-exit-*.tmp")
	if err != nil {
		return err
	}
	tmp := file.Name()
	defer os.Remove(tmp)
	if err = file.Chmod(0o600); err == nil {
		_, err = file.Write(data)
	}
	if err == nil {
		err = file.Sync()
	}
	if closeErr := file.Close(); err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(tmp, m.socksStatePath()); err != nil {
		return err
	}
	return os.Chmod(m.socksStatePath(), 0o600)
}

func (m *Manager) backupSOCKSExit() error {
	data, err := os.ReadFile(m.socksStatePath())
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	dir := filepath.Join(m.cfg.DataDir, "backups")
	if err = os.MkdirAll(dir, 0o700); err != nil {
		return err
	}
	name := fmt.Sprintf("socks-exit-%d.json", time.Now().UnixNano())
	return os.WriteFile(filepath.Join(dir, name), data, 0o600)
}

func (m *Manager) socksExitConfigured() bool {
	state, err := m.loadSOCKSExit()
	return err == nil && state.Server != "" && state.Port > 0
}

func (m *Manager) decryptSOCKSPassword(state socksExitState) (string, error) {
	if state.PasswordCipher == "" {
		return "", nil
	}
	if m.vault == nil {
		if m.cfg.Demo {
			return state.PasswordCipher, nil
		}
		return "", errors.New("SOCKS credential vault is unavailable")
	}
	return m.vault.Decrypt(state.PasswordCipher)
}

func (m *Manager) encryptSOCKSPassword(password string) (string, error) {
	if password == "" {
		return "", nil
	}
	if m.vault == nil {
		if m.cfg.Demo {
			return password, nil
		}
		return "", errors.New("SOCKS credential vault is unavailable")
	}
	return m.vault.Encrypt(password)
}

func socksExitModel(state socksExitState) model.SOCKSExit {
	result := model.SOCKSExit{
		Configured:     state.Server != "" && state.Port > 0,
		Server:         state.Server,
		Port:           state.Port,
		Version:        state.Version,
		Username:       state.Username,
		HasPassword:    state.PasswordCipher != "",
		Network:        state.Network,
		ExpectedExitIP: state.ExpectedExitIP,
		ProbeExitIP:    state.ProbeExitIP,
		ProbeLatencyMS: state.ProbeLatencyMS,
	}
	if state.ProbeCheckedAt > 0 {
		result.ProbeCheckedAt = time.Unix(state.ProbeCheckedAt, 0).UTC().Format(time.RFC3339)
	}
	return result
}

func (m *Manager) SOCKSExit(_ context.Context) (model.SOCKSExit, error) {
	state, err := m.loadSOCKSExit()
	if errors.Is(err, os.ErrNotExist) {
		return model.SOCKSExit{Version: "5", Network: "both"}, nil
	}
	if err != nil {
		return model.SOCKSExit{}, err
	}
	return socksExitModel(state), nil
}

func normalizeSOCKSExitRequest(request model.SOCKSExitRequest) (model.SOCKSExitRequest, error) {
	request.Server = strings.TrimSpace(request.Server)
	request.Version = strings.ToLower(strings.TrimSpace(request.Version))
	request.Username = strings.TrimSpace(request.Username)
	request.Network = strings.ToLower(strings.TrimSpace(request.Network))
	request.ExpectedExitIP = strings.TrimSpace(request.ExpectedExitIP)
	if request.Version == "" {
		request.Version = "5"
	}
	if request.Network == "" {
		request.Network = "both"
	}
	serverIP := net.ParseIP(request.Server)
	if request.Server == "" || len(request.Server) > 253 || strings.ContainsAny(request.Server, "/@?#[] \t\r\n") || (serverIP == nil && strings.Contains(request.Server, ":")) {
		return request, errors.New("SOCKS server must be a hostname or IP address without a scheme or port")
	}
	if serverIP == nil && !validTunnelHostname(request.Server) {
		return request, errors.New("SOCKS server must be a valid hostname or IP address")
	}
	if request.Port < 1 || request.Port > 65535 {
		return request, errors.New("SOCKS port must be between 1 and 65535")
	}
	if request.Version != "4" && request.Version != "4a" && request.Version != "5" {
		return request, errors.New("SOCKS version must be 4, 4a or 5")
	}
	if request.Network != "both" && request.Network != "tcp" {
		return request, errors.New("SOCKS network must be both or tcp")
	}
	if request.Version != "5" && request.Network != "tcp" {
		return request, errors.New("SOCKS4/4a only supports TCP")
	}
	if request.Version != "5" && request.Password != "" {
		return request, errors.New("SOCKS password authentication requires SOCKS5")
	}
	if len(request.Username) > 255 || len(request.Password) > 512 {
		return request, errors.New("SOCKS credentials are too long")
	}
	if request.ExpectedExitIP != "" && net.ParseIP(request.ExpectedExitIP) == nil {
		return request, errors.New("expected SOCKS exit IP is invalid")
	}
	return request, nil
}

func (m *Manager) socksNodesInUse(ctx context.Context) ([]model.Node, error) {
	nodes, err := m.store.Nodes(ctx)
	if err != nil {
		return nil, err
	}
	result := []model.Node{}
	for _, node := range nodes {
		if node.Egress == "socks" {
			result = append(result, node)
		}
	}
	return result, nil
}

func socksStateConnectionEqual(a, b socksExitState) bool {
	return a.Server == b.Server && a.Port == b.Port && a.Version == b.Version &&
		a.Username == b.Username && a.PasswordCipher == b.PasswordCipher &&
		a.Network == b.Network && a.ExpectedExitIP == b.ExpectedExitIP
}

func (m *Manager) ConfigureSOCKSExit(ctx context.Context, request model.SOCKSExitRequest) (model.SOCKSExit, error) {
	request, err := normalizeSOCKSExitRequest(request)
	if err != nil {
		return model.SOCKSExit{}, err
	}
	current, currentErr := m.loadSOCKSExit()
	if currentErr != nil && !errors.Is(currentErr, os.ErrNotExist) {
		return model.SOCKSExit{}, currentErr
	}
	password := request.Password
	if password == "" && !request.ClearPassword && currentErr == nil {
		password, err = m.decryptSOCKSPassword(current)
		if err != nil {
			return model.SOCKSExit{}, err
		}
	}
	if request.Version != "5" {
		password = ""
	}
	passwordCipher, err := m.encryptSOCKSPassword(password)
	if err != nil {
		return model.SOCKSExit{}, err
	}
	next := socksExitState{
		Server:         request.Server,
		Port:           request.Port,
		Version:        request.Version,
		Username:       request.Username,
		PasswordCipher: passwordCipher,
		Network:        request.Network,
		ExpectedExitIP: request.ExpectedExitIP,
	}
	if currentErr == nil {
		// Re-encryption changes ciphertext even when the plaintext is unchanged.
		// Reuse the existing value so in-use comparisons stay deterministic.
		currentPassword, decryptErr := m.decryptSOCKSPassword(current)
		if decryptErr == nil && currentPassword == password {
			next.PasswordCipher = current.PasswordCipher
		}
	}
	inUse, err := m.socksNodesInUse(ctx)
	if err != nil {
		return model.SOCKSExit{}, err
	}
	if len(inUse) > 0 && (currentErr != nil || !socksStateConnectionEqual(current, next)) {
		return model.SOCKSExit{}, fmt.Errorf("SOCKS 出站正被 %d 个节点使用；请先将这些节点切回其他出口", len(inUse))
	}
	outbound := model.SOCKSOutbound{
		Server: request.Server, Port: request.Port, Version: request.Version,
		Username: request.Username, Password: password, Network: request.Network,
	}
	if m.cfg.Demo {
		next.ProbeExitIP = "203.0.113.18"
		next.ProbeLatencyMS = 42
		next.ProbeCheckedAt = time.Now().Unix()
	} else {
		config, dns := buildSOCKSOutbound(outbound, singboxconfig.CapabilitiesFor(m.Version(ctx)))
		result, probeErr := singboxconfig.ProbeOutbound(ctx, m.cfg.SingBoxBin, "socks", config, dns)
		if probeErr != nil {
			return model.SOCKSExit{}, fmt.Errorf("SOCKS 真实代理预检失败: %w", probeErr)
		}
		if request.ExpectedExitIP != "" && result.ExitIP != request.ExpectedExitIP {
			return model.SOCKSExit{}, fmt.Errorf("SOCKS 出口 IP 不匹配: got %s, want %s", result.ExitIP, request.ExpectedExitIP)
		}
		next.ProbeExitIP = result.ExitIP
		next.ProbeLatencyMS = result.LatencyMS
		next.ProbeCheckedAt = time.Now().Unix()
	}
	if err = m.saveSOCKSExit(next); err != nil {
		return model.SOCKSExit{}, err
	}
	_ = m.store.Audit("admin", "socks_exit_configure", "system", fmt.Sprintf("server=%s port=%d version=%s network=%s", request.Server, request.Port, request.Version, request.Network))
	return socksExitModel(next), nil
}

func (m *Manager) RemoveSOCKSExit(ctx context.Context, confirm string) error {
	if confirm != "REMOVE" {
		return errors.New("confirmation must be REMOVE")
	}
	inUse, err := m.socksNodesInUse(ctx)
	if err != nil {
		return err
	}
	if len(inUse) > 0 {
		return fmt.Errorf("SOCKS 出站正被 %d 个节点使用，无法移除", len(inUse))
	}
	if err = m.backupSOCKSExit(); err != nil {
		return err
	}
	if err = os.Remove(m.socksStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = m.store.Audit("admin", "socks_exit_remove", "system", "removed after node usage check")
	return nil
}

func (m *Manager) attachSOCKSOutbound(request model.NodeCreateRequest) (model.NodeCreateRequest, error) {
	if request.Egress != "socks" {
		request.SOCKSOutbound = nil
		return request, nil
	}
	state, err := m.loadSOCKSExit()
	if err != nil {
		if errors.Is(err, os.ErrNotExist) {
			return request, errors.New("SOCKS 出站尚未配置")
		}
		return request, err
	}
	password, err := m.decryptSOCKSPassword(state)
	if err != nil {
		return request, err
	}
	request.SOCKSOutbound = &model.SOCKSOutbound{
		Server: state.Server, Port: state.Port, Version: state.Version,
		Username: state.Username, Password: password, Network: state.Network,
	}
	return request, nil
}

func buildSOCKSOutbound(config model.SOCKSOutbound, capabilities singboxconfig.Capabilities) (map[string]any, map[string]any) {
	outbound := map[string]any{
		"type":        "socks",
		"tag":         "out-socks",
		"server":      config.Server,
		"server_port": config.Port,
		"version":     config.Version,
	}
	if config.Username != "" {
		outbound["username"] = config.Username
	}
	if config.Password != "" && config.Version == "5" {
		outbound["password"] = config.Password
	}
	if config.Network != "" && config.Network != "both" {
		outbound["network"] = config.Network
	}
	if capabilities.NewDNSServers {
		outbound["domain_resolver"] = map[string]any{"server": "local"}
		return outbound, map[string]any{"servers": []any{map[string]any{"type": "local", "tag": "local"}}}
	}
	outbound["domain_strategy"] = "prefer_ipv4"
	return outbound, nil
}
