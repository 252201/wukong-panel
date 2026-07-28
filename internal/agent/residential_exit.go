package agent

import (
	"context"
	"crypto/rand"
	"encoding/base64"
	"encoding/json"
	"errors"
	"fmt"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/crypto/curve25519"
)

const (
	residentialInterface  = "wukong-exit"
	residentialRouteMark  = 102
	residentialRouteTable = 166
	residentialTunnelA    = "10.77.0.1/30"
	residentialTunnelB    = "10.77.0.2/30"
	residentialStateFile  = "residential-exit.json"
)

type residentialExitState struct {
	Endpoint       string `json:"endpoint"`
	ListenPort     int    `json:"listenPort"`
	PrivateKey     string `json:"privateKey"`
	PublicKey      string `json:"publicKey"`
	PeerPublicKey  string `json:"peerPublicKey,omitempty"`
	ExpectedExitIP string `json:"expectedExitIp,omitempty"`
}

func (m *Manager) residentialStatePath() string {
	return filepath.Join(m.cfg.SecretDir, residentialStateFile)
}

func (m *Manager) residentialExitConfigured() bool {
	state, err := m.loadResidentialExit()
	return err == nil && state.PeerPublicKey != "" && (m.cfg.Demo || regularFile("/etc/wireguard/"+residentialInterface+".conf"))
}

func (m *Manager) loadResidentialExit() (residentialExitState, error) {
	data, err := os.ReadFile(m.residentialStatePath())
	if err != nil {
		return residentialExitState{}, err
	}
	var state residentialExitState
	if err = json.Unmarshal(data, &state); err != nil {
		return state, err
	}
	return state, nil
}

func (m *Manager) saveResidentialExit(state residentialExitState) error {
	if err := os.MkdirAll(m.cfg.SecretDir, 0o700); err != nil {
		return err
	}
	data, err := json.MarshalIndent(state, "", "  ")
	if err != nil {
		return err
	}
	tmp := m.residentialStatePath() + ".tmp"
	if err = os.WriteFile(tmp, data, 0o600); err != nil {
		return err
	}
	if err = os.Rename(tmp, m.residentialStatePath()); err != nil {
		return err
	}
	return os.Chmod(m.residentialStatePath(), 0o600)
}

func wireGuardKeyPair() (privateKey, publicKey string, err error) {
	private := make([]byte, curve25519.ScalarSize)
	if _, err = rand.Read(private); err != nil {
		return "", "", err
	}
	private[0] &= 248
	private[31] &= 127
	private[31] |= 64
	public, err := curve25519.X25519(private, curve25519.Basepoint)
	if err != nil {
		return "", "", err
	}
	return base64.StdEncoding.EncodeToString(private), base64.StdEncoding.EncodeToString(public), nil
}

func validateResidentialRequest(request model.ResidentialExitRequest) (model.ResidentialExitRequest, error) {
	request.Endpoint = strings.TrimSpace(strings.TrimSuffix(request.Endpoint, "."))
	request.PeerPublicKey = strings.TrimSpace(request.PeerPublicKey)
	request.ExpectedExitIP = strings.TrimSpace(request.ExpectedExitIP)
	if request.ListenPort == 0 {
		request.ListenPort = 51820
	}
	if request.ListenPort < 1 || request.ListenPort > 65535 {
		return request, errors.New("WireGuard 监听端口无效")
	}
	if net.ParseIP(request.Endpoint) == nil && !regexp.MustCompile(`(?i)^[a-z0-9](?:[a-z0-9.-]{0,251}[a-z0-9])?$`).MatchString(request.Endpoint) {
		return request, errors.New("A 机公网地址必须是 IP 或 DNS 主机名，不能包含协议或端口")
	}
	if request.PeerPublicKey != "" {
		decoded, err := base64.StdEncoding.DecodeString(request.PeerPublicKey)
		if err != nil || len(decoded) != curve25519.PointSize {
			return request, errors.New("B 机 WireGuard 公钥无效")
		}
	}
	if request.ExpectedExitIP != "" {
		ip := net.ParseIP(request.ExpectedExitIP)
		if ip == nil || ip.To4() == nil {
			return request, errors.New("预期住宅出口必须是 IPv4 地址")
		}
	}
	return request, nil
}

func (m *Manager) ResidentialExit(ctx context.Context) (model.ResidentialExit, error) {
	state, err := m.loadResidentialExit()
	if errors.Is(err, os.ErrNotExist) {
		return model.ResidentialExit{
			Interface: residentialInterface, ListenPort: 51820,
			TunnelAddress: residentialTunnelA, PeerAddress: residentialTunnelB,
		}, nil
	}
	if err != nil {
		return model.ResidentialExit{}, err
	}
	result := residentialExitModel(state)
	result.Configured = m.residentialExitConfigured()
	result.InstallScript = renderResidentialPeerScript(state)
	if state.PeerPublicKey == "" || m.cfg.Demo {
		return result, nil
	}
	if exec.CommandContext(ctx, "wg", "show", residentialInterface).Run() == nil {
		if output, showErr := exec.CommandContext(ctx, "wg", "show", residentialInterface, "latest-handshakes").Output(); showErr == nil {
			fields := strings.Fields(string(output))
			if len(fields) >= 2 {
				if unix, parseErr := strconv.ParseInt(fields[1], 10, 64); parseErr == nil && unix > 0 {
					handshake := time.Unix(unix, 0)
					result.LatestHandshake = handshake.UTC().Format(time.RFC3339)
					result.Active = time.Since(handshake) < 3*time.Minute
				}
			}
		}
		if output, showErr := exec.CommandContext(ctx, "wg", "show", residentialInterface, "transfer").Output(); showErr == nil {
			fields := strings.Fields(string(output))
			if len(fields) >= 3 {
				result.RXBytes, _ = strconv.ParseInt(fields[1], 10, 64)
				result.TXBytes, _ = strconv.ParseInt(fields[2], 10, 64)
			}
		}
	}
	return result, nil
}

func residentialExitModel(state residentialExitState) model.ResidentialExit {
	return model.ResidentialExit{
		Configured: state.PeerPublicKey != "", Interface: residentialInterface,
		Endpoint: state.Endpoint, ListenPort: state.ListenPort, PublicKey: state.PublicKey,
		PeerPublicKey: state.PeerPublicKey, TunnelAddress: residentialTunnelA,
		PeerAddress: residentialTunnelB, ExpectedExitIP: state.ExpectedExitIP,
	}
}

func (m *Manager) ConfigureResidentialExit(ctx context.Context, request model.ResidentialExitRequest) (model.ResidentialExit, error) {
	request, err := validateResidentialRequest(request)
	if err != nil {
		return model.ResidentialExit{}, err
	}
	state, loadErr := m.loadResidentialExit()
	if errors.Is(loadErr, os.ErrNotExist) {
		state.PrivateKey, state.PublicKey, err = wireGuardKeyPair()
		if err != nil {
			return model.ResidentialExit{}, err
		}
	} else if loadErr != nil {
		return model.ResidentialExit{}, loadErr
	}
	state.Endpoint, state.ListenPort = request.Endpoint, request.ListenPort
	state.PeerPublicKey, state.ExpectedExitIP = request.PeerPublicKey, request.ExpectedExitIP
	if err = m.saveResidentialExit(state); err != nil {
		return model.ResidentialExit{}, err
	}
	if state.PeerPublicKey == "" {
		result := residentialExitModel(state)
		result.InstallScript = renderResidentialPeerScript(state)
		return result, nil
	}
	if !m.cfg.Demo {
		if err = m.installResidentialExit(ctx, state); err != nil {
			return model.ResidentialExit{}, err
		}
	}
	_ = m.store.Audit("admin", "residential_exit_configure", residentialInterface, "peer configured; private key retained on A only")
	return m.ResidentialExit(ctx)
}

func (m *Manager) installResidentialExit(ctx context.Context, state residentialExitState) error {
	for _, binary := range []string{"wg", "wg-quick", "ip"} {
		if _, err := exec.LookPath(binary); err != nil {
			return fmt.Errorf("缺少 %s；请先安装 wireguard-tools 和 iproute2", binary)
		}
	}
	if err := os.MkdirAll("/etc/wireguard", 0o700); err != nil {
		return err
	}
	if err := os.WriteFile("/etc/wireguard/"+residentialInterface+".conf", []byte(renderResidentialLocalConfig(state)), 0o600); err != nil {
		return err
	}
	if err := os.WriteFile("/usr/local/sbin/wukong-exit-guard", []byte(renderResidentialGuardScript()), 0o755); err != nil {
		return err
	}
	manager := detectServiceManager()
	if manager == "openrc" {
		if err := os.WriteFile("/etc/init.d/wukong-exit-guard", []byte(renderResidentialGuardOpenRC()), 0o755); err != nil {
			return err
		}
		if err := os.WriteFile("/etc/init.d/wukong-exit", []byte(renderResidentialWireGuardOpenRC()), 0o755); err != nil {
			return err
		}
		if err := command(ctx, "rc-update", "add", "wukong-exit-guard", "default"); err != nil {
			return err
		}
		if err := command(ctx, "rc-update", "add", "wukong-exit", "default"); err != nil {
			return err
		}
		if err := command(ctx, "rc-service", "wukong-exit-guard", "restart"); err != nil {
			return err
		}
		return command(ctx, "rc-service", "wukong-exit", "restart")
	}
	if err := os.WriteFile("/etc/systemd/system/wukong-exit-guard.service", []byte(renderResidentialGuardSystemd()), 0o644); err != nil {
		return err
	}
	dropInDir := "/etc/systemd/system/wg-quick@" + residentialInterface + ".service.d"
	if err := os.MkdirAll(dropInDir, 0o755); err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(dropInDir, "wukong-guard.conf"), []byte("[Unit]\nRequires=wukong-exit-guard.service\nAfter=wukong-exit-guard.service\n"), 0o644); err != nil {
		return err
	}
	if err := command(ctx, "systemctl", "daemon-reload"); err != nil {
		return err
	}
	if err := command(ctx, "systemctl", "enable", "--now", "wukong-exit-guard.service"); err != nil {
		return err
	}
	if err := command(ctx, "systemctl", "enable", "wg-quick@"+residentialInterface+".service"); err != nil {
		return err
	}
	return command(ctx, "systemctl", "restart", "wg-quick@"+residentialInterface+".service")
}

func (m *Manager) RemoveResidentialExit(ctx context.Context, confirm string) error {
	if confirm != "REMOVE" {
		return errors.New("请输入 REMOVE 确认移除住宅出口")
	}
	nodes, err := m.store.Nodes(ctx)
	if err != nil {
		return err
	}
	for _, node := range nodes {
		if node.Egress == "residential" {
			return fmt.Errorf("节点 %s 仍在使用住宅出口，请先切换为本机直出", node.Name)
		}
	}
	if !m.cfg.Demo {
		if detectServiceManager() == "openrc" {
			_ = command(ctx, "rc-service", "wukong-exit", "stop")
			_ = command(ctx, "rc-service", "wukong-exit-guard", "stop")
			_ = command(ctx, "rc-update", "del", "wukong-exit", "default")
			_ = command(ctx, "rc-update", "del", "wukong-exit-guard", "default")
			_ = os.Remove("/etc/init.d/wukong-exit")
			_ = os.Remove("/etc/init.d/wukong-exit-guard")
		} else {
			_ = command(ctx, "systemctl", "disable", "--now", "wg-quick@"+residentialInterface+".service")
			_ = command(ctx, "systemctl", "disable", "--now", "wukong-exit-guard.service")
			_ = os.Remove("/etc/systemd/system/wukong-exit-guard.service")
			_ = os.RemoveAll("/etc/systemd/system/wg-quick@" + residentialInterface + ".service.d")
			_ = command(ctx, "systemctl", "daemon-reload")
		}
		_ = os.Remove("/etc/wireguard/" + residentialInterface + ".conf")
		_ = os.Remove("/usr/local/sbin/wukong-exit-guard")
	}
	if err = os.Remove(m.residentialStatePath()); err != nil && !errors.Is(err, os.ErrNotExist) {
		return err
	}
	_ = m.store.Audit("admin", "residential_exit_remove", residentialInterface, "removed after node usage check")
	return nil
}

func renderResidentialLocalConfig(state residentialExitState) string {
	return fmt.Sprintf(`[Interface]
PrivateKey = %s
Address = %s
ListenPort = %d
Table = off
PostUp = ip -4 route replace default dev %%i table %d metric 100
PreDown = ip -4 route del default dev %%i table %d metric 100 || true

[Peer]
PublicKey = %s
AllowedIPs = 0.0.0.0/0
`, state.PrivateKey, residentialTunnelA, state.ListenPort, residentialRouteTable, residentialRouteTable, state.PeerPublicKey)
}

func renderResidentialGuardScript() string {
	return fmt.Sprintf(`#!/bin/sh
set -eu
case "${1:-start}" in
  start)
    ip -4 route replace unreachable default metric 42760 table %d
    ip -6 route replace unreachable default metric 42760 table %d
    ip -4 rule add pref 100 fwmark %d/0xffffffff lookup %d 2>/dev/null || true
    ip -6 rule add pref 100 fwmark %d/0xffffffff lookup %d 2>/dev/null || true
    ;;
  stop)
    ip -4 rule del pref 100 fwmark %d/0xffffffff lookup %d 2>/dev/null || true
    ip -6 rule del pref 100 fwmark %d/0xffffffff lookup %d 2>/dev/null || true
    ip -4 route flush table %d 2>/dev/null || true
    ip -6 route flush table %d 2>/dev/null || true
    ;;
  *) exit 2 ;;
esac
`, residentialRouteTable, residentialRouteTable, residentialRouteMark, residentialRouteTable, residentialRouteMark, residentialRouteTable, residentialRouteMark, residentialRouteTable, residentialRouteMark, residentialRouteTable, residentialRouteTable, residentialRouteTable)
}

func renderResidentialGuardSystemd() string {
	return `[Unit]
Description=Wukong residential egress fail-closed policy
Before=wg-quick@wukong-exit.service

[Service]
Type=oneshot
RemainAfterExit=yes
ExecStart=/usr/local/sbin/wukong-exit-guard start
ExecStop=/usr/local/sbin/wukong-exit-guard stop

[Install]
WantedBy=multi-user.target
`
}

func renderResidentialGuardOpenRC() string {
	return `#!/sbin/openrc-run
description="Wukong residential egress fail-closed policy"
command="/usr/local/sbin/wukong-exit-guard"
command_args="start"
command_background="no"
depend() { before wukong-exit; need net; }
stop() { /usr/local/sbin/wukong-exit-guard stop; }
`
}

func renderResidentialWireGuardOpenRC() string {
	return `#!/sbin/openrc-run
description="Wukong residential WireGuard exit"
depend() { need net wukong-exit-guard; }
start() { wg-quick up wukong-exit; }
stop() { wg-quick down wukong-exit; }
`
}

func peerEndpoint(state residentialExitState) string {
	if ip := net.ParseIP(state.Endpoint); ip != nil && ip.To4() == nil {
		return "[" + state.Endpoint + "]:" + strconv.Itoa(state.ListenPort)
	}
	return state.Endpoint + ":" + strconv.Itoa(state.ListenPort)
}

func renderResidentialPeerScript(state residentialExitState) string {
	return fmt.Sprintf(`#!/bin/sh
set -eu
if [ "$(id -u)" -ne 0 ]; then echo "请以 root 运行"; exit 1; fi
if command -v apk >/dev/null 2>&1; then apk add --no-cache wireguard-tools iptables
elif command -v apt-get >/dev/null 2>&1; then apt-get update && apt-get install -y wireguard-tools iptables
elif command -v dnf >/dev/null 2>&1; then dnf install -y wireguard-tools iptables
else echo "不支持的包管理器，请手动安装 wireguard-tools 与 iptables"; exit 1; fi
umask 077
mkdir -p /etc/wireguard
PRIVATE_KEY="$(wg genkey)"
PUBLIC_KEY="$(printf '%%s' "$PRIVATE_KEY" | wg pubkey)"
cat > /etc/wireguard/wukong-exit.conf <<EOF
[Interface]
PrivateKey = $PRIVATE_KEY
Address = %s
Table = off
PostUp = sysctl -w net.ipv4.ip_forward=1; OUT_IF="\$(ip -4 route show default | awk 'NR==1 {print \$5}')"; iptables -A FORWARD -i %%i -j ACCEPT; iptables -A FORWARD -o %%i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT; iptables -t nat -A POSTROUTING -o "\$OUT_IF" -s 10.77.0.0/30 -j MASQUERADE
PostDown = OUT_IF="\$(ip -4 route show default | awk 'NR==1 {print \$5}')"; iptables -D FORWARD -i %%i -j ACCEPT || true; iptables -D FORWARD -o %%i -m conntrack --ctstate RELATED,ESTABLISHED -j ACCEPT || true; iptables -t nat -D POSTROUTING -o "\$OUT_IF" -s 10.77.0.0/30 -j MASQUERADE || true

[Peer]
PublicKey = %s
Endpoint = %s
AllowedIPs = 10.77.0.1/32
PersistentKeepalive = 25
EOF
printf 'net.ipv4.ip_forward=1\n' > /etc/sysctl.d/99-wukong-exit.conf
sysctl -w net.ipv4.ip_forward=1 >/dev/null
if command -v systemctl >/dev/null 2>&1; then
  systemctl enable --now wg-quick@wukong-exit.service
elif command -v rc-update >/dev/null 2>&1; then
  cat > /etc/init.d/wukong-exit <<'EOF'
#!/sbin/openrc-run
description="Wukong residential exit peer"
depend() { need net; }
start() { wg-quick up wukong-exit; }
stop() { wg-quick down wukong-exit; }
EOF
  chmod 0755 /etc/init.d/wukong-exit
  rc-update add wukong-exit default
  rc-service wukong-exit restart
fi
echo
echo "B_PUBLIC_KEY=$PUBLIC_KEY"
echo "只把上面的 B_PUBLIC_KEY 粘贴回悟空面板；不要发送私钥。"
echo "不再使用时：curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- --remove-residential-peer"
`, residentialTunnelB, state.PublicKey, peerEndpoint(state))
}
