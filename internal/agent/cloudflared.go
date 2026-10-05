package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

const cloudflaredTokenFileMin = "2025.4.0"

var cloudflaredInstallMu sync.Mutex

func (m *Manager) ensureCloudflared(ctx context.Context) (string, error) {
	if err := m.cloudflaredUpdater().Recover(ctx); err != nil {
		return "", err
	}
	path := m.cloudflaredUpdater().Binary
	if err := validateCloudflaredRuntime(ctx, path); err == nil {
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", fmt.Errorf("cloudflared binary is unusable: %w", err)
	}
	cloudflaredInstallMu.Lock()
	defer cloudflaredInstallMu.Unlock()
	if err := validateCloudflaredRuntime(ctx, path); err == nil {
		return path, nil
	} else if !errors.Is(err, os.ErrNotExist) {
		return "", err
	}
	if err := m.cloudflaredUpdater().Install(ctx); err != nil {
		return "", err
	}
	return path, nil
}

func validateExecutable(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if !info.Mode().IsRegular() || info.Mode().Perm()&0o111 == 0 {
		return errors.New("file is not an executable regular file")
	}
	return nil
}

func validateCloudflaredRuntime(ctx context.Context, path string) error {
	if err := validateExecutable(path); err != nil {
		return err
	}
	output, err := exec.CommandContext(ctx, path, "--version").CombinedOutput()
	if err != nil {
		return fmt.Errorf("cloudflared --version: %w: %s", err, strings.TrimSpace(string(output)))
	}
	if !cloudflaredSupportsTokenFile(string(output)) {
		return fmt.Errorf("cloudflared %s or newer is required for protected token-file startup", cloudflaredTokenFileMin)
	}
	return nil
}

func cloudflaredSupportsTokenFile(output string) bool {
	fields := strings.Fields(output)
	for index, field := range fields {
		if !strings.EqualFold(field, "version") || index+1 >= len(fields) {
			continue
		}
		parts := strings.Split(strings.TrimPrefix(fields[index+1], "v"), ".")
		minimum := strings.Split(cloudflaredTokenFileMin, ".")
		if len(parts) < 2 || len(minimum) < 2 {
			return false
		}
		for position := 0; position < 2; position++ {
			actual, actualErr := strconv.Atoi(parts[position])
			wanted, wantedErr := strconv.Atoi(minimum[position])
			if actualErr != nil || wantedErr != nil {
				return false
			}
			if actual != wanted {
				return actual > wanted
			}
		}
		return true
	}
	return false
}

func cloudflaredServiceName(nodeID string) string {
	return "cloudflared-wukong-" + nodeID
}

func cloudflaredNodeKey(node model.Node) string {
	if node.Ownership == "managed" && strings.TrimSpace(node.SharedGroup) != "" {
		return node.SharedGroup
	}
	return node.ID
}

func (m *Manager) cloudflaredTokenPath(nodeID string) string {
	root := strings.TrimSpace(m.cfg.SecretDir)
	if root == "" {
		root = filepath.Join(m.cfg.DataDir, "secrets")
	}
	return filepath.Join(root, "cloudflared", nodeID+".token")
}

func (m *Manager) installCloudflaredService(ctx context.Context, nodeID, manager, binary, token string) error {
	tokenPath := m.cloudflaredTokenPath(nodeID)
	if err := os.MkdirAll(filepath.Dir(tokenPath), 0o700); err != nil {
		return err
	}
	tokenTmp := tokenPath + ".tmp"
	if err := os.WriteFile(tokenTmp, []byte(strings.TrimSpace(token)+"\n"), 0o600); err != nil {
		return err
	}
	if err := os.Rename(tokenTmp, tokenPath); err != nil {
		_ = os.Remove(tokenTmp)
		return err
	}
	service := cloudflaredServiceName(nodeID)
	if manager == "systemd" {
		unit := fmt.Sprintf(`[Unit]
Description=Wukong managed Cloudflare Tunnel %s
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=root
ExecStart=%s tunnel --no-autoupdate run --token-file %s
Restart=on-failure
RestartSec=5s
UMask=0077
NoNewPrivileges=true
PrivateTmp=true
ProtectHome=read-only
ProtectSystem=strict
ProtectKernelTunables=true
ProtectKernelModules=true
ProtectControlGroups=true
RestrictSUIDSGID=true
LockPersonality=true
CapabilityBoundingSet=
AmbientCapabilities=

[Install]
WantedBy=multi-user.target
`, service, binary, tokenPath)
		unitPath := filepath.Join("/etc/systemd/system", service+".service")
		if err := os.WriteFile(unitPath, []byte(unit), 0o644); err != nil {
			return err
		}
		if err := command(ctx, "systemctl", "daemon-reload"); err != nil {
			return err
		}
		if err := command(ctx, "systemctl", "enable", "--now", service+".service"); err != nil {
			return err
		}
	} else {
		script := fmt.Sprintf(`#!/sbin/openrc-run
name="%s"
command="%s"
command_args="tunnel --no-autoupdate run --token-file %s"
command_background=true
pidfile="/run/%s.pid"
output_log="/var/log/%s.log"
error_log="/var/log/%s.log"
depend(){ need net; after firewall; }
`, service, binary, tokenPath, service, service, service)
		initPath := filepath.Join("/etc/init.d", service)
		if err := os.WriteFile(initPath, []byte(script), 0o755); err != nil {
			return err
		}
		if err := command(ctx, "rc-update", "add", service, "default"); err != nil {
			return err
		}
		if err := command(ctx, "rc-service", service, "start"); err != nil {
			return err
		}
	}
	node := model.Node{ID: nodeID, ServiceManager: manager}
	for attempt := 0; attempt < 8; attempt++ {
		if m.cloudflaredStatus(ctx, node) == "active" {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(250 * time.Millisecond):
		}
	}
	return errors.New("cloudflared service did not become active; verify the Tunnel token")
}

func (m *Manager) cloudflaredStatus(ctx context.Context, node model.Node) string {
	return m.serviceStatus(ctx, node.ServiceManager, cloudflaredServiceName(cloudflaredNodeKey(node)))
}

func (m *Manager) removeCloudflaredService(ctx context.Context, node model.Node) error {
	key := cloudflaredNodeKey(node)
	serviceNode := node
	serviceNode.ServiceName = cloudflaredServiceName(key)
	_ = m.serviceCommand(ctx, serviceNode.ServiceManager, "stop", serviceNode.ServiceName)
	_ = m.disableService(ctx, serviceNode)
	serviceErr := m.removeService(serviceNode)
	tokenErr := os.Remove(m.cloudflaredTokenPath(key))
	if errors.Is(serviceErr, os.ErrNotExist) {
		serviceErr = nil
	}
	if errors.Is(tokenErr, os.ErrNotExist) {
		tokenErr = nil
	}
	if serviceErr != nil {
		return serviceErr
	}
	return tokenErr
}

func (m *Manager) checkCloudflaredNode(ctx context.Context, node model.Node) error {
	binary := strings.TrimSpace(m.cfg.CloudflaredBin)
	if binary == "" {
		binary = "/usr/local/bin/cloudflared"
	}
	if err := validateCloudflaredRuntime(ctx, binary); err != nil {
		return fmt.Errorf("cloudflared binary: %w", err)
	}
	info, err := os.Stat(m.cloudflaredTokenPath(cloudflaredNodeKey(node)))
	if err != nil {
		return fmt.Errorf("Cloudflare Tunnel token file: %w", err)
	}
	if info.Mode().Perm() != 0o600 {
		return fmt.Errorf("Cloudflare Tunnel token file permissions are %04o, want 0600", info.Mode().Perm())
	}
	return nil
}
