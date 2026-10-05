package agent

import (
	"context"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"runtime"
	"sort"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/componentupdate"
	"github.com/252201/wukong-panel/internal/model"
)

func (m *Manager) cloudflaredUpdater() *componentupdate.Controller {
	binary := strings.TrimSpace(m.cfg.CloudflaredBin)
	if binary == "" {
		binary = "/usr/local/bin/cloudflared"
	}
	root := m.cfg.SecretDir
	if root == "" {
		root = filepath.Join(m.cfg.DataDir, "secrets")
	}
	c := componentupdate.New(filepath.Join(root, "cloudflared-update"), binary, runtime.GOARCH)
	c.Version = func(ctx context.Context, path string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if e := validateExecutable(path); e != nil {
			return "", e
		}
		out, e := exec.CommandContext(ctx, path, "--version").Output()
		if e != nil {
			return "", e
		}
		match := regexp.MustCompile(`\bversion (\d{4}\.\d{1,2}\.\d{1,3})\b`).FindStringSubmatch(string(out))
		if len(match) != 2 {
			return "", errors.New("cannot parse cloudflared version")
		}
		return match[1], nil
	}
	c.Services = m.cloudflaredUpdateServices
	c.Restart = m.restartUpdatedService
	return c
}

func (m *Manager) cloudflaredUpdateServices(ctx context.Context) ([]componentupdate.Service, error) {
	nodes, e := m.store.Nodes(ctx)
	if e != nil {
		return nil, e
	}
	services := map[string]componentupdate.Service{}
	for _, n := range nodes {
		if n.Ownership != "managed" || normalizeProtocol(n.Protocol) != protocolVLESSWSTunnel {
			continue
		}
		key := cloudflaredNodeKey(n)
		if !regexp.MustCompile(`^[A-Za-z0-9_-]+$`).MatchString(key) || (n.ServiceManager != "systemd" && n.ServiceManager != "openrc") {
			return nil, errors.New("unsupported connector service identity")
		}
		name := cloudflaredServiceName(key)
		if previous, ok := services[name]; ok && previous.Manager != n.ServiceManager {
			return nil, errors.New("conflicting connector service managers")
		}
		services[name] = componentupdate.Service{Name: name, Manager: n.ServiceManager}
	}
	if len(services) == 0 {
		return nil, errors.New("no Wukong-managed Tunnel connectors")
	}
	result := []componentupdate.Service{}
	for _, s := range services {
		if m.serviceStatus(ctx, s.Manager, s.Name) == "active" {
			result = append(result, s)
		}
	}
	sort.Slice(result, func(i, j int) bool { return result[i].Name < result[j].Name })
	if e := m.checkManagedRuntimeProcesses(m.cloudflaredUpdater().Binary, result); e != nil {
		return nil, e
	}
	return result, nil
}

func (m *Manager) Cloudflared(ctx context.Context, r model.CloudflaredRequest) (model.CloudflaredState, error) {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	if m.cfg.Demo {
		return model.CloudflaredState{Installed: true, CurrentVersion: "2026.8.2", LatestVersion: "2026.9.3", UpdateAvailable: true, Writable: false, Reason: "demo mode"}, nil
	}
	c := m.cloudflaredUpdater()
	switch r.Operation {
	case "status":
		return c.Status(ctx)
	case "check":
		return c.Check(ctx)
	case "settings":
		if r.AutoUpdate == nil {
			return model.CloudflaredState{}, errors.New("autoUpdate is required")
		}
		return c.Configure(ctx, *r.AutoUpdate)
	case "update":
		e := c.Update(ctx, r.CurrentVersion, r.TargetVersion)
		_ = m.store.Audit("agent", "cloudflared.update", "local", r.CurrentVersion+" -> "+r.TargetVersion)
		s, statusErr := c.Status(ctx)
		return s, errors.Join(e, statusErr)
	default:
		return model.CloudflaredState{}, errors.New("unknown cloudflared operation")
	}
}

func (m *Manager) reconcileCloudflared(ctx context.Context) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	if m.cfg.Demo {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	c := m.cloudflaredUpdater()
	before, _ := c.Status(ctx)
	e := c.Auto(ctx)
	if e == nil {
		after, statusErr := c.Status(ctx)
		if statusErr == nil && before.CurrentVersion != "" && after.CurrentVersion != before.CurrentVersion {
			_ = m.store.Audit("agent", "cloudflared.auto-update", "local", before.CurrentVersion+" -> "+after.CurrentVersion)
		}
	}
	if e != nil {
		_ = m.store.Audit("agent", "cloudflared.auto-update.failed", "local", e.Error())
	}
	return e
}

func (c *Client) Cloudflared(ctx context.Context, r model.CloudflaredRequest) (model.CloudflaredState, error) {
	copyHTTP := *c.http
	copyHTTP.Timeout = 5 * time.Minute
	copyClient := *c
	copyClient.http = &copyHTTP
	var s model.CloudflaredState
	e := copyClient.request(ctx, "POST", "/cloudflared", r, &s)
	return s, e
}

func (m *Manager) recoverCloudflared(ctx context.Context) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	if m.cfg.Demo {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, time.Minute)
	defer cancel()
	return m.cloudflaredUpdater().Recover(ctx)
}

func (m *Manager) restartUpdatedService(ctx context.Context, s componentupdate.Service) error {
	if e := m.serviceCommand(ctx, s.Manager, "restart", s.Name); e != nil {
		return e
	}
	// Check consecutive samples so a connector which immediately crashes
	// cannot be reported as a successful service restart.
	for i := 0; i < 3; i++ {
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
		if m.serviceStatus(ctx, s.Manager, s.Name) != "active" {
			return fmt.Errorf("runtime service %s is not active after restart", s.Name)
		}
	}
	return nil
}

func (m *Manager) checkManagedRuntimeProcesses(binary string, services []componentupdate.Service) error {
	live, e := os.Stat(binary)
	if e != nil {
		return e
	}
	seenServices := map[string]bool{}
	procs, _ := filepath.Glob("/proc/[0-9]*/exe")
	for _, p := range procs {
		exe, err := os.Readlink(p)
		if err != nil || strings.TrimSuffix(exe, " (deleted)") != binary {
			continue
		}
		processBinary, e := os.Stat(p)
		if e != nil || !os.SameFile(live, processBinary) {
			return errors.New("runtime service is using a different executable; restart it before updating")
		}
		pid := filepath.Base(filepath.Dir(p))
		owned := false
		group, _ := os.ReadFile(filepath.Join(filepath.Dir(p), "cgroup"))
		for _, s := range services {
			if s.Manager == "systemd" {
				for _, line := range strings.Split(string(group), "\n") {
					for _, part := range strings.Split(line, "/") {
						if part == s.Name+".service" {
							owned = true
							seenServices[s.Name] = true
						}
					}
				}
			} else {
				b, _ := os.ReadFile(filepath.Join("/run", s.Name+".pid"))
				if strings.TrimSpace(string(b)) == pid {
					owned = true
					seenServices[s.Name] = true
				}
			}
		}
		if !owned {
			return errors.New("runtime binary is also used by an unmanaged process")
		}
	}
	if runtime.GOOS == "linux" {
		for _, s := range services {
			if !seenServices[s.Name] {
				return errors.New("managed service is not running the configured binary")
			}
		}
	}
	return nil
}
