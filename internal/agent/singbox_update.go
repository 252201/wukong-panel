package agent

import (
	"context"
	"errors"
	"fmt"
	"io"
	"net"
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
	"github.com/252201/wukong-panel/internal/singboxconfig"
)

func (m *Manager) singBoxUpdater() *componentupdate.Controller {
	root := m.cfg.SecretDir
	if root == "" {
		root = filepath.Join(m.cfg.DataDir, "secrets")
	}
	c := componentupdate.NewSingBox(filepath.Join(root, "sing-box-update"), m.cfg.SingBoxBin, runtime.GOARCH)
	c.ConfigDir = m.cfg.ConfigDir
	// Patch releases use the same configuration profile. A future minor/major
	// requires a panel update to extend migration and generated configuration support.
	c.AllowedTarget = func(v string) bool {
		if !regexp.MustCompile(`^\d+\.\d+\.\d+$`).MatchString(v) {
			return false
		}
		supported := strings.Split(singboxconfig.LatestSupportedVersion, ".")
		candidate := strings.Split(v, ".")
		return len(candidate) == 3 && candidate[0] == supported[0] && candidate[1] == supported[1]
	}
	c.Version = func(ctx context.Context, binary string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		if e := validateExecutable(binary); e != nil {
			return "", e
		}
		out, e := exec.CommandContext(ctx, binary, "version").Output()
		if e != nil {
			return "", e
		}
		match := regexp.MustCompile(`(?m)^sing-box version (\d+\.\d+\.\d+)\s*$`).FindStringSubmatch(string(out))
		if len(match) != 2 {
			return "", errors.New("cannot parse stable sing-box version")
		}
		return match[1], nil
	}
	c.Services = m.singBoxUpdateServices
	c.Restart = m.restartUpdatedService
	c.Stop = func(ctx context.Context, s componentupdate.Service) error {
		if e := ctx.Err(); e != nil {
			return e
		}
		status := m.serviceStatus(ctx, s.Manager, s.Name)
		if e := ctx.Err(); e != nil {
			return e
		}
		// A rollback may revisit a service already stopped by a partial update.
		if status != "active" {
			return nil
		}
		return m.serviceCommand(ctx, s.Manager, "stop", s.Name)
	}
	c.Prepare = m.prepareSingBoxUpdate
	c.Verify = func(ctx context.Context) error {
		if _, e := m.singBoxUpdateServices(ctx); e != nil {
			return e
		}
		nodes, e := m.store.Nodes(ctx)
		if e != nil {
			return e
		}
		for _, n := range nodes {
			if n.Ownership != "managed" || m.serviceStatus(ctx, n.ServiceManager, n.ServiceName) != "active" {
				continue
			}
			probeCtx, cancel := context.WithTimeout(ctx, 40*time.Second)
			_, e = singboxconfig.ProbeConfigInbound(probeCtx, c.Binary, n.ConfigPath, normalizeProtocol(n.Protocol), n.ListenPort)
			cancel()
			if e != nil {
				return fmt.Errorf("node %s failed the local proxy round trip", n.ID)
			}
		}
		return nil
	}
	return c
}

func (m *Manager) ownedSingBoxConfigs(ctx context.Context) ([]string, error) {
	if !filepath.IsAbs(m.cfg.ConfigDir) {
		return nil, errors.New("configuration directory must be absolute")
	}
	nodes, e := m.store.Nodes(ctx)
	if e != nil {
		return nil, e
	}
	owned := map[string]bool{}
	for _, n := range nodes {
		if n.Ownership != "managed" {
			return nil, errors.New("unmanaged nodes prevent runtime updates")
		}
		if filepath.Dir(n.ConfigPath) != filepath.Clean(m.cfg.ConfigDir) || filepath.Ext(n.ConfigPath) != ".json" {
			return nil, errors.New("node configuration is outside the managed directory")
		}
		owned[n.ConfigPath] = true
	}
	files, e := filepath.Glob(filepath.Join(m.cfg.ConfigDir, "*.json"))
	if e != nil {
		return nil, e
	}
	for _, p := range files {
		if !owned[p] {
			return nil, errors.New("unmanaged configuration prevents runtime updates")
		}
		info, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		if !info.Mode().IsRegular() || info.Mode().Perm()&0022 != 0 {
			return nil, errors.New("configuration must be a regular file without group/world write access")
		}
		delete(owned, p)
	}
	if len(owned) > 0 {
		return nil, errors.New("managed configuration is missing")
	}
	return files, nil
}

func (m *Manager) singBoxUpdateServices(ctx context.Context) ([]componentupdate.Service, error) {
	if _, e := m.ownedSingBoxConfigs(ctx); e != nil {
		return nil, e
	}
	nodes, e := m.store.Nodes(ctx)
	if e != nil {
		return nil, e
	}
	services := map[string]componentupdate.Service{}
	for _, n := range nodes {
		if !regexp.MustCompile(`^sing-box-wukong-[A-Za-z0-9_-]+$`).MatchString(n.ServiceName) || (n.ServiceManager != "systemd" && n.ServiceManager != "openrc") {
			return nil, errors.New("unsupported managed runtime service")
		}
		s := componentupdate.Service{Name: n.ServiceName, Manager: n.ServiceManager}
		if previous, ok := services[s.Name]; ok && previous.Manager != s.Manager {
			return nil, errors.New("conflicting runtime service managers")
		}
		services[s.Name] = s
	}
	active := []componentupdate.Service{}
	for _, s := range services {
		if m.serviceStatus(ctx, s.Manager, s.Name) == "active" {
			active = append(active, s)
		}
	}
	sort.Slice(active, func(i, j int) bool { return active[i].Name < active[j].Name })
	if e := m.checkManagedRuntimeProcesses(m.cfg.SingBoxBin, active); e != nil {
		return nil, e
	}
	return active, nil
}

func (m *Manager) prepareSingBoxUpdate(ctx context.Context, binary, target string) ([]componentupdate.ConfigFile, error) {
	paths, e := m.ownedSingBoxConfigs(ctx)
	if e != nil {
		return nil, e
	}
	temp, e := os.MkdirTemp("", "wukong-runtime-configs-*")
	if e != nil {
		return nil, e
	}
	defer os.RemoveAll(temp)
	result := []componentupdate.ConfigFile{}
	total := 0
	for _, p := range paths {
		f, e := os.Open(p)
		if e != nil {
			return nil, e
		}
		data, e := io.ReadAll(io.LimitReader(f, (1<<20)+1))
		f.Close()
		if e != nil {
			return nil, e
		}
		total += len(data)
		if len(data) > 1<<20 || total > 16<<20 {
			return nil, errors.New("managed configuration snapshot is too large")
		}
		migrated, plan, e := singboxconfig.Migrate(data, target, p)
		if e != nil || len(plan.Errors) > 0 {
			return nil, fmt.Errorf("configuration %s requires manual migration", filepath.Base(p))
		}
		for _, name := range plan.Interfaces {
			if _, e := net.InterfaceByName(name); e != nil {
				return nil, fmt.Errorf("configuration references unavailable interface %s", name)
			}
		}
		staged := filepath.Join(temp, filepath.Base(p))
		if e = os.WriteFile(staged, migrated, 0600); e != nil {
			return nil, e
		}
		checkCtx, cancel := context.WithTimeout(ctx, 15*time.Second)
		e = exec.CommandContext(checkCtx, binary, "check", "-c", staged).Run()
		cancel()
		if e != nil {
			return nil, fmt.Errorf("candidate rejects configuration %s", filepath.Base(p))
		}
		info, e := os.Lstat(p)
		if e != nil {
			return nil, e
		}
		result = append(result, componentupdate.ConfigFile{Path: p, Old: data, New: migrated, Mode: uint32(info.Mode().Perm())})
	}
	return result, nil
}

func (m *Manager) SingBoxUpdate(ctx context.Context, r model.ComponentUpdateRequest) (model.ComponentUpdateState, error) {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	if m.cfg.Demo {
		return model.ComponentUpdateState{Installed: true, CurrentVersion: "1.14.1", LatestVersion: "1.14.2", UpdateAvailable: true, Reason: "demo mode"}, nil
	}
	c := m.singBoxUpdater()
	switch r.Operation {
	case "status":
		return c.Status(ctx)
	case "check":
		return c.Check(ctx)
	case "update":
		e := c.Update(ctx, r.CurrentVersion, r.TargetVersion)
		if e == nil {
			_ = m.store.UpdateNodeConfigVersions(r.TargetVersion)
		}
		detail := r.CurrentVersion + " -> " + r.TargetVersion
		if e != nil {
			detail += " failed"
		}
		_ = m.store.Audit("agent", "sing-box.update", "local", detail)
		state, statusErr := c.Status(ctx)
		return state, errors.Join(e, statusErr)
	default:
		return model.ComponentUpdateState{}, errors.New("unknown sing-box update operation")
	}
}
func (m *Manager) recoverSingBox(ctx context.Context) error {
	m.mutation.Lock()
	defer m.mutation.Unlock()
	if m.cfg.Demo {
		return nil
	}
	ctx, cancel := context.WithTimeout(ctx, 5*time.Minute)
	defer cancel()
	return m.singBoxUpdater().Recover(ctx)
}
func (c *Client) SingBoxUpdate(ctx context.Context, r model.ComponentUpdateRequest) (model.ComponentUpdateState, error) {
	copyHTTP := *c.http
	copyHTTP.Timeout = 5 * time.Minute
	copyClient := *c
	copyClient.http = &copyHTTP
	var state model.ComponentUpdateState
	e := copyClient.request(ctx, "POST", "/sing-box-update", r, &state)
	return state, e
}
