// Package firewall manages explicit port openings without changing firewall
// policies or enabling/disabling another firewall manager.
package firewall

import (
	"context"
	"crypto/rand"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/sys/unix"
)

const nftFile = "/etc/nftables.d/wukong-panel.nft"

var zonePattern = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var idPattern = regexp.MustCompile(`^[a-f0-9]{24}$`)
var portPattern = regexp.MustCompile(`^([0-9]+)/((?:tcp)|(?:udp))$`)

type runFunc func(context.Context, string, []string, string) (string, error)
type Controller struct {
	dir    string
	demo   bool
	run    runFunc
	lookup func(string) bool
}
type record struct {
	ID       string
	Backend  string
	Port     int
	Protocol string
	Zone     string
}
type state struct {
	Rules []record `json:"rules"`
}
type fileBackup struct {
	Path string
	Data []byte
	Mode uint32
}
type journal struct {
	Backend   string
	Before    state
	Files     []fileBackup
	Active    bool
	NFT       string
	Zone      string
	Port      string
	Runtime   bool
	Permanent bool
}

func New(secretDir string, demo bool) *Controller {
	dir := ""
	if secretDir != "" {
		dir = filepath.Join(secretDir, "firewall")
	}
	return &Controller{dir: dir, demo: demo, run: runCommand, lookup: func(name string) bool { _, err := exec.LookPath(name); return err == nil }}
}

func runCommand(ctx context.Context, name string, args []string, input string) (string, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C")
	if input != "" {
		cmd.Stdin = strings.NewReader(input)
	}
	data, err := cmd.CombinedOutput()
	text := strings.TrimSpace(string(data))
	if err != nil {
		if len(text) > 2048 {
			text = text[:2048]
		}
		return text, fmt.Errorf("%s: %w: %s", name, err, text)
	}
	return text, nil
}

func (c *Controller) locked(ctx context.Context, f func() error) error {
	if c.dir == "" {
		return errors.New("未配置 Root Agent 密钥目录，无法安全保存防火墙记录")
	}
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return err
	}
	if err := os.Chmod(c.dir, 0700); err != nil {
		return err
	}
	lock, err := os.OpenFile(filepath.Join(c.dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return err
	}
	defer lock.Close()
	for {
		err = unix.Flock(int(lock.Fd()), unix.LOCK_EX|unix.LOCK_NB)
		if err == nil {
			break
		}
		if !errors.Is(err, unix.EWOULDBLOCK) {
			return err
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(50 * time.Millisecond):
		}
	}
	defer unix.Flock(int(lock.Fd()), unix.LOCK_UN)
	return f()
}

func atomicWrite(path string, data []byte, mode os.FileMode) error {
	f, err := os.CreateTemp(filepath.Dir(path), ".firewall-*")
	if err != nil {
		return err
	}
	name := f.Name()
	defer os.Remove(name)
	if err = f.Chmod(mode); err == nil {
		_, err = f.Write(data)
	}
	if err == nil {
		err = f.Sync()
	}
	closeErr := f.Close()
	if err == nil {
		err = closeErr
	}
	if err != nil {
		return err
	}
	if err = os.Rename(name, path); err != nil {
		return err
	}
	dir, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}
func (c *Controller) save(name string, v any) error {
	b, err := json.MarshalIndent(v, "", "  ")
	if err != nil {
		return err
	}
	return atomicWrite(filepath.Join(c.dir, name), b, 0600)
}
func (c *Controller) read(name string, v any) error {
	b, err := os.ReadFile(filepath.Join(c.dir, name))
	if err != nil {
		return err
	}
	return json.Unmarshal(b, v)
}
func (c *Controller) state() (state, error) {
	s := state{Rules: []record{}}
	err := c.read("ports.json", &s)
	if errors.Is(err, os.ErrNotExist) {
		err = nil
	}
	return s, err
}

func (c *Controller) Recover(ctx context.Context) error {
	return c.locked(ctx, func() error { return c.recover(ctx) })
}
func (c *Controller) recover(ctx context.Context) error {
	var j journal
	if err := c.read("pending.json", &j); errors.Is(err, os.ErrNotExist) {
		return nil
	} else if err != nil {
		return err
	}
	if c.demo {
		return errors.New("unexpected firewall recovery in demo")
	}
	// Only fixed backend paths are accepted, even for a corrupted journal.
	for _, f := range j.Files {
		allowed := j.Backend == "ufw" && (f.Path == "/etc/ufw/user.rules" || f.Path == "/etc/ufw/user6.rules") || j.Backend == "nftables" && f.Path == nftFile
		if !allowed {
			return errors.New("invalid firewall backup path")
		}
		if err := atomicWrite(f.Path, f.Data, os.FileMode(f.Mode)); err != nil {
			return err
		}
	}
	switch j.Backend {
	case "ufw":
		if j.Active {
			if _, err := c.run(ctx, "ufw", []string{"reload"}, ""); err != nil {
				return err
			}
		}
	case "firewalld":
		if !zonePattern.MatchString(j.Zone) || !portPattern.MatchString(j.Port) {
			return errors.New("invalid firewalld recovery")
		}
		for _, v := range []struct{ permanent, want bool }{{false, j.Runtime}, {true, j.Permanent}} {
			args := []string{"--zone=" + j.Zone}
			if v.permanent {
				args = append(args, "--permanent")
			}
			action := "--remove-port="
			if v.want {
				action = "--add-port="
			}
			if _, err := c.run(ctx, "firewall-cmd", append(args, action+j.Port), ""); err != nil {
				return err
			}
		}
	case "nftables":
		if !strings.HasPrefix(j.NFT, "table inet wukong_panel {") {
			return errors.New("invalid nftables recovery")
		}
		input := j.NFT + "\n"
		if _, err := c.run(ctx, "nft", []string{"list", "table", "inet", "wukong_panel"}, ""); err == nil {
			input = "delete table inet wukong_panel\n" + input
		}
		if _, err := c.run(ctx, "nft", []string{"-f", "-"}, input); err != nil {
			return err
		}
	default:
		return errors.New("invalid firewall recovery backend")
	}
	if err := c.save("ports.json", j.Before); err != nil {
		return err
	}
	return c.clearJournal()
}

func (c *Controller) clearJournal() error {
	if err := os.Remove(filepath.Join(c.dir, "pending.json")); err != nil {
		return err
	}
	dir, err := os.Open(c.dir)
	if err != nil {
		return err
	}
	defer dir.Close()
	return dir.Sync()
}

func (c *Controller) Status(ctx context.Context, zone string) (model.FirewallStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 15*time.Second)
	defer cancel()
	var result model.FirewallStatus
	err := c.locked(ctx, func() error {
		if err := c.recover(ctx); err != nil {
			return fmt.Errorf("防火墙变更恢复失败：%w", err)
		}
		s, err := c.state()
		if err != nil {
			return err
		}
		result, err = c.status(ctx, zone, s)
		return err
	})
	return result, err
}

func (c *Controller) status(ctx context.Context, zone string, s state) (model.FirewallStatus, error) {
	result := model.FirewallStatus{Backend: "none", Zones: []string{}, Rules: []model.FirewallRule{}, ProtectedPorts: []model.FirewallPort{}, CheckedAt: time.Now(), Demo: c.demo}
	if c.demo {
		result.Backend = "ufw"
		result.Active = true
		result.Writable = true
		result.ProtectedPorts = []model.FirewallPort{{Port: 22, Protocol: "tcp", Reason: "SSH"}, {Port: 443, Protocol: "tcp", Reason: "管理入口"}}
		result.Rules = []model.FirewallRule{{Port: 22, Protocol: "tcp", Protected: true, Runtime: true, Permanent: true}, {Port: 443, Protocol: "tcp", Protected: true, Runtime: true, Permanent: true}}
		for _, r := range s.Rules {
			result.Rules = append(result.Rules, model.FirewallRule{ID: r.ID, Port: r.Port, Protocol: r.Protocol, Managed: true, Runtime: true, Permanent: true})
		}
		return result, nil
	}
	ufw, firewalld, nft := c.lookup("ufw"), c.lookup("firewall-cmd"), c.lookup("nft")
	var ufwText, nftText string
	var ufwErr, nftErr error
	if ufw {
		ufwText, ufwErr = c.run(ctx, "ufw", []string{"status", "verbose"}, "")
	}
	fireActive := false
	if firewalld {
		out, err := c.run(ctx, "firewall-cmd", []string{"--state"}, "")
		fireActive = err == nil && strings.TrimSpace(out) == "running"
	}
	ufwActive := ufwErr == nil && strings.Contains(ufwText, "Status: active")
	if nft {
		nftText, nftErr = c.run(ctx, "nft", []string{"list", "table", "inet", "wukong_panel"}, "")
	}
	nftManaged := nft && nftErr == nil
	switch {
	case ufwActive:
		result.Backend = "ufw"
	case fireActive:
		result.Backend = "firewalld"
	case nftManaged:
		result.Backend = "nftables"
	case ufw:
		result.Backend = "ufw"
	case firewalld:
		result.Backend = "firewalld"
	case nft:
		result.Backend = "nftables"
	}
	switch result.Backend {
	case "ufw":
		result.Active = ufwActive
		result.Raw = ufwText
		if ufwErr != nil {
			result.Reason = "无法读取 UFW 状态：" + ufwErr.Error()
			break
		}
		added, err := c.run(ctx, "ufw", []string{"show", "added"}, "")
		if err != nil {
			result.Reason = err.Error()
			break
		}
		result.Raw += "\n\n" + added
		result.Rules = parseUFW(added, s)
		for i := range result.Rules {
			result.Rules[i].Runtime = ufwActive
		}
		result.Writable = true
		if !ufwActive {
			result.Reason = "UFW 未启用；端口规则可保存，启用防火墙后才生效。"
		}
	case "firewalld":
		result.Active = fireActive
		if !fireActive {
			result.Reason = "firewalld 未运行；请先在主机上启用后再管理端口。"
			break
		}
		out, err := c.run(ctx, "firewall-cmd", []string{"--get-zones"}, "")
		if err != nil {
			return result, err
		}
		result.Zones = strings.Fields(out)
		if zone == "" {
			zone, err = c.run(ctx, "firewall-cmd", []string{"--get-default-zone"}, "")
			if err != nil {
				return result, err
			}
		}
		if !zonePattern.MatchString(zone) || !contains(result.Zones, zone) {
			return result, errors.New("无效的 firewalld 区域")
		}
		result.Zone = zone
		runtime, err := c.run(ctx, "firewall-cmd", []string{"--zone=" + zone, "--list-ports"}, "")
		if err != nil {
			return result, err
		}
		permanent, err := c.run(ctx, "firewall-cmd", []string{"--permanent", "--zone=" + zone, "--list-ports"}, "")
		if err != nil {
			return result, err
		}
		active, _ := c.run(ctx, "firewall-cmd", []string{"--get-active-zones"}, "")
		details, _ := c.run(ctx, "firewall-cmd", []string{"--zone=" + zone, "--list-all"}, "")
		result.Raw = "Active zones:\n" + active + "\n\n" + details
		result.Rules = parseFirewalld(runtime, permanent, zone, s)
		result.Writable = true
	case "nftables":
		result.Raw = nftText
		if raw, err := c.run(ctx, "nft", []string{"list", "ruleset"}, ""); err == nil {
			result.Raw = raw
		}
		if !nftManaged {
			result.Reason = "未找到安装器创建的 nftables 悟空规则表；自定义规则暂只读。"
			break
		}
		data, err := c.run(ctx, "nft", []string{"-j", "list", "table", "inet", "wukong_panel"}, "")
		if err != nil {
			return result, err
		}
		result.Rules, result.Active, err = parseNFT(data, s)
		if err != nil {
			return result, err
		}
		if !result.Active {
			result.Reason = "悟空 nftables input 链不是默认拒绝策略；无法保证新增放行规则的效果。"
			break
		}
		if err = checkNFTPersistence(); err != nil {
			result.Reason = err.Error()
			break
		}
		result.Writable = true
	default:
		result.Reason = "未检测到 UFW、firewalld 或 nftables；请先安装并配置主机防火墙。"
	}
	if (ufwActive && fireActive) || (nftManaged && (ufwActive || fireActive)) {
		result.Writable = false
		result.Reason = "检测到多个防火墙管理器同时生效，请先在主机上理清规则归属。"
	}
	listeners, err := c.run(ctx, "ss", []string{"-H", "-lntp"}, "")
	if err != nil {
		result.Reason += " 无法读取管理监听端口，暂不可删除规则。"
	} else {
		result.ProtectedPorts = protectedPorts(listeners)
	}
	for i := range result.Rules {
		for _, p := range result.ProtectedPorts {
			if p.Port == result.Rules[i].Port && p.Protocol == result.Rules[i].Protocol {
				result.Rules[i].Protected = true
			}
		}
	}
	sort.Slice(result.Rules, func(i, j int) bool {
		a, b := result.Rules[i], result.Rules[j]
		if a.Port != b.Port {
			return a.Port < b.Port
		}
		return a.Protocol < b.Protocol
	})
	if len(result.Raw) > 32768 {
		result.Raw = result.Raw[:32768] + "\n…"
	}
	return result, nil
}

func checkNFTPersistence() error {
	if _, err := os.Stat(nftFile); err != nil {
		return errors.New("缺少悟空 nftables 持久配置，暂不修改运行规则。")
	}
	for _, path := range []string{"/etc/nftables.conf", "/etc/nftables.nft"} {
		b, err := os.ReadFile(path)
		if err == nil && strings.Contains(string(b), `include "/etc/nftables.d/wukong-panel.nft"`) {
			return nil
		}
	}
	return errors.New("悟空 nftables 配置未加入开机加载文件，暂不可写入。")
}

func (c *Controller) Add(ctx context.Context, req model.FirewallPortRequest) (model.FirewallStatus, error) {
	if req.Port < 1 || req.Port > 65535 || (req.Protocol != "tcp" && req.Protocol != "udp") {
		return model.FirewallStatus{}, errors.New("端口须为 1–65535，协议须为 TCP 或 UDP")
	}
	return c.change(ctx, req.Zone, func(status model.FirewallStatus, s state) (state, record, bool, error) {
		for _, r := range status.Rules {
			if r.Port == req.Port && r.Protocol == req.Protocol {
				return s, record{}, false, errors.New("该端口已有放行规则，无需重复添加")
			}
		}
		if len(s.Rules) >= 256 {
			return s, record{}, false, errors.New("面板端口规则已达 256 条上限")
		}
		var token [12]byte
		_, err := rand.Read(token[:])
		if err != nil {
			return s, record{}, false, err
		}
		// Hex prevents command syntax, whitespace and comment delimiters in rule IDs.
		id := hex.EncodeToString(token[:])
		r := record{ID: id, Backend: status.Backend, Port: req.Port, Protocol: req.Protocol, Zone: status.Zone}
		s.Rules = append(s.Rules, r)
		return s, r, true, nil
	})
}
func (c *Controller) Remove(ctx context.Context, id string) (model.FirewallStatus, error) {
	if !idPattern.MatchString(id) {
		return model.FirewallStatus{}, errors.New("无效的规则 ID")
	}
	// Locate the original zone, never infer a different zone from the current default.
	s, err := c.state()
	if err != nil {
		return model.FirewallStatus{}, err
	}
	zone := ""
	for _, r := range s.Rules {
		if r.ID == id {
			zone = r.Zone
		}
	}
	return c.change(ctx, zone, func(status model.FirewallStatus, s state) (state, record, bool, error) {
		for _, r := range status.Rules {
			if r.ID == id && r.Managed {
				if r.Protected {
					return s, record{}, false, errors.New("SSH / 面板管理端口受保护，不能删除放行规则")
				}
				if !c.demo && len(status.ProtectedPorts) == 0 {
					return s, record{}, false, errors.New("无法确认管理监听端口，暂不可删除规则")
				}
				for i, owned := range s.Rules {
					if owned.ID == id && owned.Backend == status.Backend {
						next := append([]record{}, s.Rules[:i]...)
						next = append(next, s.Rules[i+1:]...)
						s.Rules = next
						return s, owned, false, nil
					}
				}
			}
		}
		return s, record{}, false, errors.New("只能删除面板创建且仍能确认归属的规则")
	})
}

func (c *Controller) change(ctx context.Context, zone string, prepare func(model.FirewallStatus, state) (state, record, bool, error)) (model.FirewallStatus, error) {
	var result model.FirewallStatus
	err := c.locked(ctx, func() error {
		if err := c.recover(ctx); err != nil {
			return err
		}
		before, err := c.state()
		if err != nil {
			return err
		}
		status, err := c.status(ctx, zone, before)
		if err != nil {
			return err
		}
		if !status.Writable {
			return errors.New(status.Reason)
		}
		next, r, add, err := prepare(status, before)
		if err != nil {
			return err
		}
		if c.demo {
			if err = c.save("ports.json", next); err != nil {
				return err
			}
			result, err = c.status(ctx, zone, next)
			return err
		}
		j, err := c.snapshot(ctx, status, before, r)
		if err != nil {
			return err
		}
		if err = c.save("pending.json", j); err != nil {
			return err
		}
		if err = c.mutate(ctx, r, add); err == nil {
			err = c.save("ports.json", next)
		}
		if err != nil {
			restoreCtx, cancel := context.WithTimeout(context.Background(), 45*time.Second)
			defer cancel()
			if restoreErr := c.recover(restoreCtx); restoreErr != nil {
				return fmt.Errorf("变更失败：%v；恢复失败（保留恢复记录）：%w", err, restoreErr)
			}
			return fmt.Errorf("变更失败，已恢复原规则：%w", err)
		}
		if err = c.clearJournal(); err != nil {
			return err
		}
		result, err = c.status(ctx, zone, next)
		return err
	})
	return result, err
}

func (c *Controller) snapshot(ctx context.Context, status model.FirewallStatus, before state, r record) (journal, error) {
	j := journal{Backend: status.Backend, Before: before, Active: status.Active, Zone: r.Zone, Port: fmt.Sprintf("%d/%s", r.Port, r.Protocol)}
	paths := []string{}
	switch status.Backend {
	case "ufw":
		paths = []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules"}
	case "nftables":
		paths = []string{nftFile}
		out, err := c.run(ctx, "nft", []string{"list", "table", "inet", "wukong_panel"}, "")
		if err != nil {
			return j, err
		}
		j.NFT = out
	case "firewalld":
		for _, rule := range status.Rules {
			if rule.Port == r.Port && rule.Protocol == r.Protocol {
				j.Runtime = rule.Runtime
				j.Permanent = rule.Permanent
			}
		}
	}
	for _, path := range paths {
		b, err := os.ReadFile(path)
		if err != nil {
			return j, err
		}
		info, err := os.Stat(path)
		if err != nil {
			return j, err
		}
		j.Files = append(j.Files, fileBackup{Path: path, Data: b, Mode: uint32(info.Mode().Perm())})
	}
	return j, nil
}
func (c *Controller) mutate(ctx context.Context, r record, add bool) error {
	spec := fmt.Sprintf("%d/%s", r.Port, r.Protocol)
	switch r.Backend {
	case "ufw":
		args := []string{"allow", spec, "comment", "wukong-" + r.ID}
		if !add {
			args = append([]string{"--force", "delete"}, args...)
		}
		_, err := c.run(ctx, "ufw", args, "")
		return err
	case "firewalld":
		action := "--remove-port="
		if add {
			action = "--add-port="
		}
		for _, permanent := range []bool{false, true} {
			args := []string{"--zone=" + r.Zone, action + spec}
			if permanent {
				args = append(args, "--permanent")
			}
			if _, err := c.run(ctx, "firewall-cmd", args, ""); err != nil {
				return err
			}
		}
		return nil
	case "nftables":
		if add {
			input := fmt.Sprintf("add rule inet wukong_panel input %s dport %d accept comment \"wukong-%s\"\n", r.Protocol, r.Port, r.ID)
			if _, err := c.run(ctx, "nft", []string{"-f", "-"}, input); err != nil {
				return err
			}
		} else {
			data, err := c.run(ctx, "nft", []string{"-j", "list", "table", "inet", "wukong_panel"}, "")
			if err != nil {
				return err
			}
			var root nftRoot
			if err = json.Unmarshal([]byte(data), &root); err != nil {
				return err
			}
			found := false
			for _, item := range root.Items {
				if rule := item.Rule; rule != nil && rule.Family == "inet" && rule.Table == "wukong_panel" && rule.Chain == "input" && rule.Comment == "wukong-"+r.ID && rule.Handle > 0 {
					found = true
					if _, err = c.run(ctx, "nft", []string{"delete", "rule", "inet", "wukong_panel", "input", "handle", strconv.FormatInt(rule.Handle, 10)}, ""); err != nil {
						return err
					}
				}
			}
			if !found {
				return errors.New("nftables 规则归属已变化")
			}
		}
		out, err := c.run(ctx, "nft", []string{"list", "table", "inet", "wukong_panel"}, "")
		if err != nil {
			return err
		}
		return atomicWrite(nftFile, []byte(out+"\n"), 0644)
	default:
		return errors.New("unsupported firewall backend")
	}
}

func contains(items []string, v string) bool {
	for _, item := range items {
		if item == v {
			return true
		}
	}
	return false
}
func parseSpec(spec string) (int, string, bool) {
	m := portPattern.FindStringSubmatch(spec)
	if m == nil {
		return 0, "", false
	}
	p, err := strconv.Atoi(m[1])
	return p, m[2], err == nil && p > 0 && p <= 65535
}
func owned(s state, backend, zone string, port int, protocol, marker string) string {
	for _, r := range s.Rules {
		if r.Backend == backend && r.Zone == zone && r.Port == port && r.Protocol == protocol && (backend == "firewalld" || marker == "wukong-"+r.ID) {
			return r.ID
		}
	}
	return ""
}
func parseUFW(added string, s state) []model.FirewallRule {
	result := []model.FirewallRule{}
	re := regexp.MustCompile(`^ufw allow ([0-9]+(?:/(?:tcp|udp))?)(?: comment ['"]([^'"]+)['"])?$`)
	for _, line := range strings.Split(added, "\n") {
		m := re.FindStringSubmatch(strings.TrimSpace(line))
		if m == nil {
			continue
		}
		specs := []string{m[1]}
		if !strings.Contains(m[1], "/") {
			specs = []string{m[1] + "/tcp", m[1] + "/udp"}
		}
		for _, spec := range specs {
			p, protocol, ok := parseSpec(spec)
			if !ok {
				continue
			}
			id := owned(s, "ufw", "", p, protocol, m[2])
			result = append(result, model.FirewallRule{ID: id, Port: p, Protocol: protocol, Managed: id != "", Permanent: true})
		}
	}
	return result
}
func parseFirewalld(runtime, permanent, zone string, s state) []model.FirewallRule {
	bySpec := map[string]model.FirewallRule{}
	for i, source := range []string{runtime, permanent} {
		for _, spec := range strings.Fields(source) {
			p, protocol, ok := parseSpec(spec)
			if !ok {
				continue
			}
			r := bySpec[spec]
			r.Port = p
			r.Protocol = protocol
			r.Zone = zone
			if i == 0 {
				r.Runtime = true
			} else {
				r.Permanent = true
			}
			r.ID = owned(s, "firewalld", zone, p, protocol, "")
			r.Managed = r.ID != ""
			bySpec[spec] = r
		}
	}
	result := []model.FirewallRule{}
	for _, r := range bySpec {
		result = append(result, r)
	}
	return result
}

type nftRoot struct {
	Items []struct {
		Chain *struct{ Family, Table, Name, Hook, Policy string }
		Rule  *nftRule
	} `json:"nftables"`
}
type nftRule struct {
	Family, Table, Chain, Comment string
	Handle                        int64
	Expr                          []json.RawMessage
}

func parseNFT(data string, s state) ([]model.FirewallRule, bool, error) {
	var root nftRoot
	if err := json.Unmarshal([]byte(data), &root); err != nil {
		return nil, false, err
	}
	result := []model.FirewallRule{}
	active := false
	for _, item := range root.Items {
		if ch := item.Chain; ch != nil && ch.Family == "inet" && ch.Table == "wukong_panel" && ch.Name == "input" && ch.Hook == "input" && ch.Policy == "drop" {
			active = true
		}
		r := item.Rule
		if r == nil || r.Family != "inet" || r.Table != "wukong_panel" || r.Chain != "input" {
			continue
		}
		port := 0
		protocol := ""
		accept := false
		simple := true
		for _, expr := range r.Expr {
			var e struct {
				Match *struct {
					Op   string
					Left struct {
						Payload *struct{ Protocol, Field string }
					}
					Right json.RawMessage
				}
				Accept  json.RawMessage
				Counter json.RawMessage
			}
			if err := json.Unmarshal(expr, &e); err != nil {
				return nil, false, err
			}
			switch {
			case e.Accept != nil:
				accept = true
			case e.Match != nil && e.Match.Op == "==" && e.Match.Left.Payload != nil && e.Match.Left.Payload.Field == "dport" && (e.Match.Left.Payload.Protocol == "tcp" || e.Match.Left.Payload.Protocol == "udp"):
				if port != 0 {
					simple = false
				}
				if err := json.Unmarshal(e.Match.Right, &port); err != nil {
					simple = false
				}
				protocol = e.Match.Left.Payload.Protocol
			case e.Counter != nil:
			default:
				simple = false
			}
		}
		if !simple || !accept || port < 1 || port > 65535 {
			continue
		}
		id := owned(s, "nftables", "", port, protocol, r.Comment)
		result = append(result, model.FirewallRule{ID: id, Port: port, Protocol: protocol, Managed: id != "", Runtime: true, Permanent: true})
	}
	return result, active, nil
}

func protectedPorts(listeners string) []model.FirewallPort {
	result := []model.FirewallPort{}
	seen := map[int]bool{}
	ssh := false
	for _, line := range strings.Split(listeners, "\n") {
		reason := ""
		if strings.Contains(line, `"sshd"`) || strings.Contains(line, `"dropbear"`) {
			reason = "SSH"
			ssh = true
		} else {
			for _, name := range []string{"nginx", "caddy", "apache2", "httpd", "wukong-panel", "systemd", "tinysshd"} {
				if strings.Contains(line, `"`+name+`"`) {
					reason = "管理入口"
					break
				}
			}
		}
		if reason == "" {
			continue
		}
		fields := strings.Fields(line)
		if len(fields) < 4 {
			continue
		}
		address := fields[3]
		pos := strings.LastIndex(address, ":")
		if pos < 0 {
			continue
		}
		port, err := strconv.Atoi(address[pos+1:])
		if err != nil || port < 1 || port > 65535 || seen[port] {
			continue
		}
		seen[port] = true
		result = append(result, model.FirewallPort{Port: port, Protocol: "tcp", Reason: reason})
	}
	if !ssh && !seen[22] {
		result = append(result, model.FirewallPort{Port: 22, Protocol: "tcp", Reason: "SSH 默认保护"})
	}
	return result
}
