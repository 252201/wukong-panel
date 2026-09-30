// Package fail2ban manages only the panel's wukong-sshd jail.
package fail2ban

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/sys/unix"
)

const jail = "wukong-sshd"
const marker = "# Managed by Wukong Panel.\n"

type Controller struct {
	dir, configFile string
	logFiles        []string
	demo            bool
	run             func(context.Context, string, ...string) (string, error)
	lookup          func(string) bool
	systemd         func() bool
	read            func(string) ([]byte, error)
}
type state struct {
	Config   model.Fail2banConfig
	Hash     string
	DemoBans []string
}
type pending struct {
	File   []byte
	Exists bool
	State  state
	Active bool
}

func New(secretDir string, demo bool) *Controller {
	dir := ""
	if secretDir != "" {
		dir = filepath.Join(secretDir, "fail2ban")
	}
	c := &Controller{dir: dir, configFile: "/etc/fail2ban/jail.d/wukong-sshd.local", logFiles: []string{"/var/log/auth.log", "/var/log/secure"}, demo: demo, read: readSample}
	c.systemd = func() bool { st, err := os.Stat("/run/systemd/system"); return err == nil && st.IsDir() }
	c.lookup = func(name string) bool { _, err := exec.LookPath(name); return err == nil }
	c.run = func(ctx context.Context, name string, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 5*time.Second)
		defer cancel()
		cmd := exec.CommandContext(ctx, name, args...)
		cmd.Env = append(os.Environ(), "LC_ALL=C")
		out, err := cmd.CombinedOutput()
		if len(out) > 65536 {
			out = out[:65536]
		}
		if err != nil {
			return string(out), fmt.Errorf("%s: %w: %s", name, err, strings.TrimSpace(string(out)))
		}
		return strings.TrimSpace(string(out)), nil
	}
	return c
}

// Authentication logs can grow large; detection needs only a recent sample.
func readSample(path string) ([]byte, error) {
	f, err := os.Open(path)
	if err != nil {
		return nil, err
	}
	defer f.Close()
	info, err := f.Stat()
	if err != nil {
		return nil, err
	}
	if info.Size() > 65536 {
		if _, err = f.Seek(info.Size()-65536, io.SeekStart); err != nil {
			return nil, err
		}
	}
	return io.ReadAll(io.LimitReader(f, 65536))
}
func defaults() model.Fail2banConfig {
	return model.Fail2banConfig{MaxRetry: 5, FindTime: 600, BanTime: 3600, Mode: "normal", IgnoreIPs: []string{}}
}
func (c *Controller) load() (state, error) {
	s := state{Config: defaults()}
	if c.dir == "" {
		return s, nil
	}
	b, err := os.ReadFile(filepath.Join(c.dir, "state.json"))
	if errors.Is(err, os.ErrNotExist) {
		return s, nil
	}
	if err != nil {
		return s, err
	}
	err = json.Unmarshal(b, &s)
	return s, err
}
func atomic(path string, data []byte) error {
	if err := os.MkdirAll(filepath.Dir(path), 0700); err != nil {
		return err
	}
	f, err := os.CreateTemp(filepath.Dir(path), ".wukong-")
	if err != nil {
		return err
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if err = f.Chmod(0600); err != nil {
		return err
	}
	if _, err = f.Write(data); err != nil {
		return err
	}
	if err = f.Sync(); err != nil {
		return err
	}
	if err = f.Close(); err != nil {
		return err
	}
	if err = os.Rename(f.Name(), path); err != nil {
		return err
	}
	d, err := os.Open(filepath.Dir(path))
	if err != nil {
		return err
	}
	defer d.Close()
	return d.Sync()
}
func (c *Controller) save(name string, value any) error {
	b, err := json.Marshal(value)
	if err != nil {
		return err
	}
	return atomic(filepath.Join(c.dir, name), b)
}
func (c *Controller) lock() (func(), error) {
	if c.dir == "" {
		return nil, errors.New("缺少安全状态目录，无法管理 Fail2ban")
	}
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		return nil, err
	}
	f, err := os.OpenFile(filepath.Join(c.dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if err != nil {
		return nil, err
	}
	if err = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); err != nil {
		f.Close()
		return nil, errors.New("Fail2ban 正在处理另一项操作，请稍后重试")
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func (c *Controller) owned(s state) error {
	if c.demo {
		return nil
	}
	b, err := os.ReadFile(c.configFile)
	if errors.Is(err, os.ErrNotExist) && s.Hash == "" {
		return nil
	}
	if err != nil {
		return err
	}
	if s.Hash == "" || digest(b) != s.Hash {
		return errors.New("悟空 SSH 防护配置已被外部创建或修改，请在服务器核对后再操作")
	}
	return nil
}
func (c *Controller) environment(ctx context.Context) (backend, logpath string, ports []int) {
	if c.systemd() {
		backend = "systemd"
	}
	// A journal backend does not use logpath. File backends require actual SSH logs.
	if backend == "" {
		for _, p := range c.logFiles {
			if b, e := c.read(p); e == nil && len(b) > 0 && strings.Contains(string(b), "sshd") {
				backend = "auto"
				logpath = p
				break
			}
		}
	}
	if out, err := c.run(ctx, "ss", "-H", "-lntp"); err == nil {
		seen := map[int]bool{}
		for _, line := range strings.Split(out, "\n") {
			if !strings.Contains(line, `"sshd"`) && !strings.Contains(line, `"sshd-session"`) {
				continue
			}
			f := strings.Fields(line)
			if len(f) < 4 {
				continue
			}
			_, p, e := net.SplitHostPort(f[3])
			if e == nil {
				n, e := strconv.Atoi(p)
				if e == nil && n > 0 && n <= 65535 {
					seen[n] = true
				}
			}
		}
		for n := range seen {
			ports = append(ports, n)
		}
		sort.Ints(ports)
	}
	return
}
func (c *Controller) commands() (install, start string) {
	b, _ := c.read("/etc/os-release")
	osID := string(b)
	switch {
	case strings.Contains(osID, "ID=alpine") || strings.Contains(osID, `ID="alpine"`):
		return "apk add fail2ban fail2ban-openrc && rc-update add fail2ban default && rc-service fail2ban start", "rc-service fail2ban start"
	case strings.Contains(osID, "debian") || strings.Contains(osID, "ubuntu"):
		return "apt-get update && apt-get install -y fail2ban python3-systemd && systemctl enable --now fail2ban", "systemctl start fail2ban"
	default:
		return "", ""
	}
}
func value(out, key string) string {
	for _, l := range strings.Split(out, "\n") {
		if i := strings.Index(l, key+":"); i >= 0 {
			return strings.TrimSpace(l[i+len(key)+1:])
		}
	}
	return ""
}
func ips(out string) []string {
	result := []string{}
	for _, f := range strings.Fields(out) {
		if a, e := netip.ParseAddr(f); e == nil {
			result = append(result, a.Unmap().String())
		}
	}
	return result
}
func (c *Controller) Status(ctx context.Context) (model.Fail2banStatus, error) {
	ctx, cancel := context.WithTimeout(ctx, 12*time.Second)
	defer cancel()
	s, err := c.load()
	if err != nil {
		return model.Fail2banStatus{}, err
	}
	result := model.Fail2banStatus{Config: s.Config, SSHPorts: []int{}, BannedIPs: []string{}, OtherJails: []string{}, CheckedAt: time.Now(), Demo: c.demo}
	if c.demo {
		result.Installed = true
		result.Running = true
		result.Active = s.Config.Enabled
		result.Writable = c.dir != ""
		result.Version = "demo"
		result.Backend = "systemd"
		result.SSHPorts = []int{22}
		if result.Active {
			result.BannedIPs = append(result.BannedIPs, s.DemoBans...)
			result.TotalFailed = 14
			result.TotalBanned = 2
		}
		return result, nil
	}
	result.InstallCommand, result.StartCommand = c.commands()
	result.Installed = c.lookup("fail2ban-client")
	if !result.Installed {
		result.Reason = "未安装 Fail2ban，请在此主机执行安装命令后刷新。"
		return result, nil
	}
	result.Version, _ = c.run(ctx, "fail2ban-client", "-V")
	out, err := c.run(ctx, "fail2ban-client", "status")
	if err != nil {
		result.Reason = "Fail2ban 服务未运行或无法连接，请在此主机检查服务后刷新。"
		return result, nil
	}
	result.Running = true
	for _, j := range strings.Split(value(out, "Jail list"), ",") {
		j = strings.TrimSpace(j)
		if j == "" {
			continue
		}
		if j == jail {
			result.Active = true
		} else {
			result.OtherJails = append(result.OtherJails, j)
		}
	}
	result.Backend, _, result.SSHPorts = c.environment(ctx)
	if result.SSHPorts == nil {
		result.SSHPorts = []int{}
	}
	switch {
	case c.dir == "":
		result.Reason = "缺少安全状态目录，无法管理 Fail2ban"
	case result.Backend == "":
		result.Reason = "未检测到 systemd 日志或有效 SSH 日志文件，暂不能启用防护。"
	case len(result.SSHPorts) == 0:
		result.Reason = "无法检测 SSH 监听端口，暂不能启用防护。"
	default:
		result.Writable = true
	}
	if result.Active && result.Running {
		result.Writable = c.dir != ""
	}
	if result.Active && s.Hash == "" {
		result.Writable = false
		result.Reason = "存在非面板创建的同名 SSH 防护规则，暂不可管理"
	}
	if err = c.owned(s); err != nil {
		result.Writable = false
		result.Reason = err.Error()
	}
	if _, err = os.Stat(filepath.Join(c.dir, "pending.json")); c.dir != "" && err == nil {
		result.Writable = false
		result.Reason = "上次 Fail2ban 操作尚待恢复，请重启 Root Agent 后刷新。"
	}
	if result.Active {
		out, err = c.run(ctx, "fail2ban-client", "status", jail)
		if err != nil {
			return result, err
		}
		result.BannedIPs = ips(value(out, "Banned IP list"))
		result.TotalFailed, _ = strconv.Atoi(value(out, "Total failed"))
		result.TotalBanned, _ = strconv.Atoi(value(out, "Total banned"))
		if result.Writable {
			if e := c.verify(ctx, s.Config); e != nil {
				result.Writable = false
				result.Reason = e.Error()
			}
		}
	}
	return result, nil
}
func validate(r model.Fail2banConfig) (model.Fail2banConfig, error) {
	if r.MaxRetry < 1 || r.MaxRetry > 100 || r.FindTime < 60 || r.FindTime > 604800 || r.BanTime < 60 || r.BanTime > 2592000 {
		return r, errors.New("重试次数需为 1–100，观察窗口需为 60–604800 秒，封禁时长需为 60–2592000 秒")
	}
	if r.Mode != "normal" && r.Mode != "aggressive" {
		return r, errors.New("SSH 防护模式无效")
	}
	if len(r.IgnoreIPs) > 64 {
		return r, errors.New("可信 IP 最多 64 条")
	}
	list := []string{}
	seen := map[string]bool{}
	for _, ip := range r.IgnoreIPs {
		ip = strings.TrimSpace(ip)
		var normalized string
		if a, e := netip.ParseAddr(ip); e == nil && !a.IsUnspecified() && !a.IsMulticast() && a.Zone() == "" {
			normalized = a.Unmap().String()
		} else if p, e := netip.ParsePrefix(ip); e == nil && p.Bits() > 0 && !p.Addr().IsMulticast() && !p.Addr().Is4In6() {
			normalized = p.Masked().String()
		} else {
			return r, errors.New("可信列表只接受有效 IP 或 CIDR，不能使用全部地址范围")
		}
		if !seen[normalized] {
			seen[normalized] = true
			list = append(list, normalized)
		}
	}
	if r.Enabled && len(list) == 0 {
		return r, errors.New("启用前请填写自己的管理出口 IP 或可信 CIDR，避免误封 SSH 登录")
	}
	r.IgnoreIPs = list
	return r, nil
}
func render(r model.Fail2banConfig, backend, logpath string, ports []int) []byte {
	numbers := []string{}
	for _, p := range ports {
		numbers = append(numbers, strconv.Itoa(p))
	}
	content := fmt.Sprintf("%s[%s]\nenabled = %t\nfilter = sshd[mode=%s]\nport = %s\nbackend = %s\nusedns = no\nignoreself = true\nignoreip = 127.0.0.1/8 ::1 %s\nmaxretry = %d\nfindtime = %d\nbantime = %d\n", marker, jail, r.Enabled, r.Mode, strings.Join(numbers, ","), backend, strings.Join(r.IgnoreIPs, " "), r.MaxRetry, r.FindTime, r.BanTime)
	if backend == "systemd" {
		content += "journalmatch = _COMM=sshd + SYSLOG_IDENTIFIER=sshd + _COMM=sshd-session + _COMM=sshd-auth\n"
	} else {
		content += "logpath = " + logpath + "\n"
	}
	return []byte(content)
}
func (c *Controller) apply(ctx context.Context, enabled bool) error {
	if enabled {
		_, err := c.run(ctx, "fail2ban-client", "reload", "--if-exists", jail)
		return err
	}
	out, err := c.run(ctx, "fail2ban-client", "status")
	if err != nil {
		return err
	}
	for _, j := range strings.Split(value(out, "Jail list"), ",") {
		if strings.TrimSpace(j) == jail {
			_, err = c.run(ctx, "fail2ban-client", "stop", jail)
			return err
		}
	}
	return nil
}
func (c *Controller) restore(ctx context.Context, p pending) error {
	if !c.demo {
		if p.Exists {
			if err := atomic(c.configFile, p.File); err != nil {
				return err
			}
		} else if err := os.Remove(c.configFile); err != nil && !errors.Is(err, os.ErrNotExist) {
			return err
		}
		if _, err := c.run(ctx, "fail2ban-client", "ping"); err == nil {
			if err = c.apply(ctx, p.Active); err != nil {
				return err
			}
		}
	}
	if err := c.save("state.json", p.State); err != nil {
		return err
	}
	return os.Remove(filepath.Join(c.dir, "pending.json"))
}
func (c *Controller) Recover(ctx context.Context) error {
	if c.dir == "" {
		return nil
	}
	b, err := os.ReadFile(filepath.Join(c.dir, "pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	unlock, err := c.lock()
	if err != nil {
		return err
	}
	defer unlock()
	// Read again after acquiring the lock, so recovery cannot replay a completed transaction.
	b, err = os.ReadFile(filepath.Join(c.dir, "pending.json"))
	if errors.Is(err, os.ErrNotExist) {
		return nil
	}
	if err != nil {
		return err
	}
	var p pending
	if err = json.Unmarshal(b, &p); err != nil {
		return err
	}
	return c.restore(ctx, p)
}
func (c *Controller) Configure(ctx context.Context, r model.Fail2banConfig) (result model.Fail2banStatus, err error) {
	ctx, cancel := context.WithTimeout(ctx, 45*time.Second)
	defer cancel()
	r, err = validate(r)
	if err != nil {
		return result, err
	}
	unlock, err := c.lock()
	if err != nil {
		return result, err
	}
	defer unlock()
	result, err = c.Status(ctx)
	if err != nil {
		return result, err
	}
	if !result.Writable {
		return result, errors.New(result.Reason)
	}
	old, err := c.load()
	if err != nil {
		return result, err
	}
	if c.demo {
		old.Config = r
		if old.DemoBans == nil {
			old.DemoBans = []string{"192.0.2.47", "2001:db8::47"}
		}
		if !r.Enabled {
			old.DemoBans = []string{}
		}
		if err = c.save("state.json", old); err != nil {
			return result, err
		}
		return c.Status(ctx)
	}
	backend, logpath, ports := c.environment(ctx)
	if r.Enabled && (backend == "" || len(ports) == 0) {
		return result, errors.New("SSH 日志或监听端口已变化，请刷新后重试")
	}
	if backend == "" {
		backend = "auto"
		logpath = "/var/log/auth.log"
	}
	if len(ports) == 0 {
		ports = []int{22}
	}
	p := pending{State: old, Active: result.Active}
	p.File, err = os.ReadFile(c.configFile)
	p.Exists = err == nil
	if err != nil && !errors.Is(err, os.ErrNotExist) {
		return result, err
	}
	if err = c.save("pending.json", p); err != nil {
		return result, err
	}
	committed := false
	defer func() {
		if !committed {
			recoverCtx, cancel := context.WithTimeout(context.Background(), 20*time.Second)
			defer cancel()
			if restoreErr := c.restore(recoverCtx, p); restoreErr != nil {
				err = fmt.Errorf("%v；回滚失败，请在服务器检查 Fail2ban：%w", err, restoreErr)
			}
		}
	}()
	data := render(r, backend, logpath, ports)
	if err = atomic(c.configFile, data); err != nil {
		return result, err
	}
	if _, err = c.run(ctx, "fail2ban-client", "-t"); err != nil {
		return result, err
	}
	if err = c.apply(ctx, r.Enabled); err != nil {
		return result, err
	}
	if r.Enabled {
		if err = c.verify(ctx, r); err != nil {
			return result, err
		}
	}
	out, checkErr := c.run(ctx, "fail2ban-client", "status")
	if checkErr != nil {
		return result, checkErr
	}
	active := false
	for _, j := range strings.Split(value(out, "Jail list"), ",") {
		active = active || strings.TrimSpace(j) == jail
	}
	if active != r.Enabled {
		return result, errors.New("SSH 防护运行状态与保存配置不一致")
	}
	if err = c.save("state.json", state{Config: r, Hash: digest(data)}); err != nil {
		return result, err
	}
	if err = os.Remove(filepath.Join(c.dir, "pending.json")); err != nil {
		return result, err
	}
	committed = true
	return c.Status(ctx)
}

// Check effective values after reload: a later local file must not silently override
// the settings or remove the administrator's trusted addresses.
func (c *Controller) verify(ctx context.Context, r model.Fail2banConfig) error {
	for _, v := range []struct {
		key      string
		expected int
	}{{"maxretry", r.MaxRetry}, {"findtime", r.FindTime}, {"bantime", r.BanTime}} {
		out, err := c.run(ctx, "fail2ban-client", "get", jail, v.key)
		if err != nil {
			return err
		}
		n, e := strconv.Atoi(strings.TrimSpace(out))
		if e != nil || n != v.expected {
			return errors.New("SSH 防护运行参数与保存配置不一致，请检查其他 Fail2ban 配置文件")
		}
	}
	out, err := c.run(ctx, "fail2ban-client", "get", jail, "ignoreip")
	if err != nil {
		return err
	}
	normalize := func(text string) (netip.Prefix, bool) {
		if p, e := netip.ParsePrefix(text); e == nil {
			return p.Masked(), true
		}
		if a, e := netip.ParseAddr(text); e == nil {
			return netip.PrefixFrom(a.Unmap(), a.Unmap().BitLen()), true
		}
		return netip.Prefix{}, false
	}
	actual := map[netip.Prefix]bool{}
	for _, f := range strings.Fields(out) {
		if p, ok := normalize(strings.Trim(f, "[],'\"")); ok {
			actual[p] = true
		}
	}
	for _, ip := range append([]string{"127.0.0.0/8", "::1"}, r.IgnoreIPs...) {
		if p, ok := normalize(ip); !ok || !actual[p] {
			return errors.New("SSH 防护白名单未完整生效，请检查其他 Fail2ban 配置文件")
		}
	}
	return nil
}
func (c *Controller) Unban(ctx context.Context, ip string) (model.Fail2banStatus, error) {
	a, err := netip.ParseAddr(ip)
	if err != nil || a.IsUnspecified() || a.IsMulticast() || a.Zone() != "" {
		return model.Fail2banStatus{}, errors.New("解封地址必须是有效 IP")
	}
	ip = a.Unmap().String()
	unlock, err := c.lock()
	if err != nil {
		return model.Fail2banStatus{}, err
	}
	defer unlock()
	status, err := c.Status(ctx)
	if err != nil {
		return status, err
	}
	if !status.Writable || !status.Active {
		return status, errors.New("SSH 防护当前不可操作")
	}
	found := false
	for _, b := range status.BannedIPs {
		found = found || b == ip
	}
	if !found {
		return status, errors.New("此 IP 不在悟空 SSH 防护封禁列表中")
	}
	if c.demo {
		s, e := c.load()
		if e != nil {
			return status, e
		}
		next := []string{}
		for _, b := range s.DemoBans {
			if b != ip {
				next = append(next, b)
			}
		}
		s.DemoBans = next
		if err = c.save("state.json", s); err != nil {
			return status, err
		}
	} else {
		if _, err = c.run(ctx, "fail2ban-client", "set", jail, "unbanip", ip); err != nil {
			return status, err
		}
	}
	return c.Status(ctx)
}
