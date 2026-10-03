// Package hostsecurity operates only recognized host firewall rules and SSH jails.
// A durable journal and a separate init-managed recovery process protect changes.
package hostsecurity

import (
	"context"
	"crypto/rand"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/sys/unix"
	"io"
	"net/netip"
	"os"
	"os/exec"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"
)

type Runner func(context.Context, string, []string, string) (string, error)
type Controller struct {
	Dir, Root      string
	Demo           bool
	Run            Runner
	Lookup         func(string) bool
	Nodes          []model.Node
	Now            func() time.Time
	Arm            func(context.Context) error
	RecoveryBinary string
	NoJournal      bool
}
type command struct {
	Name  string
	Args  []string
	Input string
}
type savedFile struct {
	Path   string
	Exists bool
	Data   []byte
	Mode   uint32
	Hash   string
}
type state struct {
	Rules       []model.SecurityRule
	NFTRules    []model.SecurityRule
	NFTInactive bool
	Jail        string
	Config      model.SSHProtectionConfig
	ConfigHash  string
	ActionHash  string
	Adopted     bool
	SSHPorts    []int
	PanelPorts  []int
}
type journal struct {
	Transaction model.SecurityTransaction
	Kind        string
	BootID      string
	Backend     string
	Files       []savedFile
	Undo        []command
	Before      state
	Bans        map[string][]string
	Started     bool
	Runtime     []command
	Target      string
	BootEnabled map[string]bool
	Install     bool
}

var nameRE = regexp.MustCompile(`^[A-Za-z0-9_-]{1,64}$`)
var idRE = regexp.MustCompile(`^[a-f0-9]{32}$`)

const nftPath = "/etc/nftables.d/wukong-panel.nft"
const jailPath = "/etc/fail2ban/jail.d/zzzz-wukong-ssh.local"
const marker = "# Managed by Wukong Panel security\n"

func New(dir string, demo bool) *Controller {
	stateDir := ""
	if dir != "" {
		stateDir = filepath.Join(dir, "host-security")
	}
	return &Controller{Dir: stateDir, Demo: demo, Run: run, Lookup: func(s string) bool { _, e := exec.LookPath(s); return e == nil }, Now: time.Now}
}
func run(ctx context.Context, name string, args []string, input string) (string, error) {
	limit := 20 * time.Second
	if name == "apt-get" || name == "dnf" || name == "apk" {
		limit = 8 * time.Minute
	}
	ctx, cancel := context.WithTimeout(ctx, limit)
	defer cancel()
	cmd := exec.CommandContext(ctx, name, args...)
	cmd.Env = append(os.Environ(), "LC_ALL=C", "LANG=C", "DEBIAN_FRONTEND=noninteractive")
	cmd.Stdin = strings.NewReader(input)
	b, e := cmd.CombinedOutput()
	if len(b) > 1024*1024 {
		return "", errors.New("command output exceeds limit")
	}
	s := strings.TrimSpace(string(b))
	if e != nil {
		if len(s) > 2048 {
			s = s[:2048]
		}
		return s, fmt.Errorf("%s: %w: %s", name, e, s)
	}
	return s, nil
}
func (c *Controller) path(p string) string {
	if c.Root == "" {
		return p
	}
	return filepath.Join(c.Root, strings.TrimPrefix(p, "/"))
}
func (c *Controller) read(p string) ([]byte, error) { return os.ReadFile(c.path(p)) }
func (c *Controller) exec(ctx context.Context, n string, a ...string) (string, error) {
	return c.Run(ctx, n, a, "")
}
func digest(b []byte) string { h := sha256.Sum256(b); return hex.EncodeToString(h[:]) }
func token() string {
	b := make([]byte, 16)
	if _, e := rand.Read(b); e != nil {
		panic(e)
	}
	return hex.EncodeToString(b)
}
func atomic(path string, b []byte, mode os.FileMode) error {
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		return e
	}
	f, e := os.CreateTemp(filepath.Dir(path), ".security-")
	if e != nil {
		return e
	}
	defer os.Remove(f.Name())
	defer f.Close()
	if e = f.Chmod(mode); e == nil {
		_, e = f.Write(b)
	}
	if e == nil {
		e = f.Sync()
	}
	if e == nil {
		e = f.Close()
	}
	if e == nil {
		e = os.Rename(f.Name(), path)
	}
	if e != nil {
		return e
	}
	d, e := os.Open(filepath.Dir(path))
	if e != nil {
		return e
	}
	defer d.Close()
	return d.Sync()
}
func (c *Controller) save(name string, v any) error {
	if c.Dir == "" {
		return errors.New("security state directory unavailable")
	}
	b, e := json.Marshal(v)
	if e != nil {
		return e
	}
	return atomic(filepath.Join(c.Dir, name), b, 0600)
}
func (c *Controller) load(name string, v any) error {
	if c.Dir == "" {
		return os.ErrNotExist
	}
	b, e := os.ReadFile(filepath.Join(c.Dir, name))
	if e != nil {
		return e
	}
	return json.Unmarshal(b, v)
}
func (c *Controller) state() (state, error) {
	s := state{Config: defaults(), Rules: []model.SecurityRule{}}
	e := c.load("state.json", &s)
	if errors.Is(e, os.ErrNotExist) {
		e = nil
	}
	return s, e
}

var ErrBusy = errors.New("另一项安全操作正在进行，请稍后重试")

func (c *Controller) lock() (func(), error) {
	if c.Dir == "" {
		return nil, errors.New("未配置 Root Agent 安全状态目录")
	}
	if e := os.MkdirAll(c.Dir, 0700); e != nil {
		return nil, e
	}
	if e := os.Chmod(c.Dir, 0700); e != nil {
		return nil, e
	}
	f, e := os.OpenFile(filepath.Join(c.Dir, "lock"), os.O_CREATE|os.O_RDWR, 0600)
	if e != nil {
		return nil, e
	}
	if e = unix.Flock(int(f.Fd()), unix.LOCK_EX|unix.LOCK_NB); e != nil {
		f.Close()
		return nil, ErrBusy
	}
	return func() { _ = unix.Flock(int(f.Fd()), unix.LOCK_UN); _ = f.Close() }, nil
}
func (c *Controller) boot() string {
	b, _ := c.read("/proc/sys/kernel/random/boot_id")
	id := strings.TrimSpace(string(b))
	stat, _ := c.read("/proc/1/stat")
	text := string(stat)
	if i := strings.LastIndex(text, ")"); i >= 0 {
		fields := strings.Fields(text[i+1:])
		if len(fields) > 19 {
			id += ":" + fields[19]
		}
	}
	return id
}
func (c *Controller) backup(j *journal, paths ...string) error {
	for _, p := range paths {
		if !allowedPath(p) {
			return errors.New("invalid backup path")
		}
		f := savedFile{Path: p}
		if info, e := os.Lstat(c.path(p)); e == nil && info.Mode()&os.ModeSymlink != 0 {
			return errors.New("安全配置为符号链接，请在主机核对后操作")
		}
		b, e := c.read(p)
		if e == nil {
			info, e := os.Stat(c.path(p))
			if e != nil {
				return e
			}
			f.Exists = true
			f.Data = b
			f.Mode = uint32(info.Mode().Perm())
			f.Hash = digest(b)
		} else if !errors.Is(e, os.ErrNotExist) {
			return e
		}
		j.Files = append(j.Files, f)
	}
	return nil
}
func allowedPath(p string) bool {
	return p == "/etc/systemd/system/wukong-firewall.service" || p == "/etc/init.d/wukong-firewall" || p == "/usr/sbin/policy-rc.d" || p == nftPath || p == "/etc/nftables.conf" || p == "/etc/nftables.nft" || p == jailPath || p == "/etc/ufw/user.rules" || p == "/etc/ufw/user6.rules" || p == "/etc/ufw/ufw.conf" || p == "/etc/default/ufw" || regexp.MustCompile(`^/etc/firewalld/zones/[A-Za-z0-9_-]+\.xml$`).MatchString(p)
}
func (c *Controller) validateBackup(j journal) error {
	for _, f := range j.Files {
		if !allowedPath(f.Path) || f.Exists && digest(f.Data) != f.Hash {
			return errors.New("backup validation failed")
		}
	}
	return nil
}
func normalizeRule(r model.SecurityRule) (model.SecurityRule, error) {
	if r.Action != "allow" && r.Action != "deny" {
		return r, errors.New("规则必须为允许或拒绝")
	}
	if r.Protocol != "tcp" && r.Protocol != "udp" {
		return r, errors.New("仅支持 TCP/UDP")
	}
	if r.PortTo == 0 {
		r.PortTo = r.PortFrom
	}
	if r.PortFrom < 1 || r.PortTo > 65535 || r.PortTo < r.PortFrom {
		return r, errors.New("端口范围无效")
	}
	if r.Source == "" || r.Source == "any" {
		r.Source = "any"
	} else if a, e := netip.ParseAddr(r.Source); e == nil {
		r.Source = a.Unmap().String()
	} else if p, e := netip.ParsePrefix(r.Source); e == nil {
		if p.Bits() == 0 {
			return r, errors.New("请使用 any 表示任意来源")
		}
		if p.Addr().Is4In6() {
			return r, errors.New("请使用普通 IPv4 或 IPv6 CIDR")
		}
		if p.Bits() == p.Addr().BitLen() {
			// Native tools canonicalize /32 and /128 to a single address.
			r.Source = p.Addr().String()
		} else {
			r.Source = p.Masked().String()
		}
	} else {
		return r, errors.New("来源必须为 IP 或 CIDR")
	}
	if r.Zone != "" && !nameRE.MatchString(r.Zone) {
		return r, errors.New("区域无效")
	}
	r.Description = ""
	return r, nil
}
func portSpec(r model.SecurityRule, sep string) string {
	p := strconv.Itoa(r.PortFrom)
	if r.PortTo != r.PortFrom {
		p += sep + strconv.Itoa(r.PortTo)
	}
	return p
}
func ruleKey(r model.SecurityRule) string {
	return fmt.Sprintf("%s:%s:%d:%d:%s:%s", r.Action, r.Protocol, r.PortFrom, r.PortTo, r.Source, r.Zone)
}
func sameRule(a, b model.SecurityRule) bool { return ruleKey(a) == ruleKey(b) }
func parsedPort(s string) (int, int, string, bool) {
	p := strings.Split(s, "/")
	if len(p) != 2 || (p[1] != "tcp" && p[1] != "udp") {
		return 0, 0, "", false
	}
	v := strings.FieldsFunc(p[0], func(r rune) bool { return r == '-' || r == ':' })
	if len(v) < 1 || len(v) > 2 {
		return 0, 0, "", false
	}
	a, e := strconv.Atoi(v[0])
	b := a
	if len(v) == 2 {
		b, _ = strconv.Atoi(v[1])
	}
	return a, b, p[1], e == nil && a > 0 && b >= a && b <= 65535
}
func (c *Controller) pending() *model.SecurityTransaction {
	var j journal
	if c.load("pending.json", &j) == nil {
		var failed model.SecurityTransaction
		if c.load("recovery-error.json", &failed) == nil && failed.ID == j.Transaction.ID {
			j.Transaction.Error = failed.Error
		}
		return &j.Transaction
	}
	return nil
}
func sortRules(r []model.SecurityRule) {
	sort.Slice(r, func(i, j int) bool { return ruleKey(r[i]) < ruleKey(r[j]) })
}
func (c *Controller) revision(parts ...any) string { b, _ := json.Marshal(parts); return digest(b) }
func defaultRequired(ssh, panel []int, nodes []model.Node) []model.SecurityPort {
	r := []model.SecurityPort{}
	seen := map[string]bool{}
	add := func(p int, proto, reason string, protected bool) {
		k := fmt.Sprintf("%d/%s", p, proto)
		if !seen[k] && p > 0 && p <= 65535 {
			seen[k] = true
			r = append(r, model.SecurityPort{Port: p, Protocol: proto, Reason: reason, Protected: protected})
		}
	}
	for _, p := range ssh {
		add(p, "tcp", "SSH", true)
	}
	for _, p := range panel {
		add(p, "tcp", "面板入口", true)
	}
	add(80, "tcp", "HTTP / 证书验证", false)
	add(443, "tcp", "HTTPS", false)
	for _, n := range nodes {
		if strings.Contains(n.Protocol, "tunnel") {
			continue
		}
		proto := "tcp"
		if n.Protocol == "hysteria2" || n.Protocol == "tuic" {
			proto = "udp"
		}
		add(n.ListenPort, proto, "节点 "+n.Name, false)
	}
	return r
}
func uniquePorts(v []int) []int {
	m := map[int]bool{}
	r := []int{}
	for _, p := range v {
		if p > 0 && p <= 65535 && !m[p] {
			m[p] = true
			r = append(r, p)
		}
	}
	sort.Ints(r)
	return r
}
func (c *Controller) ports(ctx context.Context) (ssh, panel []int) {
	out, _ := c.exec(ctx, "ss", "-H", "-lntp")
	for _, l := range strings.Split(out, "\n") {
		f := strings.Fields(l)
		if len(f) < 4 {
			continue
		}
		address := f[3]
		i := strings.LastIndex(address, ":")
		if i < 0 {
			continue
		}
		p, _ := strconv.Atoi(address[i+1:])
		if strings.Contains(l, "sshd") || strings.Contains(l, "dropbear") {
			ssh = append(ssh, p)
		}
	}
	if len(ssh) == 0 {
		effective, e := c.exec(ctx, "sshd", "-T")
		if e == nil {
			for _, l := range strings.Split(effective, "\n") {
				f := strings.Fields(l)
				if len(f) == 2 && f[0] == "port" {
					p, _ := strconv.Atoi(f[1])
					ssh = append(ssh, p)
				}
			}
		}
	}
	// Never confuse the local Web listener with the public reverse proxy.
	for _, path := range []string{"/etc/nginx/conf.d/wukong-panel.conf", "/etc/nginx/http.d/wukong-panel.conf"} {
		b, e := c.read(path)
		if e != nil {
			continue
		}
		re := regexp.MustCompile(`(?m)^\s*listen\s+(?:\[::\]:|[0-9.]+:)?([0-9]+)(?:\s|;)`)
		for _, m := range re.FindAllStringSubmatch(string(b), -1) {
			p, _ := strconv.Atoi(m[1])
			for _, l := range strings.Split(out, "\n") {
				f := strings.Fields(l)
				if len(f) > 3 && strings.HasSuffix(f[3], ":"+strconv.Itoa(p)) && strings.Contains(l, "nginx") {
					panel = append(panel, p)
				}
			}
		}
	}
	return uniquePorts(ssh), uniquePorts(panel)
}
func (c *Controller) family() string {
	b, _ := c.read("/etc/os-release")
	s := strings.ToLower(string(b))
	if strings.Contains(s, "alpine") {
		return "apk"
	}
	if strings.Contains(s, "debian") || strings.Contains(s, "ubuntu") {
		return "apt"
	}
	if strings.Contains(s, "rocky") || strings.Contains(s, "almalinux") || strings.Contains(s, "rhel") || strings.Contains(s, "fedora") {
		return "dnf"
	}
	return ""
}
func (c *Controller) install(ctx context.Context, kind, backend string) (err error) {
	family := c.family()
	if family == "apt" {
		original, e := c.read("/usr/sbin/policy-rc.d")
		exists := e == nil
		if e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
		mode := os.FileMode(0755)
		if exists {
			info, e := os.Stat(c.path("/usr/sbin/policy-rc.d"))
			if e != nil {
				return e
			}
			mode = info.Mode().Perm()
		}
		if e := atomic(c.path("/usr/sbin/policy-rc.d"), []byte("#!/bin/sh\nexit 101\n"), 0755); e != nil {
			return e
		}
		defer func() {
			if exists {
				err = errors.Join(err, atomic(c.path("/usr/sbin/policy-rc.d"), original, mode))
			} else {
				if e := os.Remove(c.path("/usr/sbin/policy-rc.d")); e != nil && !errors.Is(e, os.ErrNotExist) {
					err = errors.Join(err, e)
				}
			}
		}()
	}
	pkg := "fail2ban"
	if kind == "firewall" {
		switch backend {
		case "ufw":
			pkg = "ufw"
		case "firewalld":
			pkg = "firewalld"
		case "nftables":
			pkg = "nftables"
		default:
			return errors.New("不支持此后端")
		}
	}
	switch family {
	case "apt":
		if _, e := c.exec(ctx, "apt-get", "update", "-qq"); e != nil {
			return e
		}
		args := []string{"install", "-y", pkg}
		if kind == "fail2ban" {
			args = append(args, "python3-systemd")
		}
		_, e := c.exec(ctx, "apt-get", args...)
		return e
	case "dnf":
		if kind == "fail2ban" {
			if _, e := c.exec(ctx, "dnf", "install", "-y", "epel-release"); e != nil {
				return e
			}
		}
		args := []string{"install", "-y", pkg}
		if kind == "fail2ban" {
			args = append(args, "python3-systemd")
		}
		_, e := c.exec(ctx, "dnf", args...)
		return e
	case "apk":
		_, e := c.exec(ctx, "apk", "add", pkg, pkg+"-openrc")
		return e
	}
	return errors.New("当前发行版不支持自动安装")
}
func (c *Controller) service(ctx context.Context, action, name string) error {
	if c.isSystemd() {
		_, e := c.exec(ctx, "systemctl", action, name+".service")
		return e
	}
	if c.Lookup("rc-service") {
		_, e := c.exec(ctx, "rc-service", name, action)
		return e
	}
	return errors.New("需要 systemd 或 OpenRC")
}
func (c *Controller) isSystemd() bool {
	i, e := os.Stat(c.path("/run/systemd/system"))
	return e == nil && i.IsDir()
}
func (c *Controller) readSample(p string) ([]byte, error) {
	f, e := os.Open(c.path(p))
	if e != nil {
		return nil, e
	}
	defer f.Close()
	s, e := f.Stat()
	if e != nil {
		return nil, e
	}
	if s.Size() > 65536 {
		_, e = f.Seek(-65536, io.SeekEnd)
		if e != nil {
			return nil, e
		}
	}
	return io.ReadAll(io.LimitReader(f, 65536))
}

func (c *Controller) bootEnabled(ctx context.Context, name string) bool {
	if c.isSystemd() {
		_, e := c.exec(ctx, "systemctl", "is-enabled", "--quiet", name+".service")
		return e == nil
	}
	if c.Lookup("rc-update") {
		s, e := c.exec(ctx, "rc-update", "show", "default")
		if e == nil {
			for _, l := range strings.Split(s, "\n") {
				f := strings.Fields(l)
				if len(f) > 0 && f[0] == name {
					return true
				}
			}
		}
	}
	return false
}
func (c *Controller) setBoot(ctx context.Context, name string, enabled bool) error {
	if c.bootEnabled(ctx, name) == enabled {
		return nil
	}
	if c.isSystemd() {
		op := "disable"
		if enabled {
			op = "enable"
		}
		_, e := c.exec(ctx, "systemctl", op, name+".service")
		return e
	}
	if c.Lookup("rc-update") {
		op := "del"
		if enabled {
			op = "add"
		}
		_, e := c.exec(ctx, "rc-update", op, name, "default")
		return e
	}
	return nil
}
