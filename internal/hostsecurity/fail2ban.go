package hostsecurity

import (
	"context"
	"errors"
	"fmt"
	"github.com/252201/wukong-panel/internal/model"
	"net/netip"
	"os"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func defaults() model.SSHProtectionConfig {
	return model.SSHProtectionConfig{MaxRetry: 5, FindTime: 600, BanTime: 3600, Mode: "normal", IgnoreIPs: []string{}}
}
func validateConfig(r model.SSHProtectionConfig) (model.SSHProtectionConfig, error) {
	if r.MaxRetry < 1 || r.MaxRetry > 100 || r.FindTime < 60 || r.FindTime > 604800 || r.BanTime < 60 || r.BanTime > 2592000 {
		return r, errors.New("失败次数为 1–100，窗口为 60–604800 秒，封禁为 60–2592000 秒")
	}
	if !contains([]string{"normal", "ddos", "extra", "aggressive"}, r.Mode) {
		return r, errors.New("SSH 检测模式无效")
	}
	if len(r.IgnoreIPs) > 64 {
		return r, errors.New("白名单最多 64 条")
	}
	list := []string{"127.0.0.1/8", "::1"}
	for _, s := range r.IgnoreIPs {
		s = strings.TrimSpace(s)
		if a, e := netip.ParseAddr(s); e == nil && !a.IsUnspecified() && !a.IsMulticast() && a.Zone() == "" {
			s = a.Unmap().String()
		} else if p, e := netip.ParsePrefix(s); e == nil && p.Bits() > 0 && !p.Addr().IsMulticast() && !p.Addr().Is4In6() {
			s = p.Masked().String()
		} else {
			return r, errors.New("白名单必须为有效 IP/CIDR，不能为全部地址")
		}
		if !contains(list, s) {
			list = append(list, s)
		}
	}
	sort.Strings(list)
	r.IgnoreIPs = list
	return r, nil
}
func (c *Controller) logSource(ctx context.Context) (string, string, error) {
	if !c.NoJournal && c.isSystemd() && c.Lookup("journalctl") {
		if _, e := c.exec(ctx, "python3", "-c", "import systemd.journal"); e == nil {
			sample, e := c.exec(ctx, "journalctl", "--no-pager", "-n", "20", "-o", "short", "_COMM=sshd", "+", "SYSLOG_IDENTIFIER=sshd", "+", "_COMM=sshd-session")
			if e == nil && strings.Contains(sample, "sshd") {
				return "systemd", "", nil
			}
		}
	}
	for _, p := range []string{"/var/log/auth.log", "/var/log/secure", "/var/log/messages"} {
		sample, e := c.readSample(p)
		if e == nil && strings.Contains(string(sample), "sshd") {
			return "polling", p, nil
		}
	}
	return "", "", errors.New("未发现可读取的 SSH 日志，或缺少 journal 依赖")
}
func (c *Controller) jailNames(ctx context.Context) ([]string, error) {
	out, e := c.exec(ctx, "fail2ban-client", "status")
	if e != nil {
		return nil, e
	}
	names := []string{}
	for _, n := range strings.Split(field(out, "Jail list"), ",") {
		n = strings.TrimSpace(n)
		if n == "" {
			continue
		}
		if !nameRE.MatchString(n) {
			return nil, errors.New("无法识别 jail 名称")
		}
		names = append(names, n)
	}
	sort.Strings(names)
	return names, nil
}
func intField(s, key string) int { v, _ := strconv.Atoi(field(s, key)); return v }
func parsedIPs(s string) []string {
	r := []string{}
	for _, s := range strings.Fields(s) {
		if a, e := netip.ParseAddr(s); e == nil && a.Zone() == "" {
			r = append(r, a.Unmap().String())
		}
	}
	sort.Strings(r)
	return r
}
func (c *Controller) effectiveConfig(ctx context.Context, name string) (model.SSHProtectionConfig, error) {
	r := defaults()
	for _, f := range []struct {
		key string
		dst *int
	}{{"maxretry", &r.MaxRetry}, {"findtime", &r.FindTime}, {"bantime", &r.BanTime}} {
		s, e := c.exec(ctx, "fail2ban-client", "get", name, f.key)
		if e != nil {
			return r, e
		}
		fields := strings.Fields(s)
		if len(fields) == 0 {
			return r, errors.New("empty jail setting")
		}
		v, e := strconv.ParseFloat(fields[len(fields)-1], 64)
		if e != nil || v != float64(int(v)) {
			return r, fmt.Errorf("invalid jail setting %s: %q", f.key, s)
		}
		*f.dst = int(v)
	}
	s, e := c.exec(ctx, "fail2ban-client", "get", name, "ignoreip")
	if e != nil {
		return r, e
	}
	r.IgnoreIPs = []string{}
	for _, v := range strings.Fields(s) {
		v = strings.Trim(v, "[],\"'")
		if a, e := netip.ParseAddr(v); e == nil {
			r.IgnoreIPs = append(r.IgnoreIPs, a.String())
		} else if p, e := netip.ParsePrefix(v); e == nil {
			r.IgnoreIPs = append(r.IgnoreIPs, p.String())
		}
	}
	sort.Strings(r.IgnoreIPs)
	return r, nil
}
func (c *Controller) Fail2ban(ctx context.Context) (model.Fail2banState, error) {
	s, e := c.state()
	if e != nil {
		return model.Fail2banState{}, e
	}
	r := model.Fail2banState{Installed: c.Lookup("fail2ban-client"), CheckedAt: c.Now(), Jails: []model.SSHJail{}, Config: s.Config, ManagedJail: s.Jail, SSHPorts: []int{}}
	r.SSHPorts, _ = c.ports(ctx)
	r.LogBackend, r.LogPath, e = c.logSource(ctx)
	if e != nil {
		r.Reason = e.Error()
	}
	raw := []string{}
	if c.Demo {
		r.Reason = "演示环境不执行系统安全操作"
		r.Revision = c.revision(s)
		return r, nil
	}
	if !r.Installed {
		r.Reason = "未安装 Fail2ban"
		r.Writable = c.family() != ""
		r.Revision = c.revision(s, false)
		return r, nil
	}
	names, err := c.jailNames(ctx)
	if err != nil {
		r.Reason = "Fail2ban 服务未运行或无法连接"
		// Query effective package configuration without starting a daemon or jail.
		dump, de := c.exec(ctx, "fail2ban-client", "-d")
		raw = append(raw, dump)
		if de != nil {
			r.Reason = "无法验证 Fail2ban 有效配置：" + de.Error()
		} else {
			adds := regexp.MustCompile(`(?m)^\['add', '([A-Za-z0-9_-]+)',`)
			for _, match := range adds.FindAllStringSubmatch(dump, -1) {
				name := match[1]
				if strings.Contains(strings.ToLower(name), "ssh") || regexp.MustCompile(`(?m)^\['set', '`+regexp.QuoteMeta(name)+`', '(?:addjournalmatch|addlogpath)', .*?(?:sshd|auth\.log|/secure)`).MatchString(dump) {
					r.Jails = append(r.Jails, model.SSHJail{Name: name, Config: defaults(), Banned: []string{}})
				}
			}
			if len(r.Jails) > 0 {
				r.Reason = "存在已配置但未运行的 SSH jail，请在主机启动并核对后确认接管"
			}
		}
	} else {
		for _, name := range names {
			journal, _ := c.exec(ctx, "fail2ban-client", "get", name, "journalmatch")
			logs, _ := c.exec(ctx, "fail2ban-client", "get", name, "logpath")
			if !strings.Contains(strings.ToLower(name), "ssh") && !strings.Contains(journal, "sshd") && !strings.Contains(logs, "auth.log") && !strings.Contains(logs, "/secure") {
				continue
			}
			out, e := c.exec(ctx, "fail2ban-client", "status", name)
			if e != nil {
				return r, e
			}
			cfg, e := c.effectiveConfig(ctx, name)
			if e != nil {
				r.Reason = "无法读取 SSH jail 的有效配置：" + e.Error()
				continue
			}
			if name == s.Jail {
				cfg.Mode = s.Config.Mode
			}
			j := model.SSHJail{Name: name, Managed: name == s.Jail, Failed: intField(out, "Currently failed"), TotalFailed: intField(out, "Total failed"), TotalBanned: intField(out, "Total banned"), Banned: parsedIPs(field(out, "Banned IP list")), Config: cfg}
			r.Jails = append(r.Jails, j)
			raw = append(raw, name, journal, logs, fmt.Sprint(cfg))
			r.Active = true
		}
	}
	r.Writable = r.LogBackend != "" && len(r.SSHPorts) > 0 && c.family() != ""
	if err != nil && len(r.Jails) > 0 {
		r.Writable = false
	}
	if err != nil && strings.HasPrefix(r.Reason, "无法验证") {
		r.Writable = false
	}
	if len(r.Jails) > 1 {
		r.Writable = false
		r.Reason = "存在多个 SSH jail，请在主机合并防护配置后再确认接管"
	}
	if len(r.SSHPorts) == 0 {
		r.Reason = "未识别到实际 SSH 端口"
	}
	if _, e := c.read("/etc/fail2ban/filter.d/sshd.conf"); e != nil {
		r.Writable = false
		r.Reason = "缺少发行版 SSH 过滤器"
	}
	b, e := c.read(jailPath)
	if e == nil {
		raw = append(raw, string(b))
		if s.ConfigHash == "" || digest(b) != s.ConfigHash {
			r.Writable = false
			r.Reason = "悟空覆盖文件被外部创建或修改，请先核对"
		}
	} else if !errors.Is(e, os.ErrNotExist) || s.ConfigHash != "" {
		r.Writable = false
		r.Reason = "悟空覆盖文件缺失或不可读"
	}
	if s.Jail != "" {
		for _, j := range r.Jails {
			if j.Managed && len(j.Banned) > 0 {
				if e := c.enforcement(ctx, j.Name, j.Banned, r.SSHPorts); e != nil {
					r.Writable = false
					r.Reason = e.Error()
				}
			}
			if j.Managed && s.ActionHash != "" {
				hash, e := c.actionHash(ctx, s.Jail)
				raw = append(raw, hash)
				if e != nil || hash != s.ActionHash {
					r.Writable = false
					r.Reason = "SSH 封禁动作被外部修改或无法校验"
				}
			}
			if j.Managed && (j.Config.MaxRetry != s.Config.MaxRetry || j.Config.BanTime != s.Config.BanTime || j.Config.FindTime != s.Config.FindTime) {
				r.Writable = false
				r.Reason = "SSH jail 运行配置已被外部修改"
			}
		}
	}
	if b, e := c.read("/proc/self/status"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "CapEff:") {
				v, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(l, "CapEff:")), 16, 64)
				if v&(1<<12) == 0 {
					r.Writable = false
					r.Reason = "缺少 CAP_NET_ADMIN，无法确保 SSH 封禁生效"
				}
			}
		}
	}
	if r.LogBackend != "" {
		if e := c.verifyLogFilter(ctx, r.LogBackend, r.LogPath); e != nil {
			r.Writable = false
			r.Reason = e.Error()
		}
	}

	if c.pending() != nil {
		r.Writable = false
		r.Reason = "上次安全变更尚待确认或恢复"
	}
	r.Revision = c.revision(s, raw, r.LogBackend, r.LogPath, r.SSHPorts, err == nil)
	return r, nil
}
func (c *Controller) fail2banPreview(ctx context.Context, req model.SecurityRequest) (model.SecurityPreview, error) {
	f, e := c.Fail2ban(ctx)
	if e != nil {
		return model.SecurityPreview{}, e
	}
	p := model.SecurityPreview{Revision: f.Revision, Changes: []string{}, Warnings: []string{}, RequiredPorts: []model.SecurityPort{}}
	if c.Demo {
		return p, errors.New(f.Reason)
	}
	if c.pending() != nil {
		return p, errors.New("安全变更尚待确认或恢复")
	}
	b, be := c.read(jailPath)
	s, _ := c.state()
	if be == nil && (s.ConfigHash == "" || digest(b) != s.ConfigHash) {
		return p, errors.New("覆盖文件由外部创建或修改，已禁止写入")
	}
	if be != nil && !errors.Is(be, os.ErrNotExist) {
		return p, be
	}
	if req.Operation == "install" {
		if f.Installed {
			return p, errors.New("Fail2ban 已安装")
		}
		if c.family() == "" {
			return p, errors.New("当前系统不支持自动安装")
		}
		p.Changes = []string{"安装 Fail2ban 和所需日志依赖，不自动启用 SSH 防护"}
		return p, nil
	}
	if !f.Installed {
		return p, errors.New("请先安装 Fail2ban")
	}
	if !f.Writable && req.Operation != "disable" && req.Operation != "detach" && req.Operation != "unban" {
		return p, errors.New(f.Reason)
	}
	if req.Operation != "enable" && req.Operation != "adopt" && f.ManagedJail == "" {
		return p, errors.New("请先确认接管 SSH jail")
	}
	switch req.Operation {
	case "enable", "configure", "adopt":
		cfg, e := validateConfig(req.Config)
		if e != nil {
			return p, e
		}
		if req.Operation == "enable" && f.ManagedJail == "" && len(f.Jails) > 0 {
			return p, errors.New("已有 SSH jail，请先确认接管，避免重复封禁")
		}
		if req.Operation == "adopt" {
			if f.ManagedJail != "" {
				return p, errors.New("已有悟空管理的 SSH jail")
			}
			if !nameRE.MatchString(req.Jail) {
				return p, errors.New("无效 jail")
			}
			found := false
			for _, j := range f.Jails {
				if j.Name == req.Jail {
					found = true
				}
			}
			if !found {
				return p, errors.New("SSH jail 不存在")
			}
		}
		fw, e := c.Firewall(ctx, req.Zone)
		if e != nil {
			return p, e
		}
		if !fw.Writable {
			return p, errors.New(fw.Reason)
		}
		if (fw.Backend == "ufw" || fw.Backend == "firewalld") && !fw.Active {
			return p, errors.New("请先启用主机防火墙")
		}
		if fw.Backend == "firewalld" && len(fw.Zones) > 1 {
			return p, errors.New("多个区域生效时，请在主机确认 SSH 所属区域后配置")
		}
		p.Changes = []string{fmt.Sprintf("SSH：%d 次 / %d 秒，封禁 %d 秒，模式 %s；白名单 %s", cfg.MaxRetry, cfg.FindTime, cfg.BanTime, cfg.Mode, strings.Join(cfg.IgnoreIPs, ", "))}
		p.Warnings = []string{"仅防护实际 SSH TCP 端口；白名单不会自动使用浏览器或中央主机地址"}
	case "disable":
		p.Changes = []string{"仅停用 " + f.ManagedJail + "；其他 jail 保持运行"}
	case "detach":
		p.Changes = []string{"移除悟空覆盖配置，恢复接管前的 SSH jail 配置"}
	case "reload":
		p.Changes = []string{"仅重载 " + f.ManagedJail + " 并恢复当前封禁"}
	case "unban":
		a, e := netip.ParseAddr(req.IP)
		if e != nil || a.Zone() != "" {
			return p, errors.New("解封需要有效单个 IP")
		}
		found := false
		for _, j := range f.Jails {
			if j.Managed && contains(j.Banned, a.Unmap().String()) {
				found = true
			}
		}
		if !found {
			return p, errors.New("此 IP 不在悟空 SSH jail 封禁列表")
		}
		p.Changes = []string{"解封 " + a.Unmap().String()}
	default:
		return p, errors.New("未知 SSH 防护操作")
	}
	return p, nil
}
func (c *Controller) captureBans(ctx context.Context) (map[string][]string, error) {
	r := map[string][]string{}
	if !c.Lookup("fail2ban-client") {
		return r, nil
	}
	names, e := c.jailNames(ctx)
	if e != nil {
		return r, nil
	}
	for _, n := range names {
		s, e := c.exec(ctx, "fail2ban-client", "status", n)
		if e != nil {
			return nil, e
		}
		r[n] = parsedIPs(field(s, "Banned IP list"))
	}
	return r, nil
}
func (c *Controller) resyncBans(ctx context.Context, bans map[string][]string) error {
	for n, ips := range bans {
		if !nameRE.MatchString(n) {
			return errors.New("invalid jail in recovery")
		}
		if len(ips) == 0 {
			continue
		}
		// Keep other jails and their counters running. Reapply only missing
		// native bans after a firewall reload, without restarting entire jails.
		owned, _ := c.state()
		ports := []int{}
		if n == owned.Jail {
			ports, _ = c.ports(ctx)
		}
		if c.enforcement(ctx, n, ips, ports) == nil {
			continue
		}
		for _, s := range ips {
			a, e := netip.ParseAddr(s)
			if e != nil {
				return e
			}
			if _, e = c.exec(ctx, "fail2ban-client", "set", n, "unbanip", a.String()); e != nil {
				return e
			}
			if _, e = c.exec(ctx, "fail2ban-client", "set", n, "banip", a.String()); e != nil {
				return e
			}
		}
		s, e := c.exec(ctx, "fail2ban-client", "status", n)
		if e != nil {
			return e
		}
		actual := parsedIPs(field(s, "Banned IP list"))
		for _, ip := range ips {
			if !contains(actual, ip) {
				return errors.New("无法恢复 SSH 封禁")
			}
		}
		if e := c.enforcement(ctx, n, ips, ports); e != nil {
			return e
		}
	}
	return nil
}
func renderJail(name string, cfg model.SSHProtectionConfig, enabled bool, backend, logpath, action string, ports []int) []byte {
	numbers := []string{}
	for _, p := range ports {
		numbers = append(numbers, strconv.Itoa(p))
	}
	s := fmt.Sprintf("%s[%s]\nenabled = %t\nfilter = sshd[mode=%s,_daemon=(?:auth(?:priv)?\\.\\S+\\s+)?sshd(?:-session)?]\nport = %s\nprotocol = tcp\nbackend = %s\nusedns = no\nignoreself = true\nignoreip = %s\nmaxretry = %d\nfindtime = %d\nbantime = %d\naction = %s\n", marker, name, enabled, cfg.Mode, strings.Join(numbers, ","), backend, strings.Join(cfg.IgnoreIPs, " "), cfg.MaxRetry, cfg.FindTime, cfg.BanTime, action)
	if backend == "systemd" {
		s += "journalmatch = _COMM=sshd + SYSLOG_IDENTIFIER=sshd + _COMM=sshd-session\n"
	} else {
		s += "logpath = " + logpath + "\n"
	}
	return []byte(s)
}
func (c *Controller) applyFail2ban(ctx context.Context, r model.SecurityRequest, j *journal, s *state) error {
	if r.Operation == "unban" {
		a, _ := netip.ParseAddr(r.IP)
		_, e := c.exec(ctx, "fail2ban-client", "set", s.Jail, "unbanip", a.Unmap().String())
		return e
	}
	if r.Operation == "reload" {
		if _, e := c.exec(ctx, "fail2ban-client", "reload", "--restart", "--if-exists", s.Jail); e != nil {
			return e
		}
		return c.resyncBans(ctx, j.Bans)
	}
	if r.Operation == "detach" {
		adopted := s.Adopted
		name := s.Jail
		if e := os.Remove(c.path(jailPath)); e != nil {
			return e
		}
		if _, e := c.exec(ctx, "fail2ban-client", "-t"); e != nil {
			return e
		}
		if s.Adopted {
			if _, e := c.exec(ctx, "fail2ban-client", "reload", "--restart", "--if-exists", name); e != nil {
				return e
			}
		} else {
			names, e := c.jailNames(ctx)
			if e != nil {
				return e
			}
			if contains(names, name) {
				if _, e = c.exec(ctx, "fail2ban-client", "stop", name); e != nil {
					return e
				}
			}
		}

		s.Jail = ""
		s.ConfigHash = ""
		s.ActionHash = ""
		s.Adopted = false
		s.Config = defaults()
		bans := copyBans(j.Bans)
		if !adopted {
			delete(bans, name)
		}
		return c.resyncBans(ctx, bans)
	}
	cfg := s.Config
	enabled := r.Operation != "disable"
	if enabled {
		var e error
		cfg, e = validateConfig(r.Config)
		if e != nil {
			return e
		}
	}
	if s.Jail == "" {
		s.Jail = "wukong-sshd"
	}
	if r.Operation == "adopt" {
		s.Jail = r.Jail
		s.Adopted = true
	}
	backend, logpath, e := c.logSource(ctx)
	if e != nil && enabled {
		return e
	}
	ports, _ := c.ports(ctx)
	fw, e := c.Firewall(ctx, r.Zone)
	if e != nil {
		return e
	}
	action := "nftables-multiport[name=" + s.Jail + ", port=\"" + joinPorts(ports) + "\", protocol=tcp]"
	switch fw.Backend {
	case "ufw":
		action = "iptables-multiport[name=" + s.Jail + ", port=\"" + joinPorts(ports) + "\", protocol=tcp]"
	case "firewalld":
		parts := []string{}
		for i, port := range ports {
			extra := ""
			if i > 0 {
				extra = ", actname=wk-ssh-" + strconv.Itoa(port)
			}
			parts = append(parts, "firewallcmd-rich-rules[name="+s.Jail+", zone="+fw.Zone+", port="+strconv.Itoa(port)+", protocol=tcp"+extra+"]")
		}
		action = strings.Join(parts, "\n    ")
	}
	// Default files are not modified. Validate the complete effective config before reload.
	b := renderJail(s.Jail, cfg, enabled, backend, logpath, action, ports)
	if !enabled {
		b = []byte(marker + "[" + s.Jail + "]\nenabled = false\n")
	}
	if e = atomic(c.path(jailPath), b, 0600); e != nil {
		return e
	}
	if _, e = c.exec(ctx, "fail2ban-client", "-t"); e != nil {
		return e
	}
	if _, e = c.exec(ctx, "fail2ban-client", "ping"); e != nil {
		if !enabled {
			return errors.New("Fail2ban 服务不可用")
		}
		j.Started = true
		if e = c.save("pending.json", j); e != nil {
			return e
		}
		if e = c.service(ctx, "start", "fail2ban"); e != nil {
			return e
		}
	}
	if enabled {
		if _, e = c.exec(ctx, "fail2ban-client", "reload", "--restart", "--if-exists", s.Jail); e != nil {
			return e
		}
		if _, e = c.exec(ctx, "fail2ban-client", "status", s.Jail); e != nil {
			return e
		}
		s.Config = cfg
		hash, e := c.actionHash(ctx, s.Jail)
		if e != nil {
			return e
		}
		s.ActionHash = hash
	} else {
		names, e := c.jailNames(ctx)
		if e != nil {
			return e
		}
		if contains(names, s.Jail) {
			if _, e = c.exec(ctx, "fail2ban-client", "stop", s.Jail); e != nil {
				return e
			}
		}

	}
	s.ConfigHash = digest(b)
	if enabled {
		if c.isSystemd() {
			_, e = c.exec(ctx, "systemctl", "enable", "fail2ban.service")
		} else {
			_, e = c.exec(ctx, "rc-update", "add", "fail2ban", "default")
		}
		if e != nil {
			return e
		}
	}
	bans := copyBans(j.Bans)
	if !enabled {
		delete(bans, s.Jail)
	}
	return c.resyncBans(ctx, bans)
}
func copyBans(in map[string][]string) map[string][]string {
	out := map[string][]string{}
	for n, v := range in {
		out[n] = append([]string{}, v...)
	}
	return out
}
func joinPorts(ports []int) string {
	s := []string{}
	for _, p := range ports {
		s = append(s, strconv.Itoa(p))
	}
	return strings.Join(s, ",")
}

func (c *Controller) actionHash(ctx context.Context, name string) (string, error) {
	out, e := c.exec(ctx, "fail2ban-client", "get", name, "actions")
	if e != nil {
		return "", e
	}
	action := ""
	for _, candidate := range []string{"iptables-multiport", "nftables-multiport", "firewallcmd-rich-rules"} {
		if strings.Contains(out, candidate) {
			action = candidate
			break
		}
	}
	if action == "" {
		return "", errors.New("未识别到受支持的 SSH 封禁动作")
	}

	parts := []string{out}
	names := []string{action}
	for _, name := range strings.Fields(out) {
		if regexp.MustCompile(`^wk-ssh-[0-9]{1,5}$`).MatchString(name) {
			names = append(names, name)
		}
	}
	for _, actionName := range names {
		start, e := c.exec(ctx, "fail2ban-client", "get", name, "action", actionName, "actionstart")
		if e != nil {
			return "", e
		}
		ban, e := c.exec(ctx, "fail2ban-client", "get", name, "action", actionName, "actionban")
		if e != nil {
			return "", e
		}
		parts = append(parts, actionName, start, ban)
	}
	for _, key := range []string{"failregex", "ignoreregex", "ignoreip", "logpath", "journalmatch"} {
		v, err := c.exec(ctx, "fail2ban-client", "get", name, key)
		if err != nil && key != "logpath" && key != "journalmatch" {
			return "", err
		}
		parts = append(parts, key+":"+v)
	}
	return digest([]byte(strings.Join(parts, "\n"))), nil
}

// Verify known native actions without evaluating action templates or shell code.
func (c *Controller) enforcement(ctx context.Context, name string, ips []string, ports []int) error {
	actions, e := c.exec(ctx, "fail2ban-client", "get", name, "actions")
	if e != nil {
		return e
	}
	if strings.Contains(actions, "firewallcmd-rich-rules") {
		fw, e := c.Firewall(ctx, "")
		if e != nil {
			return e
		}
		if !fw.Active || len(fw.Zones) != 1 {
			return errors.New("无法校验 SSH 封禁所在的 firewalld 区域")
		}
		out, e := c.exec(ctx, "firewall-cmd", "--zone="+fw.Zone, "--list-rich-rules")
		if e != nil {
			return e
		}
		for _, ip := range ips {
			if len(ports) == 0 {
				found := false
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, `address="`+ip+`"`) && strings.Contains(line, `protocol="tcp"`) && (strings.Contains(line, " reject") || strings.Contains(line, " drop")) {
						found = true
					}
				}
				if !found {
					return errors.New("外部 SSH 封禁未实际生效")
				}
			}
			for _, port := range ports {
				found := false
				for _, line := range strings.Split(out, "\n") {
					if strings.Contains(line, `address="`+ip+`"`) && strings.Contains(line, `port="`+strconv.Itoa(port)+`"`) && strings.Contains(line, `protocol="tcp"`) && (strings.Contains(line, " reject") || strings.Contains(line, " drop")) {
						found = true
					}
				}
				if !found {
					return errors.New("SSH 封禁未在 firewalld 实际生效：" + ip)
				}
			}
		}
		return nil
	}
	if strings.Contains(actions, "iptables-multiport") {
		for _, ip := range ips {
			bin := "iptables-save"
			if strings.Contains(ip, ":") {
				bin = "ip6tables-save"
			}
			out, e := c.exec(ctx, bin)
			if e != nil {
				return e
			}
			ban, jump := false, false
			for _, line := range strings.Split(out, "\n") {
				fields := strings.Fields(line)
				if len(fields) < 2 {
					continue
				}
				if fields[0] == "-A" && fields[1] == "f2b-"+name && (strings.Contains(line, "-s "+ip+"/32 ") || strings.Contains(line, "-s "+ip+"/128 ") || strings.Contains(line, "-s "+ip+" ")) && strings.Contains(line, "-j REJECT") {
					ban = true
				}
				if fields[1] == "INPUT" && strings.Contains(line, "-p tcp") && strings.Contains(line, "-j f2b-"+name) {
					if len(ports) == 0 {
						jump = true
					}
					for _, port := range ports {
						if strings.Contains(line, "--dports "+joinPorts(ports)) || strings.Contains(line, "--dport "+strconv.Itoa(port)+" ") {
							jump = true
						}
					}
				}
			}
			if !ban || !jump {
				return errors.New("SSH 封禁未在 iptables 实际生效：" + ip)
			}
		}
		return nil
	}
	if strings.Contains(actions, "nftables-multiport") {
		out, e := c.exec(ctx, "nft", "-s", "list", "table", "inet", "f2b-table")
		if e != nil {
			return e
		}
		for _, ip := range ips {
			set := "addr-set-" + name
			if strings.Contains(ip, ":") {
				set = "addr6-set-" + name
			}
			re := regexp.MustCompile(`(?s)set ` + regexp.QuoteMeta(set) + ` \{(.*?)\n\s*\}`)
			m := re.FindStringSubmatch(out)
			if len(m) < 2 || !contains(strings.Fields(strings.NewReplacer(",", " ", "{", " ", "}", " ").Replace(m[1])), ip) {
				return errors.New("SSH 封禁未在 nftables 地址集合生效：" + ip)
			}
			bound := false
			for _, line := range strings.Split(out, "\n") {
				if strings.Contains(line, "@"+set) && strings.Contains(line, "tcp dport") && (strings.Contains(line, "reject") || strings.Contains(line, "drop")) {
					good := true
					for _, port := range ports {
						if !regexp.MustCompile(`\b` + strconv.Itoa(port) + `\b`).MatchString(line) {
							good = false
						}
					}
					bound = good
				}
			}
			if !bound {
				return errors.New("SSH nftables 集合未绑定实际 TCP 端口")
			}
		}
		return nil
	}
	return errors.New("无法校验未知 SSH 封禁动作")
}

func (c *Controller) verifyLogFilter(ctx context.Context, backend, path string) error {
	if !c.Lookup("fail2ban-regex") {
		return errors.New("缺少 fail2ban-regex，无法验证 SSH 日志过滤器")
	}
	sample := ""
	if backend == "systemd" {
		sample, _ = c.exec(ctx, "journalctl", "--no-pager", "-n", "30", "-o", "short", "_COMM=sshd", "+", "SYSLOG_IDENTIFIER=sshd", "+", "_COMM=sshd-session")
	} else {
		b, e := c.readSample(path)
		if e != nil {
			return e
		}
		sample = string(b)
	}
	if !strings.Contains(sample, "Failed password") && !strings.Contains(sample, "Invalid user") {
		return nil
	}
	filter := c.path("/etc/fail2ban/filter.d/sshd.conf") + `[mode=normal,_daemon=(?:auth(?:priv)?\.\S+\s+)?sshd(?:-session)?]`
	out, e := c.exec(ctx, "fail2ban-regex", sample, filter)
	if e != nil {
		return fmt.Errorf("SSH 日志过滤器校验失败：%w", e)
	}
	fields := strings.Fields(field(out, "Failregex"))
	if len(fields) == 0 {
		return errors.New("无法读取 SSH 过滤器匹配结果")
	}
	n, e := strconv.Atoi(fields[0])
	if e != nil || n == 0 {
		return errors.New("发行版 SSH 过滤器无法匹配实际失败日志，请核对日志格式")
	}
	return nil
}
