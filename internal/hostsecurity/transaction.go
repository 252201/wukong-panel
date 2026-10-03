package hostsecurity

import (
	"context"
	"errors"
	"fmt"
	"github.com/252201/wukong-panel/internal/model"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"time"
)

func (c *Controller) Preview(ctx context.Context, kind string, r model.SecurityRequest) (model.SecurityPreview, error) {
	unlock, e := c.lock()
	if e != nil {
		return model.SecurityPreview{}, e
	}
	defer unlock()
	switch kind {
	case "firewall":
		return c.firewallPreview(ctx, r)
	case "fail2ban":
		return c.fail2banPreview(ctx, r)
	}
	return model.SecurityPreview{}, errors.New("unknown security resource")
}
func (c *Controller) Apply(ctx context.Context, kind string, r model.SecurityRequest) (result model.SecurityResult, err error) {
	unlock, e := c.lock()
	if e != nil {
		return result, e
	}
	defer unlock()
	if kind != "firewall" && kind != "fail2ban" {
		return result, errors.New("unknown security resource")
	}
	var p model.SecurityPreview
	if kind == "firewall" {
		p, e = c.firewallPreview(ctx, r)
	} else {
		p, e = c.fail2banPreview(ctx, r)
	}
	if e != nil {
		return result, e
	}
	if r.Revision == "" || r.Revision != p.Revision {
		return result, errors.New("状态已变化，请重新预览")
	}
	s, e := c.state()
	if e != nil {
		return result, e
	}
	bans, e := c.captureBans(ctx)
	if e != nil {
		return result, e
	}
	j := journal{Transaction: model.SecurityTransaction{ID: token(), Status: "applying", Deadline: c.Now().Add(90 * time.Second)}, Kind: kind, BootID: c.boot(), Before: s, Bans: bans}
	if kind == "firewall" {
		f, e := c.Firewall(ctx, r.Zone)
		if e != nil {
			return result, e
		}
		if e = c.firewallBackup(ctx, &j, f); e != nil {
			return result, e
		}
	} else if e = c.backup(&j, jailPath); e != nil {
		return result, e
	}
	if kind == "fail2ban" {
		j.Target = s.Jail
		if r.Operation == "adopt" {
			j.Target = r.Jail
		}
		if j.Target == "" {
			j.Target = "wukong-sshd"
		}
	}
	service := j.Backend
	if service == "nftables" {
		service = "wukong-firewall"
	}
	if kind == "fail2ban" {
		service = "fail2ban"
	}
	if service == "wukong-firewall" || service == "nftables" || service == "ufw" || service == "firewalld" || service == "fail2ban" {
		j.BootEnabled = map[string]bool{service: c.bootEnabled(ctx, service)}
	}
	if r.Operation == "install" {
		j.Install = true
		if c.family() == "apt" {
			if e = c.backup(&j, "/usr/sbin/policy-rc.d"); e != nil {
				return result, e
			}
		}
		j.Transaction.Deadline = c.Now().Add(10 * time.Minute)
	}
	if e = c.validateBackup(j); e != nil {
		return result, e
	}
	if e = c.arm(ctx); e != nil {
		return result, fmt.Errorf("无法建立独立恢复任务，未应用变更：%w", e)
	}
	if e = c.save("backup-"+j.Transaction.ID+".json", j); e != nil {
		return result, e
	}
	var verify journal
	if e = c.load("backup-"+j.Transaction.ID+".json", &verify); e != nil {
		return result, e
	}
	if e = c.validateBackup(verify); e != nil {
		return result, e
	}
	if e = c.save("pending.json", j); e != nil {
		return result, e
	}
	defer func() {
		if err != nil {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if e := c.rollback(recoveryCtx, &j); e != nil {
				err = errors.Join(err, fmt.Errorf("恢复失败，恢复任务将重试：%w", e))
			}
		}
	}()
	if r.Operation == "install" {
		err = c.install(ctx, kind, j.Backend)
		if err != nil {
			return result, err
		}
		if kind == "firewall" && j.Backend == "firewalld" {
			if e := c.service(ctx, "stop", "firewalld"); e != nil {
				return result, e
			}
			if e := c.setBoot(ctx, "firewalld", false); e != nil {
				return result, e
			}
		}
		if kind == "fail2ban" {
			if e := c.setBoot(ctx, "fail2ban", false); e != nil {
				return result, e
			}
		}
	} else if kind == "firewall" {
		err = c.applyFirewall(ctx, r, &j, &s)
		if err == nil {
			err = c.resyncBans(ctx, j.Bans)
		}
	} else {
		err = c.applyFail2ban(ctx, r, &j, &s)
	}
	if err != nil {
		return result, err
	}
	if err = c.save("state.json", s); err != nil {
		return result, err
	}
	if kind == "firewall" {
		f, e := c.Firewall(ctx, r.Zone)
		if e != nil {
			return result, e
		}
		if r.Operation == "install" && !f.Installed {
			return result, errors.New("安装后仍未检测到防火墙命令")
		}
		if r.Operation == "enable" && (!f.Active || f.Policy != "deny") {
			return result, errors.New("入站策略未实际生效")
		}
		if r.Operation == "add" {
			rr, _ := normalizeRule(r.Rule)
			rr.Zone = f.Zone
			found := false
			for _, v := range f.Rules {
				if sameRule(rr, v) {
					found = true
				}
			}
			if !found {
				return result, errors.New("新规则未实际生效")
			}
		}
		result.Firewall = &f
	} else {
		f, e := c.Fail2ban(ctx)
		if e != nil {
			return result, e
		}
		if r.Operation == "install" && !f.Installed {
			return result, errors.New("安装后仍未检测到 Fail2ban 命令")
		}
		if contains([]string{"enable", "configure", "adopt"}, r.Operation) {
			found := false
			for _, v := range f.Jails {
				if v.Name == s.Jail && v.Config.MaxRetry == s.Config.MaxRetry && v.Config.FindTime == s.Config.FindTime && v.Config.BanTime == s.Config.BanTime {
					found = true
				}
			}
			if !found || len(f.Jails) != 1 {
				return result, fmt.Errorf("SSH jail 未按配置运行：%s (%d jails)", f.Reason, len(f.Jails))
			}
		}
		result.Fail2ban = &f
	}
	j.Transaction.Deadline = c.Now().Add(90 * time.Second)
	j.Transaction.Status = "awaiting-confirmation"
	if !p.NeedsConfirmation {
		j.Transaction.Status = "confirmed"
	}
	if err = c.save("pending.json", j); err != nil {
		return result, err
	}
	result.Transaction = &j.Transaction
	if !p.NeedsConfirmation {
		err = c.finish(&j)
		if result.Firewall != nil {
			result.Firewall.Pending = nil
		}
	} else if result.Firewall != nil {
		result.Firewall.Pending = &j.Transaction
	}
	return result, err
}
func (c *Controller) finish(j *journal) error {
	if e := c.save("last.json", j.Transaction); e != nil {
		return e
	}
	if e := os.Remove(filepath.Join(c.Dir, "pending.json")); e != nil && !errors.Is(e, os.ErrNotExist) {
		return e
	}
	return nil
}
func (c *Controller) Transaction(id string) (model.SecurityTransaction, error) {
	if !idRE.MatchString(id) {
		return model.SecurityTransaction{}, errors.New("invalid transaction ID")
	}
	if p := c.pending(); p != nil && p.ID == id {
		return *p, nil
	}
	var t model.SecurityTransaction
	if e := c.load("last.json", &t); e != nil {
		return t, e
	}
	if t.ID != id {
		return t, errors.New("transaction not found")
	}
	return t, nil
}
func (c *Controller) Confirm(ctx context.Context, id string) (model.SecurityTransaction, error) {
	unlock, e := c.lock()
	if e != nil {
		return model.SecurityTransaction{}, e
	}
	defer unlock()
	if !idRE.MatchString(id) {
		return model.SecurityTransaction{}, errors.New("invalid transaction ID")
	}
	var j journal
	if e = c.load("pending.json", &j); e != nil {
		return model.SecurityTransaction{}, e
	}
	if j.Transaction.ID != id || j.Transaction.Status != "awaiting-confirmation" {
		return j.Transaction, errors.New("transaction is not awaiting confirmation")
	}
	if !c.Now().Before(j.Transaction.Deadline) || c.boot() != j.BootID {
		if e = c.rollback(ctx, &j); e != nil {
			return j.Transaction, e
		}
		return j.Transaction, errors.New("确认窗口已结束，已恢复原配置")
	}
	j.Transaction.Status = "confirmed"
	e = c.finish(&j)
	return j.Transaction, e
}
func (c *Controller) Recover(ctx context.Context) error {
	unlock, e := c.lock()
	if e != nil {
		if errors.Is(e, ErrBusy) {
			return nil
		}
		return e
	}
	defer unlock()
	var j journal
	if e = c.load("pending.json", &j); errors.Is(e, os.ErrNotExist) {
		return nil
	} else if e != nil {
		return e
	}
	if c.Now().Before(j.Transaction.Deadline) && c.boot() == j.BootID {
		return nil
	}
	return c.rollback(ctx, &j)
}
func (c *Controller) rollback(ctx context.Context, j *journal) error {
	if e := c.validateBackup(*j); e != nil {
		return e
	}
	if j.Kind != "firewall" && j.Kind != "fail2ban" {
		return errors.New("invalid journal kind")
	}
	for _, f := range j.Files {
		if f.Exists {
			if e := atomic(c.path(f.Path), f.Data, os.FileMode(f.Mode)); e != nil {
				return e
			}
		} else if j.Install && f.Path != "/usr/sbin/policy-rc.d" {
			continue
		} else if e := os.Remove(c.path(f.Path)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	// Undo appended native rule operations in reverse order, then restore service/table.
	if j.Backend == "firewalld" && len(j.Runtime) > 0 {
		if e := c.service(ctx, "start", "firewalld"); e != nil {
			return e
		}
		if _, e := c.exec(ctx, "firewall-cmd", "--reload"); e != nil {
			return e
		}
		for _, op := range j.Runtime {
			if !validFireUndo(op.Args) {
				return errors.New("invalid runtime restore")
			}
			if _, e := c.Run(ctx, op.Name, op.Args, op.Input); e != nil {
				return e
			}
		}
		// The runtime snapshot replaces individual rule undo operations, but
		// the original service state must still be restored on first enable.
		services := []command{}
		for _, op := range j.Undo {
			if op.Name == "service-start-firewalld" || op.Name == "service-stop-firewalld" {
				services = append(services, op)
			}
		}
		j.Undo = services
	}
	for i := len(j.Undo) - 1; i >= 0; i-- {
		op := j.Undo[i]
		switch op.Name {
		case "nft-restore":
			body := op.Input
			if body != "" && !strings.HasPrefix(body, "table inet wukong_panel {") {
				return errors.New("invalid nft recovery table")
			}
			if _, e := c.exec(ctx, "nft", "list", "table", "inet", "wukong_panel"); e == nil {
				body = "delete table inet wukong_panel\n" + body
			}
			if strings.TrimSpace(body) != "" {
				if _, e := c.Run(ctx, "nft", []string{"-f", "-"}, body); e != nil {
					return e
				}
			}
		case "service-start-firewalld":
			if e := c.service(ctx, "start", "firewalld"); e != nil {
				return e
			}
		case "service-stop-firewalld":
			if e := c.service(ctx, "stop", "firewalld"); e != nil {
				return e
			}
		case "ufw":
			if len(op.Args) != 2 || op.Args[0] != "--force" || !contains([]string{"enable", "disable"}, op.Args[1]) {
				return errors.New("invalid ufw recovery")
			}
			if _, e := c.exec(ctx, "ufw", op.Args...); e != nil {
				return e
			}
			if op.Args[1] == "enable" {
				// enable is a no-op when UFW is already active. Restoring the
				// files alone leaves the changed kernel rules in place. Keep
				// this here so journals written by older versions also reload.
				if _, e := c.exec(ctx, "ufw", "reload"); e != nil {
					return e
				}
			}
		case "firewall-cmd":
			if !validFireUndo(op.Args) {
				return errors.New("invalid firewalld recovery")
			}
			if _, e := c.exec(ctx, "firewall-cmd", op.Args...); e != nil {
				return e
			}
		default:
			return errors.New("invalid recovery command")
		}
	}
	if j.Kind == "fail2ban" && c.Lookup("fail2ban-client") {
		name := j.Target
		if !nameRE.MatchString(name) {
			return errors.New("invalid recovery jail")
		}
		if _, e := c.exec(ctx, "fail2ban-client", "ping"); e == nil {
			if _, e = c.exec(ctx, "fail2ban-client", "-t"); e != nil {
				return e
			}
			_, existed := j.Bans[name]
			if !existed && j.Before.ConfigHash == "" {
				names, e := c.jailNames(ctx)
				if e != nil {
					return e
				}
				if contains(names, name) {
					if _, e = c.exec(ctx, "fail2ban-client", "stop", name); e != nil {
						return e
					}
				}
			} else {
				if _, e = c.exec(ctx, "fail2ban-client", "reload", "--restart", "--if-exists", name); e != nil {
					return e
				}
			}
		}
	}
	for name, enabled := range j.BootEnabled {
		if !contains([]string{"ufw", "firewalld", "nftables", "fail2ban", "wukong-firewall"}, name) {
			return errors.New("invalid boot service")
		}
		if e := c.setBoot(ctx, name, enabled); e != nil {
			return e
		}
	}
	if e := c.resyncBans(ctx, j.Bans); e != nil {
		return e
	}
	if j.Kind == "fail2ban" && j.Started && len(j.Bans) == 0 {
		if e := c.service(ctx, "stop", "fail2ban"); e != nil {
			return e
		}
	}
	if e := c.save("state.json", j.Before); e != nil {
		return e
	}
	j.Transaction.Status = "rolled-back"
	return c.finish(j)
}
func validFireUndo(a []string) bool {
	if len(a) == 1 {
		return a[0] == "--reload"
	}
	zone := false
	for _, s := range a {
		if s == "--permanent" {
			continue
		}
		if strings.HasPrefix(s, "--zone=") {
			zone = nameRE.MatchString(strings.TrimPrefix(s, "--zone="))
			continue
		}
		ok := false
		for _, p := range []string{"--add-port=", "--remove-port=", "--add-rich-rule=", "--remove-rich-rule=", "--set-target=", "--change-interface=", "--add-source=", "--add-service=", "--add-protocol=", "--add-source-port=", "--add-icmp-block="} {
			if strings.HasPrefix(s, p) {
				ok = true
			}
		}
		if contains([]string{"--add-forward", "--add-masquerade", "--add-icmp-block-inversion"}, s) {
			ok = true
		}
		if !ok {
			return false
		}
	}
	return zone
}
func (c *Controller) arm(ctx context.Context) error {
	if c.Arm != nil {
		return c.Arm(ctx)
	}
	if c.Root != "" {
		return errors.New("test root requires explicit recovery runner")
	}
	bin, e := os.Executable()
	if c.RecoveryBinary != "" {
		bin = c.RecoveryBinary
		e = nil
	}
	if e != nil {
		return e
	}
	bin, e = filepath.EvalSymlinks(bin)
	if e != nil {
		return e
	}
	for _, p := range []string{bin, c.Dir} {
		if strings.ContainsAny(p, "\n\r\x00") {
			return errors.New("invalid recovery path")
		}
	}
	dir := filepath.Dir(c.Dir)
	if c.isSystemd() {
		body := "[Unit]\nDescription=Wukong security transaction recovery\nAfter=local-fs.target\nBefore=ufw.service firewalld.service nftables.service wukong-agent.service\n[Service]\nType=simple\nExecStart=" + strconv.Quote(bin) + " security-recovery --secret-dir " + strconv.Quote(dir) + "\nRestart=always\nRestartSec=1\n[Install]\nWantedBy=multi-user.target\n"
		if e = atomic("/etc/systemd/system/wukong-security-recovery.service", []byte(body), 0644); e != nil {
			return e
		}
		if _, e = c.exec(ctx, "systemctl", "daemon-reload"); e != nil {
			return e
		}
		if _, e = c.exec(ctx, "systemctl", "enable", "--now", "wukong-security-recovery.service"); e != nil {
			return e
		}
	} else if c.Lookup("rc-service") && c.Lookup("rc-update") {
		quote := func(s string) string { return "'" + strings.ReplaceAll(s, "'", "'\\''") + "'" }
		body := "#!/sbin/openrc-run\nname=\"Wukong security recovery\"\ncommand=" + quote(bin) + "\ncommand_args=" + quote("security-recovery --secret-dir "+quote(dir)) + "\ncommand_background=true\npidfile=\"/run/wukong-security-recovery.pid\"\ndepend() { need localmount; before ufw firewalld nftables wukong-agent; }\n"
		if e = atomic("/etc/init.d/wukong-security-recovery", []byte(body), 0755); e != nil {
			return e
		}
		if _, e = c.exec(ctx, "rc-update", "add", "wukong-security-recovery", "default"); e != nil {
			return e
		}
		if e = c.service(ctx, "start", "wukong-security-recovery"); e != nil {
			return e
		}
	} else {
		return errors.New("缺少 systemd/OpenRC，无法安排独立恢复")
	}
	deadline := time.NewTimer(5 * time.Second)
	defer deadline.Stop()
	tick := time.NewTicker(100 * time.Millisecond)
	defer tick.Stop()
	for {
		var h struct {
			Boot string
			At   time.Time
		}
		if c.load("heartbeat.json", &h) == nil && h.Boot == c.boot() && c.Now().Sub(h.At) < 3*time.Second {
			return nil
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-deadline.C:
			return errors.New("恢复进程未响应")
		case <-tick.C:
		}
	}
}
func (c *Controller) Watch(ctx context.Context) error {
	for {
		if e := c.save("heartbeat.json", struct {
			Boot string
			At   time.Time
		}{c.boot(), c.Now()}); e != nil {
			return e
		}
		if e := c.Recover(ctx); e != nil {
			var j journal
			if c.load("pending.json", &j) == nil {
				j.Transaction.Error = e.Error()
				_ = c.save("recovery-error.json", j.Transaction)
			}
		}
		select {
		case <-ctx.Done():
			return ctx.Err()
		case <-time.After(time.Second):
		}
	}
}
