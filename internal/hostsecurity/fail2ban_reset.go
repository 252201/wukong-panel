package hostsecurity

import (
	"context"
	"errors"
	"fmt"
	"io/fs"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
	"time"

	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/sys/unix"
)

const resetConfirmation = "RESET FAIL2BAN"
const resetDisabledPath = "/etc/fail2ban/jail.d/zzzz-wukong-reset.local"

var resetRoots = []string{"/etc/fail2ban", "/var/lib/fail2ban"}

// Paths are fixed by the Agent. A request never supplies a configuration path,
// package name or command. Symlinks and special files are refused, not followed.
func resetPath(p string) bool {
	if filepath.Clean(p) != p {
		return false
	}
	for _, root := range resetRoots {
		if p == root || strings.HasPrefix(p, root+"/") {
			return true
		}
	}
	return false
}
func (c *Controller) resetFiles(roots []string) ([]savedFile, error) {
	files := []savedFile{}
	total := int64(0)
	for _, root := range roots {
		for parent := filepath.Dir(root); parent != "/" && parent != "."; parent = filepath.Dir(parent) {
			info, err := os.Lstat(c.path(parent))
			if err != nil || !info.IsDir() || info.Mode()&os.ModeSymlink != 0 {
				return nil, fmt.Errorf("Fail2ban 路径父目录不安全：%s", parent)
			}
		}
		var rootStat unix.Stat_t
		statErr := unix.Lstat(c.path(root), &rootStat)
		if statErr != nil && !errors.Is(statErr, os.ErrNotExist) {
			return nil, statErr
		}
		err := filepath.WalkDir(c.path(root), func(p string, entry fs.DirEntry, err error) error {
			path := root
			if p != c.path(root) {
				rel, e := filepath.Rel(c.path(root), p)
				if e != nil {
					return e
				}
				path += "/" + filepath.ToSlash(rel)
			}
			if errors.Is(err, os.ErrNotExist) && path == root {
				files = append(files, savedFile{Path: root})
				return nil
			}
			if err != nil {
				return err
			}
			info, err := entry.Info()
			if err != nil {
				return err
			}
			if info.Mode()&os.ModeSymlink != 0 || !info.IsDir() && !info.Mode().IsRegular() {
				return fmt.Errorf("含符号链接或特殊文件，无法安全清理：%s", path)
			}
			var stat unix.Stat_t
			if e := unix.Lstat(p, &stat); e != nil {
				return e
			}
			if stat.Dev != rootStat.Dev {
				return errors.New("Fail2ban 目录包含挂载点，禁止自动清理")
			}
			if len(files) >= 4096 || info.Size() > 64<<20 {
				return errors.New("Fail2ban 备份超过安全大小限制，请由管理员处理")
			}
			f := savedFile{Path: path, Exists: true, Mode: uint32(info.Mode().Perm()), Directory: info.IsDir()}
			if !f.Directory {
				total += info.Size()
				if total > 64<<20 {
					return errors.New("Fail2ban 备份超过 64 MiB，请由管理员处理")
				}
				f.Data, err = c.read(path)
				if err != nil {
					return err
				}
				f.Hash = digest(f.Data)
			}
			files = append(files, f)
			return nil
		})
		if err != nil {
			return nil, err
		}
	}
	return files, nil
}
func validateResetFiles(files []savedFile) error {
	seen := map[string]bool{}
	for _, f := range files {
		if !resetPath(f.Path) || seen[f.Path] || f.Mode > 0777 || f.Directory && len(f.Data) != 0 || f.Exists && !f.Directory && digest(f.Data) != f.Hash {
			return errors.New("Fail2ban 清理备份校验失败")
		}
		seen[f.Path] = true
	}
	return nil
}
func (c *Controller) resetPackages(ctx context.Context) ([]string, error) {
	switch c.family() {
	case "apt":
		out, err := c.exec(ctx, "dpkg-query", "-S", "/usr/bin/fail2ban-client")
		if err != nil || !strings.HasPrefix(out, "fail2ban: ") {
			return nil, errors.New("Fail2ban 不是受支持的发行版软件包安装")
		}
		return []string{"fail2ban"}, nil
	case "dnf":
		owner, err := c.exec(ctx, "rpm", "-qf", "--qf", "%{NAME}", "/usr/bin/fail2ban-client")
		if err != nil || owner != "fail2ban-server" {
			return nil, errors.New("Fail2ban 不是受支持的发行版软件包安装")
		}
		out, err := c.exec(ctx, "rpm", "-qa", "--qf", "%{NAME}\n")
		if err != nil {
			return nil, err
		}
		packages := []string{}
		for _, p := range strings.Fields(out) {
			if p == "fail2ban" || strings.HasPrefix(p, "fail2ban-") {
				if !nameRE.MatchString(p) {
					return nil, errors.New("无效软件包名称")
				}
				packages = append(packages, p)
			}
		}
		sort.Strings(packages)
		if len(packages) == 0 || len(packages) > 32 {
			return nil, errors.New("无法识别 Fail2ban 软件包")
		}
		return packages, nil
	case "apk":
		out, err := c.exec(ctx, "apk", "info", "--who-owns", "/usr/bin/fail2ban-client")
		if err != nil || !strings.Contains(out, "owned by fail2ban-") {
			return nil, errors.New("Fail2ban 不是受支持的发行版软件包安装")
		}
		return []string{"fail2ban", "fail2ban-openrc"}, nil
	}
	return nil, errors.New("当前发行版不支持自动重新安装")
}
func (c *Controller) resetGuard(ctx context.Context) error {
	if c.Demo {
		return errors.New("演示环境不执行清理")
	}
	if !c.Lookup("fail2ban-client") {
		return errors.New("Fail2ban 尚未安装，请使用安装按钮")
	}
	if c.pending() != nil {
		return errors.New("安全变更尚待确认或恢复")
	}
	if !c.isSystemd() && !c.Lookup("rc-service") {
		return errors.New("需要 systemd 或 OpenRC")
	}
	b, err := c.read("/proc/self/status")
	if err != nil {
		return errors.New("无法验证 CAP_NET_ADMIN 权限")
	}
	caps := regexp.MustCompile(`(?m)^CapEff:\s*([0-9a-fA-F]+)`).FindSubmatch(b)
	if len(caps) != 2 {
		return errors.New("无法验证 CAP_NET_ADMIN 权限")
	}
	v, err := strconv.ParseUint(string(caps[1]), 16, 64)
	if err != nil || v&(1<<12) == 0 {
		return errors.New("缺少 CAP_NET_ADMIN，无法安全清理封禁")
	}
	// A custom launch command may use a different config, socket or database.
	for _, p := range []string{"/etc/systemd/system/fail2ban.service", "/etc/systemd/system/fail2ban.service.d", "/run/systemd/system/fail2ban.service", "/run/systemd/system/fail2ban.service.d"} {
		if _, err := os.Lstat(c.path(p)); err == nil {
			return errors.New("存在自定义 Fail2ban 服务覆盖，请由管理员核对后再清理")
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	for _, p := range []string{"/etc/default/fail2ban", "/etc/conf.d/fail2ban"} {
		if b, err := c.read(p); err == nil {
			for _, l := range strings.Split(string(b), "\n") {
				l = strings.TrimSpace(l)
				if l != "" && !strings.HasPrefix(l, "#") && !regexp.MustCompile(`^[A-Z0-9_]+\s*=\s*(?:""|'')\s*$`).MatchString(l) {
					return errors.New("存在自定义 Fail2ban 启动参数，请由管理员核对后再清理")
				}
			}
		} else if !errors.Is(err, os.ErrNotExist) {
			return err
		}
	}
	return nil
}
func (c *Controller) resetPlan(ctx context.Context) (model.SecurityPreview, error) {
	p := model.SecurityPreview{Changes: []string{}, Warnings: []string{}, RequiredPorts: []model.SecurityPort{}}
	if err := c.resetGuard(ctx); err != nil {
		return p, err
	}
	packages, err := c.resetPackages(ctx)
	if err != nil {
		return p, err
	}
	files, err := c.resetFiles([]string{resetRoots[0]})
	if err != nil {
		return p, err
	}
	// Custom persistent paths outside the bounded roots are never deleted.
	for _, f := range files {
		if !f.Exists || f.Directory {
			continue
		}
		for _, l := range strings.Split(string(f.Data), "\n") {
			parts := strings.SplitN(strings.TrimSpace(l), "=", 2)
			if len(parts) != 2 {
				continue
			}
			key := strings.TrimSpace(parts[0])
			value := strings.TrimSpace(strings.SplitN(parts[1], " #", 2)[0])
			if key == "dbfile" && value != "None" && value != ":memory:" && !(filepath.Clean(value) == value && strings.HasPrefix(value, "/var/lib/fail2ban/")) || key == "socket" && value != "/var/run/fail2ban/fail2ban.sock" && value != "/run/fail2ban/fail2ban.sock" || key == "pidfile" && value != "/var/run/fail2ban/fail2ban.pid" && value != "/run/fail2ban/fail2ban.pid" {
				return p, errors.New("存在自定义数据库或运行路径，无法完全自动清理，请由管理员处理")
			}
		}
	}
	// Validate persistent data paths now; capture contents only after stopping the daemon.
	if _, err = c.resetFiles([]string{resetRoots[1]}); err != nil {
		return p, err
	}
	names, err := c.jailNames(ctx)
	running := err == nil
	if !running && !c.fail2banStopped(ctx) {
		return p, errors.New("无法确认 Fail2ban 服务状态，禁止清理")
	}
	s, err := c.state()
	if err != nil {
		return p, err
	}
	p.Revision = c.revision("fail2ban-reset-v1", files, packages, names, running, c.bootEnabled(ctx, "fail2ban"), s)
	configNames := []string{}
	sections := regexp.MustCompile(`(?m)^\s*\[([A-Za-z0-9_-]+)\]\s*$`)
	for _, f := range files {
		if strings.Contains(f.Path, "/jail") {
			for _, m := range sections.FindAllSubmatch(f.Data, -1) {
				if string(m[1]) != "DEFAULT" && !contains(configNames, string(m[1])) {
					configNames = append(configNames, string(m[1]))
				}
			}
		}
	}
	sort.Strings(configNames)
	p.Changes = []string{"停止 Fail2ban，解除它管理的所有当前封禁（包括非 SSH 防护）", "保存并验证完整配置、数据库与面板管理状态备份", "清空 /etc/fail2ban 和 /var/lib/fail2ban，重新安装发行版软件包：" + strings.Join(packages, ", "), "恢复发行版默认过滤器和动作；所有防护保持停用，重新检查参数后再启用 SSH 登录防护"}
	if len(names) > 0 {
		p.Changes = append(p.Changes, "当前运行的防护配置："+strings.Join(names, ", "))
	}
	if len(configNames) > 0 {
		p.Changes = append(p.Changes, "将清除的配置名称（含默认模板）："+strings.Join(configNames, ", "))
	}
	p.Warnings = []string{"此操作会删除所有 Fail2ban 自定义防护、白名单、过滤器及历史封禁数据库，包括其他软件创建的配置", "重装期间及完成后，SSH 登录防护停用；主机防火墙、SSH 服务和悟空节点规则保持原样", "失败时由独立恢复任务恢复原配置和服务状态；备份保留在 Root Agent 安全目录，软件包版本不会降级；系统 SSH 日志与 Fail2ban 日志保留用于排查"}
	return p, nil
}
func (c *Controller) applyReset(ctx context.Context, r model.SecurityRequest) (result model.SecurityResult, err error) {
	p, err := c.resetPlan(ctx)
	if err != nil {
		return result, err
	}
	if r.Revision == "" || r.Revision != p.Revision {
		return result, errors.New("状态已变化，请重新预览")
	}
	if r.Confirmation != resetConfirmation {
		return result, errors.New("请输入 RESET FAIL2BAN 确认完全清理")
	}
	s, err := c.state()
	if err != nil {
		return result, err
	}
	_, e := c.jailNames(ctx)
	running := e == nil
	bans, e := c.captureBans(ctx)
	if e != nil {
		return result, e
	}
	files, e := c.resetFiles([]string{resetRoots[0]})
	if e != nil {
		return result, e
	}
	j := journal{Kind: "fail2ban", Reset: true, ResetRunning: running, ResetFiles: files, Before: s, Bans: bans, BootID: c.boot(), BootEnabled: map[string]bool{"fail2ban": c.bootEnabled(ctx, "fail2ban")}, Transaction: model.SecurityTransaction{ID: token(), Status: "applying", Deadline: c.Now().Add(10 * time.Minute)}}
	if c.family() == "apt" {
		if e = c.backup(&j, "/usr/sbin/policy-rc.d"); e != nil {
			return result, e
		}
	}
	if e = c.arm(ctx); e != nil {
		return result, fmt.Errorf("无法建立独立恢复任务，未清理：%w", e)
	}
	persist := func() error {
		if e := c.validateBackup(j); e != nil {
			return e
		}
		if e := c.save("backup-"+j.Transaction.ID+".json", j); e != nil {
			return e
		}
		var verified journal
		if e := c.load("backup-"+j.Transaction.ID+".json", &verified); e != nil {
			return e
		}
		if e := c.validateBackup(verified); e != nil {
			return e
		}
		return c.save("pending.json", j)
	}
	if e = persist(); e != nil {
		return result, e
	}
	defer func() {
		if err != nil {
			recoveryCtx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			if e := c.rollback(recoveryCtx, &j); e != nil {
				err = errors.Join(err, fmt.Errorf("恢复失败，独立任务将重试：%w", e))
			}
		}
	}()
	if e = c.service(ctx, "stop", "fail2ban"); e != nil {
		return result, e
	}
	if !c.fail2banStopped(ctx) {
		return result, errors.New("停止 Fail2ban 后仍无法确认已停用，未清理")
	}
	if _, e = c.exec(ctx, "fail2ban-client", "ping"); e == nil {
		return result, errors.New("存在不受服务管理的 Fail2ban 进程，未清理")
	}
	// Revalidate configuration after shutdown before deleting anything.
	current, e := c.resetFiles([]string{resetRoots[0]})
	if e != nil {
		return result, e
	}
	if c.revision(current) != c.revision(files) {
		return result, errors.New("停止服务期间配置发生变化，未清理")
	}
	data, e := c.resetFiles([]string{resetRoots[1]})
	if e != nil {
		return result, e
	}
	j.ResetFiles = append(files, data...)
	j.ResetCleaned = true
	if e = persist(); e != nil {
		j.ResetCleaned = false
		return result, e
	}
	if e = c.clearResetRoots(); e != nil {
		return result, e
	}
	if e = c.install(ctx, "fail2ban-reinstall", ""); e != nil {
		return result, e
	}
	if !c.Lookup("fail2ban-client") {
		return result, errors.New("重新安装后未检测到 Fail2ban")
	}
	for _, path := range []string{"/etc/fail2ban/fail2ban.conf", "/etc/fail2ban/jail.conf", "/etc/fail2ban/filter.d/sshd.conf"} {
		if _, e = c.read(path); e != nil {
			return result, fmt.Errorf("发行版默认文件未完整恢复：%s: %w", path, e)
		}
	}
	// Package defaults can enable SSH by default. Disable every supplied jail
	// in an independent local override, keeping upstream defaults untouched.
	fresh, e := c.resetFiles([]string{resetRoots[0]})
	if e != nil {
		return result, e
	}
	sectionRE := regexp.MustCompile(`(?m)^\s*\[([A-Za-z0-9_-]+)\]\s*$`)
	disabled := "[DEFAULT]\nenabled = false\n"
	seen := map[string]bool{}
	for _, f := range fresh {
		if !strings.Contains(f.Path, "/jail") {
			continue
		}
		for _, m := range sectionRE.FindAllSubmatch(f.Data, -1) {
			n := string(m[1])
			if n != "DEFAULT" && !seen[n] {
				seen[n] = true
				disabled += "\n[" + n + "]\nenabled = false\n"
			}
		}
	}
	if e = atomic(c.path(resetDisabledPath), []byte(marker+disabled), 0600); e != nil {
		return result, e
	}
	if _, e = c.exec(ctx, "fail2ban-client", "-t"); e != nil {
		return result, e
	}
	if e = c.service(ctx, "stop", "fail2ban"); e != nil {
		return result, e
	}
	if e = c.setBoot(ctx, "fail2ban", false); e != nil {
		return result, e
	}
	if !c.fail2banStopped(ctx) {
		return result, errors.New("重新安装后防护未保持停用")
	}
	s.Jail = ""
	s.Config = defaults()
	s.ConfigHash = ""
	s.ActionHash = ""
	s.Adopted = false
	if e = c.save("state.json", s); e != nil {
		return result, e
	}
	f, e := c.Fail2ban(ctx)
	if e != nil {
		return result, e
	}
	if f.Active || len(f.Jails) != 0 {
		return result, errors.New("重装后仍有活动防护或残留配置")
	}
	j.Transaction.Status = "confirmed"
	if e = c.finish(&j); e != nil {
		return result, e
	}
	result.Fail2ban = &f
	result.Transaction = &j.Transaction
	return result, nil
}
func (c *Controller) clearResetRoots() error {
	// Validate all roots before the first removal, including their parents.
	if _, e := c.resetFiles(resetRoots); e != nil {
		return e
	}
	for _, root := range resetRoots {
		if e := os.RemoveAll(c.path(root)); e != nil {
			return e
		}
	}
	return nil
}
func (c *Controller) rollbackReset(ctx context.Context, j *journal) error {
	if e := c.service(ctx, "stop", "fail2ban"); e != nil {
		return e
	}
	if !c.fail2banStopped(ctx) {
		return errors.New("恢复时无法停止 Fail2ban")
	}
	if j.ResetCleaned {
		if e := c.clearResetRoots(); e != nil {
			return e
		}
		for _, f := range j.ResetFiles {
			if !f.Exists {
				continue
			}
			if f.Directory {
				if e := os.MkdirAll(c.path(f.Path), os.FileMode(f.Mode)); e != nil {
					return e
				}
				if e := os.Chmod(c.path(f.Path), os.FileMode(f.Mode)); e != nil {
					return e
				}
			} else if e := atomic(c.path(f.Path), f.Data, os.FileMode(f.Mode)); e != nil {
				return e
			}
		}
	}
	for _, f := range j.Files {
		if f.Exists {
			if e := atomic(c.path(f.Path), f.Data, os.FileMode(f.Mode)); e != nil {
				return e
			}
		} else if e := os.Remove(c.path(f.Path)); e != nil && !errors.Is(e, os.ErrNotExist) {
			return e
		}
	}
	if e := c.save("state.json", j.Before); e != nil {
		return e
	}
	if e := c.setBoot(ctx, "fail2ban", j.BootEnabled["fail2ban"]); e != nil {
		return e
	}
	if j.ResetRunning {
		if e := c.service(ctx, "start", "fail2ban"); e != nil {
			return e
		}
		if e := c.waitFail2ban(ctx); e != nil {
			return e
		}
		if e := c.resyncBans(ctx, j.Bans); e != nil {
			return e
		}
	}
	j.Transaction.Status = "rolled-back"
	return c.finish(j)
}
