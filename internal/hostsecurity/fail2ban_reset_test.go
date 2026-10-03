package hostsecurity

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func resetFixture(t *testing.T) (*Controller, *[]string, *bool) {
	t.Helper()
	c, _, calls := configuredSSHFixture(t)
	writeTestFile(t, c, "/etc/fail2ban/jail.d/conflict.local", "[sshd]\nenabled=true\n[sshd-ddos]\nenabled=true\n")
	writeTestFile(t, c, "/var/lib/fail2ban/fail2ban.sqlite3", "old history")
	running := false
	base := c.Run
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		args := strings.Join(a, " ")
		if n == "dpkg-query" {
			return "fail2ban: /usr/bin/fail2ban-client", nil
		}
		if n == "apt-get" {
			*calls = append(*calls, n+" "+args)
			if strings.Contains(args, "--reinstall") {
				if _, err := os.Stat(c.path("/etc/fail2ban/jail.d/conflict.local")); !errors.Is(err, os.ErrNotExist) {
					t.Fatal("old config present during reinstall")
				}
				writeTestFile(t, c, "/etc/fail2ban/filter.d/sshd.conf", "fresh filter")
				writeTestFile(t, c, "/etc/fail2ban/fail2ban.conf", "[Definition]\n")
				writeTestFile(t, c, "/etc/fail2ban/jail.conf", "[DEFAULT]\nenabled=false\n")
				writeTestFile(t, c, "/etc/fail2ban/jail.d/defaults.conf", "[sshd]\nenabled=true\n[web]\nenabled=true\n")
			}
			return "", nil
		}
		if n == "systemctl" {
			*calls = append(*calls, n+" "+args)
			switch args {
			case "is-active fail2ban.service":
				if running {
					return "active", nil
				}
				return "inactive", errors.New("inactive")
			case "stop fail2ban.service":
				running = false
				return "", nil
			case "start fail2ban.service":
				running = true
				return "", nil
			}
			return "", nil
		}
		if n == "fail2ban-client" && args == "-d" {
			if _, err := os.Stat(c.path(resetDisabledPath)); err == nil {
				return "['set', 'loglevel', 'INFO']", nil
			}
		}
		if n == "fail2ban-client" && args == "ping" && running {
			return "pong", nil
		}
		if n == "fail2ban-client" && args == "status" && running {
			return "Jail list: sshd, web", nil
		}
		if n == "fail2ban-client" && strings.HasPrefix(args, "status ") && running {
			return "Banned IP list:", nil
		}
		return base(ctx, n, a, in)
	}
	return c, calls, &running
}
func TestFail2banResetRequiresConfirmationAndRechecksAllConfigurations(t *testing.T) {
	c, calls, _ := resetFixture(t)
	ctx := context.Background()
	req := model.SecurityRequest{Operation: "reinstall"}
	p, err := c.Preview(ctx, "fail2ban", req)
	if err != nil {
		t.Fatal(err)
	}
	req.Revision = p.Revision
	if _, err = c.Apply(ctx, "fail2ban", req); err == nil {
		t.Fatal("reset without explicit confirmation")
	}
	for _, v := range *calls {
		if strings.Contains(v, " stop ") || strings.Contains(v, "--reinstall") {
			t.Fatal("mutated before confirmation")
		}
	}
	req.Confirmation = resetConfirmation
	writeTestFile(t, c, "/etc/fail2ban/jail.d/other.local", "[web]\nenabled=true")
	if _, err = c.Apply(ctx, "fail2ban", req); err == nil || !strings.Contains(err.Error(), "状态已变化") {
		t.Fatalf("%v", err)
	}
	p, err = c.Preview(ctx, "fail2ban", req)
	if err != nil {
		t.Fatal(err)
	}
	req.Revision = p.Revision
	c.Arm = func(context.Context) error { return errors.New("no recovery") }
	if _, err = c.Apply(ctx, "fail2ban", req); err == nil || !strings.Contains(err.Error(), "未清理") {
		t.Fatalf("%v", err)
	}
	if _, err = os.Stat(c.path("/etc/fail2ban/jail.d/conflict.local")); err != nil {
		t.Fatal(err)
	}
}
func TestFail2banResetClearsOtherJailsAndDataButRetainsFirewallAndLogs(t *testing.T) {
	c, _, _ := resetFixture(t)
	ctx := context.Background()
	writeTestFile(t, c, "/var/log/fail2ban.log", "preserved diagnostic log")
	writeTestFile(t, c, "/etc/ufw/user.rules", "preserved rules")
	before, _ := c.state()
	before.Jail = "wukong-sshd"
	before.ConfigHash = "old"
	before.Rules = []model.SecurityRule{{Action: "allow", Protocol: "tcp", PortFrom: 46961}}
	if err := c.save("state.json", before); err != nil {
		t.Fatal(err)
	}
	req := model.SecurityRequest{Operation: "reinstall", Confirmation: resetConfirmation}
	p, err := c.Preview(ctx, "fail2ban", req)
	if err != nil {
		t.Fatal(err)
	}
	req.Revision = p.Revision
	result, err := c.Apply(ctx, "fail2ban", req)
	if err != nil {
		t.Fatal(err)
	}
	if result.Fail2ban.Active || len(result.Fail2ban.Jails) != 0 || result.Fail2ban.ManagedJail != "" {
		t.Fatalf("%+v", result)
	}
	for _, path := range []string{"/etc/fail2ban/jail.d/conflict.local", "/var/lib/fail2ban/fail2ban.sqlite3"} {
		if _, err := os.Stat(c.path(path)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("not cleared %s %v", path, err)
		}
	}
	b, err := c.read(resetDisabledPath)
	if err != nil || !strings.Contains(string(b), "[web]\nenabled = false") {
		t.Fatalf("%s %v", b, err)
	}
	for _, path := range []string{"/etc/ufw/user.rules", "/var/log/fail2ban.log"} {
		if _, err := c.read(path); err != nil {
			t.Fatal(err)
		}
	}
	after, err := c.state()
	if err != nil || len(after.Rules) != 1 || after.Jail != "" {
		t.Fatalf("%+v %v", after, err)
	}
	var backup journal
	if err = c.load("backup-"+result.Transaction.ID+".json", &backup); err != nil {
		t.Fatal(err)
	}
	found := false
	for _, f := range backup.ResetFiles {
		if f.Path == "/var/lib/fail2ban/fail2ban.sqlite3" && string(f.Data) == "old history" {
			found = true
		}
	}
	if !found || c.validateBackup(backup) != nil || c.pending() != nil {
		t.Fatal("backup absent or invalid")
	}
	if _, err = c.Apply(ctx, "fail2ban", req); err == nil {
		t.Fatal("duplicate reset accepted")
	}
}
func TestFail2banResetFailedReinstallRestoresEveryConfigAndRunningState(t *testing.T) {
	for _, started := range []bool{false, true} {
		t.Run(stringBool(started), func(t *testing.T) {
			c, _, running := resetFixture(t)
			*running = started
			if err := os.Mkdir(c.path("/etc/fail2ban/empty-directory"), 0750); err != nil {
				t.Fatal(err)
			}
			base := c.Run
			c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
				if n == "apt-get" && strings.Contains(strings.Join(a, " "), "--reinstall") {
					writeTestFile(t, c, "/etc/fail2ban/new-file.conf", "created by package")
					return "", errors.New("injected reinstall failure")
				}
				return base(ctx, n, a, in)
			}
			req := model.SecurityRequest{Operation: "reinstall", Confirmation: resetConfirmation}
			p, err := c.Preview(context.Background(), "fail2ban", req)
			if err != nil {
				t.Fatal(err)
			}
			req.Revision = p.Revision
			if _, err = c.Apply(context.Background(), "fail2ban", req); err == nil || !strings.Contains(err.Error(), "injected") {
				t.Fatalf("%v", err)
			}
			b, err := c.read("/var/lib/fail2ban/fail2ban.sqlite3")
			if err != nil || string(b) != "old history" {
				t.Fatalf("%s %v", b, err)
			}
			if _, err := os.Stat(c.path("/etc/fail2ban/jail.d/conflict.local")); err != nil {
				t.Fatal(err)
			}
			if _, err := os.Stat(c.path("/etc/fail2ban/new-file.conf")); !errors.Is(err, os.ErrNotExist) {
				t.Fatal("new package file survived rollback")
			}
			info, err := os.Stat(c.path("/etc/fail2ban/empty-directory"))
			if err != nil || info.Mode().Perm() != 0750 {
				t.Fatal("directory mode lost", err)
			}
			if *running != started || c.pending() != nil {
				t.Fatal("service state or pending transaction not restored")
			}
		})
	}
}
func stringBool(v bool) string {
	if v {
		return "running"
	}
	return "stopped"
}
func TestFail2banResetDurableRecoveryAfterProcessCrash(t *testing.T) {
	c, _, running := resetFixture(t)
	*running = true
	ctx := context.Background()
	files, err := c.resetFiles(resetRoots)
	if err != nil {
		t.Fatal(err)
	}
	before, err := c.state()
	if err != nil {
		t.Fatal(err)
	}
	j := journal{Kind: "fail2ban", Reset: true, ResetCleaned: true, ResetRunning: true, ResetFiles: files, Before: before, Bans: map[string][]string{}, BootEnabled: map[string]bool{"fail2ban": false}, Transaction: model.SecurityTransaction{ID: token(), Status: "applying", Deadline: time.Now().Add(-time.Second)}}
	if err = c.save("pending.json", j); err != nil {
		t.Fatal(err)
	}
	if err = c.clearResetRoots(); err != nil {
		t.Fatal(err)
	}
	writeTestFile(t, c, "/etc/fail2ban/partial.conf", "unfinished reinstall")
	*running = false
	restarted := *c
	if err = restarted.Recover(ctx); err != nil {
		t.Fatal(err)
	}
	if !*running || restarted.pending() != nil {
		t.Fatal("did not recover")
	}
	b, err := c.read("/var/lib/fail2ban/fail2ban.sqlite3")
	if err != nil || string(b) != "old history" {
		t.Fatal(err)
	}
}
func TestFail2banResetUnsafePathsAndBackupCorruption(t *testing.T) {
	for _, scenario := range []string{"symlink-root", "symlink-child", "outside-db", "custom-launch", "no-cap", "bad-owner"} {
		t.Run(scenario, func(t *testing.T) {
			c, _, _ := resetFixture(t)
			switch scenario {
			case "symlink-root":
				_ = os.RemoveAll(c.path("/var/lib/fail2ban"))
				_ = os.Symlink(t.TempDir(), c.path("/var/lib/fail2ban"))
			case "symlink-child":
				_ = os.Symlink("/tmp", c.path("/etc/fail2ban/external"))
			case "outside-db":
				writeTestFile(t, c, "/etc/fail2ban/fail2ban.local", "[Definition]\ndbfile=/srv/custom.sqlite3")
			case "custom-launch":
				writeTestFile(t, c, "/etc/systemd/system/fail2ban.service.d/custom.conf", "custom")
			case "no-cap":
				writeTestFile(t, c, "/proc/self/status", "CapEff: 0000000000000000")
			case "bad-owner":
				base := c.Run
				c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
					if n == "dpkg-query" {
						return "custom: /usr/bin/fail2ban-client", nil
					}
					return base(ctx, n, a, in)
				}
			}
			if _, err := c.Preview(context.Background(), "fail2ban", model.SecurityRequest{Operation: "reinstall"}); err == nil {
				t.Fatal("unsafe reset accepted")
			}
		})
	}
	files := []savedFile{{Path: "/etc/fail2ban/x", Exists: true, Data: []byte("x"), Hash: digest([]byte("x"))}}
	if err := validateResetFiles(files); err != nil {
		t.Fatal(err)
	}
	files[0].Path = "/etc/fail2ban/../ssh/sshd_config"
	if validateResetFiles(files) == nil {
		t.Fatal("traversal allowed")
	}
	files[0].Path = filepath.Join("/etc/fail2ban", "x")
	files[0].Data = []byte("bad")
	if validateResetFiles(files) == nil {
		t.Fatal("corrupt backup accepted")
	}
}
