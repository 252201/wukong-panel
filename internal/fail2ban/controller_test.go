package fail2ban

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestValidation(t *testing.T) {
	good := defaults()
	good.Enabled = true
	good.IgnoreIPs = []string{"203.0.113.7", "2001:db8:abcd::/48", "203.0.113.7"}
	normalized, err := validate(good)
	if err != nil || len(normalized.IgnoreIPs) != 2 {
		t.Fatalf("%+v %v", normalized, err)
	}
	for _, ip := range []string{"0.0.0.0/0", "::/0", "example.org", "203.0.113.7\nbantime=-1", "--all", "fe80::1%eth0", "::", "ff02::1"} {
		r := good
		r.IgnoreIPs = []string{ip}
		if _, err = validate(r); err == nil {
			t.Fatalf("accepted %q", ip)
		}
	}
	for _, r := range []model.Fail2banConfig{{Enabled: true, MaxRetry: 5, FindTime: 600, BanTime: 3600, Mode: "normal"}, {MaxRetry: 0, FindTime: 600, BanTime: 3600, Mode: "normal"}, {MaxRetry: 5, FindTime: 1, BanTime: 3600, Mode: "normal"}, {MaxRetry: 5, FindTime: 600, BanTime: 3600, Mode: "$(id)"}} {
		if _, err := validate(r); err == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}

type nativeMock struct {
	active               bool
	failTest, failReload bool
	commands             []string
	bans                 []string
}

func nativeController(t *testing.T) (*Controller, *nativeMock) {
	t.Helper()
	dir := t.TempDir()
	c := New(dir, false)
	c.configFile = filepath.Join(dir, "etc", "wukong-sshd.local")
	c.lookup = func(name string) bool { return true }
	c.systemd = func() bool { return true }
	c.read = func(path string) ([]byte, error) {
		switch path {
		case "/run/systemd/system":
			return []byte{}, nil
		case "/etc/os-release":
			return []byte("ID=debian"), nil
		}
		return nil, os.ErrNotExist
	}
	m := &nativeMock{bans: []string{"192.0.2.47", "2001:db8::47"}}
	c.run = func(_ context.Context, name string, args ...string) (string, error) {
		cmd := strings.Join(append([]string{name}, args...), " ")
		m.commands = append(m.commands, cmd)
		if len(args) == 3 && args[0] == "get" && args[1] == jail {
			data, _ := os.ReadFile(c.configFile)
			switch args[2] {
			case "ignoreip":
				return strings.TrimSpace(strings.Split(strings.Split(string(data), "ignoreip = ")[1], "\n")[0]), nil
			case "maxretry", "findtime", "bantime":
				return strings.TrimSpace(strings.Split(strings.Split(string(data), args[2]+" = ")[1], "\n")[0]), nil
			}
		}
		switch cmd {
		case "ss -H -lntp":
			return `LISTEN 0 128 0.0.0.0:46961 0.0.0.0:* users:(("sshd",pid=1,fd=3))` + "\n" + `LISTEN 0 128 [::]:46961 [::]:* users:(("sshd",pid=1,fd=4))`, nil
		case "fail2ban-client -V":
			return "1.1.0", nil
		case "fail2ban-client status":
			j := "nginx-http-auth"
			if m.active {
				j += ", wukong-sshd"
			}
			return "Status\n|- Number of jail: 2\n`- Jail list: " + j, nil
		case "fail2ban-client status wukong-sshd":
			return "|- Total failed: 14\n|- Total banned: 2\n`- Banned IP list: " + strings.Join(m.bans, " "), nil
		case "fail2ban-client -t":
			if m.failTest {
				return "", errors.New("missing python-systemd")
			}
			return "OK", nil
		case "fail2ban-client reload --if-exists wukong-sshd":
			if m.failReload {
				m.failReload = false
				return "", errors.New("action failed")
			}
			m.active = true
			return "OK", nil
		case "fail2ban-client stop wukong-sshd":
			m.active = false
			return "OK", nil
		case "fail2ban-client ping":
			return "pong", nil
		}
		if len(args) == 4 && args[0] == "set" && args[1] == jail && args[2] == "unbanip" {
			next := []string{}
			for _, b := range m.bans {
				if b != args[3] {
					next = append(next, b)
				}
			}
			m.bans = next
			return "1", nil
		}
		return "", errors.New("unexpected command: " + cmd)
	}
	return c, m
}
func enableConfig() model.Fail2banConfig {
	r := defaults()
	r.Enabled = true
	r.IgnoreIPs = []string{"203.0.113.7"}
	return r
}
func TestNativeJailLifecycleAndIsolation(t *testing.T) {
	c, m := nativeController(t)
	ctx := context.Background()
	got, err := c.Configure(ctx, enableConfig())
	if err != nil || !got.Active || got.SSHPorts[0] != 46961 || len(got.BannedIPs) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	b, err := os.ReadFile(c.configFile)
	if err != nil || !strings.Contains(string(b), "port = 46961") || !strings.Contains(string(b), "journalmatch = _COMM=sshd") || strings.Contains(string(b), "logpath") {
		t.Fatalf("config %s %v", b, err)
	}
	// Reject arbitrary IPs/CIDRs and never unban across other jails.
	for _, ip := range []string{"--all", "192.0.2.0/24", "203.0.113.8"} {
		if _, err = c.Unban(ctx, ip); err == nil {
			t.Fatalf("unban %s accepted", ip)
		}
	}
	got, err = c.Unban(ctx, "192.0.2.47")
	if err != nil || len(got.BannedIPs) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
	r := enableConfig()
	r.BanTime = 7200
	got, err = c.Configure(ctx, r)
	if err != nil || !got.Active || got.Config.BanTime != 7200 || len(got.BannedIPs) != 1 {
		t.Fatalf("reload %+v %v", got, err)
	}
	r.Enabled = false
	got, err = c.Configure(ctx, r)
	if err != nil || got.Active {
		t.Fatalf("disable %+v %v", got, err)
	}
	for _, cmd := range m.commands {
		if cmd == "fail2ban-client stop" || cmd == "fail2ban-client reload" || strings.Contains(cmd, "nginx-http-auth") || strings.Contains(cmd, "--unban") {
			t.Fatalf("unscoped mutation %s", cmd)
		}
	}
}
func TestRollbackAndRecovery(t *testing.T) {
	for _, failure := range []string{"validation", "reload"} {
		t.Run(failure, func(t *testing.T) {
			c, m := nativeController(t)
			ctx := context.Background()
			if _, err := c.Configure(ctx, enableConfig()); err != nil {
				t.Fatal(err)
			}
			old, _ := os.ReadFile(c.configFile)
			if failure == "validation" {
				m.failTest = true
			} else {
				m.failReload = true
			}
			r := enableConfig()
			r.MaxRetry = 2
			if _, err := c.Configure(ctx, r); err == nil {
				t.Fatal("failure accepted")
			}
			now, _ := os.ReadFile(c.configFile)
			if string(now) != string(old) || !m.active {
				t.Fatal("failed to restore previous file/runtime")
			}
			saved, _ := c.load()
			if saved.Config.MaxRetry != 5 {
				t.Fatal("failed to restore state")
			}
			// Simulate process death with a durable transaction before the next apply.
			p := pending{File: old, Exists: true, State: saved, Active: true}
			if err := c.save("pending.json", p); err != nil {
				t.Fatal(err)
			}
			if err := atomic(c.configFile, []byte("broken")); err != nil {
				t.Fatal(err)
			}
			if err := c.Recover(ctx); err != nil {
				t.Fatal(err)
			}
			now, _ = os.ReadFile(c.configFile)
			if string(now) != string(old) {
				t.Fatal("crash recovery failed")
			}
		})
	}
}
func TestUnownedAndExternalEditsAreReadOnly(t *testing.T) {
	c, m := nativeController(t)
	ctx := context.Background()
	m.active = true
	if _, err := c.Configure(ctx, enableConfig()); err == nil {
		t.Fatal("adopted an unowned running jail")
	}
	m.active = false
	if err := atomic(c.configFile, []byte("[wukong-sshd]\nenabled=true\n")); err != nil {
		t.Fatal(err)
	}
	if _, err := c.Configure(ctx, enableConfig()); err == nil {
		t.Fatal("overwrote unowned file")
	}
	// A file generated by another admin tool is never adopted implicitly.
}
func TestDisableWorksWithoutSSHListener(t *testing.T) {
	c, m := nativeController(t)
	ctx := context.Background()
	if _, err := c.Configure(ctx, enableConfig()); err != nil {
		t.Fatal(err)
	}
	run := c.run
	c.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "ss" {
			return "", errors.New("ss unavailable")
		}
		return run(ctx, name, args...)
	}
	r := enableConfig()
	r.Enabled = false
	if _, err := c.Configure(ctx, r); err != nil {
		t.Fatal(err)
	}
	if m.active {
		t.Fatal("jail still active")
	}
}
func TestRuntimeWhitelistOverrideIsRejectedAndRestored(t *testing.T) {
	c, m := nativeController(t)
	ctx := context.Background()
	run := c.run
	c.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if len(args) == 3 && args[0] == "get" && args[2] == "ignoreip" {
			return "127.0.0.0/8 ::1", nil
		}
		return run(ctx, name, args...)
	}
	if _, err := c.Configure(ctx, enableConfig()); err == nil {
		t.Fatal("accepted ineffective whitelist")
	}
	if m.active {
		t.Fatal("new jail not rolled back")
	}
	if _, err := os.Stat(c.configFile); !os.IsNotExist(err) {
		t.Fatal("new configuration not rolled back")
	}
}

func TestMissingPackageAndFileLogBackend(t *testing.T) {
	c, _ := nativeController(t)
	c.lookup = func(string) bool { return false }
	got, err := c.Status(context.Background())
	if err != nil || got.Installed || got.Writable || !strings.Contains(got.InstallCommand, "python3-systemd") {
		t.Fatalf("%+v %v", got, err)
	}
	c.lookup = func(string) bool { return true }
	c.systemd = func() bool { return false }
	c.read = func(path string) ([]byte, error) {
		if path == "/var/log/auth.log" {
			return []byte("Sep 30 sshd: Failed password"), nil
		}
		return nil, os.ErrNotExist
	}
	got, err = c.Configure(context.Background(), enableConfig())
	if err != nil || got.Backend != "auto" {
		t.Fatalf("%+v %v", got, err)
	}
	b, _ := os.ReadFile(c.configFile)
	if !strings.Contains(string(b), "logpath = /var/log/auth.log") || strings.Contains(string(b), "journalmatch") {
		t.Fatalf("%s", b)
	}
}
func TestDemoNeverRunsNativeCommands(t *testing.T) {
	c := New(t.TempDir(), true)
	c.run = func(context.Context, string, ...string) (string, error) {
		t.Fatal("native command in demo")
		return "", nil
	}
	got, err := c.Configure(context.Background(), enableConfig())
	if err != nil || !got.Active || len(got.BannedIPs) != 2 {
		t.Fatalf("%+v %v", got, err)
	}
	got, err = c.Unban(context.Background(), "192.0.2.47")
	if err != nil || len(got.BannedIPs) != 1 {
		t.Fatalf("%+v %v", got, err)
	}
}
