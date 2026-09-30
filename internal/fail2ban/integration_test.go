package fail2ban

import (
	"context"
	"fmt"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

// Optional real-client test. F2B_SOURCE_DIR points to an official Fail2ban source
// checkout. All configuration, logs, sockets and actions are isolated; the dummy
// action never changes the host firewall. No production service is contacted.
func TestRealClientIsolatedLifecycle(t *testing.T) {
	source := os.Getenv("F2B_SOURCE_DIR")
	if source == "" {
		t.Skip("set F2B_SOURCE_DIR for isolated real Fail2ban client verification")
	}
	dir := t.TempDir()
	configDir := filepath.Join(dir, "config")
	if err := os.CopyFS(configDir, os.DirFS(filepath.Join(source, "config"))); err != nil {
		t.Fatal(err)
	}
	socketDir, err := os.MkdirTemp("/tmp", "wk-f2b-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(socketDir) })
	socket := filepath.Join(socketDir, "socket")
	pid := filepath.Join(socketDir, "pid")
	authlog := filepath.Join(dir, "auth.log")
	log := filepath.Join(dir, "fail2ban.log")
	if err = os.WriteFile(authlog, []byte("Sep 30 12:00:00 fixture sshd[101]: Server listening on 0.0.0.0 port 22.\n"), 0600); err != nil {
		t.Fatal(err)
	}
	local := fmt.Sprintf("[DEFAULT]\nbanaction = wukong-test\nbanaction_allports = wukong-test\nbackend = polling\n[fixture-other]\nenabled = true\nfilter = sshd\nlogpath = %s\n", authlog)
	for name, data := range map[string]string{"jail.local": local, "fail2ban.local": fmt.Sprintf("[Definition]\nlogtarget = %s\ndbfile = None\n", log), "action.d/wukong-test.conf": "[Definition]\nactionstart =\nactionstop =\nactioncheck =\nactionban = /usr/bin/true\nactionunban = /usr/bin/true\n"} {
		if err = os.WriteFile(filepath.Join(configDir, name), []byte(data), 0600); err != nil {
			t.Fatal(err)
		}
	}
	invoke := func(ctx context.Context, args ...string) (string, error) {
		ctx, cancel := context.WithTimeout(ctx, 10*time.Second)
		defer cancel()
		all := append([]string{filepath.Join(source, "bin", "fail2ban-client"), "-c", configDir, "--socket", socket, "--pidfile", pid}, args...)
		cmd := exec.CommandContext(ctx, "python3", all...)
		cmd.Env = append(os.Environ(), "PYTHONPATH="+source, "LC_ALL=C", "PATH="+filepath.Join(source, "bin")+":"+os.Getenv("PATH"))
		out, err := cmd.CombinedOutput()
		if err != nil {
			return string(out), fmt.Errorf("%v: %w %s", args, err, out)
		}
		return strings.TrimSpace(string(out)), nil
	}
	ctx := context.Background()
	if _, err = invoke(ctx, "start"); err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		if out, err := invoke(context.Background(), "stop"); err != nil {
			t.Log(out, err)
		}
	})
	c := New(filepath.Join(dir, "secrets"), false)
	c.configFile = filepath.Join(configDir, "jail.d", "wukong-sshd.local")
	c.logFiles = []string{authlog}
	c.lookup = func(string) bool { return true }
	c.systemd = func() bool { return false }
	c.read = func(path string) ([]byte, error) {
		if path == authlog {
			return os.ReadFile(path)
		}
		return nil, os.ErrNotExist
	}
	c.run = func(ctx context.Context, name string, args ...string) (string, error) {
		if name == "ss" {
			return `LISTEN 0 128 0.0.0.0:22 0.0.0.0:* users:(("sshd",pid=1,fd=3))`, nil
		}
		return invoke(ctx, args...)
	}
	got, err := c.Configure(ctx, enableConfig())
	if err != nil || !got.Active {
		t.Fatalf("enable %+v %v", got, err)
	}
	if _, err = invoke(ctx, "set", jail, "banip", "192.0.2.47"); err != nil {
		t.Fatal(err)
	}
	deadline := time.Now().Add(5 * time.Second)
	for {
		got, err = c.Status(ctx)
		if err == nil && len(got.BannedIPs) == 1 {
			break
		}
		if time.Now().After(deadline) {
			t.Fatalf("ban %+v %v", got, err)
		}
		time.Sleep(100 * time.Millisecond)
	}
	r := enableConfig()
	r.MaxRetry = 3
	r.BanTime = 7200
	got, err = c.Configure(ctx, r)
	if err != nil || !got.Active || len(got.BannedIPs) != 1 {
		t.Fatalf("reload preserves ban %+v %v", got, err)
	}
	got, err = c.Unban(ctx, "192.0.2.47")
	if err != nil || len(got.BannedIPs) != 0 {
		t.Fatalf("unban %+v %v", got, err)
	}
	// Exercise actual SSH filtering and automatic bans, including ignored sources.
	f, err := os.OpenFile(authlog, os.O_APPEND|os.O_WRONLY, 0600)
	if err != nil {
		t.Fatal(err)
	}
	stamp := time.Now().Format("Jan _2 15:04:05")
	for n := 0; n < 3; n++ {
		_, _ = fmt.Fprintf(f, "%s fixture sshd[101]: Failed password for root from 192.0.2.48 port 45678 ssh2\n", stamp)
		_, _ = fmt.Fprintf(f, "%s fixture sshd[101]: Failed password for root from 203.0.113.7 port 45678 ssh2\n", stamp)
	}
	_ = f.Close()
	deadline = time.Now().Add(8 * time.Second)
	for {
		got, err = c.Status(ctx)
		if err == nil && len(got.BannedIPs) == 1 && got.BannedIPs[0] == "192.0.2.48" {
			break
		}
		if time.Now().After(deadline) {
			contents, _ := os.ReadFile(log)
			t.Fatalf("automatic ban/allowlist %+v %v log=%s", got, err, contents)
		}
		time.Sleep(150 * time.Millisecond)
	}
	r.Enabled = false
	got, err = c.Configure(ctx, r)
	if err != nil || got.Active || len(got.OtherJails) != 1 || got.OtherJails[0] != "fixture-other" {
		t.Fatalf("disable/isolation %+v %v", got, err)
	}
}
