package hostsecurity

import (
	"context"
	"errors"
	"os"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func configuredSSHFixture(t *testing.T) (*Controller, *string, *[]string) {
	t.Helper()
	c := testController(t)
	base := c.Run
	dump := "['add', 'sshd', 'polling']\n['start', 'sshd']"
	calls := []string{}
	c.Lookup = func(n string) bool {
		return n == "ufw" || n == "fail2ban-client" || n == "fail2ban-regex" || n == "systemctl"
	}
	writeTestFile(t, c, "/run/systemd/system/fixture", "")
	writeTestFile(t, c, "/etc/fail2ban/filter.d/sshd.conf", "filter fixture")
	writeTestFile(t, c, "/var/log/auth.log", "sshd: accepted connection")
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		args := strings.Join(a, " ")
		calls = append(calls, n+" "+args)
		if n == "fail2ban-client" {
			switch args {
			case "-d":
				return dump, nil
			case "-t":
				return "configuration valid", nil
			default:
				return "", errors.New("not running")
			}
		}
		if n == "systemctl" {
			if args == "is-active fail2ban.service" {
				return "inactive", errors.New("inactive")
			}
			if args == "start fail2ban.service" {
				return "", errors.New("injected service start failure")
			}
			return "", nil
		}
		return base(ctx, n, a, in)
	}
	return c, &dump, &calls
}

func TestConfiguredDefaultSSHActivationPreviewAndFailureRecovery(t *testing.T) {
	c, _, calls := configuredSSHFixture(t)
	ctx := context.Background()
	f, e := c.Fail2ban(ctx)
	if e != nil || !f.Writable || !f.CanActivate || f.Active || len(f.Jails) != 1 || !f.Jails[0].ConfiguredOnly {
		t.Fatalf("%+v %v", f, e)
	}
	if _, e = c.Preview(ctx, "fail2ban", model.SecurityRequest{Operation: "enable", Config: defaults()}); e == nil {
		t.Fatal("created duplicate protection")
	}
	req := model.SecurityRequest{Operation: "adopt", Jail: "sshd", Config: defaults()}
	p, e := c.Preview(ctx, "fail2ban", req)
	if e != nil || !strings.Contains(strings.Join(p.Changes, " "), "46961") || !strings.Contains(strings.Join(p.Changes, " "), "开机启动") {
		t.Fatalf("%+v %v", p, e)
	}
	req.Revision = p.Revision
	if _, e = c.Apply(ctx, "fail2ban", req); e == nil || !strings.Contains(e.Error(), "injected") {
		t.Fatalf("%v", e)
	}
	if _, e = os.Stat(c.path(jailPath)); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("override not restored: %v", e)
	}
	if c.pending() != nil {
		t.Fatal("failed start left pending transaction")
	}
	s, e := c.state()
	if e != nil || s.Jail != "" {
		t.Fatalf("ownership not restored: %+v %v", s, e)
	}
	found := false
	for _, call := range *calls {
		if call == "systemctl stop fail2ban.service" {
			found = true
		}
	}
	if !found {
		t.Fatal("did not restore stopped service")
	}
}

func TestConfiguredSSHActivationGuardsAndStaleConfiguration(t *testing.T) {
	for _, name := range []string{"other-jail", "multiple-ssh", "custom-ssh", "malformed-add", "no-capability", "no-log", "external-override", "running-service", "unknown-service"} {
		t.Run(name, func(t *testing.T) {
			c, dump, _ := configuredSSHFixture(t)
			switch name {
			case "other-jail":
				*dump += "\n['add', 'web', 'polling']"
			case "multiple-ssh":
				*dump += "\n['add', 'sshd-ddos', 'polling']"
			case "custom-ssh":
				*dump = "['add', 'custom-ssh', 'polling']"
			case "malformed-add":
				*dump += "\n['add', 'invalid name', 'polling']"
			case "no-capability":
				writeTestFile(t, c, "/proc/self/status", "CapEff:\t0000000000000000\n")
			case "no-log":
				_ = os.Remove(c.path("/var/log/auth.log"))
			case "external-override":
				writeTestFile(t, c, jailPath, "external")
			case "running-service", "unknown-service":
				base := c.Run
				c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
					if n == "systemctl" && strings.Join(a, " ") == "is-active fail2ban.service" {
						if name == "running-service" {
							return "active", nil
						}
						return "unknown", errors.New("unknown")
					}
					return base(ctx, n, a, in)
				}
			}
			f, e := c.Fail2ban(context.Background())
			if e != nil || f.Writable || f.CanActivate {
				t.Fatalf("unsafe activation: %+v %v", f, e)
			}
			if _, e = c.Preview(context.Background(), "fail2ban", model.SecurityRequest{Operation: "adopt", Jail: "sshd", Config: defaults()}); e == nil {
				t.Fatal("unsafe preview allowed")
			}
		})
	}
	c, dump, calls := configuredSSHFixture(t)
	req := model.SecurityRequest{Operation: "adopt", Jail: "sshd", Config: defaults()}
	p, e := c.Preview(context.Background(), "fail2ban", req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	*dump += "\n['set', 'sshd', 'maxretry', 8]"
	if _, e = c.Apply(context.Background(), "fail2ban", req); e == nil || !strings.Contains(e.Error(), "状态已变化") {
		t.Fatalf("%v", e)
	}
	for _, call := range *calls {
		if call == "systemctl start fail2ban.service" {
			t.Fatal("stale preview started service")
		}
	}
}

func TestFail2banStartupWaitsForReadiness(t *testing.T) {
	c := testController(t)
	attempts := 0
	c.Run = func(context.Context, string, []string, string) (string, error) {
		attempts++
		if attempts < 3 {
			return "", errors.New("starting")
		}
		return "pong", nil
	}
	if e := c.waitFail2ban(context.Background()); e != nil || attempts != 3 {
		t.Fatalf("attempts=%d %v", attempts, e)
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	c.Run = func(context.Context, string, []string, string) (string, error) { return "", errors.New("starting") }
	if e := c.waitFail2ban(ctx); !errors.Is(e, context.Canceled) {
		t.Fatalf("%v", e)
	}
}
