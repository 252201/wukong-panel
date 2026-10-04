package hostsecurity

import (
	"context"
	"errors"
	"fmt"
	"net/netip"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

type manualBanFixture struct {
	c                 *Controller
	bans              []string
	ignore            string
	duration          int
	calls             []string
	failBan, noKernel bool
}

func newManualBanFixture(t *testing.T) *manualBanFixture {
	t.Helper()
	c := testController(t)
	f := &manualBanFixture{c: c, bans: []string{"9.9.9.9"}, ignore: "127.0.0.1/8 ::1", duration: 3600}
	base := c.Run
	c.Lookup = func(n string) bool { return n == "ufw" || n == "fail2ban-client" || n == "fail2ban-regex" }
	c.LocalAddresses = func() ([]netip.Addr, error) {
		return []netip.Addr{netip.MustParseAddr("192.0.2.10"), netip.MustParseAddr("2001:db8::10")}, nil
	}
	cfg := defaults()
	writeTestFile(t, c, "/etc/fail2ban/filter.d/sshd.conf", "filter fixture")
	writeTestFile(t, c, "/var/log/auth.log", "sshd: accepted connection")
	writeTestFile(t, c, jailPath, "managed fixture")
	if e := c.save("state.json", state{Jail: "wukong-sshd", Config: cfg, ConfigHash: digest([]byte("managed fixture"))}); e != nil {
		t.Fatal(e)
	}
	var log strings.Builder
	for _, ip := range []string{"8.8.8.8", "9.9.9.9", "192.0.2.10", "2001:db8::10", "2001:4860:4860::8888"} {
		fmt.Fprintln(&log, foundLine("wukong-sshd", ip, c.Now().Add(-time.Minute)))
	}
	writeTestFile(t, c, "/var/log/fail2ban.log", log.String())
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		args := strings.Join(a, " ")
		f.calls = append(f.calls, n+" "+args)
		if n == "fail2ban-client" {
			switch args {
			case "status":
				return "Jail list: wukong-sshd", nil
			case "status wukong-sshd":
				return "Currently failed: 1\nTotal failed: 2\nTotal banned: 1\nBanned IP list: " + strings.Join(f.bans, " "), nil
			case "get logtarget":
				return "/var/log/fail2ban.log", nil
			case "get wukong-sshd journalmatch":
				return "", nil
			case "get wukong-sshd logpath":
				return "/var/log/auth.log", nil
			case "get wukong-sshd maxretry":
				return "5", nil
			case "get wukong-sshd findtime":
				return "600", nil
			case "get wukong-sshd bantime":
				return fmt.Sprint(f.duration), nil
			case "get wukong-sshd ignoreip":
				return f.ignore, nil
			case "get wukong-sshd actions":
				return "iptables-multiport", nil
			}
			if len(a) == 4 && a[0] == "set" && a[1] == "wukong-sshd" {
				if a[2] == "banip" {
					f.bans = append(f.bans, a[3])
					if f.failBan {
						return "", errors.New("injected ban failure")
					}
					return "1", nil
				}
				if a[2] == "unbanip" {
					kept := []string{}
					for _, ip := range f.bans {
						if ip != a[3] {
							kept = append(kept, ip)
						}
					}
					f.bans = kept
					return "1", nil
				}
			}
			return "", errors.New("unexpected fail2ban command: " + args)
		}
		if n == "iptables-save" || n == "ip6tables-save" {
			out := "-A INPUT -p tcp -m multiport --dports 46961 -j f2b-wukong-sshd\n"
			for _, ip := range f.bans {
				if f.noKernel && ip != "9.9.9.9" {
					continue
				}
				out += "-A f2b-wukong-sshd -s " + ip + " -j REJECT\n"
			}
			return out, nil
		}
		return base(ctx, n, a, in)
	}
	return f
}
func TestManualBanGuards(t *testing.T) {
	for _, name := range []string{"injection", "cidr", "zone", "loopback", "mapped-loopback", "unspecified", "multicast", "link-local", "own-v4", "own-v6", "whitelist-v4", "whitelist-v6", "hostname-whitelist", "other-jail", "missing-jail", "missing-source", "already-banned", "no-addresses", "no-log", "external-config"} {
		t.Run(name, func(t *testing.T) {
			f := newManualBanFixture(t)
			req := model.SecurityRequest{Operation: "ban", Jail: "wukong-sshd", IP: "8.8.8.8"}
			switch name {
			case "injection":
				req.IP = "8.8.8.8; touch /tmp/pwn"
			case "cidr":
				req.IP = "8.8.8.0/24"
			case "zone":
				req.IP = "fe80::1%eth0"
			case "loopback":
				req.IP = "127.0.0.1"
			case "mapped-loopback":
				req.IP = "::ffff:127.0.0.1"
			case "unspecified":
				req.IP = "::"
			case "multicast":
				req.IP = "ff02::1"
			case "link-local":
				req.IP = "169.254.1.1"
			case "own-v4":
				req.IP = "192.0.2.10"
			case "own-v6":
				req.IP = "2001:db8::10"
			case "whitelist-v4":
				f.ignore += " 8.8.8.0/24"
			case "whitelist-v6":
				req.IP = "2001:4860:4860::8888"
				f.ignore += " 2001:4860::/32"
			case "hostname-whitelist":
				f.ignore += " trusted.example.com"
			case "other-jail":
				req.Jail = "external-sshd"
			case "missing-jail":
				req.Jail = ""
			case "missing-source":
				req.IP = "1.1.1.1"
			case "already-banned":
				req.IP = "9.9.9.9"
			case "no-addresses":
				f.c.LocalAddresses = func() ([]netip.Addr, error) { return nil, errors.New("unavailable") }
			case "no-log":
				writeTestFile(t, f.c, "/var/log/fail2ban.log", "")
			case "external-config":
				writeTestFile(t, f.c, jailPath, "changed externally")
			}
			if _, err := f.c.Preview(context.Background(), "fail2ban", req); err == nil {
				t.Fatal("unsafe manual ban accepted")
			}
			for _, call := range f.calls {
				if strings.Contains(call, " banip ") {
					t.Fatal("preview mutated jail", call)
				}
			}
		})
	}
}
func TestManualBanApplyUnbanAndRecovery(t *testing.T) {
	for _, ip := range []string{"::ffff:8.8.8.8", "2001:4860:4860::8888"} {
		t.Run(ip, func(t *testing.T) {
			f := newManualBanFixture(t)
			ctx := context.Background()
			req := model.SecurityRequest{Operation: "ban", IP: ip, Jail: "wukong-sshd"}
			p, e := f.c.Preview(ctx, "fail2ban", req)
			if e != nil {
				t.Fatal(e)
			}
			req.Revision = p.Revision
			result, e := f.c.Apply(ctx, "fail2ban", req)
			if e != nil {
				t.Fatal(e)
			}
			target := netip.MustParseAddr(ip).Unmap().String()
			if result.Transaction.Status != "confirmed" || !contains(result.Fail2ban.Jails[0].Banned, target) || !contains(f.bans, "9.9.9.9") {
				t.Fatalf("bad result %+v", result)
			}
			beforeCalls := len(f.calls)
			if _, e = f.c.Apply(ctx, "fail2ban", req); e == nil {
				t.Fatal("repeated ban accepted")
			}
			for _, call := range f.calls[beforeCalls:] {
				if strings.Contains(call, " banip ") {
					t.Fatal("duplicate side effect")
				}
			}
			req = model.SecurityRequest{Operation: "unban", Jail: "wukong-sshd", IP: target}
			p, e = f.c.Preview(ctx, "fail2ban", req)
			if e != nil {
				t.Fatal(e)
			}
			req.Revision = p.Revision
			if _, e = f.c.Apply(ctx, "fail2ban", req); e != nil {
				t.Fatal(e)
			}
			if contains(f.bans, target) || !contains(f.bans, "9.9.9.9") {
				t.Fatal("unban changed unrelated bans")
			}
			s, _ := f.c.state()
			f.bans = append(f.bans, target, "1.1.1.1")
			j := journal{Kind: "fail2ban", BanIP: target, BanStarted: true, Target: s.Jail, Before: s, Bans: map[string][]string{s.Jail: {"9.9.9.9"}}, BootID: f.c.boot(), Transaction: model.SecurityTransaction{ID: token(), Status: "applying", Deadline: f.c.Now().Add(-time.Second)}}
			if e = f.c.save("pending.json", j); e != nil {
				t.Fatal(e)
			}
			beforeCalls = len(f.calls)
			if e = f.c.Recover(ctx); e != nil {
				t.Fatal(e)
			}
			if contains(f.bans, target) || !contains(f.bans, "1.1.1.1") || f.c.pending() != nil {
				t.Fatal("recovery lost independent bans", f.bans)
			}
			for _, call := range f.calls[beforeCalls:] {
				if strings.Contains(call, "reload") {
					t.Fatal("recovery restarted jail")
				}
			}
		})
	}
}
func TestManualBanChangedStateAndFailedEnforcement(t *testing.T) {
	for _, name := range []string{"whitelist-changed", "source-expired", "target-changed", "arm-failed", "command-failed", "no-enforcement"} {
		t.Run(name, func(t *testing.T) {
			f := newManualBanFixture(t)
			ctx := context.Background()
			req := model.SecurityRequest{Operation: "ban", IP: "8.8.8.8", Jail: "wukong-sshd"}
			p, e := f.c.Preview(ctx, "fail2ban", req)
			if e != nil {
				t.Fatal(e)
			}
			req.Revision = p.Revision
			switch name {
			case "whitelist-changed":
				f.ignore += " 8.8.8.8"
			case "source-expired":
				f.c.Now = func() time.Time { return time.Now().Add(25 * time.Hour) }
			case "target-changed":
				req.IP = "2001:4860:4860::8888"
			case "arm-failed":
				f.c.Arm = func(context.Context) error { return errors.New("no recovery") }
			case "command-failed":
				f.failBan = true
			case "no-enforcement":
				f.noKernel = true
			}
			if _, e = f.c.Apply(ctx, "fail2ban", req); e == nil {
				t.Fatal("unsafe/failed apply succeeded")
			}
			if contains(f.bans, "8.8.8.8") || !contains(f.bans, "9.9.9.9") || f.c.pending() != nil {
				t.Fatal("failed apply not restored", f.bans)
			}
		})
	}
}
func TestPermanentBanConfig(t *testing.T) {
	cfg := defaults()
	cfg.BanTime = -1
	got, e := validateConfig(cfg)
	if e != nil || got.BanTime != -1 {
		t.Fatal(got, e)
	}
	body := string(renderJail("wukong-sshd", got, true, "polling", "/var/log/auth.log", "iptables-multiport", []int{46961}))
	if !strings.Contains(body, "bantime = -1") || banDuration(-1) != "永久（不自动解除）" {
		t.Fatal(body)
	}
	for _, duration := range []int{-2, 0, 59, 2592001} {
		cfg.BanTime = duration
		if _, e = validateConfig(cfg); e == nil {
			t.Fatal("invalid duration", duration)
		}
	}
	f := newManualBanFixture(t)
	f.duration = -1
	s, _ := f.c.state()
	s.Config.BanTime = -1
	if e = f.c.save("state.json", s); e != nil {
		t.Fatal(e)
	}
	p, e := f.c.Preview(context.Background(), "fail2ban", model.SecurityRequest{Operation: "ban", Jail: "wukong-sshd", IP: "8.8.8.8"})
	if e != nil || !strings.Contains(strings.Join(p.Warnings, " "), "永久") {
		t.Fatal(p, e)
	}
	j := journal{Kind: "fail2ban", Target: s.Jail, Before: s, BanIP: "8.8.8.8", Bans: map[string][]string{s.Jail: {"8.8.8.8"}}}
	if f.c.validateBackup(j) == nil {
		t.Fatal("journal would undo preexisting ban")
	}
}

func TestManualBanDoesNotUndoAnExternalBanBeforeDispatch(t *testing.T) {
	f := newManualBanFixture(t)
	ctx := context.Background()
	req := model.SecurityRequest{Operation: "ban", Jail: "wukong-sshd", IP: "8.8.8.8"}
	p, e := f.c.Preview(ctx, "fail2ban", req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	base := f.c.Run
	f.c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		if n == "fail2ban-client" && strings.Join(a, " ") == "status wukong-sshd" && f.c.pending() != nil && !contains(f.bans, "8.8.8.8") {
			f.bans = append(f.bans, "8.8.8.8")
		}
		return base(ctx, n, a, in)
	}
	if _, e = f.c.Apply(ctx, "fail2ban", req); e == nil {
		t.Fatal("concurrent external ban ignored")
	}
	if !contains(f.bans, "8.8.8.8") || f.c.pending() != nil {
		t.Fatal("undid external ban")
	}
}
