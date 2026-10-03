package hostsecurity

import (
	"context"
	"encoding/json"
	"errors"
	"github.com/252201/wukong-panel/internal/model"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"
)

func testController(t *testing.T) *Controller {
	t.Helper()
	root := t.TempDir()
	c := New(filepath.Join(root, "secrets"), false)
	c.Root = root
	c.Arm = func(context.Context) error { return nil }
	c.Lookup = func(n string) bool { return n == "ufw" }
	c.Run = func(_ context.Context, n string, a []string, _ string) (string, error) {
		args := strings.Join(a, " ")
		switch {
		case n == "ufw" && args == "status verbose":
			return "Status: active\nDefault: deny (incoming), allow (outgoing)", nil
		case n == "ufw" && args == "show added":
			return "Added user rules (see 'ufw status' for running firewall):\nufw allow 46961/tcp\nufw allow 9443/tcp\nufw allow 8080/tcp", nil
		case n == "ss":
			return "LISTEN 0 128 0.0.0.0:46961 0.0.0.0:* users:((\"sshd\",pid=1,fd=3))\nLISTEN 0 128 [::]:9443 [::]:* users:((\"nginx\",pid=2,fd=3))", nil
		case n == "ufw":
			return "", nil
		}
		return "", errors.New("unavailable " + n)
	}
	writeTestFile(t, c, "/etc/os-release", "ID=debian\n")
	writeTestFile(t, c, "/proc/self/status", "CapEff:\t0000000000001000\n")
	writeTestFile(t, c, "/proc/sys/kernel/random/boot_id", "boot-a")
	writeTestFile(t, c, "/etc/nginx/conf.d/wukong-panel.conf", "server {\n listen 9443 ssl;\n listen [::]:9443 ssl;\n}\n")
	return c
}
func writeTestFile(t *testing.T, c *Controller, p, body string) {
	t.Helper()
	if e := os.MkdirAll(filepath.Dir(c.path(p)), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.WriteFile(c.path(p), []byte(body), 0600); e != nil {
		t.Fatal(e)
	}
}
func TestRuleValidation(t *testing.T) {
	base := model.SecurityRule{Action: "allow", Protocol: "tcp", PortFrom: 123, Source: "2001:db8::1/64"}
	r, e := normalizeRule(base)
	if e != nil || r.Source != "2001:db8::/64" || r.PortTo != 123 {
		t.Fatalf("%+v %v", r, e)
	}
	for _, mutate := range []func(*model.SecurityRule){func(r *model.SecurityRule) { r.Source = "1.2.3.4;touch /tmp/pwn" }, func(r *model.SecurityRule) { r.Zone = "public --reload" }, func(r *model.SecurityRule) { r.PortFrom = 0 }, func(r *model.SecurityRule) { r.PortTo = 65536 }, func(r *model.SecurityRule) { r.Protocol = "tcp\nflush ruleset" }, func(r *model.SecurityRule) { r.Action = "reject;rm" }} {
		r := base
		mutate(&r)
		if _, e := normalizeRule(r); e == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
}
func TestUFWParsesOnlyCompleteRules(t *testing.T) {
	v := parseUFW("ufw allow 123/tcp\nufw deny from 192.0.2.0/24 to any port 200:205 proto udp\nufw allow in on eth0 to any port 22\nufw allow 443\nufw route allow 100/tcp")
	if len(v) != 5 || !v[0].Adoptable || !v[1].Adoptable || v[2].Adoptable || !v[3].Adoptable || v[3].Protocol != "tcp/udp" || v[4].Adoptable {
		t.Fatalf("%+v", v)
	}
	if v[1].PortTo != 205 || v[1].Source != "192.0.2.0/24" {
		t.Fatal(v[1])
	}
}
func TestNFTParseAndExternalChains(t *testing.T) {
	s := `{"nftables":[{"chain":{"family":"inet","table":"wukong_panel","name":"input","hook":"input","policy":"drop"}},{"rule":{"family":"inet","table":"wukong_panel","chain":"input","expr":[{"match":{"op":"==","left":{"payload":{"protocol":"ip6","field":"saddr"}},"right":{"prefix":{"addr":"2001:db8::","len":64}}}},{"match":{"op":"==","left":{"payload":{"protocol":"udp","field":"dport"}},"right":{"range":[100,200]}}},{"drop":null}]}}]}`
	r, p, complex := parseNFT(s)
	if complex || p != "deny" || len(r) != 1 || r[0].PortTo != 200 || r[0].Source != "2001:db8::/64" {
		t.Fatalf("%+v %s %t", r, p, complex)
	}
	var root map[string]any
	_ = json.Unmarshal([]byte(s), &root)
	root["nftables"] = append(root["nftables"].([]any), map[string]any{"chain": map[string]string{"table": "unknown", "hook": "input"}})
	b, _ := json.Marshal(root)
	_, _, complex = parseNFT(string(b))
	if !complex {
		t.Fatal("external input chain was writable")
	}
}
func TestProtectedPortsAndStaleRevision(t *testing.T) {
	c := testController(t)
	ctx := context.Background()
	f, e := c.Firewall(ctx, "")
	if e != nil {
		t.Fatal(e)
	}
	if !f.Writable || len(f.RequiredPorts) != 4 || !f.Rules[0].Protected {
		t.Fatalf("%+v", f)
	}
	for _, r := range f.Rules {
		if r.PortFrom == 46961 && !r.Protected {
			t.Fatal("non-default SSH not protected")
		}
	}
	req := model.SecurityRequest{Operation: "add", Rule: model.SecurityRule{Action: "deny", Protocol: "tcp", PortFrom: 46961, Source: "192.0.2.5"}}
	if _, e := c.Preview(ctx, "firewall", req); e == nil {
		t.Fatal("allowed SSH block")
	}
	req.Rule.PortFrom = 1234
	p, e := c.Preview(ctx, "firewall", req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	writeTestFile(t, c, "/etc/ufw/user.rules", "external edit")
	if _, e := c.Apply(ctx, "firewall", req); e == nil || !strings.Contains(e.Error(), "状态已变化") {
		t.Fatalf("%v", e)
	}
	if c.pending() != nil {
		t.Fatal("stale request created transaction")
	}
}
func TestAdoptThenDeleteNeedsRecoveryAndProtectsSSH(t *testing.T) {
	c := testController(t)
	ctx := context.Background()
	f, _ := c.Firewall(ctx, "")
	var ordinary, ssh string
	for _, r := range f.Rules {
		if r.PortFrom == 8080 {
			ordinary = r.ID
		}
		if r.PortFrom == 46961 {
			ssh = r.ID
		}
	}
	apply := func(r model.SecurityRequest) model.SecurityResult {
		t.Helper()
		p, e := c.Preview(ctx, "firewall", r)
		if e != nil {
			t.Fatal(e)
		}
		r.Revision = p.Revision
		v, e := c.Apply(ctx, "firewall", r)
		if e != nil {
			t.Fatal(e)
		}
		return v
	}
	apply(model.SecurityRequest{Operation: "adopt", RuleID: ssh})
	if _, e := c.Preview(ctx, "firewall", model.SecurityRequest{Operation: "delete", RuleID: ssh}); e == nil {
		t.Fatal("deleted SSH")
	}
	apply(model.SecurityRequest{Operation: "adopt", RuleID: ordinary})
	v := apply(model.SecurityRequest{Operation: "delete", RuleID: ordinary})
	if v.Transaction.Status != "awaiting-confirmation" {
		t.Fatal(v)
	}
	if _, e := c.Preview(ctx, "firewall", model.SecurityRequest{Operation: "enable"}); e == nil {
		t.Fatal("concurrent mutation accepted")
	}
	if _, e := c.Confirm(ctx, v.Transaction.ID); e != nil {
		t.Fatal(e)
	}
	if c.pending() != nil {
		t.Fatal("confirmed transaction still pending")
	}
	if _, e := c.Confirm(ctx, v.Transaction.ID); e == nil {
		t.Fatal("confirmation replay accepted")
	}
}
func TestWatchdogTimeoutAndRebootRestoreBackup(t *testing.T) {
	for _, mode := range []string{"timeout", "reboot"} {
		t.Run(mode, func(t *testing.T) {
			c := testController(t)
			ctx := context.Background()
			writeTestFile(t, c, "/etc/ufw/user.rules", "original")
			req := model.SecurityRequest{Operation: "disable"}
			p, e := c.Preview(ctx, "firewall", req)
			if e != nil {
				t.Fatal(e)
			}
			req.Revision = p.Revision
			v, e := c.Apply(ctx, "firewall", req)
			if e != nil {
				t.Fatal(e)
			}
			writeTestFile(t, c, "/etc/ufw/user.rules", "changed")
			if mode == "timeout" {
				c.Now = func() time.Time { return v.Transaction.Deadline.Add(time.Second) }
			} else {
				writeTestFile(t, c, "/proc/sys/kernel/random/boot_id", "boot-b")
			}
			if e := c.Recover(ctx); e != nil {
				t.Fatal(e)
			}
			b, _ := c.read("/etc/ufw/user.rules")
			if string(b) != "original" {
				t.Fatal(string(b))
			}
			v2, e := c.Transaction(v.Transaction.ID)
			if e != nil || v2.Status != "rolled-back" {
				t.Fatalf("%+v %v", v2, e)
			}
		})
	}
}
func TestUnarmedRecoveryAndCorruptBackupBlockWrites(t *testing.T) {
	c := testController(t)
	ctx := context.Background()
	req := model.SecurityRequest{Operation: "disable"}
	p, _ := c.Preview(ctx, "firewall", req)
	req.Revision = p.Revision
	c.Arm = func(context.Context) error { return errors.New("init failed") }
	if _, e := c.Apply(ctx, "firewall", req); e == nil {
		t.Fatal("applied without watchdog")
	}
	if c.pending() != nil {
		t.Fatal("changed state without recovery")
	}
	j := journal{Kind: "firewall", Transaction: model.SecurityTransaction{Deadline: time.Time{}}, Files: []savedFile{{Path: "/etc/shadow", Exists: true, Data: []byte("bad"), Hash: digest([]byte("bad"))}}}
	_ = c.save("pending.json", j)
	if e := c.Recover(ctx); e == nil {
		t.Fatal("restored arbitrary path")
	}
	j.Files = []savedFile{{Path: "/etc/ufw/user.rules", Exists: true, Data: []byte("tampered"), Hash: "wrong"}}
	_ = c.save("pending.json", j)
	if e := c.Recover(ctx); e == nil {
		t.Fatal("accepted corrupt backup")
	}
}
func TestNoCapabilityAndBackendConflict(t *testing.T) {
	c := testController(t)
	writeTestFile(t, c, "/proc/self/status", "CapEff: 0000000000000000")
	f, e := c.Firewall(context.Background(), "")
	if e != nil || f.Writable || !strings.Contains(f.Reason, "CAP_NET_ADMIN") {
		t.Fatalf("%+v %v", f, e)
	}
	writeTestFile(t, c, "/proc/self/status", "CapEff: 0000000000001000")
	old := c.Run
	c.Lookup = func(s string) bool { return s == "ufw" || s == "firewall-cmd" }
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		if n == "firewall-cmd" && strings.Join(a, " ") == "--state" {
			return "running", nil
		}
		return old(ctx, n, a, in)
	}
	f, e = c.Firewall(context.Background(), "")
	if e != nil || f.Writable || !strings.Contains(f.Reason, "多个") {
		t.Fatalf("%+v %v", f, e)
	}
}
func TestMissingPortsAndTunnelExclusion(t *testing.T) {
	c := testController(t)
	old := c.Run
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		if n == "ss" || n == "sshd" {
			return "", errors.New("missing")
		}
		return old(ctx, n, a, in)
	}
	if _, e := c.Preview(context.Background(), "firewall", model.SecurityRequest{Operation: "enable"}); e == nil {
		t.Fatal("guessed default port")
	}
	p, e := c.Preview(context.Background(), "firewall", model.SecurityRequest{Operation: "enable", SSHPorts: []int{46961}, PanelPorts: []int{9443}})
	if e != nil || len(p.RequiredPorts) != 4 {
		t.Fatalf("%+v %v", p, e)
	}
	c.Nodes = []model.Node{{Name: "Tunnel", Protocol: "vless-ws-tunnel", ListenPort: 1111}, {Name: "Loopback", Protocol: "trojan", ListenPort: 2222, ConfigPath: "/nodes/loopback.json"}, {Name: "HY2", Protocol: "hysteria2", ListenPort: 3333, ConfigPath: "/nodes/hy2.json"}}
	writeTestFile(t, c, "/nodes/loopback.json", `{"inbounds":[{"listen":"127.0.0.1","listen_port":2222}]}`)
	writeTestFile(t, c, "/nodes/hy2.json", `{"inbounds":[{"listen":"::","listen_port":3333}]}`)
	r := defaultRequired(nil, nil, c.publicNodes(context.Background()))
	if len(r) != 3 || r[2].Protocol != "udp" || r[2].Port != 3333 {
		t.Fatalf("%+v", r)
	}
}
func TestSSHConfigValidationAndRendering(t *testing.T) {
	cfg, e := validateConfig(defaults())
	if e != nil {
		t.Fatal(e)
	}
	for _, ip := range []string{"0.0.0.0/0", "::/0", "1.2.3.4\nbanaction=evil", "$(touch /tmp/pwn)", "fe80::1%eth0"} {
		r := defaults()
		r.IgnoreIPs = []string{ip}
		if _, e = validateConfig(r); e == nil {
			t.Fatal("accepted " + ip)
		}
	}
	b := string(renderJail("wukong-sshd", cfg, true, "systemd", "", "nftables-multiport[port=46961, protocol=tcp]", []int{46961}))
	if strings.Contains(b, "logpath") || !strings.Contains(b, "journalmatch") || !strings.Contains(b, "port = 46961") {
		t.Fatal(b)
	}
	b = string(renderJail("sshd", cfg, true, "polling", "/var/log/auth.log", "iptables-multiport[port=46961]", []int{46961}))
	if !strings.Contains(b, "logpath = /var/log/auth.log") || strings.Contains(b, "journalmatch") {
		t.Fatal(b)
	}
}
func TestFirewalldRuntimePreservesRichAndBindings(t *testing.T) {
	c := testController(t)
	c.Run = func(_ context.Context, _ string, _ []string, _ string) (string, error) {
		return "public (active)\n  target: default\n  interfaces: eth0\n  sources: 192.0.2.0/24\n  services: ssh dhcpv6-client\n  ports: 8080/tcp\n  protocols:\n  forward: yes\n  masquerade: no\n  forward-ports:\n  source-ports:\n  icmp-blocks:\n  rich rules:\n    rule family=\"ipv4\" source address=\"192.0.2.1\" port port=\"46961\" protocol=\"tcp\" drop", nil
	}
	ops, e := c.fireRuntime(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	joined := ""
	for _, op := range ops {
		if !validFireUndo(op.Args) {
			t.Fatal(op)
		}
		joined += strings.Join(op.Args, " ") + "\n"
	}
	if !strings.Contains(joined, "--change-interface=eth0") || !strings.Contains(joined, "--add-rich-rule=rule family") {
		t.Fatal(joined)
	}
}

func TestNFTDisabledDenyAndArrayEstablished(t *testing.T) {
	rules := []model.SecurityRule{{Action: "deny", Protocol: "tcp", PortFrom: 8080, PortTo: 8080, Source: "any", Adoptable: true}}
	if strings.Contains(renderNFT(rules, false), "8080 drop") || !strings.Contains(renderNFT(rules, true), "8080 drop") {
		t.Fatal("disabled nftables still denies traffic")
	}
	body := `{"nftables":[{"chain":{"family":"inet","table":"wukong_panel","name":"input","hook":"input","policy":"drop"}},{"rule":{"table":"wukong_panel","chain":"input","expr":[{"match":{"op":"in","left":{"ct":{"key":"state"}},"right":["established","related"]}},{"accept":null}]}}]}`
	_, _, complex := parseNFT(body)
	if complex {
		t.Fatal("native nft 1.1 array syntax rejected")
	}
}
func TestFirewalldAnySourceRichRoundTrip(t *testing.T) {
	for _, source := range []string{"any", "192.0.2.1", "2001:db8::/64"} {
		r := model.SecurityRule{Action: "deny", Protocol: "udp", PortFrom: 1234, PortTo: 1240, Source: source, Zone: "public"}
		v, ok := parseRich(richRule(r), "public")
		if !ok || !sameRule(v, r) {
			t.Fatalf("%+v %+v", r, v)
		}
	}
}
func TestInactiveConfiguredSSHJailsStayReadOnly(t *testing.T) {
	c := testController(t)
	base := c.Run
	c.Lookup = func(n string) bool { return n == "ufw" || n == "fail2ban-client" || n == "fail2ban-regex" }
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		if n == "fail2ban-client" {
			if len(a) == 1 && a[0] == "-d" {
				return "['add', 'sshd', 'polling']\n['add', 'sshd-ddos', 'polling']", nil
			}
			return "", errors.New("not running")
		}
		return base(ctx, n, a, in)
	}
	writeTestFile(t, c, "/etc/fail2ban/filter.d/sshd.conf", "filter fixture")
	writeTestFile(t, c, "/var/log/auth.log", "sshd: accepted connection")
	f, e := c.Fail2ban(context.Background())
	if e != nil || f.Active || f.Writable || len(f.Jails) != 2 {
		t.Fatalf("%+v %v", f, e)
	}
	if _, e = c.Preview(context.Background(), "fail2ban", model.SecurityRequest{Operation: "enable", Config: defaults()}); e == nil {
		t.Fatal("duplicate configured jails allowed")
	}
}
func TestSSHFilterMismatchAndLostNativeBan(t *testing.T) {
	c := testController(t)
	c.Lookup = func(string) bool { return true }
	writeTestFile(t, c, "/var/log/auth.log", "sshd: Failed password for user from 192.0.2.1")
	c.Run = func(_ context.Context, n string, a []string, _ string) (string, error) {
		if n == "fail2ban-regex" {
			return "Failregex: 0 total", nil
		}
		if n == "fail2ban-client" {
			return "iptables-multiport", nil
		}
		if n == "iptables-save" {
			return "-A INPUT -p tcp -m multiport --dports 46961 -j f2b-wukong-sshd", nil
		}
		return "", errors.New("unavailable")
	}
	if e := c.verifyLogFilter(context.Background(), "polling", "/var/log/auth.log"); e == nil {
		t.Fatal("nonmatching filter accepted")
	}
	if e := c.enforcement(context.Background(), "wukong-sshd", []string{"192.0.2.1"}, []int{46961}); e == nil {
		t.Fatal("missing kernel ban reported active")
	}
}

func TestNFTDoesNotAdoptContradictoryOrNegatedMatches(t *testing.T) {
	for _, expr := range []string{
		`{"match":{"op":"!=","left":{"meta":{"key":"iifname"}},"right":"lo"}},{"accept":null}`,
		`{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":80}},{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":443}},{"accept":null}`,
	} {
		_, _, complex := parseNFT(`{"nftables":[{"rule":{"table":"wukong_panel","chain":"input","expr":[` + expr + `]}}]}`)
		if !complex {
			t.Fatal("unsafe simplification", expr)
		}
	}
}
func TestSecurityRejectsMissingStateAndSymlinkBackup(t *testing.T) {
	c := testController(t)
	if e := c.LoadFirewall(context.Background()); e == nil {
		t.Fatal("loader created default deny without saved ports")
	}
	path := c.path("/etc/ufw/user.rules")
	if e := os.MkdirAll(filepath.Dir(path), 0700); e != nil {
		t.Fatal(e)
	}
	if e := os.Symlink("untrusted", path); e != nil {
		t.Fatal(e)
	}
	if e := c.backup(&journal{}, "/etc/ufw/user.rules"); e == nil {
		t.Fatal("symlink backup accepted")
	}
}

func TestFailedFirstInstallRollsBackWithoutMissingNativeCommands(t *testing.T) {
	c := testController(t)
	base := c.Run
	c.Lookup = func(string) bool { return false }
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		if n == "apt-get" {
			return "", errors.New("repository unavailable")
		}
		if n == "ufw" {
			t.Fatal("attempted recovery of backend that did not exist")
		}
		return base(ctx, n, a, in)
	}
	req := model.SecurityRequest{Operation: "install"}
	p, e := c.Preview(context.Background(), "firewall", req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	_, e = c.Apply(context.Background(), "firewall", req)
	if e == nil || !strings.Contains(e.Error(), "repository unavailable") {
		t.Fatal(e)
	}
	if c.pending() != nil {
		t.Fatal("failed install left a recovery loop")
	}
	if _, e = os.Stat(c.path("/usr/sbin/policy-rc.d")); !errors.Is(e, os.ErrNotExist) {
		t.Fatal("temporary package startup guard left behind", e)
	}
}

func TestFirewalldICMPGuardsAreProtected(t *testing.T) {
	for _, protocol := range []string{"icmp", "ipv6-icmp"} {
		r, ok := parseRich(`rule protocol value="`+protocol+`" accept`, "public")
		if !ok || !r.Protected || r.Adoptable || r.Protocol != protocol {
			t.Fatalf("unsafe ICMP guard: %+v", r)
		}
	}
	if _, ok := parseRich(`rule protocol value="tcp" accept`, "public"); ok {
		t.Fatal("unrestricted external protocol rule recognized as guard")
	}
}

func TestFirewalldRuntimeRollbackRestoresStoppedService(t *testing.T) {
	c := testController(t)
	c.Lookup = func(name string) bool { return name == "systemctl" }
	if e := os.MkdirAll(c.path("/run/systemd/system"), 0700); e != nil {
		t.Fatal(e)
	}
	calls := []string{}
	c.Run = func(_ context.Context, name string, args []string, _ string) (string, error) {
		calls = append(calls, name+" "+strings.Join(args, " "))
		return "", nil
	}
	j := journal{Kind: "firewall", Backend: "firewalld", Transaction: model.SecurityTransaction{ID: token()}, Runtime: []command{{Name: "firewall-cmd", Args: []string{"--zone=public", "--add-port=5566/tcp"}}}, Undo: []command{{Name: "service-stop-firewalld"}, {Name: "firewall-cmd", Args: []string{"--zone=public", "--remove-port=8080/tcp"}}}}
	if e := c.rollback(context.Background(), &j); e != nil {
		t.Fatal(e)
	}
	joined := strings.Join(calls, "\n")
	if !strings.Contains(joined, "systemctl stop firewalld.service") || strings.Contains(joined, "--remove-port=") {
		t.Fatalf("runtime backup failed to restore original daemon state: %s", joined)
	}
}

func TestSingleHostCIDRMatchesNativeAddress(t *testing.T) {
	for source, want := range map[string]string{"192.0.2.8/32": "192.0.2.8", "2001:db8::8/128": "2001:db8::8"} {
		r, e := normalizeRule(model.SecurityRule{Action: "deny", Protocol: "udp", PortFrom: 23456, Source: source})
		if e != nil || r.Source != want {
			t.Fatalf("CIDR canonicalization: %+v %v", r, e)
		}
	}
	if _, e := normalizeRule(model.SecurityRule{Action: "allow", Protocol: "tcp", PortFrom: 123, Source: "::ffff:192.0.2.8/120"}); e == nil {
		t.Fatal("ambiguous mapped CIDR accepted")
	}
}
