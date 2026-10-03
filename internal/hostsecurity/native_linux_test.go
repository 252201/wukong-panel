//go:build linux

package hostsecurity

import (
	"context"
	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/crypto/ssh"
	"net"
	"os"
	"os/exec"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"
)

func TestNativeNoCapabilities(t *testing.T) {
	if os.Getenv("WUKONG_SECURITY_NO_CAPS") == "" {
		t.Skip("isolated Linux container only")
	}
	c := New(t.TempDir(), false)
	f, e := c.Firewall(context.Background(), "")
	if e != nil {
		t.Fatal(e)
	}
	if f.Writable || !strings.Contains(f.Reason, "CAP_NET_ADMIN") {
		t.Fatalf("false firewall capability: %+v", f)
	}
	fb, e := c.Fail2ban(context.Background())
	if e != nil {
		t.Fatal(e)
	}
	if fb.Installed && fb.Writable {
		t.Fatalf("false SSH enforcement capability: %+v", fb)
	}
	t.Log("No capabilities: writes unavailable; no false protection status")
}
func TestSecurityNetworkChild(t *testing.T) {
	op := os.Getenv("WUKONG_SECURITY_CHILD")
	if op == "" {
		t.Skip("network namespace helper only")
	}
	addr := os.Getenv("WUKONG_SECURITY_ADDR")
	source := os.Getenv("WUKONG_SECURITY_SOURCE")
	dialer := net.Dialer{Timeout: 2 * time.Second}
	if source != "" {
		dialer.LocalAddr = &net.TCPAddr{IP: net.ParseIP(source)}
	}
	conn, e := dialer.Dial("tcp", addr)
	if op == "blocked" {
		if e == nil {
			conn.Close()
			t.Fatal("unexpected connection through firewall")
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	defer conn.Close()
	if op == "tcp" {
		return
	}
	password := "integration-only-password"
	if op == "ssh-fail" {
		password = "not-the-password"
	}
	cfg := &ssh.ClientConfig{User: "wukongtest", Auth: []ssh.AuthMethod{ssh.Password(password)}, HostKeyCallback: ssh.InsecureIgnoreHostKey(), Timeout: 3 * time.Second}
	_ = conn.SetDeadline(time.Now().Add(3 * time.Second))
	sshConn, ch, req, e := ssh.NewClientConn(conn, addr, cfg)
	if op == "ssh-fail" {
		if e == nil {
			sshConn.Close()
			t.Fatal("wrong SSH password accepted")
		}
		if !strings.Contains(e.Error(), "unable to authenticate") {
			t.Fatal(e)
		}
		return
	}
	if e != nil {
		t.Fatal(e)
	}
	client := ssh.NewClient(sshConn, ch, req)
	defer client.Close()
	session, e := client.NewSession()
	if e != nil {
		t.Fatal(e)
	}
	defer session.Close()
	if e = session.Run("true"); e != nil {
		t.Fatal(e)
	}
}
func nativeConnect(t *testing.T, op, addr, source string) {
	t.Helper()
	bin, _ := os.Executable()
	ctx, cancel := context.WithTimeout(context.Background(), 8*time.Second)
	defer cancel()
	cmd := exec.CommandContext(ctx, "ip", "netns", "exec", "security-client", bin, "-test.run", "^TestSecurityNetworkChild$", "-test.v")
	cmd.Env = append(os.Environ(), "WUKONG_SECURITY_CHILD="+op, "WUKONG_SECURITY_ADDR="+addr, "WUKONG_SECURITY_SOURCE="+source)
	b, e := cmd.CombinedOutput()
	if e != nil {
		t.Fatalf("namespace %s %s source=%s: %v\n%s", op, addr, source, e, b)
	}
}
func nativeApply(t *testing.T, c *Controller, kind string, r model.SecurityRequest) model.SecurityResult {
	t.Helper()
	ctx := context.Background()
	p, e := c.Preview(ctx, kind, r)
	if e != nil {
		t.Fatalf("preview %s %s: %v", kind, r.Operation, e)
	}
	r.Revision = p.Revision
	v, e := c.Apply(ctx, kind, r)
	if e != nil {
		t.Fatalf("apply %s %s: %v", kind, r.Operation, e)
	}
	if v.Transaction != nil && v.Transaction.Status == "awaiting-confirmation" {
		if _, e = c.Confirm(ctx, v.Transaction.ID); e != nil {
			t.Fatal(e)
		}
	}
	return v
}
func waitNative(t *testing.T, description string, check func() bool) {
	t.Helper()
	deadline := time.Now().Add(15 * time.Second)
	for time.Now().Before(deadline) {
		if check() {
			return
		}
		time.Sleep(200 * time.Millisecond)
	}
	t.Fatal("timed out: " + description)
}
func TestNativeSecurity(t *testing.T) {
	backend := os.Getenv("WUKONG_SECURITY_NATIVE")
	if backend == "" {
		t.Skip("disposable Linux environment only")
	}
	if !contains([]string{"ufw", "firewalld", "nftables"}, backend) {
		t.Fatal(backend)
	}
	ctx := context.Background()
	c := New("/etc/wukong-panel-security-test", false)
	c.RecoveryBinary = "/wukong-panel"
	// Ensure there is a recognizable SSH event and a known good password login.
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.4")
	if os.Getenv("WUKONG_SECURITY_INSTALL") == "1" {
		if _, e := c.exec(ctx, "apt-get", "purge", "-y", "ufw", "fail2ban"); e != nil {
			t.Fatal(e)
		}
		nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "install"})
		nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "install"})
		f, e := c.Firewall(ctx, "")
		if e != nil || !f.Installed || f.Active {
			t.Fatalf("installer enabled inbound protection %+v %v", f, e)
		}
		fb, e := c.Fail2ban(ctx)
		if e != nil || !fb.Installed || fb.Active {
			t.Fatalf("installer started SSH jails %+v %v", fb, e)
		}
		t.Log("actual package installation leaves firewall and SSH protection inactive")
	}

	switch backend {
	case "ufw":
		if _, e := c.exec(ctx, "ufw", "allow", "5566/tcp"); e != nil {
			t.Fatal(e)
		}
	case "firewalld":
		if e := c.service(ctx, "start", "firewalld"); e != nil {
			t.Fatal(e)
		}
		for _, a := range [][]string{{"--zone=public", "--change-interface=test-host"}, {"--zone=public", "--add-port=5566/tcp"}, {"--zone=public", "--add-rich-rule=rule family=\"ipv4\" source address=\"192.0.2.8\" port port=\"7777\" protocol=\"tcp\" accept"}} {
			if _, e := c.exec(ctx, "firewall-cmd", a...); e != nil {
				t.Fatal(e)
			}
		}
	case "nftables":
		if _, e := c.Run(ctx, "nft", []string{"-f", "-"}, "table inet unrelated { chain output { type filter hook output priority 50; policy accept; }\n}\n"+renderNFT([]model.SecurityRule{{Action: "allow", Protocol: "tcp", PortFrom: 5566, PortTo: 5566, Source: "any", Adoptable: true}}, false)); e != nil {
			t.Fatal(e)
		}
	}
	f, e := c.Firewall(ctx, "")
	if e != nil {
		t.Fatal(e)
	}
	if f.Backend != backend || !f.Writable {
		t.Fatalf("native detection: %+v", f)
	}
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "enable", Zone: f.Zone})
	f, e = c.Firewall(ctx, "")
	if e != nil || f.Policy != "deny" || !f.Active {
		t.Fatalf("policy %+v %v", f, e)
	}
	protected := map[int]bool{}
	external := false
	for _, r := range f.Rules {
		if r.PortFrom == 5566 {
			external = true
			if r.Managed {
				t.Fatal("implicitly adopted external rule")
			}
		}
		if r.Protected {
			protected[r.PortFrom] = true
		}
	}
	if !external || !protected[46961] || !protected[9443] {
		t.Fatalf("rules %+v", f.Rules)
	}
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.4")
	nativeConnect(t, "tcp", "10.203.0.1:9443", "")
	nativeConnect(t, "tcp", "[fd42:203::1]:9443", "")
	listener, e := net.Listen("tcp", ":22222")
	if e != nil {
		t.Fatal(e)
	}
	defer listener.Close()
	go func() {
		for {
			conn, e := listener.Accept()
			if e != nil {
				return
			}
			conn.Close()
		}
	}()
	nativeConnect(t, "blocked", "10.203.0.1:22222", "")
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "add", Zone: f.Zone, Rule: model.SecurityRule{Action: "allow", Protocol: "tcp", PortFrom: 22222, Source: "any"}})
	nativeConnect(t, "tcp", "10.203.0.1:22222", "")
	nativeConnect(t, "tcp", "[fd42:203::1]:22222", "")
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "add", Zone: f.Zone, Rule: model.SecurityRule{Action: "deny", Protocol: "tcp", PortFrom: 22222, Source: "10.203.0.2"}})
	nativeConnect(t, "blocked", "10.203.0.1:22222", "10.203.0.2")
	nativeConnect(t, "tcp", "10.203.0.1:22222", "10.203.0.4")
	f, _ = c.Firewall(ctx, "")
	var blockID string
	for _, r := range f.Rules {
		if r.Action == "deny" && r.Source == "10.203.0.2" {
			blockID = r.ID
		}
	}
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "delete", RuleID: blockID, Zone: f.Zone})
	nativeConnect(t, "tcp", "10.203.0.1:22222", "10.203.0.2")
	// Persisted native rules survive a service reload without erasing external rules.
	switch backend {
	case "ufw":
		_, e = c.exec(ctx, "ufw", "reload")
	case "firewalld":
		_, e = c.exec(ctx, "firewall-cmd", "--reload")
	case "nftables":
		body, _ := c.read(nftPath)
		_, e = c.Run(ctx, "nft", []string{"-f", "-"}, "delete table inet wukong_panel\n"+string(body))
	}
	if e != nil {
		t.Fatal(e)
	}
	nativeConnect(t, "tcp", "10.203.0.1:22222", "")
	if backend == "nftables" {
		if _, e = c.exec(ctx, "nft", "list", "table", "inet", "unrelated"); e != nil {
			t.Fatal("third-party table lost", e)
		}
	}
	// Test SSH protection using real failed authentications and actual network blocks.
	if e = c.service(ctx, "start", "fail2ban"); e != nil {
		t.Fatal(e)
	}
	cfg := defaults()
	cfg.MaxRetry = 3
	cfg.IgnoreIPs = []string{"10.203.0.3"}
	fb, e := c.Fail2ban(ctx)
	if e != nil {
		t.Fatal(e)
	}
	if !fb.Writable {
		t.Fatalf("SSH prerequisites %+v", fb)
	}
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "enable", Config: cfg, Zone: f.Zone})
	fb, e = c.Fail2ban(ctx)
	if e != nil || !fb.Active {
		t.Fatalf("jail %+v %v", fb, e)
	}
	t.Logf("%s: real SSH logging backend=%s; non-default port=46961", backend, fb.LogBackend)
	for i := 0; i < 3; i++ {
		nativeConnect(t, "ssh-fail", "10.203.0.1:46961", "10.203.0.2")
	}
	waitNative(t, "real SSH ban", func() bool {
		v, _ := c.Fail2ban(ctx)
		return len(v.Jails) > 0 && contains(v.Jails[0].Banned, "10.203.0.2")
	})
	nativeConnect(t, "blocked", "10.203.0.1:46961", "10.203.0.2")
	nativeConnect(t, "tcp", "10.203.0.1:9443", "10.203.0.2")
	nativeConnect(t, "tcp", "10.203.0.1:22222", "10.203.0.2")
	for i := 0; i < 5; i++ {
		nativeConnect(t, "ssh-fail", "10.203.0.1:46961", "10.203.0.3")
	}
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.3")
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.4")
	// A panel-triggered firewall mutation restores all active jail bans after any reload.
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "add", Zone: f.Zone, Rule: model.SecurityRule{Action: "allow", Protocol: "udp", PortFrom: 23456, Source: "any"}})
	nativeConnect(t, "blocked", "10.203.0.1:46961", "10.203.0.2")
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "unban", IP: "10.203.0.2"})
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.2")
	// IPv6 addresses are parsed, listed and enforced independently of IPv4.
	if _, e = c.exec(ctx, "fail2ban-client", "set", "wukong-sshd", "banip", "fd42:203::2"); e != nil {
		t.Fatal(e)
	}
	waitNative(t, "IPv6 enforcement", func() bool {
		out, _ := c.exec(ctx, "fail2ban-client", "status", "wukong-sshd")
		return strings.Contains(out, "fd42:203::2")
	})
	nativeConnect(t, "blocked", "[fd42:203::1]:46961", "")
	nativeConnect(t, "tcp", "[fd42:203::1]:9443", "")
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "unban", IP: "fd42:203::2"})
	// Exercise the file backend on systemd too, using a second real SSH daemon log.
	if c.isSystemd() {
		nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "disable"})
		if e = c.service(ctx, "stop", "wukong-test-sshd"); e != nil {
			t.Fatal(e)
		}
		if e = os.MkdirAll("/run/sshd", 0755); e != nil {
			t.Fatal(e)
		}
		sshd := exec.Command("/usr/sbin/sshd", "-D", "-e")
		sshd.Stderr = &sshLogWriter{path: "/var/log/auth.log"}
		if e = sshd.Start(); e != nil {
			t.Fatal(e)
		}
		defer func() { _ = sshd.Process.Kill(); _ = sshd.Wait() }()
		time.Sleep(300 * time.Millisecond)
		nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.4")
		c.NoJournal = true
		nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "enable", Config: cfg, Zone: f.Zone})
		for i := 0; i < 3; i++ {
			nativeConnect(t, "ssh-fail", "10.203.0.1:46961", "10.203.0.2")
		}
		waitNative(t, "file-log ban", func() bool {
			v, _ := c.Fail2ban(ctx)
			return len(v.Jails) > 0 && contains(v.Jails[0].Banned, "10.203.0.2")
		})
		nativeConnect(t, "blocked", "10.203.0.1:46961", "10.203.0.2")
		nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "unban", IP: "10.203.0.2"})
		t.Log("journal and polling: real failed SSH connections banned and unbanned")
	}
	// A separate recovery service keeps working after the real Root Agent is killed.
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "disable"})
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "detach"})
	// Adoption keeps the existing jail name and restores the original on detach.
	original := defaults()
	original.MaxRetry = 9
	source, path, se := c.logSource(ctx)
	if se != nil {
		t.Fatal(se)
	}
	old := renderJail("legacy-ssh", original, true, source, path, "nftables-multiport[name=legacy-ssh,port=46961,protocol=tcp]", []int{46961})
	otherPath := "/var/log/wukong-other.log"
	if e = os.WriteFile(otherPath, []byte(""), 0600); e != nil {
		t.Fatal(e)
	}
	other := renderJail("security-other", original, true, "polling", otherPath, "nftables-multiport[name=security-other,port=22222,protocol=tcp]", []int{22222})
	originalPath := "/etc/fail2ban/jail.d/zy-native-original.local"
	if e = os.WriteFile(originalPath, append(old, other...), 0600); e != nil {
		t.Fatal(e)
	}
	if _, e = c.exec(ctx, "fail2ban-client", "reload"); e != nil {
		t.Fatal(e)
	}
	fb, e = c.Fail2ban(ctx)
	if e != nil || len(fb.Jails) != 1 || fb.Jails[0].Managed {
		t.Fatalf("existing jail %+v %v", fb, e)
	}
	if _, e = c.Preview(ctx, "fail2ban", model.SecurityRequest{Operation: "enable", Config: cfg}); e == nil {
		t.Fatal("duplicated an existing SSH jail")
	}
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "adopt", Jail: "legacy-ssh", Config: cfg, Zone: f.Zone})
	if _, e = c.exec(ctx, "fail2ban-client", "set", "security-other", "banip", "192.0.2.80"); e != nil {
		t.Fatal(e)
	}
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "disable"})
	otherStatus, e := c.exec(ctx, "fail2ban-client", "status", "security-other")
	if e != nil || !strings.Contains(otherStatus, "192.0.2.80") {
		t.Fatalf("other jail changed %s %v", otherStatus, e)
	}
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "detach"})
	restored, e := c.effectiveConfig(ctx, "legacy-ssh")
	if e != nil || restored.MaxRetry != 9 {
		t.Fatalf("original jail not restored %+v %v", restored, e)
	}
	unchanged, e := os.ReadFile(originalPath)
	if e != nil || string(unchanged) != string(append(old, other...)) {
		t.Fatal("modified upstream fixture config")
	}
	for _, name := range []string{"legacy-ssh", "security-other"} {
		if _, e = c.exec(ctx, "fail2ban-client", "stop", name); e != nil {
			t.Fatal(e)
		}
	}
	if e = os.Remove(originalPath); e != nil {
		t.Fatal(e)
	}
	t.Log("adopt/detach: original jail name and settings restored; unrelated jail and ban preserved")

	agentDir := t.TempDir()
	agent := exec.Command("/wukong-panel", "agent", "--data-dir", agentDir, "--secret-dir", filepath.Dir(c.Dir), "--agent-token", "isolated-integration-agent", "--agent-socket", filepath.Join(agentDir, "agent.sock"), "--network-probe-targets", "127.0.0.1", "--network-probe-domestic-targets", "127.0.0.1")
	if e = agent.Start(); e != nil {
		t.Fatal(e)
	}
	defer func() { _ = agent.Process.Kill(); _ = agent.Wait() }()
	time.Sleep(300 * time.Millisecond)
	req := model.SecurityRequest{Operation: "disable", Zone: f.Zone}
	p, e := c.Preview(ctx, "firewall", req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	result, e := c.Apply(ctx, "firewall", req)
	if e != nil {
		t.Fatal(e)
	}
	if result.Transaction == nil || result.Transaction.Status != "awaiting-confirmation" {
		t.Fatal(result)
	}
	delta := time.Until(result.Transaction.Deadline)
	if delta < 85*time.Second || delta > 91*time.Second {
		t.Fatalf("wrong confirmation window %s", delta)
	}
	_ = agent.Process.Kill()
	var pending journal
	if e = c.load("pending.json", &pending); e != nil {
		t.Fatal(e)
	}
	pending.Transaction.Deadline = time.Now().Add(2 * time.Second)
	if e = c.save("pending.json", pending); e != nil {
		t.Fatal(e)
	}
	waitNative(t, "independent recovery after Agent death", func() bool {
		v, e := c.Transaction(result.Transaction.ID)
		return e == nil && v.Status == "rolled-back"
	})
	f, e = c.Firewall(ctx, "")
	if e != nil || f.Policy != "deny" {
		t.Fatalf("recovery policy %+v %v", f, e)
	}
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.4")
	t.Logf("PASS %s: IPv4/IPv6 allow/deny, protected ports, existing rules, persistence, SSH-only bans, whitelist, unban, independent 90s recovery", backend)
}

type sshLogWriter struct {
	mu   sync.Mutex
	path string
}

func (w *sshLogWriter) Write(p []byte) (int, error) {
	w.mu.Lock()
	defer w.mu.Unlock()
	f, e := os.OpenFile(w.path, os.O_CREATE|os.O_APPEND|os.O_WRONLY, 0600)
	if e != nil {
		return 0, e
	}
	defer f.Close()
	for _, line := range strings.Split(strings.TrimSpace(string(p)), "\n") {
		if line != "" {
			if _, e = f.WriteString(time.Now().Format("Jan _2 15:04:05") + " fixture sshd[123]: " + line + "\n"); e != nil {
				return 0, e
			}
		}
	}
	return len(p), nil
}

func TestNativePrepareReboot(t *testing.T) {
	if os.Getenv("WUKONG_SECURITY_NATIVE") == "" {
		t.Skip("isolated Linux only")
	}
	c := New("/etc/wukong-panel-security-test", false)
	c.RecoveryBinary = "/wukong-panel"
	ctx := context.Background()
	f, e := c.Firewall(ctx, "")
	if e != nil {
		t.Fatal(e)
	}
	req := model.SecurityRequest{Operation: "disable", Zone: f.Zone}
	p, e := c.Preview(ctx, "firewall", req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = p.Revision
	v, e := c.Apply(ctx, "firewall", req)
	if e != nil {
		t.Fatal(e)
	}
	if v.Transaction == nil || v.Transaction.Status != "awaiting-confirmation" {
		t.Fatal(v)
	}
	if e = os.WriteFile("/etc/wukong-panel-security-test/reboot-id", []byte(v.Transaction.ID), 0600); e != nil {
		t.Fatal(e)
	}
	if c.isSystemd() {
		if _, e = c.exec(ctx, "systemctl", "enable", "wukong-test-sshd.service", "nginx.service"); e != nil {
			t.Fatal(e)
		}
	} else {
		for _, name := range []string{"syslog", "sshd", "nginx"} {
			if _, e = c.exec(ctx, "rc-update", "add", name, "default"); e != nil {
				t.Fatal(e)
			}
		}
	}
	t.Log("left real unconfirmed transaction for PID 1 restart; full 90 second window retained")
}
func TestNativeAfterReboot(t *testing.T) {
	if os.Getenv("WUKONG_SECURITY_NATIVE") == "" {
		t.Skip("isolated Linux only")
	}
	c := New("/etc/wukong-panel-security-test", false)
	id, e := os.ReadFile("/etc/wukong-panel-security-test/reboot-id")
	if e != nil {
		t.Fatal(e)
	}
	waitNative(t, "boot recovery", func() bool { v, e := c.Transaction(string(id)); return e == nil && v.Status == "rolled-back" })
	f, e := c.Firewall(context.Background(), "")
	if e != nil || !f.Active || f.Policy != "deny" {
		t.Fatalf("reboot state %+v %v", f, e)
	}
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.4")
	nativeConnect(t, "tcp", "[fd42:203::1]:9443", "")
	t.Log("PID 1 restart recovered pending transaction and management connectivity")
}
