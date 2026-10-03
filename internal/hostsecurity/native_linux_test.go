//go:build linux

package hostsecurity

import (
	"context"
	"errors"
	"github.com/252201/wukong-panel/internal/model"
	"golang.org/x/crypto/ssh"
	"golang.org/x/net/icmp"
	"golang.org/x/net/ipv4"
	"golang.org/x/net/ipv6"
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
	if op == "icmp4" || op == "icmp6" {
		network, bind, protocol := "ip4:icmp", "0.0.0.0", 1
		var requestType, replyType icmp.Type = ipv4.ICMPTypeEcho, ipv4.ICMPTypeEchoReply
		if op == "icmp6" {
			network, bind, protocol = "ip6:ipv6-icmp", "::", 58
			requestType, replyType = ipv6.ICMPTypeEchoRequest, ipv6.ICMPTypeEchoReply
		}
		conn, e := icmp.ListenPacket(network, bind)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		id := os.Getpid() & 0xffff
		msg := icmp.Message{Type: requestType, Body: &icmp.Echo{ID: id, Seq: 1, Data: []byte("wukong-network-test")}}
		body, e := msg.Marshal(nil)
		if e != nil {
			t.Fatal(e)
		}
		if _, e = conn.WriteTo(body, &net.IPAddr{IP: net.ParseIP(addr)}); e != nil {
			t.Fatal(e)
		}
		_ = conn.SetReadDeadline(time.Now().Add(2 * time.Second))
		buf := make([]byte, 1500)
		for {
			n, _, e := conn.ReadFrom(buf)
			if e != nil {
				t.Fatal(e)
			}
			reply, e := icmp.ParseMessage(protocol, buf[:n])
			if e != nil {
				t.Fatal(e)
			}
			if echo, ok := reply.Body.(*icmp.Echo); ok && reply.Type == replyType && echo.ID == id && echo.Seq == 1 {
				return
			}
		}
	}
	if op == "udp" || op == "udp-blocked" {
		dialer := net.Dialer{Timeout: 2 * time.Second}
		if source != "" {
			dialer.LocalAddr = &net.UDPAddr{IP: net.ParseIP(source)}
		}
		conn, e := dialer.Dial("udp", addr)
		if e != nil {
			t.Fatal(e)
		}
		defer conn.Close()
		_ = conn.SetDeadline(time.Now().Add(2 * time.Second))
		if _, e = conn.Write([]byte("wukong-udp-test")); e != nil {
			t.Fatal(e)
		}
		buf := make([]byte, 100)
		n, e := conn.Read(buf)
		if op == "udp-blocked" {
			if e == nil {
				t.Fatal("UDP deny allowed a reply")
			}
			return
		}
		if e != nil || string(buf[:n]) != "wukong-udp-test" {
			t.Fatalf("UDP reply: %q %v", buf[:n], e)
		}
		return
	}
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
		// First enable from a stopped daemon must return to stopped on timeout.
		if e := c.service(ctx, "stop", "firewalld"); e != nil {
			t.Fatal(e)
		}
		r := model.SecurityRequest{Operation: "enable"}
		p, e := c.Preview(ctx, "firewall", r)
		if e != nil {
			t.Fatal(e)
		}
		r.Revision = p.Revision
		v, e := c.Apply(ctx, "firewall", r)
		if e != nil {
			t.Fatal(e)
		}
		if v.Transaction == nil || v.Transaction.Status != "awaiting-confirmation" {
			t.Fatal(v)
		}
		c.Now = func() time.Time { return v.Transaction.Deadline.Add(time.Second) }
		if e := c.Recover(ctx); e != nil {
			t.Fatal(e)
		}
		c.Now = time.Now
		f, e := c.Firewall(ctx, "")
		if e != nil || f.Active {
			t.Fatalf("first-enable timeout left daemon active: %+v %v", f, e)
		}
		t.Log("firewalld first-enable timeout restores original stopped service")
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
	nativeConnect(t, "icmp4", "10.203.0.1", "")
	nativeConnect(t, "icmp6", "fd42:203::1", "")
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
	nativeConfiguredSSHActivation(t, c, f.Zone)
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
	udp, e := net.ListenPacket("udp", ":23456")
	if e != nil {
		t.Fatal(e)
	}
	defer udp.Close()
	go func() {
		buf := make([]byte, 100)
		for {
			n, addr, e := udp.ReadFrom(buf)
			if e != nil {
				return
			}
			_, _ = udp.WriteTo(buf[:n], addr)
		}
	}()
	nativeConnect(t, "udp-blocked", "10.203.0.1:23456", "")
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "add", Zone: f.Zone, Rule: model.SecurityRule{Action: "allow", Protocol: "udp", PortFrom: 23456, Source: "any"}})
	nativeConnect(t, "udp", "10.203.0.1:23456", "")
	nativeConnect(t, "udp", "[fd42:203::1]:23456", "")
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "add", Zone: f.Zone, Rule: model.SecurityRule{Action: "deny", Protocol: "udp", PortFrom: 23456, Source: "10.203.0.2/32"}})
	nativeConnect(t, "udp-blocked", "10.203.0.1:23456", "10.203.0.2")
	nativeConnect(t, "udp", "10.203.0.1:23456", "10.203.0.4")
	nativeConnect(t, "udp", "[fd42:203::1]:23456", "")
	nativeConnect(t, "blocked", "10.203.0.1:46961", "10.203.0.2")
	if backend == "ufw" {
		nativeUFWRegressions(t, c, f.Zone)
		// The recovery reload must preserve the active SSH-only ban too.
		nativeConnect(t, "blocked", "10.203.0.1:46961", "10.203.0.2")
		nativeConnect(t, "tcp", "10.203.0.1:9443", "10.203.0.2")
	}
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

// Reproduce the v1.7.0 production failures using real UFW and packets. These
// tests keep UFW active during recovery; disable/enable alone misses the bug.
func nativeUFWRegressions(t *testing.T, c *Controller, zone string) {
	t.Helper()
	ctx := context.Background()
	listener, e := net.Listen("tcp", ":33333")
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
	for _, port := range []string{"33334", "33335"} {
		udp, e := net.ListenPacket("udp", ":"+port)
		if e != nil {
			t.Fatal(e)
		}
		defer udp.Close()
		go func() {
			buf := make([]byte, 100)
			for {
				n, addr, e := udp.ReadFrom(buf)
				if e != nil {
					return
				}
				_, _ = udp.WriteTo(buf[:n], addr)
			}
		}()
	}
	add := func(action, protocol, source string, from, to int) {
		t.Helper()
		nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "add", Zone: zone, Rule: model.SecurityRule{Action: action, Protocol: protocol, PortFrom: from, PortTo: to, Source: source}})
	}
	find := func(action, protocol, source string, from int) model.SecurityRule {
		t.Helper()
		f, e := c.Firewall(ctx, zone)
		if e != nil {
			t.Fatal(e)
		}
		for _, r := range f.Rules {
			if r.Action == action && r.Protocol == protocol && r.Source == source && r.PortFrom == from {
				return r
			}
		}
		t.Fatal("rule not found", action, protocol, source, from)
		return model.SecurityRule{}
	}
	// Replacing an external rule requires explicit adoption, even if simple.
	if _, e := c.Preview(ctx, "firewall", model.SecurityRequest{Operation: "add", Rule: model.SecurityRule{Action: "deny", Protocol: "tcp", PortFrom: 5566, Source: "any"}}); e == nil || !strings.Contains(e.Error(), "接管") {
		t.Fatal("implicitly replaced third-party allow", e)
	}
	for _, source := range []string{"10.203.0.4/32", "fd42:203::2/128"} {
		add("allow", "tcp", source, 33333, 33333)
	}
	nativeConnect(t, "tcp", "10.203.0.1:33333", "10.203.0.4")
	nativeConnect(t, "tcp", "[fd42:203::1]:33333", "")
	for _, source := range []string{"10.203.0.4/32", "fd42:203::2/128"} {
		add("deny", "tcp", source, 33333, 33333)
		if strings.Contains(source, ":") {
			nativeConnect(t, "blocked", "[fd42:203::1]:33333", "")
			nativeConnect(t, "tcp", "10.203.0.1:33333", "10.203.0.4")
		} else {
			nativeConnect(t, "blocked", "10.203.0.1:33333", "10.203.0.4")
			nativeConnect(t, "tcp", "[fd42:203::1]:33333", "")
		}
		add("allow", "tcp", source, 33333, 33333)
		nativeConnect(t, "tcp", "10.203.0.1:33333", "10.203.0.4")
		nativeConnect(t, "tcp", "[fd42:203::1]:33333", "")
	}
	add("allow", "udp", "10.203.0.0/24", 33334, 33335)
	add("allow", "udp", "fd42:203::/64", 33334, 33335)
	add("deny", "udp", "fd42:203::/64", 33334, 33335)
	for _, port := range []string{"33334", "33335"} {
		nativeConnect(t, "udp-blocked", "[fd42:203::1]:"+port, "")
		nativeConnect(t, "udp", "10.203.0.1:"+port, "10.203.0.4")
	}
	add("allow", "udp", "fd42:203::/64", 33334, 33335)
	// A new IPv6-only deny must precede the broader IPv6 range allow.
	add("deny", "udp", "fd42:203::2/128", 33334, 33334)
	nativeConnect(t, "udp-blocked", "[fd42:203::1]:33334", "")
	nativeConnect(t, "udp", "[fd42:203::1]:33335", "")
	nativeConnect(t, "udp", "10.203.0.1:33334", "10.203.0.4")
	block := find("deny", "udp", "fd42:203::2", 33334)
	nativeApply(t, c, "firewall", model.SecurityRequest{Operation: "delete", RuleID: block.ID})
	nativeConnect(t, "udp", "[fd42:203::1]:33334", "")
	// Inject a failure after deleting the conflicting allow. Both kernel rules
	// and original ownership/IDs must recover, with the firewall still active.
	before, e := c.state()
	if e != nil {
		t.Fatal(e)
	}
	old := find("allow", "tcp", "10.203.0.4", 33333)
	base := c.Run
	c.Run = func(ctx context.Context, name string, args []string, input string) (string, error) {
		if name == "ufw" && len(args) > 0 && args[0] == "prepend" {
			return "", errors.New("injected replacement failure")
		}
		return base(ctx, name, args, input)
	}
	r := model.SecurityRequest{Operation: "add", Rule: model.SecurityRule{Action: "deny", Protocol: "tcp", PortFrom: 33333, Source: "10.203.0.4"}}
	p, e := c.Preview(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	r.Revision = p.Revision
	_, e = c.Apply(ctx, "firewall", r)
	c.Run = base
	if e == nil || !strings.Contains(e.Error(), "injected replacement failure") || c.pending() != nil {
		t.Fatal("failed replacement did not recover", e)
	}
	if got := find("allow", "tcp", "10.203.0.4", 33333); got.ID != old.ID || !got.Managed {
		t.Fatal("ownership lost after failed replacement", got)
	}
	nativeConnect(t, "tcp", "10.203.0.1:33333", "10.203.0.4")
	// Wait the complete 90-second window without Confirm or in-process Recover.
	// The independent recovery daemon must restore the active kernel rules.
	r = model.SecurityRequest{Operation: "delete", RuleID: old.ID}
	p, e = c.Preview(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	r.Revision = p.Revision
	v, e := c.Apply(ctx, "firewall", r)
	if e != nil || v.Transaction == nil || v.Transaction.Status != "awaiting-confirmation" {
		t.Fatal("delete confirmation", v, e)
	}
	if d := time.Until(v.Transaction.Deadline); d < 85*time.Second || d > 91*time.Second {
		t.Fatal("wrong confirmation window", d)
	}
	nativeConnect(t, "blocked", "10.203.0.1:33333", "10.203.0.4")
	nativeConnect(t, "tcp", "[fd42:203::1]:33333", "")
	deadline := v.Transaction.Deadline.Add(15 * time.Second)
	for {
		x, e := c.Transaction(v.Transaction.ID)
		if e == nil && x.Status == "rolled-back" {
			break
		}
		if time.Now().After(deadline) {
			t.Fatal("independent active-firewall recovery did not finish", x, e)
		}
		time.Sleep(500 * time.Millisecond)
	}
	nativeConnect(t, "tcp", "10.203.0.1:33333", "10.203.0.4")
	nativeConnect(t, "tcp", "[fd42:203::1]:33333", "")
	for _, port := range []string{"33334", "33335"} {
		nativeConnect(t, "udp", "[fd42:203::1]:"+port, "")
	}
	after, e := c.state()
	if e != nil || c.revision(before) != c.revision(after) {
		t.Fatal("original ownership/state not restored", e)
	}
	if got := find("allow", "tcp", "10.203.0.4", 33333); got.ID != old.ID {
		t.Fatal("original ID lost on timeout", got)
	}
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.4")
	nativeConnect(t, "tcp", "10.203.0.1:9443", "")
	nativeConnect(t, "tcp", "[fd42:203::1]:9443", "")
	t.Log("UFW regressions: managed allow/deny replacements, IPv6 prepend, CIDR/UDP ranges, failed replacement and full 90s active-kernel recovery passed")
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

// Exercise the package-default configured-but-stopped SSH protection without
// requiring a beginner to start a daemon from a shell before panel adoption.
func nativeConfiguredSSHActivation(t *testing.T, c *Controller, zone string) {
	t.Helper()
	ctx := context.Background()
	// Use a separate peer: the next fresh jail can legitimately replay recent
	// authentication failures, so this scenario must not pre-ban its test IP.
	if _, e := c.exec(ctx, "ip", "netns", "exec", "security-client", "ip", "addr", "add", "10.203.0.5/24", "dev", "test-client"); e != nil {
		t.Fatal(e)
	}
	defer c.exec(ctx, "ip", "netns", "exec", "security-client", "ip", "addr", "del", "10.203.0.5/24", "dev", "test-client")
	if e := c.service(ctx, "stop", "fail2ban"); e != nil {
		t.Fatal(e)
	}
	backend, path, e := c.logSource(ctx)
	if e != nil {
		t.Fatal(e)
	}
	originalPath := "/etc/fail2ban/jail.d/zzz-native-configured.local"
	original := renderJail("sshd", defaults(), true, backend, path, "nftables-multiport[name=sshd,port=22,protocol=tcp]", []int{22})
	if e = os.WriteFile(originalPath, original, 0600); e != nil {
		t.Fatal(e)
	}
	defer os.Remove(originalPath)
	beforeBoot := c.bootEnabled(ctx, "fail2ban")
	fb, e := c.Fail2ban(ctx)
	if e != nil || fb.Active || !fb.CanActivate || !fb.Writable || len(fb.Jails) != 1 || !fb.Jails[0].ConfiguredOnly {
		t.Fatalf("configured stopped SSH %+v %v", fb, e)
	}
	cfg := defaults()
	cfg.MaxRetry = 3
	cfg.IgnoreIPs = []string{"10.203.0.3"}
	req := model.SecurityRequest{Operation: "adopt", Jail: "sshd", Config: cfg, Zone: zone}
	preview, e := c.Preview(ctx, "fail2ban", req)
	if e != nil {
		t.Fatal(e)
	}
	req.Revision = preview.Revision
	base := c.Run
	injected := false
	c.Run = func(ctx context.Context, n string, a []string, in string) (string, error) {
		out, err := base(ctx, n, a, in)
		args := strings.Join(a, " ")
		if !injected && err == nil && (n == "systemctl" && args == "start fail2ban.service" || n == "rc-service" && args == "fail2ban start") {
			injected = true
			return out, errors.New("injected failure after actual Fail2ban startup")
		}
		return out, err
	}
	_, failure := c.Apply(ctx, "fail2ban", req)
	c.Run = base
	if !injected || failure == nil || c.pending() != nil || !c.fail2banStopped(ctx) || c.bootEnabled(ctx, "fail2ban") != beforeBoot {
		t.Fatalf("failed activation did not restore stopped service: injected=%v failure=%v", injected, failure)
	}
	if _, e = os.Stat(jailPath); !errors.Is(e, os.ErrNotExist) {
		t.Fatalf("failed activation left override: %v", e)
	}
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "adopt", Jail: "sshd", Config: cfg, Zone: zone})
	fb, e = c.Fail2ban(ctx)
	if e != nil || !fb.Active || fb.ManagedJail != "sshd" || len(fb.Jails) != 1 || !fb.Jails[0].Managed || fb.Jails[0].ConfiguredOnly {
		t.Fatalf("activated SSH %+v %v", fb, e)
	}
	current, e := os.ReadFile(originalPath)
	if e != nil || string(current) != string(original) {
		t.Fatal("changed original SSH configuration", e)
	}
	for i := 0; i < 3; i++ {
		nativeConnect(t, "ssh-fail", "10.203.0.1:46961", "10.203.0.5")
	}
	waitNative(t, "adopted stopped SSH ban", func() bool {
		v, _ := c.Fail2ban(ctx)
		return len(v.Jails) == 1 && contains(v.Jails[0].Banned, "10.203.0.5")
	})
	nativeConnect(t, "blocked", "10.203.0.1:46961", "10.203.0.5")
	nativeConnect(t, "tcp", "10.203.0.1:9443", "10.203.0.5")
	nativeConnect(t, "ssh-ok", "10.203.0.1:46961", "10.203.0.3")
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "unban", IP: "10.203.0.5"})
	nativeConnect(t, "tcp", "10.203.0.1:46961", "10.203.0.5")
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "disable"})
	nativeApply(t, c, "fail2ban", model.SecurityRequest{Operation: "detach"})
	if e = c.service(ctx, "stop", "fail2ban"); e != nil {
		t.Fatal(e)
	}
	if e = os.Remove(originalPath); e != nil {
		t.Fatal(e)
	}
	t.Log("configured inactive SSH: preview/adopt/start, startup failure rollback, original config retained, actual port 46961 ban/whitelist/unban passed")
}
