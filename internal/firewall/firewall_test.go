package firewall

import (
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"sync"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

const testID = "00112233445566778899aabb"

func TestUFWOwnershipAndBroadRules(t *testing.T) {
	s := state{Rules: []record{{ID: testID, Backend: "ufw", Port: 8443, Protocol: "tcp"}}}
	rules := parseUFW("ufw allow 22\nufw allow 8443/tcp comment 'wukong-"+testID+"'\nufw allow 8443/udp comment 'wukong-"+testID+"'\nufw allow from 192.0.2.1 to any port 9000 proto tcp\nufw deny 25/tcp", s)
	if len(rules) != 4 {
		t.Fatalf("rules=%+v", rules)
	}
	if rules[0].Port != 22 || rules[1].Protocol != "udp" || !rules[2].Managed || rules[3].Managed {
		t.Fatalf("ownership=%+v", rules)
	}
	if len(parseUFW("ufw allow 0/tcp\nufw allow 65536/udp\nufw allow 8000:9000/tcp", s)) != 0 {
		t.Fatal("invalid ports parsed")
	}
}

func TestNFTOnlyOwnsSimpleAcceptRules(t *testing.T) {
	s := state{Rules: []record{{ID: testID, Backend: "nftables", Port: 8443, Protocol: "tcp"}}}
	prefix := `{"family":"inet","table":"wukong_panel","chain":"input","handle":10,"comment":"wukong-` + testID + `","expr":`
	match := `{"match":{"op":"==","left":{"payload":{"protocol":"tcp","field":"dport"}},"right":8443}}`
	data := `{"nftables":[{"chain":{"family":"inet","table":"wukong_panel","name":"input","hook":"input","policy":"drop"}},` +
		`{"rule":` + prefix + `[` + match + `,{"accept":null}]}},` +
		`{"rule":` + prefix + `[` + match + `,{"match":{"op":"==","left":{"payload":{"protocol":"ip","field":"saddr"}},"right":"192.0.2.1"}},{"accept":null}]}},` +
		`{"rule":` + prefix + `[` + match + `,{"drop":null}]}},` +
		`{"rule":` + prefix + `[` + match + `,` + match + `,{"accept":null}]}}]}`
	rules, active, err := parseNFT(data, s)
	if err != nil || !active || len(rules) != 1 || !rules[0].Managed {
		t.Fatalf("rules=%+v active=%v err=%v", rules, active, err)
	}
	changed := strings.ReplaceAll(data, `"policy":"drop"`, `"policy":"accept"`)
	_, active, _ = parseNFT(changed, s)
	if active {
		t.Fatal("accept policy treated as managed drop chain")
	}
}

func TestManagementListeners(t *testing.T) {
	text := `LISTEN 0 128 [::]:2222 [::]:* users:(("sshd",pid=1,fd=3))
LISTEN 0 128 127.0.0.1:9443 0.0.0.0:* users:(("wukong-panel",pid=2,fd=5))
LISTEN 0 128 0.0.0.0:443 0.0.0.0:* users:(("nginx",pid=3,fd=6))
LISTEN 0 128 *:9000 *:* users:(("sing-box",pid=4,fd=7))`
	ports := protectedPorts(text)
	if len(ports) != 3 || ports[0].Port != 2222 || ports[1].Port != 9443 || ports[2].Port != 443 {
		t.Fatalf("ports=%+v", ports)
	}
	if p := protectedPorts(""); len(p) != 1 || p[0].Port != 22 {
		t.Fatalf("fallback=%+v", p)
	}
}

// Mock native firewalld responses and split runtime/permanent failure so tests
// never touch the developer machine's firewall.
type fakeFirewalld struct {
	runtime, permanent map[string]bool
	failPermanent      bool
	failSS             bool
	calls              []string
}

func newFakeController(t *testing.T) (*Controller, *fakeFirewalld) {
	t.Helper()
	f := &fakeFirewalld{runtime: map[string]bool{"22/tcp": true}, permanent: map[string]bool{"22/tcp": true}}
	c := New(t.TempDir(), false)
	c.lookup = func(name string) bool { return name == "firewall-cmd" }
	c.run = func(_ context.Context, name string, args []string, input string) (string, error) {
		command := strings.Join(args, " ")
		f.calls = append(f.calls, name+" "+command)
		if name == "ss" {
			if f.failSS {
				return "", errors.New("ss missing")
			}
			return `LISTEN 0 128 *:2222 *:* users:(("sshd",pid=1,fd=3))`, nil
		}
		if name != "firewall-cmd" || input != "" {
			t.Fatalf("unexpected command %s %v", name, args)
		}
		switch command {
		case "--state":
			return "running", nil
		case "--get-zones":
			return "public trusted", nil
		case "--get-default-zone":
			return "public", nil
		case "--get-active-zones":
			return "public\n interfaces: eth0", nil
		}
		target := f.runtime
		permanent := contains(args, "--permanent")
		if permanent {
			target = f.permanent
		}
		if contains(args, "--list-ports") {
			var ports []string
			for p, enabled := range target {
				if enabled {
					ports = append(ports, p)
				}
			}
			return strings.Join(ports, " "), nil
		}
		if contains(args, "--list-all") {
			return "public (active)\n services: ssh", nil
		}
		for _, a := range args {
			if strings.HasPrefix(a, "--add-port=") || strings.HasPrefix(a, "--remove-port=") {
				if permanent && f.failPermanent {
					f.failPermanent = false
					return "", errors.New("injected permanent write failure")
				}
				_, port, _ := strings.Cut(a, "=")
				target[port] = strings.HasPrefix(a, "--add-port=")
				return "success", nil
			}
		}
		return "", fmt.Errorf("unexpected args %v", args)
	}
	return c, f
}

func TestFirewalldRoundTripAndProtection(t *testing.T) {
	ctx := context.Background()
	c, f := newFakeController(t)
	status, err := c.Add(ctx, model.FirewallPortRequest{Port: 8443, Protocol: "tcp", Zone: "trusted"})
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, r := range status.Rules {
		if r.Port == 8443 {
			if !r.Managed || !r.Runtime || !r.Permanent || r.Zone != "trusted" {
				t.Fatalf("rule=%+v", r)
			}
			id = r.ID
		}
	}
	if !idPattern.MatchString(id) {
		t.Fatalf("id=%q", id)
	}
	if _, err = c.Add(ctx, model.FirewallPortRequest{Port: 8443, Protocol: "tcp", Zone: "trusted"}); err == nil {
		t.Fatal("duplicate accepted")
	}
	if _, err = c.Remove(ctx, id); err != nil {
		t.Fatal(err)
	}
	if f.runtime["8443/tcp"] || f.permanent["8443/tcp"] || !f.runtime["22/tcp"] {
		t.Fatal("incorrect deletion")
	}
	status, err = c.Add(ctx, model.FirewallPortRequest{Port: 2222, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	for _, r := range status.Rules {
		if r.Port == 2222 {
			if !r.Protected {
				t.Fatal("custom SSH port not protected")
			}
			if _, err = c.Remove(ctx, r.ID); err == nil {
				t.Fatal("removed SSH rule")
			}
		}
	}
	if _, err = c.Remove(ctx, testID); err == nil {
		t.Fatal("non-owned ID accepted")
	}
	for _, call := range f.calls {
		if strings.Contains(call, "reload") || strings.Contains(call, "--set-default") {
			t.Fatalf("policy-changing call=%s", call)
		}
	}
}

func TestSplitWriteFailureRestoresAndClearsJournal(t *testing.T) {
	c, f := newFakeController(t)
	f.failPermanent = true
	_, err := c.Add(context.Background(), model.FirewallPortRequest{Port: 8443, Protocol: "tcp"})
	if err == nil || !strings.Contains(err.Error(), "已恢复") {
		t.Fatalf("err=%v", err)
	}
	if f.runtime["8443/tcp"] || f.permanent["8443/tcp"] {
		t.Fatal("partial change not reverted")
	}
	if _, err = os.Stat(filepath.Join(c.dir, "pending.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("journal=%v", err)
	}
	s, err := c.state()
	if err != nil || len(s.Rules) != 0 {
		t.Fatalf("state=%+v err=%v", s, err)
	}
}

func TestRestartRecoversInterruptedDelete(t *testing.T) {
	c, f := newFakeController(t)
	r := record{ID: testID, Backend: "firewalld", Zone: "trusted", Port: 8443, Protocol: "udp"}
	before := state{Rules: []record{r}}
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		t.Fatal(err)
	}
	if err := c.save("pending.json", journal{Backend: "firewalld", Before: before, Zone: r.Zone, Port: "8443/udp", Runtime: true, Permanent: true}); err != nil {
		t.Fatal(err)
	}
	if err := c.save("ports.json", state{}); err != nil {
		t.Fatal(err)
	}
	// Simulate an interrupted deletion: runtime gone while permanent survives.
	f.permanent["8443/udp"] = true
	if err := c.Recover(context.Background()); err != nil {
		t.Fatal(err)
	}
	if !f.runtime["8443/udp"] || !f.permanent["8443/udp"] {
		t.Fatal("recovery lost previous rule")
	}
	s, err := c.state()
	if err != nil || len(s.Rules) != 1 || s.Rules[0].ID != testID {
		t.Fatalf("state=%+v err=%v", s, err)
	}
}

func TestValidationAndUnknownListenersBlockDeletion(t *testing.T) {
	c, f := newFakeController(t)
	for _, req := range []model.FirewallPortRequest{{Port: 0, Protocol: "tcp"}, {Port: 65536, Protocol: "udp"}, {Port: 80, Protocol: "tcp;reboot"}, {Port: 80, Protocol: "tcp", Zone: "public;reboot"}} {
		if _, err := c.Add(context.Background(), req); err == nil {
			t.Fatalf("invalid input accepted: %+v", req)
		}
	}
	status, err := c.Add(context.Background(), model.FirewallPortRequest{Port: 8443, Protocol: "tcp"})
	if err != nil {
		t.Fatal(err)
	}
	var id string
	for _, r := range status.Rules {
		if r.Managed {
			id = r.ID
		}
	}
	f.failSS = true
	if _, err = c.Remove(context.Background(), id); err == nil {
		t.Fatal("delete without listener protection accepted")
	}
	if !f.runtime["8443/tcp"] {
		t.Fatal("blocked deletion still changed native rule")
	}
}

func TestDemoConcurrentAddsAreDurable(t *testing.T) {
	c := New(t.TempDir(), true)
	var wg sync.WaitGroup
	for i := 0; i < 12; i++ {
		wg.Add(1)
		go func(p int) {
			defer wg.Done()
			if _, err := c.Add(context.Background(), model.FirewallPortRequest{Port: p, Protocol: "tcp"}); err != nil {
				t.Error(err)
			}
		}(8000 + i)
	}
	wg.Wait()
	s, err := c.state()
	if err != nil || len(s.Rules) != 12 {
		t.Fatalf("state=%+v err=%v", s, err)
	}
	st, err := os.Stat(filepath.Join(c.dir, "ports.json"))
	if err != nil || st.Mode().Perm() != 0600 {
		t.Fatalf("permissions=%v err=%v", st, err)
	}
}

func TestNativeCommandBoundaries(t *testing.T) {
	c := New(t.TempDir(), false)
	// Stop before persisting nftables, while inspecting the exact command.
	c.run = func(_ context.Context, name string, args []string, input string) (string, error) {
		if name != "nft" || strings.Join(args, " ") != "-f -" || !strings.HasPrefix(input, "add rule inet wukong_panel input udp dport 8443 accept comment ") {
			t.Fatalf("unexpected nft command %s %v %s", name, args, input)
		}
		return "", errors.New("stop before write")
	}
	_ = c.mutate(context.Background(), record{ID: testID, Backend: "nftables", Port: 8443, Protocol: "udp"}, true)
	c.run = func(_ context.Context, name string, args []string, input string) (string, error) {
		expected := "--force delete allow 8443/tcp comment wukong-" + testID
		if name != "ufw" || strings.Join(args, " ") != expected || input != "" {
			t.Fatalf("unexpected UFW command %s %v", name, args)
		}
		return "", nil
	}
	if err := c.mutate(context.Background(), record{ID: testID, Backend: "ufw", Port: 8443, Protocol: "tcp"}, false); err != nil {
		t.Fatal(err)
	}
}

func TestInactiveUFWAndConflictingManagers(t *testing.T) {
	for _, active := range []bool{false, true} {
		c := New(t.TempDir(), false)
		c.lookup = func(name string) bool { return name == "ufw" || name == "firewall-cmd" && active }
		c.run = func(_ context.Context, name string, args []string, _ string) (string, error) {
			switch name + " " + strings.Join(args, " ") {
			case "ufw status verbose":
				if active {
					return "Status: active", nil
				}
				return "Status: inactive", nil
			case "ufw show added":
				return "ufw allow 8443/tcp", nil
			case "firewall-cmd --state":
				return "running", nil
			case "ss -H -lntp":
				return "", nil
			default:
				t.Fatalf("unexpected command %s %v", name, args)
				return "", nil
			}
		}
		status, err := c.Status(context.Background(), "")
		if err != nil || len(status.Rules) != 1 || status.Rules[0].Runtime != active || status.Active != active {
			t.Fatalf("status=%+v err=%v", status, err)
		}
		if active && status.Writable {
			t.Fatal("conflicting active firewall managers permit writes")
		}
		if !active && (!status.Writable || !strings.Contains(status.Reason, "启用防火墙后才生效")) {
			t.Fatal("inactive UFW state misleading")
		}
	}
}

func TestNFTRecoveryWhenTableDisappeared(t *testing.T) {
	c := New(t.TempDir(), false)
	if err := os.MkdirAll(c.dir, 0700); err != nil {
		t.Fatal(err)
	}
	table := "table inet wukong_panel { chain input { type filter hook input priority 100; policy drop; } }"
	if err := c.save("pending.json", journal{Backend: "nftables", NFT: table, Before: state{Rules: []record{}}}); err != nil {
		t.Fatal(err)
	}
	restored := false
	c.run = func(_ context.Context, name string, args []string, input string) (string, error) {
		if name != "nft" {
			t.Fatalf("unexpected %s", name)
		}
		if len(args) > 0 && args[0] == "list" {
			return "", errors.New("table no longer exists")
		}
		if strings.Join(args, " ") != "-f -" || input != table+"\n" {
			t.Fatalf("invalid recovery args=%v input=%s", args, input)
		}
		restored = true
		return "", nil
	}
	if err := c.Recover(context.Background()); err != nil || !restored {
		t.Fatalf("restored=%v err=%v", restored, err)
	}
}
