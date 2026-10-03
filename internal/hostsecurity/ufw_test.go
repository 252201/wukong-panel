package hostsecurity

import (
	"context"
	"errors"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func TestUFWOppositeRuleRequiresOwnershipAndReviewedReplacement(t *testing.T) {
	for _, action := range []string{"allow", "deny"} {
		t.Run(action, func(t *testing.T) {
			c := testController(t)
			base := c.Run
			oldAction := "allow"
			if action == "allow" {
				oldAction = "deny"
			}
			c.Run = func(ctx context.Context, name string, args []string, input string) (string, error) {
				if name == "ufw" && strings.Join(args, " ") == "show added" {
					return "ufw allow 46961/tcp\nufw allow 9443/tcp\nufw " + oldAction + " from 2001:db8::8 to any port 30000:30002 proto udp", nil
				}
				return base(ctx, name, args, input)
			}
			r := model.SecurityRequest{Operation: "add", Rule: model.SecurityRule{Action: action, Protocol: "udp", PortFrom: 30000, PortTo: 30002, Source: "2001:db8::8/128"}}
			if _, e := c.Preview(context.Background(), "firewall", r); e == nil || !strings.Contains(e.Error(), "接管") {
				t.Fatalf("implicitly replaced external rule: %v", e)
			}
			old := model.SecurityRule{ID: token(), Action: oldAction, Protocol: "udp", PortFrom: 30000, PortTo: 30002, Source: "2001:db8::8", Managed: true}
			if e := c.save("state.json", state{Rules: []model.SecurityRule{old}}); e != nil {
				t.Fatal(e)
			}
			p, e := c.Preview(context.Background(), "firewall", r)
			if e != nil || !p.NeedsConfirmation || len(p.Changes) != 2 || !strings.Contains(p.Changes[0], ruleKey(old)) {
				t.Fatalf("replacement not reviewed with confirmation: %+v %v", p, e)
			}
			// A protected entry must still fail before any replacement occurs.
			r.Rule = model.SecurityRule{Action: "deny", Protocol: "tcp", PortFrom: 46961, Source: "any"}
			if _, e := c.Preview(context.Background(), "firewall", r); e == nil {
				t.Fatal("replaced protected SSH rule")
			}
		})
	}
}

func TestUFWFailedReloadKeepsRecoveryPendingAndRetries(t *testing.T) {
	c := testController(t)
	ctx := context.Background()
	writeTestFile(t, c, "/etc/ufw/user.rules", "original")
	r := model.SecurityRequest{Operation: "disable"}
	p, e := c.Preview(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	r.Revision = p.Revision
	v, e := c.Apply(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	writeTestFile(t, c, "/etc/ufw/user.rules", "changed")
	base := c.Run
	reloads, fail := 0, true
	c.Run = func(ctx context.Context, name string, args []string, input string) (string, error) {
		if name == "ufw" && strings.Join(args, " ") == "reload" {
			reloads++
			b, _ := c.read("/etc/ufw/user.rules")
			if string(b) != "original" {
				t.Fatal("reload ran before restoring configuration")
			}
			if fail {
				return "", errors.New("kernel reload failed")
			}
		}
		return base(ctx, name, args, input)
	}
	c.Now = func() time.Time { return v.Transaction.Deadline.Add(time.Second) }
	if e := c.Recover(ctx); e == nil || !strings.Contains(e.Error(), "kernel reload failed") {
		t.Fatalf("reported success without kernel recovery: %v", e)
	}
	if c.pending() == nil {
		t.Fatal("lost retry journal after reload failure")
	}
	fail = false
	if e := c.Recover(ctx); e != nil {
		t.Fatal(e)
	}
	v2, e := c.Transaction(v.Transaction.ID)
	if e != nil || v2.Status != "rolled-back" || c.pending() != nil || reloads != 2 {
		t.Fatalf("retry did not finish kernel recovery: %+v reloads=%d %v", v2, reloads, e)
	}
}

func TestUFWLegacyJournalReloadsOnlyOriginallyActiveFirewall(t *testing.T) {
	for _, op := range []string{"enable", "disable"} {
		t.Run(op, func(t *testing.T) {
			c := testController(t)
			base := c.Run
			calls := []string{}
			c.Run = func(ctx context.Context, name string, args []string, input string) (string, error) {
				if name == "ufw" {
					calls = append(calls, strings.Join(args, " "))
				}
				return base(ctx, name, args, input)
			}
			// This is the journal shape persisted by v1.7.0, including before reboot.
			j := journal{Kind: "firewall", Backend: "ufw", Transaction: model.SecurityTransaction{ID: token()}, Undo: []command{{Name: "ufw", Args: []string{"--force", op}}}}
			if e := c.rollback(context.Background(), &j); e != nil {
				t.Fatal(e)
			}
			want := "--force " + op
			if op == "enable" {
				want += "\nreload"
			}
			if got := strings.Join(calls, "\n"); got != want {
				t.Fatalf("legacy recovery %q: %q, want %q", op, got, want)
			}
		})
	}
}
