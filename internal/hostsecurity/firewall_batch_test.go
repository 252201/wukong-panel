package hostsecurity

import (
	"context"
	"errors"
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/252201/wukong-panel/internal/model"
)

func batchController(t *testing.T) *Controller {
	c := testController(t)
	run := c.Run
	writeTestFile(t, c, "/etc/ufw/user.rules", "ufw allow 46961/tcp\nufw allow 9443/tcp\nufw allow 8080/tcp\nufw allow 8081/udp\n")
	c.Run = func(ctx context.Context, n string, a []string, input string) (string, error) {
		args := strings.Join(a, " ")
		if n == "ufw" && args == "show added" {
			b, e := c.read("/etc/ufw/user.rules")
			return string(b), e
		}
		if n == "ufw" && len(a) > 2 && a[0] == "--force" && a[1] == "delete" {
			b, e := c.read("/etc/ufw/user.rules")
			if e != nil {
				return "", e
			}
			line := "ufw " + strings.Join(a[2:], " ") + "\n"
			return "", atomic(c.path("/etc/ufw/user.rules"), []byte(strings.ReplaceAll(string(b), line, "")), 0644)
		}
		return run(ctx, n, a, input)
	}
	return c
}
func batchIDs(t *testing.T, c *Controller) []string {
	t.Helper()
	f, e := c.Firewall(context.Background(), "")
	if e != nil {
		t.Fatal(e)
	}
	ids := []string{}
	for _, r := range f.Rules {
		if r.PortFrom == 8080 || r.PortFrom == 8081 {
			ids = append(ids, r.ID)
		}
	}
	if len(ids) != 2 {
		t.Fatal(f)
	}
	return ids
}
func batchApply(t *testing.T, c *Controller, r model.SecurityRequest) model.SecurityResult {
	t.Helper()
	ctx := context.Background()
	p, e := c.Preview(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	r.Revision = p.Revision
	result, e := c.Apply(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	return result
}
func TestFirewallBatchSelectionRejectsWholeInvalidSet(t *testing.T) {
	c := batchController(t)
	ctx := context.Background()
	ids := batchIDs(t, c)
	f, _ := c.Firewall(ctx, "")
	var ssh string
	for _, r := range f.Rules {
		if r.Protected {
			ssh = r.ID
			break
		}
	}
	for _, r := range []model.SecurityRequest{
		{Operation: "batch-adopt"},
		{Operation: "batch-adopt", RuleIDs: []string{ids[0], ids[0]}},
		{Operation: "batch-adopt", RuleID: ids[0], RuleIDs: ids},
		{Operation: "batch-adopt", RuleIDs: []string{ids[0], strings.Repeat("f", 32)}},
		{Operation: "batch-adopt", RuleIDs: []string{ids[0], "22;touch /tmp/invalid"}},
		{Operation: "adopt", RuleID: ids[0], RuleIDs: ids},
		{Operation: "batch-delete", RuleIDs: ids},
		{Operation: "batch-adopt", RuleIDs: make([]string, 101)},
	} {
		if _, e := c.Preview(ctx, "firewall", r); e == nil {
			t.Fatalf("accepted %+v", r)
		}
	}
	batchApply(t, c, model.SecurityRequest{Operation: "batch-adopt", RuleIDs: append(ids, ssh)})
	for _, op := range []string{"batch-adopt", "batch-delete"} {
		if _, e := c.Preview(ctx, "firewall", model.SecurityRequest{Operation: op, RuleIDs: []string{ids[0], ssh}}); e == nil {
			t.Fatal("managed/protected set accepted")
		}
	}
	complex := []model.SecurityRule{{ID: ids[0], Adoptable: false}, {ID: ids[1], Adoptable: true}}
	if _, e := selectedFirewallRules(model.SecurityRequest{Operation: "batch-adopt", RuleIDs: ids}, complex); e == nil {
		t.Fatal("complex rule accepted")
	}
}
func TestFirewallBatchAdoptDeleteAndReplay(t *testing.T) {
	c := batchController(t)
	ctx := context.Background()
	ids := batchIDs(t, c)
	before, _ := c.read("/etc/ufw/user.rules")
	r := model.SecurityRequest{Operation: "batch-adopt", RuleIDs: ids}
	p, e := c.Preview(ctx, "firewall", r)
	if e != nil || len(p.Changes) != 2 || p.NeedsConfirmation {
		t.Fatalf("%+v %v", p, e)
	}
	r.Revision = p.Revision
	v, e := c.Apply(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	after, _ := c.read("/etc/ufw/user.rules")
	if string(before) != string(after) {
		t.Fatal("adoption rewrote firewall")
	}
	if _, e = c.Apply(ctx, "firewall", r); e == nil {
		t.Fatal("duplicate adoption accepted")
	}
	if len(v.Firewall.Rules) != 4 {
		t.Fatal(v)
	}
	v = batchApply(t, c, model.SecurityRequest{Operation: "batch-delete", RuleIDs: ids})
	if v.Transaction.Status != "awaiting-confirmation" || len(v.Firewall.Rules) != 2 {
		t.Fatal(v)
	}
	if _, e = c.Confirm(ctx, v.Transaction.ID); e != nil {
		t.Fatal(e)
	}
	if _, e = c.Preview(ctx, "firewall", model.SecurityRequest{Operation: "batch-delete", RuleIDs: ids}); e == nil {
		t.Fatal("deleted set replayed")
	}
}
func TestFirewallBatchDeleteRollbackAndStaleState(t *testing.T) {
	for _, mode := range []string{"second-failure", "no-effect", "timeout", "arm-failure", "stale"} {
		t.Run(mode, func(t *testing.T) {
			c := batchController(t)
			ctx := context.Background()
			ids := batchIDs(t, c)
			batchApply(t, c, model.SecurityRequest{Operation: "batch-adopt", RuleIDs: ids})
			// Newly created panel rules use random IDs, unlike externally adopted rules.
			if mode == "no-effect" {
				s, _ := c.state()
				for i := range s.Rules {
					s.Rules[i].ID = token()
				}
				if e := c.save("state.json", s); e != nil {
					t.Fatal(e)
				}
				ids = batchIDs(t, c)
			}
			before, _ := c.read("/etc/ufw/user.rules")
			stateBefore, _ := c.state()
			r := model.SecurityRequest{Operation: "batch-delete", RuleIDs: ids}
			p, e := c.Preview(ctx, "firewall", r)
			if e != nil {
				t.Fatal(e)
			}
			r.Revision = p.Revision
			calls := 0
			run := c.Run
			c.Run = func(ctx context.Context, n string, a []string, input string) (string, error) {
				if n == "ufw" && len(a) > 1 && a[0] == "--force" && a[1] == "delete" {
					calls++
					if mode == "no-effect" {
						return "", nil
					}
					out, e := run(ctx, n, a, input)
					if mode == "second-failure" && calls == 2 {
						return out, errors.New("injected after second delete")
					}
					return out, e
				}
				return run(ctx, n, a, input)
			}
			if mode == "arm-failure" {
				c.Arm = func(context.Context) error { return errors.New("recovery unavailable") }
			}
			if mode == "stale" {
				writeTestFile(t, c, "/etc/ufw/user6.rules", "external modification")
			}
			v, e := c.Apply(ctx, "firewall", r)
			if mode == "timeout" {
				if e != nil {
					t.Fatal(e)
				}
				c.Now = func() time.Time { return v.Transaction.Deadline.Add(time.Second) }
				if e = c.Recover(ctx); e != nil {
					t.Fatal(e)
				}
			} else if e == nil {
				t.Fatal("failure accepted")
			}
			if (mode == "arm-failure" || mode == "stale") && calls != 0 {
				t.Fatal("mutated before validation/recovery")
			}
			after, _ := c.read("/etc/ufw/user.rules")
			stateAfter, _ := c.state()
			if string(before) != string(after) || !reflect.DeepEqual(stateBefore, stateAfter) {
				t.Fatalf("partial restoration: %s %+v", after, stateAfter)
			}
		})
	}
}

func TestFirewallBatchExternalEditDuringBackupIsNotOverwritten(t *testing.T) {
	c := batchController(t)
	ctx := context.Background()
	ids := batchIDs(t, c)
	batchApply(t, c, model.SecurityRequest{Operation: "batch-adopt", RuleIDs: ids})
	r := model.SecurityRequest{Operation: "batch-delete", RuleIDs: ids}
	p, e := c.Preview(ctx, "firewall", r)
	if e != nil {
		t.Fatal(e)
	}
	r.Revision = p.Revision
	b, _ := c.read("/etc/ufw/user.rules")
	external := string(b) + "ufw allow 8090/tcp\n"
	c.Arm = func(context.Context) error { return atomic(c.path("/etc/ufw/user.rules"), []byte(external), 0644) }
	if _, e = c.Apply(ctx, "firewall", r); e == nil || !strings.Contains(e.Error(), "状态已变化") {
		t.Fatal(e)
	}
	actual, _ := c.read("/etc/ufw/user.rules")
	if string(actual) != external || c.pending() != nil {
		t.Fatal("overwrote external edit or armed change")
	}
}
