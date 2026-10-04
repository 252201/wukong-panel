package hostsecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func TestFail2banBatchMatchesCLIAndKeepsFreshCollections(t *testing.T) {
	c := testController(t)
	c.Lookup = func(string) bool { return true }
	version, batches, queries := 1, 0, 0
	response := func(q []string) string {
		switch q[len(q)-1] {
		case "maxretry":
			return "5"
		case "findtime":
			return "600"
		case "bantime":
			return fmt.Sprint(3600 * version)
		case "ignoreip":
			return "127.0.0.1/8 ::1"
		case "actions":
			return "iptables-multiport wk-ssh-9443"
		default:
			return strings.Join(q, " ")
		}
	}
	c.Run = func(_ context.Context, name string, args []string, input string) (string, error) {
		if name == "python3" {
			batches++
			var commands [][]string
			if err := json.Unmarshal([]byte(input), &commands); err != nil {
				t.Fatal(err)
			}
			replies := []fail2banReply{}
			for _, q := range commands {
				replies = append(replies, fail2banReply{q, response(q), true})
				if q[len(q)-1] == "actions" {
					for _, a := range []string{"iptables-multiport", "wk-ssh-9443"} {
						for _, field := range []string{"actionstart", "actionban"} {
							query := []string{"get", "sshd", "action", a, field}
							replies = append(replies, fail2banReply{query, response(query), true})
						}
					}
				}
			}
			out, _ := json.Marshal(replies)
			return string(out), nil
		}
		queries++
		return response(args), nil
	}
	ctx := context.Background()
	r := newFail2banReader(c)
	r.prefetch(ctx, fail2banJailReads("sshd"))
	before, err := r.effectiveConfig(ctx, "sshd")
	if err != nil || before.BanTime != 3600 {
		t.Fatalf("%+v %v", before, err)
	}
	batchHash, err := r.actionHash(ctx, "sshd")
	if err != nil || batches != 1 || queries != 0 {
		t.Fatalf("batches=%d CLI=%d error=%v", batches, queries, err)
	}
	// The old CLI path produces the identical ownership fingerprint.
	fallback := newFail2banReader(c)
	cliHash, err := fallback.actionHash(ctx, "sshd")
	if err != nil || cliHash != batchHash {
		t.Fatalf("hash changed: %s %s %v", cliHash, batchHash, err)
	}
	version = 2
	after, err := c.effectiveConfig(ctx, "sshd")
	if err != nil || after.BanTime != 7200 || batches != 2 {
		t.Fatalf("stale settings: %+v %v", after, err)
	}
	canceled, cancel := context.WithCancel(ctx)
	cancel()
	if _, err := r.exec(canceled, "get", "sshd", "bantime"); !errors.Is(err, context.Canceled) {
		t.Fatal(err)
	}
}

func TestFail2banBatchFallbackPreservesFailures(t *testing.T) {
	for _, mode := range []string{"missing-module", "invalid-json", "failed-field", "unexpected-command"} {
		t.Run(mode, func(t *testing.T) {
			c := testController(t)
			c.Lookup = func(string) bool { return true }
			c.Run = func(_ context.Context, name string, args []string, _ string) (string, error) {
				if name == "python3" {
					switch mode {
					case "missing-module":
						return "", errors.New("module unavailable")
					case "invalid-json":
						return "invalid", nil
					case "failed-field":
						return `[{"args":["get","sshd","maxretry"],"ok":false,"output":"5"}]`, nil
					default:
						return `[{"args":["get","other","maxretry"],"ok":true,"output":"5"}]`, nil
					}
				}
				return "", errors.New("actual setting unavailable")
			}
			if _, err := c.effectiveConfig(context.Background(), "sshd"); err == nil || !strings.Contains(err.Error(), "actual setting unavailable") {
				t.Fatal(err)
			}
		})
	}
}

func TestVerifiedFail2banResultOnlyIgnoresItsOwnPendingTransaction(t *testing.T) {
	f := newManualBanFixture(t)
	ctx := context.Background()
	id := strings.Repeat("a", 32)
	if err := f.c.save("pending.json", journal{Transaction: model.SecurityTransaction{ID: id}}); err != nil {
		t.Fatal(err)
	}
	for _, own := range []string{"", strings.Repeat("b", 32), id} {
		state, err := f.c.fail2ban(ctx, own)
		if err != nil || state.Writable != (own == id) {
			t.Fatalf("transaction=%q writable=%t reason=%s error=%v", own, state.Writable, state.Reason, err)
		}
	}
	// Suppressing the self-pending marker cannot hide an unrelated config drift.
	f.duration = 7200
	state, err := f.c.fail2ban(ctx, id)
	if err != nil || state.Writable || !strings.Contains(state.Reason, "外部修改") {
		t.Fatalf("%+v %v", state, err)
	}
}

func TestFail2banApplyReturnsUsableVerifiedState(t *testing.T) {
	f := newManualBanFixture(t)
	request := model.SecurityRequest{Operation: "ban", IP: "8.8.8.8", Jail: "wukong-sshd"}
	preview, err := f.c.Preview(context.Background(), "fail2ban", request)
	if err != nil {
		t.Fatal(err)
	}
	request.Revision = preview.Revision
	result, err := f.c.Apply(context.Background(), "fail2ban", request)
	if err != nil || result.Fail2ban == nil || !result.Fail2ban.Writable || result.Transaction.Status != "confirmed" || f.c.pending() != nil {
		t.Fatalf("%+v %v", result, err)
	}
}
