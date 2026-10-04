package hostsecurity

import (
	"context"
	"encoding/json"
	"fmt"
	"github.com/252201/wukong-panel/internal/model"
	"os"
	"strings"
	"testing"
	"time"
)

func foundLine(jail, ip string, at time.Time) string {
	return fmt.Sprintf("%s,123 fail2ban.filter [123]: INFO [%s] Found %s - %s", at.Format("2006-01-02 15:04:05"), jail, ip, at.Format("2006-01-02 15:04:05"))
}
func TestFailureSourcesAggregateOnlyRecognizedJailRecords(t *testing.T) {
	now := time.Now().In(time.Local).Truncate(time.Second)
	first := foundLine("wukong-sshd", "8.8.8.8", now.Add(-time.Minute))
	entries := []failureEntry{{message: first}, {message: first}, {message: foundLine("wukong-sshd", "::ffff:8.8.8.8", now)},
		{message: foundLine("wukong-sshd", "2001:4860:4860::8888", now.Add(-30*time.Second))},
		{message: foundLine("other-sshd", "9.9.9.9", now)},
		{message: foundLine("wukong-sshd", "9.9.9.9", now.Add(-25*time.Hour))},
		{message: foundLine("wukong-sshd", "1.1.1.1", now.Add(time.Hour))},
		{message: foundLine("wukong-sshd", "8.8.8.8;touch", now)},
		{message: strings.Replace(first, "Found", "Ignore", 1)},
		{message: "sshd[123]: username injected " + first},
		{message: strings.Replace(first, "INFO", "ERROR", 1)},
	}
	sources, limited := aggregateFailures(entries, "wukong-sshd", now.Add(-24*time.Hour), now)
	if limited || len(sources) != 2 || sources[0].IP != "8.8.8.8" || sources[0].Count != 2 || !sources[0].LastSeen.Equal(now) {
		t.Fatalf("sources %+v limited %v", sources, limited)
	}
}
func TestFailureSourcesBoundsAndJailIsolation(t *testing.T) {
	now := time.Now().In(time.Local).Truncate(time.Second)
	entries := []failureEntry{}
	for i := 1; i <= 75; i++ {
		entries = append(entries, failureEntry{message: foundLine("sshd", fmt.Sprintf("8.8.8.%d", i), now.Add(time.Duration(-i)*time.Second))})
	}
	sources, limited := aggregateFailures(entries, "sshd", now.Add(-24*time.Hour), now)
	if !limited || len(sources) != 50 || sources[0].IP != "8.8.8.1" {
		t.Fatalf("%+v %v", sources, limited)
	}
	other, _ := aggregateFailures(entries, "other", now.Add(-24*time.Hour), now)
	if len(other) != 0 {
		t.Fatal("jail data leaked")
	}
}
func TestFailureSourcesFileRotationAndUnsupportedTarget(t *testing.T) {
	c := testController(t)
	now := time.Now().In(time.Local).Truncate(time.Second)
	c.Now = func() time.Time { return now }
	c.Run = func(_ context.Context, name string, args []string, _ string) (string, error) {
		return "Current logging target is:\n`- /var/log/fail2ban.log", nil
	}
	writeTestFile(t, c, "/var/log/fail2ban.log.1", foundLine("wukong-sshd", "8.8.8.8", now.Add(-time.Minute))+"\n")
	writeTestFile(t, c, "/var/log/fail2ban.log", foundLine("wukong-sshd", "8.8.8.8", now)+"\n")
	state := model.Fail2banState{Active: true, Jails: []model.SSHJail{{Name: "wukong-sshd"}}}
	c.failureSources(context.Background(), &state)
	if !state.FailureSourcesAvailable || state.Jails[0].Failures[0].Count != 2 {
		t.Fatalf("%+v", state)
	}
	c.Run = func(context.Context, string, []string, string) (string, error) { return "/etc/shadow", nil }
	state = model.Fail2banState{Active: true, Jails: []model.SSHJail{{Name: "wukong-sshd"}}}
	c.failureSources(context.Background(), &state)
	if state.FailureSourcesAvailable || state.FailureSourcesReason == "" {
		t.Fatal("unsupported path looked like an empty successful sample")
	}
}
func TestFailureLogTailLimitAndRejectSymlink(t *testing.T) {
	c := testController(t)
	now := time.Now().In(time.Local).Truncate(time.Second)
	line := foundLine("sshd", "8.8.8.8", now)
	writeTestFile(t, c, "/var/log/fail2ban.log", strings.Repeat("x", failureLogLimit)+"\n"+line+"\n")
	data, limited, err := c.failureLogTail("/var/log/fail2ban.log")
	if err != nil || !limited || !strings.Contains(string(data), line) || len(data) > failureLogLimit {
		t.Fatalf("tail %d %v %v", len(data), limited, err)
	}
	if err = os.Symlink(c.path("/var/log/fail2ban.log"), c.path("/var/log/fail2ban.log.1")); err != nil {
		t.Fatal(err)
	}
	if _, _, err = c.failureLogTail("/var/log/fail2ban.log.1"); err == nil {
		t.Fatal("followed symlink")
	}
}
func TestFailureSourcesJournalAndMissingLog(t *testing.T) {
	c := testController(t)
	now := time.Now().In(time.Local).Truncate(time.Second)
	c.Now = func() time.Time { return now }
	if err := os.MkdirAll(c.path("/run/systemd/system"), 0700); err != nil {
		t.Fatal(err)
	}
	c.Lookup = func(name string) bool { return name == "journalctl" }
	c.Run = func(_ context.Context, name string, args []string, _ string) (string, error) {
		if name == "fail2ban-client" {
			return "STDOUT", nil
		}
		row, _ := json.Marshal(map[string]string{"MESSAGE": foundLine("sshd", "8.8.8.8", now), "__REALTIME_TIMESTAMP": fmt.Sprint(now.UnixMicro())})
		return string(row), nil
	}
	state := model.Fail2banState{Active: true, Jails: []model.SSHJail{{Name: "sshd"}}}
	c.failureSources(context.Background(), &state)
	if !state.FailureSourcesAvailable || len(state.Jails[0].Failures) != 1 {
		t.Fatalf("%+v", state)
	}
	c.Run = func(context.Context, string, []string, string) (string, error) { return "/var/log/fail2ban.log", nil }
	state = model.Fail2banState{Active: true, Jails: []model.SSHJail{{Name: "sshd"}}}
	c.failureSources(context.Background(), &state)
	if state.FailureSourcesAvailable || state.FailureSourcesReason == "" {
		t.Fatal("missing log looked successful")
	}
}
