package singboxconfig

import (
	"os"
	"strings"
	"testing"
)

func TestQW110RegressionSample(t *testing.T) {
	data, err := os.ReadFile("testdata/qw-1.10.json")
	if err != nil {
		t.Fatal(err)
	}
	output, plan, err := Migrate(data, "1.13.14", "qw-1.10.json")
	if err != nil || len(plan.Errors) != 0 || len(plan.Changes) != 5 {
		t.Fatalf("unexpected migration plan: err=%v plan=%+v", err, plan)
	}
	text := string(output)
	for _, required := range []string{`"action": "sniff"`, `"action": "reject"`, `"domain_resolver"`, `"bind_interface": "tun0"`} {
		if !strings.Contains(text, required) {
			t.Fatalf("missing %s", required)
		}
	}
}

func TestMultipleInboundsReceiveStableDistinctTags(t *testing.T) {
	input := []byte(`{"inbounds":[{"type":"hysteria2","sniff":true},{"type":"hysteria2","domain_strategy":"ipv6_only"}]}`)
	output, plan, err := Migrate(input, "1.13.14", "multi.json")
	if err != nil || len(plan.Errors) != 0 || !strings.Contains(string(output), `"wukong-in-1"`) || !strings.Contains(string(output), `"wukong-in-2"`) {
		t.Fatalf("multi inbound migration failed: err=%v plan=%+v output=%s", err, plan, output)
	}
}
