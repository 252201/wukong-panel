package singboxconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilities(t *testing.T) {
	if CapabilitiesFor("1.10.7").RuleActions || !CapabilitiesFor("1.13.14").NoLegacyInbound || CapabilitiesFor("1.13.14").NoLegacyDNS {
		t.Fatal("version capabilities are incorrect")
	}
}

func TestMigrateHY2LegacyConfiguration(t *testing.T) {
	input := `{
  "inbounds": [{"type":"hysteria2","listen":"::","listen_port":443,"sniff":true,"sniff_override_destination":true}],
  "outbounds": [
    {"type":"direct","tag":"direct","domain_strategy":"prefer_ipv6","bind_interface":"tun0"},
    {"type":"block","tag":"block"}
  ],
  "route": {"rules":[{"domain_suffix":["example.com"],"outbound":"block"}],"final":"direct"},
  "unknown_extension":{"keep":true}
}`
	output, plan, err := Migrate([]byte(input), "1.13.14", "test.json")
	if err != nil || len(plan.Errors) != 0 || len(plan.Changes) < 5 {
		t.Fatalf("migration failed: err=%v plan=%+v", err, plan)
	}
	text := string(output)
	for _, removed := range []string{`"sniff":`, `"sniff_override_destination":`, `"domain_strategy":`, `"type": "block"`} {
		if strings.Contains(text, removed) {
			t.Fatalf("legacy field remains: %s\n%s", removed, text)
		}
	}
	for _, required := range []string{`"action": "sniff"`, `"action": "reject"`, `"domain_resolver"`, `"unknown_extension"`} {
		if !strings.Contains(text, required) {
			t.Fatalf("migrated field missing: %s\n%s", required, text)
		}
	}
	if len(plan.Interfaces) != 1 || plan.Interfaces[0] != "tun0" {
		t.Fatalf("interface references not reported: %+v", plan.Interfaces)
	}
	var root map[string]any
	if json.Unmarshal(output, &root) != nil {
		t.Fatal("migration emitted invalid JSON")
	}
}

func TestMigrateTUNAndRejectWireGuard(t *testing.T) {
	input := `{"inbounds":[{"type":"tun","inet4_address":"172.19.0.1/30","inet6_address":["fd00::1/126"],"gso":true}],"outbounds":[{"type":"wireguard","tag":"wg"}]}`
	output, plan, err := Migrate([]byte(input), "1.13.14", "tun.json")
	if err != nil || !strings.Contains(string(output), `"address"`) || len(plan.Errors) != 1 {
		t.Fatalf("unexpected result: err=%v plan=%+v output=%s", err, plan, output)
	}
}

func TestMigrationIsIdempotent(t *testing.T) {
	input := []byte(`{"inbounds":[{"type":"hysteria2","tag":"in"}],"outbounds":[{"type":"direct","tag":"direct","domain_resolver":{"server":"local","strategy":"prefer_ipv6"}}],"dns":{"servers":[{"type":"local","tag":"local"}]},"route":{"rules":[{"action":"sniff"}],"final":"direct"}}`)
	first, plan, err := Migrate(input, "1.13.14", "modern.json")
	if err != nil || len(plan.Changes) != 0 {
		t.Fatalf("modern config changed: err=%v plan=%+v", err, plan)
	}
	second, secondPlan, err := Migrate(first, "1.13.14", "modern.json")
	if err != nil || len(secondPlan.Changes) != 0 || string(first) != string(second) {
		t.Fatal("migration is not idempotent")
	}
}

func TestNoopDoesNotAddRoute(t *testing.T) {
	input := []byte(`{"inbounds":[{"type":"hysteria2","tag":"in"}],"outbounds":[{"type":"direct","tag":"direct"}]}`)
	output, plan, err := Migrate(input, "1.13.14", "noop.json")
	if err != nil || len(plan.Changes) != 0 || strings.Contains(string(output), `"route"`) {
		t.Fatalf("no-op migration added fields: err=%v plan=%+v output=%s", err, plan, output)
	}
}
