package singboxconfig

import (
	"encoding/json"
	"strings"
	"testing"
)

func TestCapabilities(t *testing.T) {
	if CapabilitiesFor("1.10.7").RuleActions || !CapabilitiesFor("1.13.14").NoLegacyInbound || CapabilitiesFor("1.13.14").NoLegacyDNS || !CapabilitiesFor(LatestSupportedVersion).NoLegacyDNS {
		t.Fatal("version capabilities are incorrect")
	}
}

func TestMigrateLegacyDNSServersToModernFormats(t *testing.T) {
	input := []byte(`{
  "dns": {
    "servers": [
      {"address":"1.1.1.1","strategy":"ipv4_only"},
      {"address":"local","tag":"local"},
      {"tag":"google","address":"https://dns.google/dns-query","address_resolver":"local","strategy":"prefer_ipv6","client_subnet":"1.1.1.1"},
      {"address":"fakeip","tag":"fakeip"}
    ],
    "rules": [{"domain":["google.com"],"server":"google"}],
    "fakeip": {"enabled":true,"inet4_range":"198.18.0.0/15","inet6_range":"fc00::/18"}
  }
}`)
	output, plan, err := Migrate(input, LatestSupportedVersion, "dns.json")
	if err != nil || len(plan.Errors) != 0 || len(plan.Changes) == 0 {
		t.Fatalf("legacy DNS migration failed: err=%v plan=%+v output=%s", err, plan, output)
	}
	var root map[string]any
	if err = json.Unmarshal(output, &root); err != nil {
		t.Fatal(err)
	}
	dns := root["dns"].(map[string]any)
	if _, exists := dns["fakeip"]; exists {
		t.Fatalf("legacy fakeip wrapper remains: %s", output)
	}
	if dns["strategy"] != "ipv4_only" {
		t.Fatalf("default DNS strategy was not preserved: %#v", dns["strategy"])
	}
	servers := dns["servers"].([]any)
	if len(servers) != 4 {
		t.Fatalf("unexpected migrated server count: %#v", servers)
	}
	for index, item := range servers {
		server := item.(map[string]any)
		if _, exists := server["address"]; exists {
			t.Fatalf("legacy address remains in server %d: %#v", index, server)
		}
	}
	google := servers[2].(map[string]any)
	if google["type"] != "https" || google["server"] != "dns.google" || google["domain_resolver"] != "local" || google["inet4_range"] != nil {
		t.Fatalf("HTTPS DNS server was not migrated correctly: %#v", google)
	}
	fakeIP := servers[3].(map[string]any)
	if fakeIP["type"] != "fakeip" || fakeIP["inet4_range"] != "198.18.0.0/15" || fakeIP["inet6_range"] != "fc00::/18" {
		t.Fatalf("FakeIP server was not migrated correctly: %#v", fakeIP)
	}
	rules := dns["rules"].([]any)
	googleRule := rules[0].(map[string]any)
	if googleRule["strategy"] != "prefer_ipv6" || googleRule["client_subnet"] != "1.1.1.1" {
		t.Fatalf("tagged DNS server options were not moved to its rule: %#v", googleRule)
	}
	second, secondPlan, secondErr := Migrate(output, LatestSupportedVersion, "dns.json")
	if secondErr != nil || len(secondPlan.Changes) != 0 || string(second) != string(output) {
		t.Fatalf("DNS migration is not idempotent: err=%v plan=%+v\n%s\n%s", secondErr, secondPlan, output, second)
	}
}

func TestMigrateLegacyDNSRCodeServer(t *testing.T) {
	input := []byte(`{
  "dns": {
    "servers": [{"address":"rcode://refused","tag":"blocked"}],
    "rules": [{"domain":["ads.example"],"server":"blocked"}],
    "final": "blocked"
  }
}`)
	output, plan, err := Migrate(input, LatestSupportedVersion, "rcode.json")
	if err != nil || len(plan.Errors) != 0 {
		t.Fatalf("RCode migration failed: err=%v plan=%+v output=%s", err, plan, output)
	}
	var root map[string]any
	if err = json.Unmarshal(output, &root); err != nil {
		t.Fatal(err)
	}
	dns := root["dns"].(map[string]any)
	if len(dns["servers"].([]any)) != 0 {
		t.Fatalf("RCode server was not removed: %s", output)
	}
	if _, exists := dns["final"]; exists {
		t.Fatalf("RCode final reference remains: %s", output)
	}
	rules := dns["rules"].([]any)
	if len(rules) != 2 {
		t.Fatalf("default RCode rule was not added: %#v", rules)
	}
	for _, item := range rules {
		rule := item.(map[string]any)
		if rule["action"] != "predefined" || rule["rcode"] != "REFUSED" {
			t.Fatalf("unexpected RCode rule: %#v", rule)
		}
		if _, exists := rule["server"]; exists {
			t.Fatalf("RCode rule still references removed server: %#v", rule)
		}
	}
}

func TestMigrateSingBox14DNSCacheFields(t *testing.T) {
	input := []byte(`{
  "dns": {"servers":[{"type":"local","tag":"local"}],"independent_cache":true},
  "experimental": {"cache_file":{"enabled":true,"store_rdrc":true,"rdrc_timeout":"7d"}}
}`)
	output, plan, err := Migrate(input, LatestSupportedVersion, "cache.json")
	if err != nil || len(plan.Errors) != 0 {
		t.Fatalf("1.14 DNS cache migration failed: err=%v plan=%+v output=%s", err, plan, output)
	}
	text := string(output)
	for _, removed := range []string{"independent_cache", "store_rdrc", "rdrc_timeout"} {
		if strings.Contains(text, `"`+removed+`"`) {
			t.Fatalf("obsolete cache field remains: %s\n%s", removed, text)
		}
	}
	if !strings.Contains(text, `"store_dns": true`) {
		t.Fatalf("store_rdrc was not migrated to store_dns: %s", text)
	}
}

func TestPlanBlocksSingBox14LegacyDNSFilters(t *testing.T) {
	input := []byte(`{
  "dns": {
    "servers": [{"type":"local","tag":"local"}],
    "rules": [{"ip_cidr":["192.0.2.0/24"]},{"query_type":["AAAA"],"strategy":"prefer_ipv6"}]
  }
}`)
	_, plan, err := Migrate(input, LatestSupportedVersion, "filters.json")
	if err != nil || len(plan.Errors) < 2 {
		t.Fatalf("unsafe 1.14 DNS filters were not blocked: err=%v plan=%+v", err, plan)
	}
	if !strings.Contains(strings.Join(plan.Errors, "\n"), "match_response") {
		t.Fatalf("legacy address filter error does not explain the safe migration: %+v", plan.Errors)
	}
}

func TestPlanBlocksUnknownHTTPClientsField(t *testing.T) {
	_, plan, err := Migrate([]byte(`{"http_clients":{},"inbounds":[],"outbounds":[]}`), LatestSupportedVersion, "http-clients.json")
	if err != nil || len(plan.Errors) != 1 || !strings.Contains(plan.Errors[0], "http_clients") {
		t.Fatalf("unknown http_clients field was not blocked: err=%v plan=%+v", err, plan)
	}
}

func TestPlanBlocksInvalidDNSRootAndRemovedOutboundRule(t *testing.T) {
	_, invalidRoot, err := Migrate([]byte(`{"dns":[]}`), LatestSupportedVersion, "invalid-dns.json")
	if err != nil || len(invalidRoot.Errors) != 1 || !strings.Contains(invalidRoot.Errors[0], "dns must be an object") {
		t.Fatalf("invalid DNS root was not blocked: err=%v plan=%+v", err, invalidRoot)
	}
	input := []byte(`{
  "dns": {
    "servers": [{"type":"local","tag":"local"}],
    "rules": [{"type":"logical","rules":[{"outbound":"any"}]}]
  }
}`)
	_, plan, err := Migrate(input, LatestSupportedVersion, "outbound-rule.json")
	if err != nil || len(plan.Errors) != 1 || !strings.Contains(plan.Errors[0], "outbound matching") {
		t.Fatalf("removed DNS outbound rule was not blocked: err=%v plan=%+v", err, plan)
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

func TestMigrationPlanJSONUsesEmptyArraysInsteadOfNull(t *testing.T) {
	_, filePlan, err := Migrate([]byte(`{"inbounds":[],"outbounds":[],"route":{"rules":[]}}`), "1.13.14", "noop.json")
	if err != nil {
		t.Fatal(err)
	}
	data, err := json.Marshal(Plan{Target: "1.13.14", Compatible: true, Files: []FilePlan{filePlan}})
	if err != nil {
		t.Fatal(err)
	}
	text := string(data)
	for _, field := range []string{`"changes":null`, `"warnings":null`, `"errors":null`} {
		if strings.Contains(text, field) {
			t.Fatalf("migration plan contains nullable collection %s: %s", field, text)
		}
	}
}
