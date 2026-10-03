package hostsecurity

import (
	"context"
	"fmt"
	"reflect"
	"strings"
	"testing"

	"github.com/252201/wukong-panel/internal/model"
)

func legacyUFWFile(family, action string, ports ...int) string {
	any, chain, target := "0.0.0.0/0", "ufw-user-input", "ACCEPT"
	if family == "ipv6" {
		any, chain = "::/0", "ufw6-user-input"
	}
	if action == "deny" {
		target = "DROP"
	}
	body := "### RULES ###\n"
	for _, port := range ports {
		body += fmt.Sprintf("### tuple ### %s any %d %s any %s in\n", action, port, any, any)
		for _, proto := range []string{"tcp", "udp"} {
			body += fmt.Sprintf("-A %s -p %s --dport %d -j %s\n", chain, proto, port, target)
		}
	}
	return body + "### END RULES ###\n"
}

func TestUFWLegacyMixedFamilies(t *testing.T) {
	ports := []int{20100, 30100, 40100, 29999, 39999, 49999, 20102, 30102, 40102, 21967, 31967, 41967}
	added := "ufw allow 22/tcp\n"
	for _, port := range ports {
		added += fmt.Sprintf("ufw allow %d\n", port)
	}
	rules := reconcileUFW(added, legacyUFWFile("ipv4", "allow", ports...), legacyUFWFile("ipv6", "allow", ports[:3]...))
	if len(rules) != 13 {
		t.Fatal(rules)
	}
	for index, r := range rules[1:] {
		want := []string{"ipv4"}
		if index < 3 {
			want = append(want, "ipv6")
		}
		if !r.Adoptable || r.Action != "allow" || r.Protocol != "tcp/udp" || !reflect.DeepEqual(r.AddressFamilies, want) {
			t.Fatalf("incorrect family or protocol: %+v, want %v", r, want)
		}
	}
}

func TestUFWLegacyRequiresCompleteNativeBlocks(t *testing.T) {
	good := legacyUFWFile("ipv4", "allow", 20100)
	for name, bad := range map[string]string{
		"missing":                 "",
		"missing udp":             strings.ReplaceAll(good, "-A ufw-user-input -p udp --dport 20100 -j ACCEPT\n", ""),
		"destination restriction": strings.ReplaceAll(good, "-p tcp --dport", "-d 192.0.2.1 -p tcp --dport"),
		"unexpected rule":         strings.ReplaceAll(good, "### END RULES ###", "-A ufw-user-input -j DROP\n### END RULES ###"),
		"duplicate":               strings.ReplaceAll(good, "### END RULES ###", strings.TrimPrefix(good, "### RULES ###\n")),
		"missing terminator":      strings.ReplaceAll(good, "### END RULES ###", ""),
		"interface tuple":         strings.ReplaceAll(good, "any 0.0.0.0/0 in", "any 0.0.0.0/0 in_eth0"),
	} {
		t.Run(name, func(t *testing.T) {
			r := reconcileUFW("ufw allow 20100", bad, "")[0]
			if r.Adoptable || r.Action != "" {
				t.Fatalf("accepted incomplete or complex block: %+v", r)
			}
		})
	}
	bad6 := strings.ReplaceAll(legacyUFWFile("ipv6", "allow", 20100), "-p udp", "-p icmpv6")
	if r := reconcileUFW("ufw allow 20100", good, bad6)[0]; r.Adoptable || r.Action != "" {
		t.Fatalf("ignored corrupt second family: %+v", r)
	}
	for _, input := range []string{"ufw allow 0", "ufw allow 65536", "ufw allow 20:30", "ufw allow 20100;touch /tmp/pwn", "ufw allow in on eth0 to any port 20100", "ufw route allow 20100"} {
		if r := reconcileUFW(input, good, "")[0]; r.Adoptable {
			t.Fatalf("accepted unsupported input: %+v", r)
		}
	}
}

func legacyUFWController(t *testing.T, action string, port int) *Controller {
	c := testController(t)
	base := c.Run
	c.Run = func(ctx context.Context, name string, args []string, input string) (string, error) {
		if name == "ufw" && strings.Join(args, " ") == "show added" {
			return fmt.Sprintf("ufw allow 46961/tcp\nufw allow 9443/tcp\nufw %s %d\n", action, port), nil
		}
		return base(ctx, name, args, input)
	}
	writeTestFile(t, c, "/etc/ufw/user.rules", legacyUFWFile("ipv4", action, port))
	writeTestFile(t, c, "/etc/ufw/user6.rules", legacyUFWFile("ipv6", action, port))
	return c
}

func TestUFWLegacyWritableAdoptionAndGroupedDeletion(t *testing.T) {
	c := legacyUFWController(t, "allow", 31967)
	ctx := context.Background()
	f, err := c.Firewall(ctx, "")
	if err != nil || !f.Writable {
		t.Fatalf("simple legacy rules blocked firewall: %+v, %v", f, err)
	}
	var legacy model.SecurityRule
	for _, r := range f.Rules {
		if r.Protocol == "tcp/udp" {
			legacy = r
		}
	}
	request := model.SecurityRequest{Operation: "adopt", RuleID: legacy.ID}
	preview, err := c.Preview(ctx, "firewall", request)
	if err != nil {
		t.Fatal(err)
	}
	request.Revision = preview.Revision
	if _, err = c.Apply(ctx, "firewall", request); err != nil {
		t.Fatal(err)
	}
	request.Operation = "delete"
	preview, err = c.Preview(ctx, "firewall", request)
	if err != nil || !preview.NeedsConfirmation || len(preview.Warnings) < 2 {
		t.Fatalf("missing grouped-delete confirmation: %+v, %v", preview, err)
	}
	if args := strings.Join(ufwArgs(legacy, true), " "); args != "--force delete allow 31967" {
		t.Fatalf("split a combined rule during deletion: %q", args)
	}
	if _, err = normalizeRule(model.SecurityRule{Action: "allow", Protocol: "tcp/udp", PortFrom: 31967}); err == nil {
		t.Fatal("new requests must still use explicit TCP or UDP")
	}
	add := model.SecurityRequest{Operation: "add", Rule: model.SecurityRule{Action: "deny", Protocol: "tcp", PortFrom: 31967, Source: "any"}}
	if _, err = c.Preview(ctx, "firewall", add); err == nil || !strings.Contains(err.Error(), "合并规则") {
		t.Fatalf("single-protocol replacement could silently remove UDP: %v", err)
	}
}

func TestUFWLegacyProtectsSSHAndRejectsChanges(t *testing.T) {
	ctx := context.Background()
	c := legacyUFWController(t, "allow", 46961)
	f, _ := c.Firewall(ctx, "")
	for _, rule := range f.Rules {
		if rule.Protocol == "tcp/udp" && !rule.Protected {
			t.Fatal("combined SSH rule was not protected")
		}
	}
	c = legacyUFWController(t, "deny", 46961)
	if _, err := c.Preview(ctx, "firewall", model.SecurityRequest{Operation: "enable"}); err == nil || !strings.Contains(err.Error(), "拒绝规则") {
		t.Fatalf("combined rule bypassed SSH protection: %v", err)
	}
	c = legacyUFWController(t, "allow", 31967)
	request := model.SecurityRequest{Operation: "enable"}
	preview, err := c.Preview(ctx, "firewall", request)
	if err != nil {
		t.Fatal(err)
	}
	request.Revision = preview.Revision
	writeTestFile(t, c, "/etc/ufw/user6.rules", "externally changed")
	if _, err = c.Apply(ctx, "firewall", request); err == nil {
		t.Fatal("overwrote externally changed legacy rules")
	}
}

func TestUFWLegacySingleFamilyCanAddMissingProtocolCoverage(t *testing.T) {
	c := legacyUFWController(t, "allow", 31967)
	writeTestFile(t, c, "/etc/ufw/user6.rules", "### RULES ###\n### END RULES ###\n")
	request := model.SecurityRequest{Operation: "add", Rule: model.SecurityRule{Action: "allow", Protocol: "udp", PortFrom: 31967, Source: "any"}}
	if _, err := c.Preview(context.Background(), "firewall", request); err != nil {
		t.Fatalf("IPv4-only combined rule blocked adding IPv6 coverage: %v", err)
	}
}
