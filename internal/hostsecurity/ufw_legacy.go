package hostsecurity

import (
	"fmt"
	"strings"

	"github.com/252201/wukong-panel/internal/model"
)

func ruleProtocolMatches(rule model.SecurityRule, protocol string) bool {
	return rule.Protocol == protocol || (rule.Protocol == "tcp/udp" && (protocol == "tcp" || protocol == "udp"))
}

// show added deduplicates address families. Verify legacy protocol-less rules
// against their complete persisted blocks before permitting adoption or writes.
func reconcileUFW(added, ipv4, ipv6 string) []model.SecurityRule {
	rules := parseUFW(added)
	for i := range rules {
		r := &rules[i]
		if r.Protocol != "tcp/udp" {
			continue
		}
		valid := true
		for _, file := range []struct{ family, body string }{{"ipv4", ipv4}, {"ipv6", ipv6}} {
			found, complete := ufwLegacyBlock(file.body, file.family, *r)
			if !complete {
				valid = false
			}
			if found {
				r.AddressFamilies = append(r.AddressFamilies, file.family)
			}
		}
		if !valid || len(r.AddressFamilies) == 0 {
			action := r.Action
			r.Action = ""
			r.Adoptable = false
			r.Description = fmt.Sprintf("ufw %s %d", action, r.PortFrom)
		}
	}
	return rules
}

func ufwLegacyBlock(body, family string, rule model.SecurityRule) (bool, bool) {
	any, chain := "0.0.0.0/0", "ufw-user-input"
	if family == "ipv6" {
		any, chain = "::/0", "ufw6-user-input"
	}
	header := fmt.Sprintf("### tuple ### %s any %d %s any %s in", rule.Action, rule.PortFrom, any, any)
	target := "ACCEPT"
	if rule.Action == "deny" {
		target = "DROP"
	}
	expected := map[string]bool{}
	for _, proto := range []string{"tcp", "udp"} {
		expected[fmt.Sprintf("-A %s -p %s --dport %d -j %s", chain, proto, rule.PortFrom, target)] = true
	}
	inRules, capture, found, valid := false, false, false, true
	seen := map[string]bool{}
	finish := func() {
		if capture && len(seen) != 2 {
			valid = false
		}
		capture = false
	}
	for _, line := range strings.Split(body, "\n") {
		line = strings.TrimSpace(line)
		if line == "### RULES ###" {
			inRules = true
			continue
		}
		if line == "### END RULES ###" {
			finish()
			inRules = false
			continue
		}
		if !inRules || line == "" {
			continue
		}
		if strings.HasPrefix(line, "### tuple ###") {
			finish()
			if strings.HasPrefix(line, header+" ") {
				valid = false
			}
			if line == header {
				if found {
					valid = false
				}
				found, capture = true, true
				seen = map[string]bool{}
			}
			continue
		}
		if capture {
			if !expected[line] || seen[line] {
				valid = false
			}
			seen[line] = true
		}
	}
	finish()
	if found && inRules {
		valid = false
	}
	return found, valid
}
