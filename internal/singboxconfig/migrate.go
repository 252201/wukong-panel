package singboxconfig

import (
	"encoding/json"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"sort"
	"strconv"
	"strings"
)

type Capabilities struct {
	Version         string `json:"version"`
	RuleActions     bool   `json:"ruleActions"`
	NewDNSServers   bool   `json:"newDnsServers"`
	NoLegacyInbound bool   `json:"noLegacyInbound"`
	NoLegacyDNS     bool   `json:"noLegacyDns"`
}

type FilePlan struct {
	Path       string   `json:"path"`
	Changes    []string `json:"changes"`
	Warnings   []string `json:"warnings"`
	Errors     []string `json:"errors"`
	Interfaces []string `json:"interfaces,omitempty"`
}

type Plan struct {
	Target            string     `json:"target"`
	Compatible        bool       `json:"compatible"`
	RequiresMigration bool       `json:"requiresMigration"`
	Files             []FilePlan `json:"files"`
	Changes           int        `json:"changes"`
	Warnings          int        `json:"warnings"`
	Errors            int        `json:"errors"`
}

func newFilePlan(path string) FilePlan {
	return FilePlan{Path: path, Changes: []string{}, Warnings: []string{}, Errors: []string{}, Interfaces: []string{}}
}

func CapabilitiesFor(version string) Capabilities {
	major, minor := parseVersion(version)
	atLeast := func(wantMajor, wantMinor int) bool {
		return major > wantMajor || major == wantMajor && minor >= wantMinor
	}
	return Capabilities{Version: strings.TrimPrefix(version, "v"), RuleActions: atLeast(1, 11), NewDNSServers: atLeast(1, 12), NoLegacyInbound: atLeast(1, 13), NoLegacyDNS: atLeast(1, 14)}
}

func parseVersion(version string) (int, int) {
	parts := strings.Split(strings.TrimPrefix(version, "v"), ".")
	if len(parts) < 2 {
		return 0, 0
	}
	major, _ := strconv.Atoi(parts[0])
	minor, _ := strconv.Atoi(parts[1])
	return major, minor
}

func PlanDirectory(dir, target string) (Plan, error) {
	files, err := filepath.Glob(filepath.Join(dir, "*.json"))
	if err != nil {
		return Plan{}, err
	}
	plan := Plan{Target: strings.TrimPrefix(target, "v"), Compatible: true, Files: []FilePlan{}}
	for _, path := range files {
		data, readErr := os.ReadFile(path)
		filePlan := newFilePlan(path)
		if readErr != nil {
			filePlan.Errors = append(filePlan.Errors, readErr.Error())
		} else {
			_, filePlan, readErr = Migrate(data, target, path)
			if readErr != nil && len(filePlan.Errors) == 0 {
				filePlan.Errors = append(filePlan.Errors, readErr.Error())
			}
		}
		plan.Changes += len(filePlan.Changes)
		plan.Warnings += len(filePlan.Warnings)
		plan.Errors += len(filePlan.Errors)
		plan.Files = append(plan.Files, filePlan)
	}
	plan.RequiresMigration = plan.Changes > 0
	plan.Compatible = plan.Errors == 0
	return plan, nil
}

func MigrateDirectory(sourceDir, outputDir, target string) (Plan, error) {
	plan, err := PlanDirectory(sourceDir, target)
	if err != nil {
		return plan, err
	}
	if !plan.Compatible {
		return plan, errors.New("one or more sing-box configurations require manual migration")
	}
	if err = os.MkdirAll(outputDir, 0o700); err != nil {
		return plan, err
	}
	for _, file := range plan.Files {
		data, readErr := os.ReadFile(file.Path)
		if readErr != nil {
			return plan, readErr
		}
		migrated, _, migrateErr := Migrate(data, target, file.Path)
		if migrateErr != nil {
			return plan, migrateErr
		}
		if err = os.WriteFile(filepath.Join(outputDir, filepath.Base(file.Path)), migrated, 0o600); err != nil {
			return plan, err
		}
	}
	return plan, nil
}

func Migrate(data []byte, target, path string) ([]byte, FilePlan, error) {
	result := newFilePlan(path)
	var root map[string]any
	if err := json.Unmarshal(data, &root); err != nil {
		result.Errors = append(result.Errors, "invalid JSON: "+err.Error())
		return nil, result, err
	}
	major, minor := parseVersion(target)
	if major != 1 || minor < 10 {
		result.Errors = append(result.Errors, "unsupported target version "+target)
		return data, result, nil
	}
	caps := CapabilitiesFor(target)
	if !caps.NoLegacyInbound {
		result.Warnings = append(result.Warnings, "target does not require the 1.13 migration profile")
	}

	_, routeExisted := root["route"]
	route := object(root, "route")
	_, rulesExisted := route["rules"]
	rules := array(route, "rules")
	inbounds, _ := root["inbounds"].([]any)
	usedTags := map[string]bool{}
	for _, item := range inbounds {
		if inbound, ok := item.(map[string]any); ok {
			if tag, _ := inbound["tag"].(string); tag != "" {
				usedTags[tag] = true
			}
		}
	}
	preRules := []any{}
	for index, item := range inbounds {
		inbound, ok := item.(map[string]any)
		if !ok {
			continue
		}
		legacy := hasAny(inbound, "sniff", "sniff_override_destination", "sniff_timeout", "domain_strategy", "udp_disable_domain_unmapping")
		if legacy && caps.NoLegacyInbound {
			tag := stringValue(inbound["tag"])
			if tag == "" {
				tag = uniqueTag(fmt.Sprintf("wukong-in-%d", index+1), usedTags)
				inbound["tag"] = tag
				result.Changes = append(result.Changes, fmt.Sprintf("inbound %d: add stable tag %s", index+1, tag))
			}
			if strategy := stringValue(inbound["domain_strategy"]); strategy != "" {
				preRules = append(preRules, map[string]any{"inbound": tag, "action": "resolve", "strategy": strategy})
				result.Changes = append(result.Changes, fmt.Sprintf("%s: move domain_strategy to resolve rule action", tag))
			}
			sniff, _ := inbound["sniff"].(bool)
			override, _ := inbound["sniff_override_destination"].(bool)
			if sniff || override {
				action := map[string]any{"inbound": tag, "action": "sniff"}
				if timeout := stringValue(inbound["sniff_timeout"]); timeout != "" {
					action["timeout"] = timeout
				}
				preRules = append(preRules, action)
				result.Changes = append(result.Changes, fmt.Sprintf("%s: move sniff fields to sniff rule action", tag))
			}
			if disable, _ := inbound["udp_disable_domain_unmapping"].(bool); disable {
				preRules = append(preRules, map[string]any{"inbound": tag, "action": "route-options", "udp_disable_domain_unmapping": true})
				result.Changes = append(result.Changes, fmt.Sprintf("%s: move UDP domain unmapping option to route action", tag))
			}
			for _, field := range []string{"sniff", "sniff_override_destination", "sniff_timeout", "domain_strategy", "udp_disable_domain_unmapping"} {
				delete(inbound, field)
			}
		}
		if stringValue(inbound["type"]) == "tun" {
			mergeLegacyArray(inbound, "address", []string{"inet4_address", "inet6_address"}, &result)
			mergeLegacyArray(inbound, "route_address", []string{"inet4_route_address", "inet6_route_address"}, &result)
			mergeLegacyArray(inbound, "route_exclude_address", []string{"inet4_route_exclude_address", "inet6_route_exclude_address"}, &result)
			if _, exists := inbound["gso"]; exists {
				delete(inbound, "gso")
				result.Changes = append(result.Changes, "TUN inbound: remove obsolete gso option")
			}
		}
	}

	outbounds, _ := root["outbounds"].([]any)
	special := map[string]string{}
	directOptions := map[string]map[string]any{}
	kept := make([]any, 0, len(outbounds))
	needsResolver := false
	for _, item := range outbounds {
		outbound, ok := item.(map[string]any)
		if !ok {
			kept = append(kept, item)
			continue
		}
		typ, tag := stringValue(outbound["type"]), stringValue(outbound["tag"])
		if typ == "wireguard" && caps.NoLegacyInbound {
			result.Errors = append(result.Errors, fmt.Sprintf("WireGuard outbound %q requires manual endpoint migration", tag))
		}
		if (typ == "block" || typ == "dns") && caps.NoLegacyInbound {
			if tag == "" {
				result.Errors = append(result.Errors, fmt.Sprintf("untagged legacy %s outbound cannot be migrated safely", typ))
				kept = append(kept, item)
				continue
			}
			special[tag] = typ
			result.Changes = append(result.Changes, fmt.Sprintf("remove legacy %s outbound %s", typ, tag))
			continue
		}
		if typ == "direct" && caps.NoLegacyInbound && hasAny(outbound, "override_address", "override_port") {
			if tag == "" {
				result.Errors = append(result.Errors, "untagged direct outbound with destination override requires manual migration")
			} else {
				opts := map[string]any{}
				for _, key := range []string{"override_address", "override_port"} {
					if value, exists := outbound[key]; exists {
						opts[key] = value
						delete(outbound, key)
					}
				}
				directOptions[tag] = opts
				result.Changes = append(result.Changes, fmt.Sprintf("direct outbound %s: move destination override to route actions", tag))
			}
		}
		if strategy := stringValue(outbound["domain_strategy"]); strategy != "" && caps.NewDNSServers {
			outbound["domain_resolver"] = map[string]any{"server": "wukong-local", "strategy": strategy}
			delete(outbound, "domain_strategy")
			needsResolver = true
			result.Changes = append(result.Changes, fmt.Sprintf("outbound %s: migrate domain_strategy to domain_resolver", tag))
		}
		if iface := stringValue(outbound["bind_interface"]); iface != "" {
			result.Interfaces = append(result.Interfaces, iface)
		}
		kept = append(kept, outbound)
	}
	root["outbounds"] = kept

	for _, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		renameLegacyRuleKey(rule, &result)
		outbound := stringValue(rule["outbound"])
		if typ := special[outbound]; typ != "" {
			delete(rule, "outbound")
			if typ == "block" {
				rule["action"] = "reject"
			} else {
				rule["action"] = "hijack-dns"
			}
		}
		if opts := directOptions[outbound]; opts != nil {
			rule["action"] = "route"
			for key, value := range opts {
				rule[key] = value
			}
		}
	}
	if final := stringValue(route["final"]); special[final] != "" {
		if special[final] == "block" {
			rules = append(rules, map[string]any{"action": "reject"})
		} else {
			rules = append(rules, map[string]any{"protocol": "dns", "action": "hijack-dns"})
		}
		delete(route, "final")
	}
	if final := stringValue(route["final"]); directOptions[final] != nil {
		rule := map[string]any{"action": "route", "outbound": final}
		for key, value := range directOptions[final] {
			rule[key] = value
		}
		rules = append(rules, rule)
		delete(route, "final")
	}
	combinedRules := append(preRules, rules...)
	if rulesExisted || len(combinedRules) > 0 {
		route["rules"] = combinedRules
	} else {
		delete(route, "rules")
	}
	if !routeExisted && len(route) == 0 {
		delete(root, "route")
	}

	if needsResolver {
		dns := object(root, "dns")
		servers := array(dns, "servers")
		found := false
		for _, item := range servers {
			server, _ := item.(map[string]any)
			if stringValue(server["tag"]) == "wukong-local" {
				found = true
			}
		}
		if !found {
			dns["servers"] = append(servers, map[string]any{"type": "local", "tag": "wukong-local"})
			result.Changes = append(result.Changes, "add local DNS resolver for migrated outbounds")
		}
	}
	removeECHLegacy(root, &result)
	sort.Strings(result.Interfaces)
	result.Interfaces = uniqueStrings(result.Interfaces)
	output, err := json.MarshalIndent(root, "", "  ")
	if err != nil {
		result.Errors = append(result.Errors, err.Error())
		return nil, result, err
	}
	return append(output, '\n'), result, nil
}

func object(parent map[string]any, key string) map[string]any {
	if value, ok := parent[key].(map[string]any); ok {
		return value
	}
	value := map[string]any{}
	parent[key] = value
	return value
}

func array(parent map[string]any, key string) []any {
	if value, ok := parent[key].([]any); ok {
		return value
	}
	value := []any{}
	parent[key] = value
	return value
}

func hasAny(value map[string]any, keys ...string) bool {
	for _, key := range keys {
		if _, exists := value[key]; exists {
			return true
		}
	}
	return false
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func uniqueTag(base string, used map[string]bool) string {
	result := base
	for index := 2; used[result]; index++ {
		result = fmt.Sprintf("%s-%d", base, index)
	}
	used[result] = true
	return result
}

func mergeLegacyArray(value map[string]any, destination string, sources []string, plan *FilePlan) {
	items := toArray(value[destination])
	changed := false
	for _, source := range sources {
		if legacy, exists := value[source]; exists {
			items = append(items, toArray(legacy)...)
			delete(value, source)
			changed = true
		}
	}
	if changed {
		value[destination] = items
		plan.Changes = append(plan.Changes, fmt.Sprintf("TUN inbound: merge legacy address fields into %s", destination))
	}
}

func toArray(value any) []any {
	if value == nil {
		return nil
	}
	if values, ok := value.([]any); ok {
		return values
	}
	return []any{value}
}

func renameLegacyRuleKey(rule map[string]any, plan *FilePlan) {
	if value, exists := rule["rule_set_ipcidr_match_source"]; exists {
		rule["rule_set_ip_cidr_match_source"] = value
		delete(rule, "rule_set_ipcidr_match_source")
		plan.Changes = append(plan.Changes, "rename rule_set_ipcidr_match_source")
	}
}

func removeECHLegacy(value any, plan *FilePlan) {
	switch current := value.(type) {
	case map[string]any:
		for _, key := range []string{"pq_signature_schemes_enabled", "dynamic_record_sizing_disabled"} {
			if _, exists := current[key]; exists {
				delete(current, key)
				plan.Changes = append(plan.Changes, "remove obsolete ECH field "+key)
			}
		}
		for _, child := range current {
			removeECHLegacy(child, plan)
		}
	case []any:
		for _, child := range current {
			removeECHLegacy(child, plan)
		}
	}
}

func uniqueStrings(values []string) []string {
	result := values[:0]
	for _, value := range values {
		if len(result) == 0 || result[len(result)-1] != value {
			result = append(result, value)
		}
	}
	return result
}
