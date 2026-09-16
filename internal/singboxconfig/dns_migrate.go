package singboxconfig

import (
	"fmt"
	"net/url"
	"reflect"
	"strconv"
	"strings"
)

type legacyDNSServerOptions struct {
	index         int
	tag           string
	strategy      string
	clientSubnet  string
	defaultServer bool
}

type legacyDNSRCode struct {
	index         int
	tag           string
	rcode         string
	defaultServer bool
}

func migrateDNS(root map[string]any, caps Capabilities, plan *FilePlan) {
	dnsValue, exists := root["dns"]
	if !exists {
		if caps.NoLegacyDNS {
			if _, exists := root["http_clients"]; exists {
				plan.Errors = append(plan.Errors, "top-level http_clients is not supported by sing-box 1.14; identify and migrate this client configuration manually")
			}
		}
		return
	}
	dns, ok := dnsValue.(map[string]any)
	if !ok {
		if caps.NoLegacyDNS {
			plan.Errors = append(plan.Errors, "dns must be an object for sing-box 1.14")
		}
		return
	}
	if caps.NewDNSServers {
		migrateLegacyDNSServers(dns, plan)
	}
	if caps.NoLegacyDNS {
		validateDNS14(root, dns, plan)
	}
}

func migrateLegacyDNSServers(dns map[string]any, plan *FilePlan) {
	serversValue, serversExist := dns["servers"]
	if !serversExist {
		migrateLegacyFakeIP(dns, nil, plan)
		return
	}
	servers, ok := serversValue.([]any)
	if !ok {
		plan.Errors = append(plan.Errors, "dns.servers must be an array before sing-box 1.14 migration")
		return
	}

	legacyOptions := []legacyDNSServerOptions{}
	rcodes := []legacyDNSRCode{}
	converted := make([]any, 0, len(servers))
	changed := false
	final := stringValue(dns["final"])
	for index, item := range servers {
		server, ok := item.(map[string]any)
		if !ok {
			converted = append(converted, item)
			continue
		}
		migrated := cloneObject(server)
		tag := stringValue(server["tag"])
		option := legacyDNSServerOptions{index: index, tag: tag, defaultServer: (final == "" && index == 0) || (final != "" && final == tag)}
		if value, exists := server["strategy"]; exists {
			strategy, valid := value.(string)
			if !valid {
				plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d].strategy must be a string", index))
			} else {
				option.strategy = strategy
			}
			delete(migrated, "strategy")
			changed = true
		}
		if value, exists := server["client_subnet"]; exists {
			clientSubnet, valid := value.(string)
			if !valid {
				plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d].client_subnet must be a string", index))
			} else {
				option.clientSubnet = clientSubnet
			}
			delete(migrated, "client_subnet")
			changed = true
		}
		if option.strategy != "" || option.clientSubnet != "" || hasAny(server, "strategy", "client_subnet") {
			legacyOptions = append(legacyOptions, option)
		}

		if address, exists := server["address"]; exists {
			addressText, valid := address.(string)
			if !valid {
				plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d].address must be a string", index))
				converted = append(converted, item)
				continue
			}
			typ, fields, rcode, err := parseLegacyDNSAddress(addressText)
			if err != nil {
				plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d]: %v", index, err))
				converted = append(converted, item)
				continue
			}
			migrateLegacyDNSDialFields(migrated, index, plan)
			delete(migrated, "address")
			delete(migrated, "address_resolver")
			delete(migrated, "address_strategy")
			if rcode != "" {
				rcodes = append(rcodes, legacyDNSRCode{index: index, tag: tag, rcode: rcode, defaultServer: option.defaultServer})
				changed = true
				continue
			}
			migrated["type"] = typ
			for key, value := range fields {
				migrated[key] = value
			}
			converted = append(converted, migrated)
			changed = true
			plan.Changes = append(plan.Changes, fmt.Sprintf("dns.servers[%d]: migrate legacy address to %s server", index, typ))
			continue
		}

		if hasAny(server, "address_resolver", "address_strategy") {
			migrateLegacyDNSDialFields(migrated, index, plan)
			changed = true
		}
		if _, exists := server["type"]; exists {
			converted = append(converted, migrated)
		} else {
			converted = append(converted, item)
		}
	}
	if changed {
		dns["servers"] = converted
	}
	migrateLegacyDNSServerOptions(dns, legacyOptions, plan)
	migrateLegacyDNSRCodes(dns, rcodes, plan)
	migrateLegacyFakeIP(dns, converted, plan)
}

func cloneObject(value map[string]any) map[string]any {
	result := make(map[string]any, len(value))
	for key, item := range value {
		result[key] = item
	}
	return result
}

func migrateLegacyDNSDialFields(server map[string]any, index int, plan *FilePlan) {
	moveLegacyDNSField(server, "address_resolver", "domain_resolver", fmt.Sprintf("dns.servers[%d]", index), plan)
	moveLegacyDNSField(server, "address_strategy", "domain_strategy", fmt.Sprintf("dns.servers[%d]", index), plan)
}

func moveLegacyDNSField(value map[string]any, oldKey, newKey, location string, plan *FilePlan) {
	oldValue, exists := value[oldKey]
	if !exists {
		return
	}
	if current, alreadyExists := value[newKey]; alreadyExists && !reflect.DeepEqual(current, oldValue) {
		plan.Errors = append(plan.Errors, fmt.Sprintf("%s contains conflicting %s and %s", location, oldKey, newKey))
		return
	}
	if _, alreadyExists := value[newKey]; !alreadyExists {
		value[newKey] = oldValue
		plan.Changes = append(plan.Changes, fmt.Sprintf("%s: rename %s to %s", location, oldKey, newKey))
	}
	delete(value, oldKey)
}

func parseLegacyDNSAddress(address string) (string, map[string]any, string, error) {
	address = strings.TrimSpace(address)
	if address == "" {
		return "", nil, "", fmt.Errorf("legacy DNS server address is empty")
	}
	switch strings.ToLower(address) {
	case "local":
		return "local", map[string]any{}, "", nil
	case "fakeip":
		return "fakeip", map[string]any{}, "", nil
	}
	if !strings.Contains(address, "://") {
		return "udp", map[string]any{"server": address}, "", nil
	}
	parsed, err := url.Parse(address)
	if err != nil || parsed.Scheme == "" || parsed.Host == "" {
		return "", nil, "", fmt.Errorf("invalid legacy DNS server address %q", address)
	}
	if parsed.User != nil || parsed.RawQuery != "" || parsed.Fragment != "" {
		return "", nil, "", fmt.Errorf("legacy DNS server address %q contains unsupported URL components", address)
	}
	scheme := strings.ToLower(parsed.Scheme)
	if scheme == "dhcp" {
		if parsed.Path != "" && parsed.Path != "/" {
			return "", nil, "", fmt.Errorf("legacy DHCP DNS server address %q contains an unsupported path", address)
		}
		interfaceName := parsed.Hostname()
		if interfaceName == "auto" || interfaceName == "" {
			return "dhcp", map[string]any{}, "", nil
		}
		return "dhcp", map[string]any{"interface": interfaceName}, "", nil
	}
	if scheme == "rcode" {
		if parsed.Path != "" && parsed.Path != "/" || parsed.Port() != "" {
			return "", nil, "", fmt.Errorf("legacy RCode DNS server address %q contains an unsupported path or port", address)
		}
		code := strings.TrimPrefix(strings.ToLower(parsed.Hostname()), "/")
		if !validLegacyRCode(code) {
			return "", nil, "", fmt.Errorf("legacy DNS RCode %q is unsupported", code)
		}
		return "", nil, strings.ToUpper(code), nil
	}
	if scheme != "tcp" && scheme != "udp" && scheme != "tls" && scheme != "https" && scheme != "quic" && scheme != "h3" {
		return "", nil, "", fmt.Errorf("legacy DNS server scheme %q cannot be migrated automatically", scheme)
	}
	fields := map[string]any{"server": parsed.Hostname()}
	if fields["server"] == "" {
		return "", nil, "", fmt.Errorf("legacy DNS server address %q has no server host", address)
	}
	if port := parsed.Port(); port != "" {
		value, portErr := strconv.Atoi(port)
		if portErr != nil || value < 1 || value > 65535 {
			return "", nil, "", fmt.Errorf("legacy DNS server address %q has an invalid port", address)
		}
		fields["server_port"] = value
	}
	if scheme != "https" && scheme != "h3" && parsed.Path != "" && parsed.Path != "/" {
		return "", nil, "", fmt.Errorf("legacy DNS server address %q contains an unsupported path", address)
	}
	if scheme == "https" || scheme == "h3" {
		path := parsed.EscapedPath()
		if path != "" && path != "/" && path != "/dns-query" {
			fields["path"] = path
		}
	}
	return scheme, fields, "", nil
}

func validLegacyRCode(value string) bool {
	switch value {
	case "success", "format_error", "server_failure", "name_error", "not_implemented", "refused":
		return true
	default:
		return false
	}
}

func migrateLegacyDNSServerOptions(dns map[string]any, options []legacyDNSServerOptions, plan *FilePlan) {
	if len(options) == 0 {
		return
	}
	rules, rulesExist, rulesValid := dnsRules(dns, plan)
	if !rulesValid {
		return
	}
	for _, option := range options {
		if option.strategy != "" {
			migrateLegacyDNSServerOption(dns, rules, rulesExist, option, "strategy", option.strategy, plan)
		}
		if option.clientSubnet != "" {
			migrateLegacyDNSServerOption(dns, rules, rulesExist, option, "client_subnet", option.clientSubnet, plan)
		}
	}
}

func migrateLegacyDNSServerOption(dns map[string]any, rules []any, rulesExist bool, option legacyDNSServerOptions, key, value string, plan *FilePlan) {
	matched := false
	if option.tag != "" && rulesExist {
		for index, item := range rules {
			rule, ok := item.(map[string]any)
			if !ok || stringValue(rule["server"]) != option.tag {
				continue
			}
			matched = true
			setMigratedDNSOption(rule, key, value, fmt.Sprintf("dns.rules[%d]", index), plan)
		}
	}
	if matched {
		return
	}
	if !option.defaultServer {
		plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d]: %s for tagged server %q has no matching DNS rule; manual migration required", option.index, key, option.tag))
		return
	}
	setMigratedDNSOption(dns, key, value, "dns", plan)
}

func setMigratedDNSOption(value map[string]any, key, next, location string, plan *FilePlan) {
	if current, exists := value[key]; exists {
		if currentText, ok := current.(string); !ok || currentText != next {
			plan.Errors = append(plan.Errors, fmt.Sprintf("%s contains conflicting %s values", location, key))
		}
		return
	}
	value[key] = next
	plan.Changes = append(plan.Changes, fmt.Sprintf("%s: move legacy DNS %s", location, key))
}

func migrateLegacyDNSRCodes(dns map[string]any, rcodes []legacyDNSRCode, plan *FilePlan) {
	if len(rcodes) == 0 {
		return
	}
	rules, _, rulesValid := dnsRules(dns, plan)
	if !rulesValid {
		return
	}
	if rules == nil {
		rules = []any{}
	}
	final := stringValue(dns["final"])
	changed := false
	for _, rcode := range rcodes {
		used := false
		if rcode.tag != "" {
			for index, item := range rules {
				rule, ok := item.(map[string]any)
				if !ok || stringValue(rule["server"]) != rcode.tag {
					continue
				}
				if action := stringValue(rule["action"]); action != "" && action != "predefined" {
					plan.Errors = append(plan.Errors, fmt.Sprintf("dns.rules[%d] references RCode server %q with incompatible action %q", index, rcode.tag, action))
					continue
				}
				if existing := stringValue(rule["rcode"]); existing != "" && !strings.EqualFold(existing, rcode.rcode) {
					plan.Errors = append(plan.Errors, fmt.Sprintf("dns.rules[%d] contains a conflicting RCode", index))
					continue
				}
				delete(rule, "server")
				rule["action"] = "predefined"
				rule["rcode"] = rcode.rcode
				plan.Changes = append(plan.Changes, fmt.Sprintf("dns.rules[%d]: replace legacy RCode server with predefined action", index))
				used = true
				changed = true
			}
		}
		if final != "" && final == rcode.tag {
			dns["final"] = ""
			final = ""
			rules = append(rules, map[string]any{"action": "predefined", "rcode": rcode.rcode})
			plan.Changes = append(plan.Changes, "dns: replace RCode final server with predefined action")
			used = true
			changed = true
		} else if final == "" && rcode.defaultServer {
			rules = append(rules, map[string]any{"action": "predefined", "rcode": rcode.rcode})
			plan.Changes = append(plan.Changes, "dns: replace default RCode server with predefined action")
			used = true
			changed = true
		}
		if !used {
			plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d]: RCode server %q is not referenced by a DNS rule or default", rcode.index, rcode.tag))
		}
	}
	if changed {
		dns["rules"] = rules
	}
	if stringValue(dns["final"]) == "" {
		delete(dns, "final")
	}
}

func migrateLegacyFakeIP(dns map[string]any, servers []any, plan *FilePlan) {
	legacy, exists := dns["fakeip"]
	if !exists {
		return
	}
	fakeIP, ok := legacy.(map[string]any)
	if !ok {
		plan.Errors = append(plan.Errors, "dns.fakeip must be an object before sing-box 1.14 migration")
		return
	}
	fakeServers := []map[string]any{}
	for _, item := range servers {
		server, ok := item.(map[string]any)
		if ok && stringValue(server["type"]) == "fakeip" {
			fakeServers = append(fakeServers, server)
		}
	}
	enabled := true
	if value, hasEnabled := fakeIP["enabled"]; hasEnabled {
		var valid bool
		enabled, valid = value.(bool)
		if !valid {
			plan.Errors = append(plan.Errors, "dns.fakeip.enabled must be a boolean")
			return
		}
	}
	if enabled && len(fakeServers) != 1 {
		plan.Errors = append(plan.Errors, fmt.Sprintf("dns.fakeip is enabled but found %d fakeip DNS servers; manual migration required", len(fakeServers)))
		return
	}
	if !enabled && len(fakeServers) > 0 {
		plan.Errors = append(plan.Errors, "dns.fakeip is disabled but a fakeip DNS server is configured; manual migration required")
		return
	}
	if len(fakeServers) == 1 {
		for _, key := range []string{"inet4_range", "inet6_range"} {
			if value, hasValue := fakeIP[key]; hasValue {
				if current, exists := fakeServers[0][key]; exists && !reflect.DeepEqual(current, value) {
					plan.Errors = append(plan.Errors, fmt.Sprintf("dns.fakeip and fakeip server contain conflicting %s values", key))
					continue
				}
				if _, exists := fakeServers[0][key]; !exists {
					fakeServers[0][key] = value
					plan.Changes = append(plan.Changes, fmt.Sprintf("fakeip DNS server: move %s from legacy dns.fakeip", key))
				}
			}
		}
	}
	delete(dns, "fakeip")
	plan.Changes = append(plan.Changes, "dns: remove legacy fakeip wrapper")
}

func dnsRules(dns map[string]any, plan *FilePlan) ([]any, bool, bool) {
	value, exists := dns["rules"]
	if !exists {
		return nil, false, true
	}
	rules, ok := value.([]any)
	if !ok {
		plan.Errors = append(plan.Errors, "dns.rules must be an array before sing-box 1.14 migration")
		return nil, true, false
	}
	return rules, true, true
}

func validateDNS14(root, dns map[string]any, plan *FilePlan) {
	if _, exists := dns["independent_cache"]; exists {
		delete(dns, "independent_cache")
		plan.Changes = append(plan.Changes, "dns: remove obsolete independent_cache")
	}
	if _, exists := dns["fakeip"]; exists {
		plan.Errors = append(plan.Errors, "dns.fakeip legacy wrapper remains after migration")
	}
	if servers, ok := dns["servers"].([]any); ok {
		for index, item := range servers {
			server, ok := item.(map[string]any)
			if !ok {
				continue
			}
			if _, exists := server["address"]; exists {
				plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d] still uses removed legacy address format", index))
			}
			if _, exists := server["address_resolver"]; exists {
				plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d] still uses removed address_resolver", index))
			}
			if _, exists := server["address_strategy"]; exists {
				plan.Errors = append(plan.Errors, fmt.Sprintf("dns.servers[%d] still uses removed address_strategy", index))
			}
		}
	}
	validateDNSRuleFields(dns, plan)
	validateLegacyDNSCache(root, plan)
	if _, exists := root["http_clients"]; exists {
		plan.Errors = append(plan.Errors, "top-level http_clients is not supported by sing-box 1.14; identify and migrate this client configuration manually")
	}
}

func validateDNSRuleFields(dns map[string]any, plan *FilePlan) {
	rules, _, valid := dnsRules(dns, plan)
	if !valid {
		return
	}
	state := dnsRuleValidationState{}
	for index, item := range rules {
		rule, ok := item.(map[string]any)
		if !ok {
			continue
		}
		validateDNSRule(rule, fmt.Sprintf("dns.rules[%d]", index), &state, plan)
	}
	if state.hasQuerySelector && state.hasLegacyStrategy {
		plan.Errors = append(plan.Errors, "dns rules combine ip_version/query_type with legacy strategy; migrate the rules to explicit response matching or remove the conflict")
	}
}

type dnsRuleValidationState struct {
	hasQuerySelector  bool
	hasLegacyStrategy bool
}

func validateDNSRule(rule map[string]any, location string, state *dnsRuleValidationState, plan *FilePlan) {
	renameLegacyRuleKey(rule, plan)
	if hasEffectiveDNSQuerySelector(rule) {
		state.hasQuerySelector = true
	}
	if value, exists := rule["strategy"]; exists {
		strategy, ok := value.(string)
		if !ok {
			plan.Errors = append(plan.Errors, fmt.Sprintf("%s.strategy must be a string", location))
		} else if strategy != "" {
			state.hasLegacyStrategy = true
		}
	}
	if hasEffectiveDNSAddressFilter(rule) && !boolValue(rule["match_response"]) {
		plan.Errors = append(plan.Errors, fmt.Sprintf("%s uses legacy address filters without match_response; migrate through evaluate + match_response", location))
	}
	if value, exists := rule["rule_set_ip_cidr_accept_empty"]; exists {
		if enabled, ok := value.(bool); !ok {
			plan.Errors = append(plan.Errors, fmt.Sprintf("%s.rule_set_ip_cidr_accept_empty must be a boolean", location))
		} else if enabled {
			plan.Errors = append(plan.Errors, fmt.Sprintf("%s uses rule_set_ip_cidr_accept_empty, which needs manual response-matching migration", location))
		} else {
			delete(rule, "rule_set_ip_cidr_accept_empty")
			plan.Changes = append(plan.Changes, fmt.Sprintf("%s: remove disabled legacy rule_set_ip_cidr_accept_empty", location))
		}
	}
	for _, key := range []string{"geosite", "geoip", "source_geoip"} {
		if _, exists := rule[key]; exists {
			plan.Errors = append(plan.Errors, fmt.Sprintf("%s uses removed %s matching; migrate to rule_set manually", location, key))
		}
	}
	if _, exists := rule["outbound"]; exists {
		plan.Errors = append(plan.Errors, fmt.Sprintf("%s uses removed outbound matching; migrate to an outbound domain_resolver manually", location))
	}
	if nestedValue, exists := rule["rules"]; exists {
		nested, ok := nestedValue.([]any)
		if !ok {
			plan.Errors = append(plan.Errors, fmt.Sprintf("%s.rules must be an array", location))
			return
		}
		for index, item := range nested {
			nestedRule, ok := item.(map[string]any)
			if !ok {
				continue
			}
			validateDNSRule(nestedRule, fmt.Sprintf("%s.rules[%d]", location, index), state, plan)
		}
	}
}

func hasEffectiveDNSQuerySelector(rule map[string]any) bool {
	if value, exists := rule["ip_version"]; exists {
		switch current := value.(type) {
		case float64:
			if current == 4 || current == 6 {
				return true
			}
		case int:
			if current == 4 || current == 6 {
				return true
			}
		default:
			return true
		}
	}
	if value, exists := rule["query_type"]; exists {
		switch current := value.(type) {
		case string:
			return current != ""
		case []any:
			return len(current) > 0
		default:
			return true
		}
	}
	return false
}

func hasEffectiveDNSAddressFilter(rule map[string]any) bool {
	if value, exists := rule["ip_cidr"]; exists {
		switch current := value.(type) {
		case string:
			if current != "" {
				return true
			}
		case []any:
			if len(current) > 0 {
				return true
			}
		default:
			return true
		}
	}
	if value, exists := rule["ip_is_private"]; exists {
		if enabled, ok := value.(bool); !ok || enabled {
			return true
		}
	}
	return false
}

func boolValue(value any) bool {
	result, _ := value.(bool)
	return result
}

func validateLegacyDNSCache(root map[string]any, plan *FilePlan) {
	experimental, ok := root["experimental"].(map[string]any)
	if !ok {
		return
	}
	cache, ok := experimental["cache_file"].(map[string]any)
	if !ok {
		return
	}
	value, exists := cache["store_rdrc"]
	if exists {
		enabled, valid := value.(bool)
		if !valid {
			plan.Errors = append(plan.Errors, "experimental.cache_file.store_rdrc must be a boolean")
			return
		}
		if enabled {
			if current, hasStoreDNS := cache["store_dns"]; hasStoreDNS {
				if currentEnabled, ok := current.(bool); !ok || !currentEnabled {
					plan.Errors = append(plan.Errors, "experimental.cache_file.store_rdrc conflicts with store_dns=false")
					return
				}
			} else {
				cache["store_dns"] = true
				plan.Changes = append(plan.Changes, "experimental.cache_file: replace store_rdrc with store_dns")
			}
		} else {
			plan.Changes = append(plan.Changes, "experimental.cache_file: remove disabled store_rdrc")
		}
		delete(cache, "store_rdrc")
	}
	if _, exists := cache["rdrc_timeout"]; exists {
		delete(cache, "rdrc_timeout")
		plan.Changes = append(plan.Changes, "experimental.cache_file: remove obsolete rdrc_timeout")
	}
}
