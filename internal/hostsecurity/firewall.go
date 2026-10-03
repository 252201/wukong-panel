package hostsecurity

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"github.com/252201/wukong-panel/internal/model"
	"os"
	"path/filepath"
	"regexp"
	"sort"
	"strconv"
	"strings"
)

func (c *Controller) Firewall(ctx context.Context, zone string) (model.FirewallState, error) {
	s, e := c.state()
	if e != nil {
		return model.FirewallState{}, e
	}
	r := model.FirewallState{CheckedAt: c.Now(), Rules: []model.SecurityRule{}, Zones: []string{}, Policy: "unknown", Pending: c.pending()}
	ssh, panel := c.ports(ctx)
	if len(ssh) == 0 {
		ssh = s.SSHPorts
	}
	if len(panel) == 0 {
		panel = s.PanelPorts
	}
	r.RequiredPorts = defaultRequired(ssh, panel, c.publicNodes(ctx))
	if c.Demo {
		r.Backend = "nftables"
		r.Installed = true
		r.Reason = "演示环境不执行系统安全操作"
		r.Rules = s.Rules
		r.Revision = c.revision(s)
		return r, nil
	}
	raw := []string{}
	active := []string{}
	ufw, fire, nft := c.Lookup("ufw"), c.Lookup("firewall-cmd"), c.Lookup("nft")
	ut := ""
	var ue error
	if ufw {
		ut, ue = c.exec(ctx, "ufw", "status", "verbose")
		raw = append(raw, ut)
		if ue == nil && strings.Contains(ut, "Status: active") {
			active = append(active, "ufw")
		}
	}
	if fire {
		out, e := c.exec(ctx, "firewall-cmd", "--state")
		if e == nil && out == "running" {
			active = append(active, "firewalld")
		}
	}
	nt := ""
	var ne error
	if nft {
		nt, ne = c.exec(ctx, "nft", "-s", "list", "ruleset")
		raw = append(raw, nt)
		if ne == nil && strings.Contains(nt, "table inet wukong_panel") {
			active = append(active, "nftables")
		}
	}
	if len(active) > 0 {
		r.Backend = active[0]
		r.Active = true
	} else {
		switch c.family() {
		case "apt":
			r.Backend = "ufw"
		case "dnf":
			r.Backend = "firewalld"
		case "apk":
			r.Backend = "nftables"
		}
		if r.Backend == "" {
			if ufw {
				r.Backend = "ufw"
			} else if fire {
				r.Backend = "firewalld"
			} else if nft {
				r.Backend = "nftables"
			}
		}
	}
	if len(active) == 0 {
		if ufw && !fire {
			r.Backend = "ufw"
		} else if fire && !ufw {
			r.Backend = "firewalld"
		}
	}

	r.Writable = true
	switch r.Backend {
	case "ufw":
		r.Installed = ufw
		if ufw {
			if ue != nil {
				r.Writable = false
				r.Reason = ue.Error()
			} else {
				added, e := c.exec(ctx, "ufw", "show", "added")
				raw = append(raw, added)
				if e != nil {
					r.Writable = false
					r.Reason = e.Error()
				} else {
					r.Rules = parseUFW(added)
				}
				if strings.Contains(ut, "deny (incoming)") {
					r.Policy = "deny"
				} else if strings.Contains(ut, "allow (incoming)") {
					r.Policy = "allow"
				}
			}
		}
	case "firewalld":
		r.Installed = fire
		bin := "firewall-cmd"
		if !r.Active && fire {
			bin = "firewall-offline-cmd"
			if !c.Lookup(bin) {
				r.Writable = false
				r.Reason = "缺少 firewalld 离线配置工具"
				break
			}
			zone, e = c.exec(ctx, bin, "--get-default-zone")
			if e != nil || !nameRE.MatchString(zone) {
				r.Writable = false
				r.Reason = "无法读取默认防火墙区域"
				break
			}
			r.Zones = []string{zone}
		}
		if fire {
			z := ""
			if r.Active {
				z, e = c.exec(ctx, "firewall-cmd", "--get-active-zones")
			} else {
				all, er := c.exec(ctx, bin, "--list-all-zones")
				if er != nil {
					return r, er
				}
				raw = append(raw, all)
				bound := []string{}
				current := ""
				for _, line := range strings.Split(all, "\n") {
					if line != "" && !strings.HasPrefix(line, " ") {
						f := strings.Fields(line)
						if len(f) > 0 {
							current = f[0]
						}
					}
					if (strings.HasPrefix(strings.TrimSpace(line), "interfaces:") || strings.HasPrefix(strings.TrimSpace(line), "sources:")) && len(strings.Fields(strings.TrimSpace(line))) > 1 && !contains(bound, current) {
						bound = append(bound, current)
					}
				}
				if len(bound) > 1 {
					r.Writable = false
					r.Reason = "停用的 firewalld 有多个绑定区域，请在主机核对 SSH 入口后启动"
				}
				if len(bound) == 1 {
					zone = bound[0]
					r.Zones = []string{zone}
				}
			}
			raw = append(raw, z)
			for _, l := range strings.Split(z, "\n") {
				if l != "" && !strings.HasPrefix(l, " ") {
					f := strings.Fields(l)
					if len(f) > 0 {
						r.Zones = append(r.Zones, f[0])
					}
				}
			}
			if len(r.Zones) == 0 {
				v, e := c.exec(ctx, "firewall-cmd", "--get-default-zone")
				if e != nil {
					return r, e
				}
				r.Zones = []string{v}
			}
			if zone == "" {
				zone = r.Zones[0]
			}
			if !nameRE.MatchString(zone) || !contains(r.Zones, zone) {
				return r, errors.New("请选择正在生效的防火墙区域")
			}
			r.Zone = zone
			details, e := c.exec(ctx, bin, "--zone="+zone, "--list-all")
			if e != nil {
				return r, e
			}
			raw = append(raw, details)
			r.Policy = strings.ToLower(field(details, "target"))
			if r.Policy == "drop" || r.Policy == "reject" {
				r.Policy = "deny"
			}
			ports, e := c.exec(ctx, bin, "--zone="+zone, "--list-ports")
			if e != nil {
				return r, e
			}
			raw = append(raw, ports)
			for _, p := range strings.Fields(ports) {
				a, b, proto, ok := parsedPort(p)
				if ok {
					r.Rules = append(r.Rules, model.SecurityRule{Action: "allow", Protocol: proto, PortFrom: a, PortTo: b, Source: "any", Zone: zone, Adoptable: true})
				}
			}
			rich, e := c.exec(ctx, bin, "--zone="+zone, "--list-rich-rules")
			if e != nil {
				return r, e
			}
			raw = append(raw, rich)
			for _, l := range strings.Split(rich, "\n") {
				if strings.TrimSpace(l) == "" {
					continue
				}
				rr, ok := parseRich(l, zone)
				if !ok {
					rr = model.SecurityRule{Description: l, Zone: zone}
				}
				r.Rules = append(r.Rules, rr)
			}
		}
	case "nftables":
		r.Installed = nft
		if nft {
			if ne != nil {
				r.Writable = false
				r.Reason = ne.Error()
			} else {
				data, e := c.exec(ctx, "nft", "-j", "-s", "list", "ruleset")
				if e != nil {
					return r, e
				}
				rules, policy, complex := parseNFT(data)
				r.Rules = rules
				r.Policy = policy
				if s.NFTInactive && policy == "allow" {
					r.Active = false
					for _, stored := range s.NFTRules {
						if stored.Action == "deny" {
							r.Rules = append(r.Rules, stored)
						}
					}
				}
				if complex {
					r.Writable = false
					r.Reason = "存在无法安全识别的 nftables 链或规则，请先在主机核对"
				}
				raw = append(raw, data)
			}
		}
	default:
		r.Writable = false
		r.Reason = "不支持当前发行版或防火墙后端"
	}
	if nft && ne == nil && r.Backend != "nftables" {
		data, er := c.exec(ctx, "nft", "-j", "-s", "list", "ruleset")
		raw = append(raw, data)
		var root nftRoot
		if er != nil || json.Unmarshal([]byte(data), &root) != nil {
			r.Writable = false
			r.Reason = "无法核对其他防火墙链"
		} else {
			for _, item := range root.Items {
				if ch := item.Chain; ch != nil && ch.Hook == "input" {
					known := strings.HasPrefix(ch.Table, "f2b-") || (r.Backend == "firewalld" && ch.Table == "firewalld") || (r.Backend == "ufw" && ch.Table == "filter" && ch.Name == "INPUT")
					if !known {
						r.Writable = false
						r.Reason = "存在其他入站防火墙链，请先核对，暂只读"
					}
				}
				if rr := item.Rule; rr != nil && r.Backend == "ufw" && rr.Table == "filter" && rr.Chain == "INPUT" {
					banJump := false
					for _, expr := range rr.Expr {
						var m map[string]json.RawMessage
						_ = json.Unmarshal(expr, &m)
						var j struct{ Target string }
						_ = json.Unmarshal(m["jump"], &j)
						if strings.HasPrefix(j.Target, "f2b-") {
							banJump = true
						}
					}
					if banJump {
						continue
					}
					for _, expr := range rr.Expr {
						var v map[string]json.RawMessage
						_ = json.Unmarshal(expr, &v)
						if j, ok := v["jump"]; ok {
							var target struct{ Target string }
							_ = json.Unmarshal(j, &target)
							if strings.HasPrefix(target.Target, "ufw-") || strings.HasPrefix(target.Target, "ufw6-") || strings.HasPrefix(target.Target, "f2b-") {
								continue
							}
						}
						if _, ok := v["counter"]; ok {
							continue
						}
						r.Writable = false
						r.Reason = "UFW 入站链存在外部规则，暂只读"
					}
				}
			}
		}
	}

	for _, rule := range r.Rules {
		if rule.Action == "" {
			r.Writable = false
			r.Reason = "存在无法安全识别的外部规则，暂只读"
		}
	}

	if len(active) > 1 {
		r.Writable = false
		r.Reason = "多个防火墙管理器同时生效，暂只读"
	}
	// Presence of a command is not proof of NET_ADMIN, even for root in containers.
	if b, e := c.read("/proc/self/status"); e == nil {
		for _, l := range strings.Split(string(b), "\n") {
			if strings.HasPrefix(l, "CapEff:") {
				v, _ := strconv.ParseUint(strings.TrimSpace(strings.TrimPrefix(l, "CapEff:")), 16, 64)
				if v&(1<<12) == 0 {
					r.Writable = false
					r.Reason = "当前进程缺少 CAP_NET_ADMIN，无法管理主机防火墙"
				}
			}
		}
	}
	for i := range r.Rules {
		rr := &r.Rules[i]
		if rr.ID == "" {
			rr.ID = c.revision(ruleKey(*rr), rr.Description)[:32]
		}
		for _, owned := range s.Rules {
			if sameRule(*rr, owned) && rr.Adoptable {
				rr.Managed = true
				rr.ID = owned.ID
			}
		}
		for _, p := range r.RequiredPorts {
			if p.Protected && rr.Protocol == p.Protocol && p.Port >= rr.PortFrom && p.Port <= rr.PortTo {
				rr.Protected = true
			}
		}
	}
	sortRules(r.Rules)
	sort.Strings(r.Zones)
	config := []string{}
	for _, p := range []string{"/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf", "/etc/default/ufw", nftPath, "/etc/nftables.conf", "/etc/nftables.nft", jailPath} {
		b, _ := c.read(p)
		config = append(config, digest(b))
	}
	if r.Zone != "" {
		b, _ := c.read("/etc/firewalld/zones/" + r.Zone + ".xml")
		config = append(config, digest(b))
	}
	r.Revision = c.revision(s, raw, config, r.RequiredPorts, r.Backend, r.Zone, r.Active)
	return r, nil
}
func (c *Controller) publicNodes(ctx context.Context) []model.Node {
	r := []model.Node{}
	for _, n := range c.Nodes {
		if strings.Contains(n.Protocol, "tunnel") {
			continue
		}
		b, e := c.read(n.ConfigPath)
		if e != nil {
			continue
		}
		var cfg struct {
			Inbounds []struct {
				Listen     string `json:"listen"`
				ListenPort int    `json:"listen_port"`
			}
		}
		if json.Unmarshal(b, &cfg) != nil {
			continue
		}
		for _, in := range cfg.Inbounds {
			if in.ListenPort == n.ListenPort && in.Listen != "127.0.0.1" && in.Listen != "::1" {
				r = append(r, n)
				break
			}
		}
	}
	return r
}
func contains(v []string, x string) bool {
	for _, s := range v {
		if s == x {
			return true
		}
	}
	return false
}
func field(s, key string) string {
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if i := strings.Index(l, key+":"); i >= 0 {
			return strings.TrimSpace(l[i+len(key)+1:])
		}
	}
	return ""
}
func parseUFW(s string) []model.SecurityRule {
	result := []model.SecurityRule{}
	re := regexp.MustCompile(`^ufw (allow|deny) (?:in )?([0-9]+(?::[0-9]+)?)/(tcp|udp)(?: comment ['"]([^'"]*)['"])?$`)
	full := regexp.MustCompile(`^ufw (allow|deny) (?:in )?from (\S+) to any port ([0-9]+(?::[0-9]+)?) proto (tcp|udp)(?: comment ['"]([^'"]*)['"])?$`)
	for _, l := range strings.Split(s, "\n") {
		l = strings.TrimSpace(l)
		if !strings.HasPrefix(l, "ufw ") {
			continue
		}
		var r model.SecurityRule
		if m := re.FindStringSubmatch(l); m != nil {
			a, b, p, ok := parsedPort(m[2] + "/" + m[3])
			r = model.SecurityRule{Action: m[1], Protocol: p, PortFrom: a, PortTo: b, Source: "any", Adoptable: ok}
		} else if m := full.FindStringSubmatch(l); m != nil {
			a, b, p, ok := parsedPort(m[3] + "/" + m[4])
			r = model.SecurityRule{Action: m[1], Protocol: p, PortFrom: a, PortTo: b, Source: m[2], Adoptable: ok}
			if nr, e := normalizeRule(r); e == nil {
				nr.Adoptable = ok
				r = nr
			} else {
				r.Adoptable = false
			}
		} else {
			r.Description = l
		}
		result = append(result, r)
	}
	return result
}
func richRule(r model.SecurityRule) string {
	if r.Source == "any" {
		action := "accept"
		if r.Action == "deny" {
			action = "drop"
		}
		return fmt.Sprintf(`rule port port="%s" protocol="%s" %s`, portSpec(r, "-"), r.Protocol, action)
	}
	family := "ipv4"
	if strings.Contains(r.Source, ":") {
		family = "ipv6"
	}
	action := "accept"
	if r.Action == "deny" {
		action = "drop"
	}
	return fmt.Sprintf(`rule family="%s" source address="%s" port port="%s" protocol="%s" %s`, family, r.Source, portSpec(r, "-"), r.Protocol, action)
}
func parseRich(s, zone string) (model.SecurityRule, bool) {
	for _, protocol := range []string{"icmp", "ipv6-icmp"} {
		if strings.TrimSpace(s) == `rule protocol value="`+protocol+`" accept` {
			return model.SecurityRule{Action: "allow", Protocol: protocol, Source: "any", Zone: zone, Protected: true, Description: s}, true
		}
	}
	any := regexp.MustCompile(`^rule port port="([0-9]+(?:-[0-9]+)?)" protocol="(tcp|udp)" (accept|drop)$`)
	if m := any.FindStringSubmatch(strings.TrimSpace(s)); m != nil {
		a, b, p, ok := parsedPort(m[1] + "/" + m[2])
		act := "allow"
		if m[3] == "drop" {
			act = "deny"
		}
		r, e := normalizeRule(model.SecurityRule{Action: act, Protocol: p, PortFrom: a, PortTo: b, Source: "any", Zone: zone})
		r.Adoptable = ok && e == nil
		return r, r.Adoptable
	}
	// Recognize a simple external reject (including Fail2ban rich rules),
	// while keeping it read only because reject is not a managed drop action.
	reject := regexp.MustCompile(`^rule family="(ipv4|ipv6)" source address="([^" ]+)" port port="([0-9]+(?:-[0-9]+)?)" protocol="(tcp|udp)" reject(?: type="[a-z0-9-]+")?$`)
	if m := reject.FindStringSubmatch(strings.TrimSpace(s)); m != nil {
		a, b, p, ok := parsedPort(m[3] + "/" + m[4])
		r, e := normalizeRule(model.SecurityRule{Action: "deny", Protocol: p, PortFrom: a, PortTo: b, Source: m[2], Zone: zone})
		if ok && e == nil {
			r.Description = s
			return r, true
		}
	}

	re := regexp.MustCompile(`^rule family="(ipv4|ipv6)" source address="([^" ]+)" port port="([0-9]+(?:-[0-9]+)?)" protocol="(tcp|udp)" (accept|drop)$`)
	m := re.FindStringSubmatch(strings.TrimSpace(s))
	if m == nil {
		return model.SecurityRule{}, false
	}
	a, b, p, ok := parsedPort(m[3] + "/" + m[4])
	act := "allow"
	if m[5] == "drop" {
		act = "deny"
	}
	r, e := normalizeRule(model.SecurityRule{Action: act, Protocol: p, PortFrom: a, PortTo: b, Source: m[2], Zone: zone})
	r.Adoptable = ok && e == nil
	return r, r.Adoptable
}

type nftRoot struct {
	Items []struct {
		Table *struct{ Family, Name string }
		Chain *struct{ Family, Table, Name, Hook, Policy string }
		Rule  *struct {
			Family, Table, Chain, Comment string
			Expr                          []json.RawMessage
		}
	} `json:"nftables"`
}

func parseNFT(s string) ([]model.SecurityRule, string, bool) {
	var root nftRoot
	if json.Unmarshal([]byte(s), &root) != nil {
		return nil, "unknown", true
	}
	result := []model.SecurityRule{}
	policy := "allow"
	complex := false
	for _, item := range root.Items {
		if ch := item.Chain; ch != nil {
			if ch.Hook == "input" && ch.Table != "wukong_panel" && !strings.HasPrefix(ch.Table, "f2b-") {
				complex = true
			}
			if ch.Table == "wukong_panel" {
				if ch.Name != "input" || ch.Hook != "input" {
					complex = true
				}
				policy = ch.Policy
				if policy == "drop" {
					policy = "deny"
				}
				if policy == "accept" {
					policy = "allow"
				}
			}
		}
		rr := item.Rule
		if rr == nil {
			continue
		}
		if rr.Table != "wukong_panel" {
			continue
		}
		if rr.Chain != "input" {
			complex = true
			continue
		}
		r := model.SecurityRule{Source: "any"}
		ports, sources, verdicts := 0, 0, 0
		simple := true
		essential := false
		for _, b := range rr.Expr {
			var m map[string]json.RawMessage
			_ = json.Unmarshal(b, &m)
			if _, ok := m["accept"]; ok {
				r.Action = "allow"
				verdicts++
				continue
			}
			if _, ok := m["drop"]; ok {
				r.Action = "deny"
				verdicts++
				continue
			}
			if _, ok := m["counter"]; ok {
				continue
			}
			var match struct {
				Op   string
				Left struct {
					Payload *struct{ Protocol, Field string }
					Meta    *struct{ Key string }
					CT      *struct{ Key string }
				}
				Right json.RawMessage
			}
			if json.Unmarshal(m["match"], &match) != nil {
				simple = false
				continue
			}
			p := match.Left.Payload
			switch {
			case p != nil && p.Field == "dport" && (p.Protocol == "tcp" || p.Protocol == "udp") && match.Op == "==":
				ports++
				r.Protocol = p.Protocol
				if json.Unmarshal(match.Right, &r.PortFrom) == nil {
					r.PortTo = r.PortFrom
				} else {
					var v struct {
						Range []int `json:"range"`
					}
					if json.Unmarshal(match.Right, &v) == nil && len(v.Range) == 2 {
						r.PortFrom = v.Range[0]
						r.PortTo = v.Range[1]
					} else {
						simple = false
					}
				}
			case p != nil && p.Field == "saddr" && (p.Protocol == "ip" || p.Protocol == "ip6") && match.Op == "==":
				sources++
				if json.Unmarshal(match.Right, &r.Source) != nil {
					var v struct {
						Prefix struct {
							Addr string
							Len  int
						}
					}
					if json.Unmarshal(match.Right, &v) == nil && v.Prefix.Addr != "" {
						r.Source = fmt.Sprintf("%s/%d", v.Prefix.Addr, v.Prefix.Len)
					} else {
						simple = false
					}
				}
				if (p.Protocol == "ip" && strings.Contains(r.Source, ":")) || (p.Protocol == "ip6" && !strings.Contains(r.Source, ":")) {
					simple = false
				}
			default:
				simple = false
				var right string
				_ = json.Unmarshal(match.Right, &right)
				if match.Op == "==" && match.Left.Meta != nil && (match.Left.Meta.Key == "iifname" || match.Left.Meta.Key == "iif") && right == "lo" {
					essential = true
				}
				if (match.Op == "==" || match.Op == "in") && match.Left.CT != nil && match.Left.CT.Key == "state" {
					var set struct{ Set []string }
					if json.Unmarshal(match.Right, &set) != nil {
						_ = json.Unmarshal(match.Right, &set.Set)
					}
					if len(set.Set) == 2 && contains(set.Set, "established") && contains(set.Set, "related") {
						essential = true
					}
				}
				if match.Op == "==" && match.Left.Meta != nil && match.Left.Meta.Key == "l4proto" && (right == "icmp" || right == "ipv6-icmp") {
					essential = true
				}
				if match.Op == "==" && p != nil && ((p.Protocol == "ip" && p.Field == "protocol" && right == "icmp") || (p.Protocol == "ip6" && p.Field == "nexthdr" && right == "ipv6-icmp")) {
					essential = true
				}
			}
		}
		if simple && ports == 1 && sources <= 1 && verdicts == 1 {
			nr, e := normalizeRule(r)
			if e == nil {
				nr.Adoptable = true
				result = append(result, nr)
				continue
			}
		}
		if !essential || r.Action != "allow" || len(rr.Expr) != 2 {
			complex = true
			result = append(result, model.SecurityRule{Description: "复杂规则：" + rr.Comment})
		}
	}
	return result, policy, complex
}
func renderNFT(rules []model.SecurityRule, active bool) string {
	policy := "accept"
	if active {
		policy = "drop"
	}
	var b strings.Builder
	b.WriteString("table inet wukong_panel {\n chain input {\n  type filter hook input priority 100; policy " + policy + ";\n  iifname lo accept\n  ct state established,related accept\n  meta l4proto icmp accept\n  meta l4proto ipv6-icmp accept\n")
	copyRules := append([]model.SecurityRule{}, rules...)
	sort.SliceStable(copyRules, func(i, j int) bool { return copyRules[i].Action == "deny" && copyRules[j].Action != "deny" })
	for _, r := range copyRules {
		if !r.Adoptable || (!active && r.Action == "deny") {
			continue
		}
		b.WriteString("  ")
		if r.Source != "any" {
			proto := "ip"
			if strings.Contains(r.Source, ":") {
				proto = "ip6"
			}
			b.WriteString(proto + " saddr " + r.Source + " ")
		}
		act := "accept"
		if r.Action == "deny" {
			act = "drop"
		}
		b.WriteString(r.Protocol + " dport " + portSpec(r, "-") + " " + act + "\n")
	}
	b.WriteString(" }\n}\n")
	return b.String()
}
func (c *Controller) applyNFT(ctx context.Context, rules []model.SecurityRule, active bool) error {
	body := renderNFT(rules, active)
	if _, e := c.exec(ctx, "nft", "list", "table", "inet", "wukong_panel"); e == nil {
		body = "delete table inet wukong_panel\n" + body
	}
	if _, e := c.Run(ctx, "nft", []string{"-c", "-f", "-"}, body); e != nil {
		return e
	}
	if _, e := c.Run(ctx, "nft", []string{"-f", "-"}, body); e != nil {
		return e
	}
	return atomic(c.path(nftPath), []byte(renderNFT(rules, active)), 0644)
}

// A separate loader never runs the distribution's global flush/reload script.
func (c *Controller) persistNFT(ctx context.Context) error {
	bin, e := os.Executable()
	if c.RecoveryBinary != "" {
		bin = c.RecoveryBinary
		e = nil
	}
	if e != nil {
		return e
	}
	bin, e = filepath.EvalSymlinks(bin)
	if e != nil {
		return e
	}
	dir := filepath.Dir(c.Dir)
	if strings.ContainsAny(bin+dir, "\n\r\x00") {
		return errors.New("invalid firewall loader path")
	}
	if c.isSystemd() {
		body := "[Unit]\nDescription=Wukong owned nftables table\nAfter=local-fs.target nftables.service wukong-security-recovery.service\nBefore=wukong-agent.service\n[Service]\nType=oneshot\nExecStart=" + strconv.Quote(bin) + " security-firewall --secret-dir " + strconv.Quote(dir) + "\nRemainAfterExit=yes\nRestart=on-failure\nRestartSec=1\n[Install]\nWantedBy=multi-user.target\n"
		if e = atomic(c.path("/etc/systemd/system/wukong-firewall.service"), []byte(body), 0644); e != nil {
			return e
		}
		if _, e = c.exec(ctx, "systemctl", "daemon-reload"); e != nil {
			return e
		}
	} else if c.Lookup("rc-update") {
		quote := func(v string) string { return "'" + strings.ReplaceAll(v, "'", "'\\''") + "'" }
		body := "#!/sbin/openrc-run\nname=\"Wukong owned nftables table\"\ndepend() { need localmount; after nftables wukong-security-recovery; before wukong-agent; }\nstart() { " + quote(bin) + " security-firewall --secret-dir " + quote(dir) + "; }\n"
		if e = atomic(c.path("/etc/init.d/wukong-firewall"), []byte(body), 0755); e != nil {
			return e
		}
	} else {
		return errors.New("缺少独立 nftables 启动加载器")
	}
	return c.setBoot(ctx, "wukong-firewall", true)
}
func (c *Controller) LoadFirewall(ctx context.Context) error {
	if _, e := os.Stat(filepath.Join(c.Dir, "state.json")); e != nil {
		return e
	}
	unlock, e := c.lock()
	if e != nil {
		return e
	}
	defer unlock()
	s, e := c.state()
	if e != nil {
		return e
	}
	if !s.NFTInactive && (len(s.SSHPorts) == 0 || len(s.PanelPorts) == 0) {
		return errors.New("missing saved management ports")
	}
	for _, r := range s.NFTRules {
		if _, e := normalizeRule(r); e != nil {
			return e
		}
	}
	return c.applyNFT(ctx, s.NFTRules, !s.NFTInactive)
}

func ufwArgs(r model.SecurityRule, remove bool) []string {
	a := []string{}
	if remove {
		a = append(a, "--force", "delete")
	}
	if !remove && r.Action == "deny" {
		// UFW numbers IPv6 after IPv4. prepend selects the beginning of the
		// rule's own address family, including when its ruleset is empty.
		a = append(a, "prepend")
	}
	a = append(a, r.Action)
	if r.Source == "any" {
		a = append(a, portSpec(r, ":")+"/"+r.Protocol)
	} else {
		a = append(a, "from", r.Source, "to", "any", "port", portSpec(r, ":"), "proto", r.Protocol)
	}
	return a
}

// UFW cannot keep two actions for the same match: inserting the opposite
// action is skipped (and appending it may silently replace the old action).
// Only explicitly managed, unprotected rules may be replaced in an add preview.
func ufwReplacements(r model.SecurityRule, rules []model.SecurityRule) ([]model.SecurityRule, error) {
	replaced := []model.SecurityRule{}
	for _, old := range rules {
		match := old
		match.Action = r.Action
		if old.Action == r.Action || !sameRule(match, r) {
			continue
		}
		if old.Protected {
			return nil, errors.New("SSH 和面板入口规则受保护")
		}
		if !old.Adoptable || !old.Managed {
			return nil, errors.New("存在相同条件的外部规则，请先确认接管后再替换")
		}
		replaced = append(replaced, old)
	}
	return replaced, nil
}

func fireArgs(r model.SecurityRule, remove, permanent bool) []string {
	a := []string{"--zone=" + r.Zone}
	if permanent {
		a = append(a, "--permanent")
	}
	op := "--add-"
	if remove {
		op = "--remove-"
	}
	if r.Source == "any" && r.Action == "allow" {
		return append(a, op+"port="+portSpec(r, "-")+"/"+r.Protocol)
	}
	return append(a, op+"rich-rule="+richRule(r))
}
func (c *Controller) changeRule(ctx context.Context, backend string, r model.SecurityRule, remove bool, j *journal) error {
	switch backend {
	case "ufw":
		_, e := c.exec(ctx, "ufw", ufwArgs(r, remove)...)
		return e
	case "firewalld":
		for _, perm := range []bool{false, true} {
			args := fireArgs(r, remove, perm)
			inverse := fireArgs(r, !remove, perm)
			j.Undo = append(j.Undo, command{Name: "firewall-cmd", Args: inverse})
			if e := c.save("pending.json", j); e != nil {
				return e
			}
			if _, e := c.exec(ctx, "firewall-cmd", args...); e != nil {
				return e
			}
		}
		return nil
	}
	return errors.New("invalid rule backend")
}
func (c *Controller) firewallPreview(ctx context.Context, r model.SecurityRequest) (model.SecurityPreview, error) {
	for _, ports := range [][]int{r.SSHPorts, r.PanelPorts} {
		if len(ports) > 64 {
			return model.SecurityPreview{}, errors.New("管理端口最多 64 个")
		}
		for _, port := range ports {
			if port < 1 || port > 65535 {
				return model.SecurityPreview{}, errors.New("管理端口需为 1–65535")
			}
		}
	}

	f, e := c.Firewall(ctx, r.Zone)
	if e != nil {
		return model.SecurityPreview{}, e
	}
	p := model.SecurityPreview{Revision: f.Revision, Changes: []string{}, Warnings: []string{}, RequiredPorts: f.RequiredPorts}
	if c.Demo {
		return p, errors.New(f.Reason)
	}
	if f.Pending != nil {
		return p, errors.New("上次安全变更尚待确认或恢复")
	}
	if !f.Writable {
		return p, errors.New(f.Reason)
	}
	if r.Operation == "install" {
		if f.Installed {
			return p, errors.New("组件已安装")
		}
		p.Changes = []string{"安装 " + f.Backend + "，保持防火墙未启用"}
		return p, nil
	}
	if !f.Installed {
		return p, errors.New("请先安装防火墙组件")
	}
	ssh, panel := c.ports(ctx)
	state, _ := c.state()
	if len(ssh) == 0 {
		ssh = state.SSHPorts
	}
	if len(panel) == 0 {
		panel = state.PanelPorts
	}
	if len(ssh) == 0 {
		ssh = uniquePorts(r.SSHPorts)
	}
	if len(panel) == 0 {
		panel = uniquePorts(r.PanelPorts)
	}
	if len(ssh) == 0 || len(panel) == 0 {
		return p, errors.New("无法识别 SSH 或面板入口，请填写并确认真实端口")
	}
	p.RequiredPorts = defaultRequired(ssh, panel, c.publicNodes(ctx))
	switch r.Operation {
	case "enable":
		for _, rr := range f.Rules {
			if !rr.Adoptable {
				return p, errors.New("已有复杂规则无法判断管理端口可达性，请先核对")
			}
			for _, port := range p.RequiredPorts {
				if rr.Action == "deny" && rr.Protocol == port.Protocol && port.Port >= rr.PortFrom && port.Port <= rr.PortTo {
					return p, errors.New("已有拒绝规则覆盖需保留的端口，请先核对并处理")
				}
			}
		}
		if f.Backend == "firewalld" && f.Active {
			if _, e := c.fireRuntime(ctx); e != nil {
				return p, e
			}
		}
		p.Changes = []string{"默认拒绝其他入站，保留已有规则，放行下方端口"}
		p.NeedsConfirmation = true
	case "disable":
		fb, e := c.Fail2ban(ctx)
		if e != nil {
			return p, e
		}
		if fb.Active && (f.Backend == "ufw" || f.Backend == "firewalld") {
			return p, errors.New("请先停用依赖此防火墙的 SSH 防护")
		}
		p.Changes = []string{"关闭当前防火墙入站保护；保留配置"}
		p.NeedsConfirmation = true
	case "add":
		rr, e := normalizeRule(r.Rule)
		if e != nil {
			return p, e
		}
		rr.Zone = f.Zone
		for _, v := range f.Rules {
			if sameRule(rr, v) {
				return p, errors.New("已有相同规则")
			}
		}
		for _, v := range p.RequiredPorts {
			if v.Protected && rr.Action == "deny" && v.Protocol == rr.Protocol && v.Port >= rr.PortFrom && v.Port <= rr.PortTo {
				return p, errors.New("不能拒绝 SSH 或面板入口端口")
			}
		}
		p.NeedsConfirmation = rr.Action == "deny"
		if f.Backend == "ufw" {
			replaced, e := ufwReplacements(rr, f.Rules)
			if e != nil {
				return p, e
			}
			for _, old := range replaced {
				p.Changes = append(p.Changes, "delete "+ruleKey(old))
				p.NeedsConfirmation = true
			}
		}
		p.Changes = append(p.Changes, ruleKey(rr))
	case "delete", "adopt":
		var rr *model.SecurityRule
		for _, v := range f.Rules {
			if v.ID == r.RuleID {
				copy := v
				rr = &copy
				break
			}
		}
		if rr == nil || !rr.Adoptable {
			return p, errors.New("只能操作完整识别的简单规则")
		}
		if r.Operation == "delete" {
			if !rr.Managed {
				return p, errors.New("请先确认接管此规则")
			}
			if rr.Protected {
				return p, errors.New("SSH 和面板入口规则受保护")
			}
			p.NeedsConfirmation = true
		} else if rr.Managed {
			return p, errors.New("规则已由悟空管理")
		}
		p.Changes = []string{r.Operation + " " + ruleKey(*rr)}
	default:
		return p, errors.New("未知防火墙操作")
	}
	if f.Backend == "firewalld" && r.Operation == "enable" && f.Active && f.Policy != "deny" {
		p.Warnings = append(p.Warnings, "将更新区域默认策略并重载；保留所有区域运行规则及封禁")
	}
	p.Warnings = append(p.Warnings, "主机规则不代替云安全组或 NAT 映射")
	return p, nil
}
func (c *Controller) applyFirewall(ctx context.Context, r model.SecurityRequest, j *journal, s *state) error {
	f, e := c.Firewall(ctx, r.Zone)
	if e != nil {
		return e
	}
	if r.Operation == "adopt" {
		for _, rr := range f.Rules {
			if rr.ID == r.RuleID {
				rr.Managed = true
				s.Rules = append(s.Rules, rr)
				return nil
			}
		}
		return errors.New("规则不存在")
	}
	if f.Backend == "firewalld" && !f.Active && r.Operation == "enable" {
		ssh, panel := c.ports(ctx)
		if len(ssh) == 0 {
			ssh = s.SSHPorts
		}
		if len(panel) == 0 {
			panel = s.PanelPorts
		}
		if len(ssh) == 0 {
			ssh = r.SSHPorts
		}
		if len(panel) == 0 {
			panel = r.PanelPorts
		}
		for _, port := range defaultRequired(ssh, panel, c.publicNodes(ctx)) {
			rr := model.SecurityRule{ID: token(), Action: "allow", Protocol: port.Protocol, PortFrom: port.Port, PortTo: port.Port, Source: "any", Zone: f.Zone, Managed: true, Adoptable: true, Protected: port.Protected}
			exists := false
			for _, old := range f.Rules {
				if sameRule(rr, old) {
					exists = true
				}
			}
			if !exists {
				if _, e = c.exec(ctx, "firewall-offline-cmd", fireArgs(rr, false, false)...); e != nil {
					return e
				}
				s.Rules = append(s.Rules, rr)
			}
		}
		if e = c.service(ctx, "start", "firewalld"); e != nil {
			return e
		}
		f, e = c.Firewall(ctx, r.Zone)
		if e != nil {
			return e
		}
		if !f.Writable {
			return errors.New(f.Reason)
		}
	}
	rules := append([]model.SecurityRule{}, f.Rules...)
	if r.Operation == "add" {
		rr, _ := normalizeRule(r.Rule)
		rr.Zone = f.Zone
		if f.Backend == "ufw" {
			replaced, e := ufwReplacements(rr, f.Rules)
			if e != nil {
				return e
			}
			removed := map[string]bool{}
			for _, old := range replaced {
				if e := c.changeRule(ctx, f.Backend, old, true, j); e != nil {
					return e
				}
				removed[old.ID] = true
			}
			// Do not reuse s.Rules' backing array: the rollback journal retains
			// the original slice and must restore every original rule/ID.
			kept := make([]model.SecurityRule, 0, len(s.Rules))
			for _, old := range s.Rules {
				if !removed[old.ID] {
					kept = append(kept, old)
				}
			}
			s.Rules = kept
		}
		rr.Managed = true
		rr.Adoptable = true
		rr.ID = token()
		rules = append(rules, rr)
		s.Rules = append(s.Rules, rr)
		if f.Backend != "nftables" {
			if e = c.changeRule(ctx, f.Backend, rr, false, j); e != nil {
				return e
			}
		}
	}
	if r.Operation == "delete" {
		filtered := []model.SecurityRule{}
		for _, rr := range rules {
			if rr.ID == r.RuleID {
				if f.Backend != "nftables" {
					if e = c.changeRule(ctx, f.Backend, rr, true, j); e != nil {
						return e
					}
				}
			} else {
				filtered = append(filtered, rr)
			}
		}
		rules = filtered
		filtered = []model.SecurityRule{}
		for _, rr := range s.Rules {
			if rr.ID != r.RuleID {
				filtered = append(filtered, rr)
			}
		}
		s.Rules = filtered
	}
	if r.Operation == "enable" {
		if f.Backend == "ufw" {
			b, e := c.read("/etc/default/ufw")
			if e != nil && !errors.Is(e, os.ErrNotExist) {
				return e
			}
			text := string(b)
			re := regexp.MustCompile(`(?m)^IPV6=.*$`)
			if re.MatchString(text) {
				text = re.ReplaceAllString(text, "IPV6=yes")
			} else {
				text += "\nIPV6=yes\n"
			}
			if e = atomic(c.path("/etc/default/ufw"), []byte(text), 0644); e != nil {
				return e
			}
		}
		ssh, panel := c.ports(ctx)
		if len(ssh) == 0 {
			ssh = s.SSHPorts
		}
		if len(panel) == 0 {
			panel = s.PanelPorts
		}
		if len(ssh) == 0 {
			ssh = r.SSHPorts
		}
		if len(panel) == 0 {
			panel = r.PanelPorts
		}
		s.SSHPorts = uniquePorts(ssh)
		s.PanelPorts = uniquePorts(panel)
		for _, p := range defaultRequired(ssh, panel, c.publicNodes(ctx)) {
			rr := model.SecurityRule{ID: token(), Action: "allow", Protocol: p.Protocol, PortFrom: p.Port, PortTo: p.Port, Source: "any", Zone: f.Zone, Managed: true, Adoptable: true, Protected: p.Protected}
			exists := false
			for _, v := range rules {
				if sameRule(rr, v) {
					exists = true
				}
			}
			if exists && f.Backend == "ufw" {
				if e = c.changeRule(ctx, f.Backend, rr, false, j); e != nil {
					return e
				}
			}
			if !exists {
				rules = append(rules, rr)
				s.Rules = append(s.Rules, rr)
				if f.Backend != "nftables" {
					if e = c.changeRule(ctx, f.Backend, rr, false, j); e != nil {
						return e
					}
				}
			}
		}
	}
	switch f.Backend {
	case "nftables":
		active := f.Active && f.Policy == "deny"
		if r.Operation == "enable" {
			active = true
		}
		if r.Operation == "disable" {
			active = false
		}
		s.NFTRules = append([]model.SecurityRule{}, rules...)
		s.NFTInactive = !active
		if e = c.applyNFT(ctx, rules, active); e != nil {
			return e
		}
		if e = c.persistNFT(ctx); e != nil {
			return e
		}
		return e
	case "ufw":
		if r.Operation == "enable" {
			for _, a := range [][]string{{"default", "deny", "incoming"}, {"default", "allow", "outgoing"}, {"--force", "enable"}} {
				if _, e = c.exec(ctx, "ufw", a...); e != nil {
					return e
				}
			}
		} else if r.Operation == "disable" {
			_, e = c.exec(ctx, "ufw", "--force", "disable")
		}
		if e == nil && r.Operation == "enable" {
			e = c.setBoot(ctx, "ufw", true)
		}
		return e
	case "firewalld":
		if r.Operation == "disable" {
			if e = c.service(ctx, "stop", "firewalld"); e != nil {
				return e
			}
			return c.setBoot(ctx, "firewalld", false)
		}
		if r.Operation == "enable" {
			if e = c.setBoot(ctx, "firewalld", true); e != nil {
				return e
			}
			if !f.Active {
				return errors.New("请先启动 firewalld 后重新预览")
			}
			// DROP zones do not inherit the default target's ICMP allowance.
			// Preserve PMTU discovery, IPv6 control traffic and ping explicitly.
			for _, protocol := range []string{"icmp", "ipv6-icmp"} {
				for _, permanent := range []bool{false, true} {
					args := []string{"--zone=" + f.Zone, `--add-rich-rule=rule protocol value="` + protocol + `" accept`}
					undo := []string{"--zone=" + f.Zone, `--remove-rich-rule=rule protocol value="` + protocol + `" accept`}
					if permanent {
						args = append(args, "--permanent")
						undo = append(undo, "--permanent")
					}
					query := append([]string{}, args...)
					query[1] = strings.Replace(query[1], "--add-rich-rule=", "--query-rich-rule=", 1)
					if _, e = c.exec(ctx, "firewall-cmd", query...); e == nil {
						continue
					}
					j.Undo = append(j.Undo, command{Name: "firewall-cmd", Args: undo})
					if e = c.save("pending.json", j); e != nil {
						return e
					}
					if _, e = c.exec(ctx, "firewall-cmd", args...); e != nil {
						return e
					}
				}
			}
			if f.Policy != "deny" {
				runtime, e := c.fireRuntime(ctx)
				if e != nil {
					return e
				}
				target, e := c.exec(ctx, "firewall-cmd", "--permanent", "--zone="+f.Zone, "--get-target")
				if e != nil {
					return e
				}
				_ = target
				if len(j.Runtime) == 0 {
					j.Runtime = runtime
				}
				if e = c.save("pending.json", j); e != nil {
					return e
				}
				if _, e = c.exec(ctx, "firewall-cmd", "--permanent", "--zone="+f.Zone, "--set-target=DROP"); e != nil {
					return e
				}
				if _, e = c.exec(ctx, "firewall-cmd", "--reload"); e != nil {
					return e
				}
				for _, op := range runtime {
					if _, e = c.Run(ctx, op.Name, op.Args, op.Input); e != nil {
						return e
					}
				}
				return c.resyncBans(ctx, j.Bans)
			}
		}
	}
	return nil
}

// Reconstruct runtime-only settings after a firewalld reload. Reject unfamiliar
// output rather than silently discarding interface bindings or forwarding rules.
func (c *Controller) fireRuntime(ctx context.Context) ([]command, error) {
	out, e := c.exec(ctx, "firewall-cmd", "--list-all-zones")
	if e != nil {
		return nil, e
	}
	ops := []command{}
	zone := ""
	for _, l := range strings.Split(out, "\n") {
		if l == "" {
			continue
		}
		if !strings.HasPrefix(l, " ") {
			f := strings.Fields(l)
			if len(f) > 0 {
				zone = f[0]
			}
			if !nameRE.MatchString(zone) {
				return nil, errors.New("invalid zone")
			}
			continue
		}
		if strings.HasPrefix(strings.TrimSpace(l), "rule ") {
			ops = append(ops, command{Name: "firewall-cmd", Args: []string{"--zone=" + zone, "--add-rich-rule=" + strings.TrimSpace(l)}})
			continue
		}
		f := strings.SplitN(strings.TrimSpace(l), ":", 2)
		if len(f) != 2 {
			continue
		}
		key, v := f[0], strings.TrimSpace(f[1])
		if v == "" || v == "no" {
			continue
		}
		prefix := ""
		switch key {
		case "target", "priority", "ingress-priority", "egress-priority", "icmp-block-inversion", "forward":
			if key == "forward" && v == "yes" {
				prefix = "--add-forward"
			} else if key == "icmp-block-inversion" && v == "yes" {
				prefix = "--add-icmp-block-inversion"
			} else {
				continue
			}
		case "interfaces":
			prefix = "--change-interface="
		case "sources":
			prefix = "--add-source="
		case "services":
			prefix = "--add-service="
		case "ports":
			prefix = "--add-port="
		case "protocols":
			prefix = "--add-protocol="
		case "source-ports":
			prefix = "--add-source-port="
		case "icmp-blocks":
			prefix = "--add-icmp-block="
		case "masquerade":
			prefix = "--add-masquerade"
		case "rich rules":
			continue
		default:
			if strings.HasPrefix(strings.TrimSpace(l), "rule ") {
				ops = append(ops, command{Name: "firewall-cmd", Args: []string{"--zone=" + zone, "--add-rich-rule=" + strings.TrimSpace(l)}})
				continue
			}
			return nil, errors.New("当前 firewalld 运行配置无法完整保存：" + key)
		}
		if strings.HasSuffix(prefix, "=") {
			for _, value := range strings.Fields(v) {
				ops = append(ops, command{Name: "firewall-cmd", Args: []string{"--zone=" + zone, prefix + value}})
			}
		} else {
			ops = append(ops, command{Name: "firewall-cmd", Args: []string{"--zone=" + zone, prefix}})
		}
	}
	return ops, nil
}

// Firewall backup is constrained to the selected manager's files/table.
func (c *Controller) firewallBackup(ctx context.Context, j *journal, f model.FirewallState) error {
	j.Backend = f.Backend
	switch f.Backend {
	case "ufw":
		if e := c.backup(j, "/etc/ufw/user.rules", "/etc/ufw/user6.rules", "/etc/ufw/ufw.conf", "/etc/default/ufw"); e != nil {
			return e
		}
		a := []string{"--force", "disable"}
		if f.Active {
			a = []string{"--force", "enable"}
		}
		j.Undo = []command{{Name: "ufw", Args: a}}
	case "nftables":
		if e := c.backup(j, nftPath, "/etc/systemd/system/wukong-firewall.service", "/etc/init.d/wukong-firewall"); e != nil {
			return e
		}
		body, e := c.exec(ctx, "nft", "-s", "list", "table", "inet", "wukong_panel")
		if e != nil {
			body = ""
		}
		j.Undo = []command{{Name: "nft-restore", Input: body}}
	case "firewalld":
		if f.Active {
			var e error
			j.Runtime, e = c.fireRuntime(ctx)
			if e != nil {
				return e
			}
		}
		if e := c.backup(j, "/etc/firewalld/zones/"+f.Zone+".xml"); e != nil {
			return e
		}
		if !f.Active {
			j.Undo = []command{{Name: "service-stop-firewalld"}}
		} else {
			j.Undo = []command{{Name: "service-start-firewalld"}}
		}
	}
	if !f.Installed {
		j.Undo = nil
		j.Runtime = nil
	}
	return nil
}
