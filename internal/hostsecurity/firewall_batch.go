package hostsecurity

import (
	"errors"
	"github.com/252201/wukong-panel/internal/model"
)

// Resolve the complete selection before any mutation. Mixed or invalid batches
// fail as a whole; callers never silently skip protected or external rules.
func selectedFirewallRules(r model.SecurityRequest, rules []model.SecurityRule) ([]model.SecurityRule, error) {
	ids := []string{r.RuleID}
	if r.Operation == "batch-adopt" || r.Operation == "batch-delete" {
		if r.RuleID != "" || len(r.RuleIDs) < 1 || len(r.RuleIDs) > 100 {
			return nil, errors.New("批量操作需选择 1–100 条规则，不能同时指定单条规则")
		}
		ids = r.RuleIDs
	}
	seen := map[string]bool{}
	selected := make([]model.SecurityRule, 0, len(ids))
	adopt := r.Operation == "adopt" || r.Operation == "batch-adopt"
	for _, id := range ids {
		if !idRE.MatchString(id) || seen[id] {
			return nil, errors.New("规则 ID 无效或重复")
		}
		seen[id] = true
		var rule *model.SecurityRule
		for _, v := range rules {
			if v.ID == id {
				copy := v
				rule = &copy
				break
			}
		}
		if rule == nil || !rule.Adoptable {
			return nil, errors.New("只能操作完整识别的简单规则")
		}
		if adopt {
			if rule.Managed {
				return nil, errors.New("规则已由悟空管理")
			}
		} else {
			if !rule.Managed {
				return nil, errors.New("请先确认接管此规则")
			}
			if rule.Protected {
				return nil, errors.New("SSH 和面板入口规则受保护")
			}
		}
		selected = append(selected, *rule)
	}
	return selected, nil
}
