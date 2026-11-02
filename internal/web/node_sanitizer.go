package web

import (
	"encoding/base64"
	"encoding/json"
	"net/url"
	"regexp"
	"strings"
)

// Regex matching regional indicator symbols (flag emojis)
var flagEmojiRegex = regexp.MustCompile(`[\x{1F1E6}-\x{1F1FF}]{2}`)

type regionPattern struct {
	Flag     string
	Patterns []*regexp.Regexp
}

var regionRules = []regionPattern{
	{
		Flag: "🇭🇰",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)香港|hong\s*kong|hongkong|(?:^|[^a-z0-9])hkg?(?:[^a-z0-9]|$)|深港|沪港|穗港|京港`),
		},
	},
	{
		Flag: "🇹🇼",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)台湾|台灣|taiwan|taipei|(?:^|[^a-z0-9])twn?(?:[^a-z0-9]|$)|台北|新北|台中|高雄|台南`),
		},
	},
	{
		Flag: "🇯🇵",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)日本|japan|tokyo|osaka|(?:^|[^a-z0-9])jpn?(?:[^a-z0-9]|$)|东京|大阪|川崎|名古屋|福冈|冲绳|北海道`),
		},
	},
	{
		Flag: "🇸🇬",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)新加坡|狮城|星加坡|singapore|(?:^|[^a-z0-9])sgp?(?:[^a-z0-9]|$)|坡县`),
		},
	},
	{
		Flag: "🇺🇸",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)美国|美國|united\s*states|(?:^|[^a-z0-9])usa?(?:[^a-z0-9]|$)|america|los\s*angeles|san\s*jose|silicon\s*valley|new\s*york|seattle|chicago|dallas|miami|phoenix|portland|oregon|洛杉矶|圣何塞|硅谷|西雅图|芝加哥|纽约|达拉斯|迈阿密|波特兰|俄勒冈|凤凰城`),
		},
	},
	{
		Flag: "🇰🇷",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)韩国|韓國|korea|seoul|(?:^|[^a-z0-9])kor?(?:[^a-z0-9]|$)|首尔|仁川|釜山`),
		},
	},
	{
		Flag: "🇬🇧",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)英国|英國|united\s*kingdom|(?:^|[^a-z0-9])(?:uk|gbr?)(?:[^a-z0-9]|$)|london|manchester|伦敦|曼彻斯特|大不列颠`),
		},
	},
	{
		Flag: "🇩🇪",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)德国|德國|germany|deutschland|(?:^|[^a-z0-9])deu?(?:[^a-z0-9]|$)|frankfurt|berlin|munich|法兰克福|柏林|慕尼黑`),
		},
	},
	{
		Flag: "🇫🇷",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)法国|法國|france|(?:^|[^a-z0-9])fra?(?:[^a-z0-9]|$)|paris|巴黎|马赛`),
		},
	},
	{
		Flag: "🇨🇦",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)加拿大|canada|(?:^|[^a-z0-9])can?(?:[^a-z0-9]|$)|toronto|vancouver|montreal|多伦多|温哥华|蒙特利尔`),
		},
	},
	{
		Flag: "🇦🇺",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)澳大利亚|澳大利亞|澳洲|australia|(?:^|[^a-z0-9])aus?(?:[^a-z0-9]|$)|sydney|melbourne|悉尼|墨尔本|布里斯班`),
		},
	},
	{
		Flag: "🇷🇺",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)俄罗斯|俄羅斯|russia|(?:^|[^a-z0-9])rus?(?:[^a-z0-9]|$)|moscow|saint\s*petersburg|莫斯科|圣彼得堡|海参崴`),
		},
	},
	{
		Flag: "🇳🇱",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)荷兰|荷蘭|netherlands|holland|(?:^|[^a-z0-9])nld?(?:[^a-z0-9]|$)|amsterdam|阿姆斯特丹`),
		},
	},
	{
		Flag: "🇹🇷",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)土耳其|turkey|türkiye|(?:^|[^a-z0-9])tur?(?:[^a-z0-9]|$)|istanbul|伊斯坦布尔`),
		},
	},
	{
		Flag: "🇮🇳",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)印度|india|(?:^|[^a-z0-9])ind?(?:[^a-z0-9]|$)|mumbai|delhi|孟买|新德里`),
		},
	},
	{
		Flag: "🇲🇾",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)马来西亚|馬來西亞|大马|malaysia|(?:^|[^a-z0-9])mys?(?:[^a-z0-9]|$)|kuala\s*lumpur|吉隆坡`),
		},
	},
	{
		Flag: "🇹🇭",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)泰国|泰國|thailand|(?:^|[^a-z0-9])tha?(?:[^a-z0-9]|$)|bangkok|曼谷`),
		},
	},
	{
		Flag: "🇵🇭",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)菲律宾|菲律賓|philippines|(?:^|[^a-z0-9])phl?(?:[^a-z0-9]|$)|manila|马尼拉`),
		},
	},
	{
		Flag: "🇻🇳",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)越南|vietnam|(?:^|[^a-z0-9])vnm?(?:[^a-z0-9]|$)|ho\s*chi\s*minh|hanoi|胡志明|河内`),
		},
	},
	{
		Flag: "🇮🇩",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)印尼|印度尼西亚|indonesia|(?:^|[^a-z0-9])idn?(?:[^a-z0-9]|$)|jakarta|雅加达`),
		},
	},
	{
		Flag: "🇦🇪",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)阿联酋|阿拉伯联合酋长国|uae|dubai|迪拜`),
		},
	},
	{
		Flag: "🇨🇭",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)瑞士|switzerland|(?:^|[^a-z0-9])che?(?:[^a-z0-9]|$)|zurich|geneva|苏黎世|日内瓦`),
		},
	},
	{
		Flag: "🇸🇪",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)瑞典|sweden|(?:^|[^a-z0-9])swe?(?:[^a-z0-9]|$)|stockholm|斯德哥尔摩`),
		},
	},
	{
		Flag: "🇳🇴",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)挪威|norway|(?:^|[^a-z0-9])nor?(?:[^a-z0-9]|$)|oslo|奥斯陆`),
		},
	},
	{
		Flag: "🇫🇮",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)芬兰|finland|(?:^|[^a-z0-9])fin?(?:[^a-z0-9]|$)|helsinki|赫尔辛基`),
		},
	},
	{
		Flag: "🇪🇸",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)西班牙|spain|(?:^|[^a-z0-9])esp?(?:[^a-z0-9]|$)|madrid|barcelona|马德里|巴塞罗那`),
		},
	},
	{
		Flag: "🇮🇹",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)意大利|italy|(?:^|[^a-z0-9])ita?(?:[^a-z0-9]|$)|milan|rome|米兰|罗马`),
		},
	},
	{
		Flag: "🇧🇷",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)巴西|brazil|(?:^|[^a-z0-9])bra?(?:[^a-z0-9]|$)|sao\s*paulo|圣保罗`),
		},
	},
	{
		Flag: "🇦🇷",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)阿根廷|argentina|(?:^|[^a-z0-9])arg?(?:[^a-z0-9]|$)|buenos\s*aires|布宜诺斯艾利斯`),
		},
	},
	{
		Flag: "🇿🇦",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)南非|south\s*africa|(?:^|[^a-z0-9])zaf?(?:[^a-z0-9]|$)|johannesburg|约翰内斯堡`),
		},
	},
	{
		Flag: "🇨🇳",
		Patterns: []*regexp.Regexp{
			regexp.MustCompile(`(?i)中国|中华|china|(?:^|[^a-z0-9])chn?(?:[^a-z0-9]|$)|北京|上海|广州|深圳|杭州|成都|重庆|武汉|南京`),
		},
	},
}

var regionMetaMap = map[string]struct {
	Code string
	Name string
}{
	"🇭🇰": {Code: "HK", Name: "香港"},
	"🇹🇼": {Code: "TW", Name: "台湾"},
	"🇯🇵": {Code: "JP", Name: "日本"},
	"🇸🇬": {Code: "SG", Name: "新加坡"},
	"🇺🇸": {Code: "US", Name: "美国"},
	"🇰🇷": {Code: "KR", Name: "韩国"},
	"🇬🇧": {Code: "GB", Name: "英国"},
	"🇩🇪": {Code: "DE", Name: "德国"},
	"🇫🇷": {Code: "FR", Name: "法国"},
	"🇳🇱": {Code: "NL", Name: "荷兰"},
	"🇷🇺": {Code: "RU", Name: "俄罗斯"},
	"🇮🇳": {Code: "IN", Name: "印度"},
	"🇦🇺": {Code: "AU", Name: "澳大利亚"},
	"🇨🇦": {Code: "CA", Name: "加拿大"},
	"🇹🇷": {Code: "TR", Name: "土耳其"},
	"🇲🇾": {Code: "MY", Name: "马来西亚"},
	"🇹🇭": {Code: "TH", Name: "泰国"},
	"🇵🇭": {Code: "PH", Name: "菲律宾"},
	"🇻🇳": {Code: "VN", Name: "越南"},
	"🇮🇩": {Code: "ID", Name: "印尼"},
	"🇦🇪": {Code: "AE", Name: "阿联酋"},
	"🇨🇭": {Code: "CH", Name: "瑞士"},
	"🇸🇪": {Code: "SE", Name: "瑞典"},
	"🇳🇴": {Code: "NO", Name: "挪威"},
	"🇫🇮": {Code: "FI", Name: "芬兰"},
	"🇪🇸": {Code: "ES", Name: "西班牙"},
	"🇮🇹": {Code: "IT", Name: "意大利"},
	"🇧🇷": {Code: "BR", Name: "巴西"},
	"🇦🇷": {Code: "AR", Name: "阿根廷"},
	"🇿🇦": {Code: "ZA", Name: "南非"},
	"🇨🇳": {Code: "CN", Name: "中国"},
}

var canonicalRegionOrder = []string{
	"🇭🇰", "🇹🇼", "🇯🇵", "🇸🇬", "🇺🇸", "🇰🇷", "🇬🇧", "🇩🇪", "🇫🇷", "🇳🇱",
	"🇷🇺", "🇮🇳", "🇦🇺", "🇨🇦", "🇹🇷", "🇲🇾", "🇹🇭", "🇵🇭", "🇻🇳", "🇮🇩",
	"🇦🇪", "🇨🇭", "🇸🇪", "🇳🇴", "🇫🇮", "🇪🇸", "🇮🇹", "🇧🇷", "🇦🇷", "🇿🇦",
	"🇨🇳",
}

// RegionMeta describes detected country / regional identity for node grouping.
type RegionMeta struct {
	Code      string `json:"code"`
	Name      string `json:"name"`
	Flag      string `json:"flag"`
	GroupName string `json:"groupName"`
	AutoName  string `json:"autoName"`
}

// RegionalProxyGroup represents a grouped set of proxies belonging to a country / region.
type RegionalProxyGroup struct {
	Flag      string   `json:"flag"`
	Name      string   `json:"name"`
	GroupName string   `json:"groupName"`
	AutoName  string   `json:"autoName"`
	Proxies   []string `json:"proxies"`
}

// DetectNodeRegion determines the regional identity of a node name.
// For chained nodes ("前置 ➔ 落地"), the region of the exit node is prioritized.
func DetectNodeRegion(name string) RegionMeta {
	target := name
	if idx := strings.LastIndex(target, "➔"); idx >= 0 {
		target = strings.TrimSpace(target[idx+len("➔"):])
	} else if idx := strings.LastIndex(target, "->"); idx >= 0 {
		target = strings.TrimSpace(target[idx+len("->"):])
	}

	// 1. Check if target contains flag emoji
	if flags := flagEmojiRegex.FindAllString(target, -1); len(flags) > 0 {
		flag := flags[len(flags)-1]
		if meta, ok := regionMetaMap[flag]; ok {
			return RegionMeta{
				Code:      meta.Code,
				Name:      meta.Name,
				Flag:      flag,
				GroupName: flag + " " + meta.Name + "节点",
				AutoName:  "♻️ " + meta.Name + "自动",
			}
		}
	}

	// 2. Check regionRules patterns
	for _, rule := range regionRules {
		for _, pattern := range rule.Patterns {
			if pattern.MatchString(target) {
				if meta, ok := regionMetaMap[rule.Flag]; ok {
					return RegionMeta{
						Code:      meta.Code,
						Name:      meta.Name,
						Flag:      rule.Flag,
						GroupName: rule.Flag + " " + meta.Name + "节点",
						AutoName:  "♻️ " + meta.Name + "自动",
					}
				}
			}
		}
	}

	return RegionMeta{
		Code:      "OTHER",
		Name:      "其他地区",
		Flag:      "🌐",
		GroupName: "🌐 其他节点",
		AutoName:  "♻️ 其他自动",
	}
}

// GroupProxiesByRegion partitions proxy names into ordered regional groups.
func GroupProxiesByRegion(proxyNames []string) []RegionalProxyGroup {
	proxiesByFlag := make(map[string][]string)
	for _, name := range proxyNames {
		region := DetectNodeRegion(name)
		proxiesByFlag[region.Flag] = append(proxiesByFlag[region.Flag], name)
	}

	var groups []RegionalProxyGroup
	for _, flag := range canonicalRegionOrder {
		proxies, ok := proxiesByFlag[flag]
		if ok && len(proxies) > 0 {
			meta := regionMetaMap[flag]
			groups = append(groups, RegionalProxyGroup{
				Flag:      flag,
				Name:      meta.Name,
				GroupName: flag + " " + meta.Name + "节点",
				AutoName:  "♻️ " + meta.Name + "自动",
				Proxies:   proxies,
			})
		}
	}

	if otherProxies, ok := proxiesByFlag["🌐"]; ok && len(otherProxies) > 0 {
		groups = append(groups, RegionalProxyGroup{
			Flag:      "🌐",
			Name:      "其他地区",
			GroupName: "🌐 其他节点",
			AutoName:  "♻️ 其他自动",
			Proxies:   otherProxies,
		})
	}

	return groups
}

var (
	rateBracketRegex = regexp.MustCompile(`(?i)\[\s*[0-9.]+\s*(?:x|倍率?)\s*\]|\(\s*[0-9.]+\s*(?:x|倍率?)\s*\)`)
	adKeywordRegex   = regexp.MustCompile(`(?i)剩余流量|到期时间|官网|防失联|发布页|最新地址|最新网址|客服|TG群|交流群|TG频道|禁止BT|请勿测速|打卡返利|永久域名|http://|https://|www\.|t\.me`)
	urlRegex         = regexp.MustCompile(`(?i)https?://[^\s|｜)\]]+|\bwww\.[a-z0-9-]+\.[a-z]+(?::[0-9]+)?(?:/[^\s|｜)\]]*)?`)
	inlineAdRegex    = regexp.MustCompile(`(?i)(?:剩余流量|到期时间|官网|防失联|发布页|最新地址|最新网址|客服|TG群|交流群|TG频道|禁止BT|请勿测速|打卡返利|永久域名)[^|｜\n]*`)
	trimSepRegex     = regexp.MustCompile(`^[|｜\s\-_/]+|[|｜\s\-_/]+$`)
)

// SanitizeNodeName removes advertising texts, rate indicators, and promotional noise.
func SanitizeNodeName(raw string) string {
	s := strings.TrimSpace(raw)
	if s == "" {
		return ""
	}

	// 1. Remove bracketed rates
	s = rateBracketRegex.ReplaceAllString(s, "")

	// 2. Split into segments by pipe
	if strings.ContainsAny(s, "|｜") {
		parts := strings.FieldsFunc(s, func(r rune) bool {
			return r == '|' || r == '｜'
		})
		var cleanParts []string
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" && !adKeywordRegex.MatchString(trimmed) {
				cleanParts = append(cleanParts, trimmed)
			}
		}
		if len(cleanParts) > 0 {
			s = strings.Join(cleanParts, " | ")
		}
	}

	// 3. Clean ' - ' separated trailing ad parts
	if strings.Contains(s, " - ") {
		parts := strings.Split(s, " - ")
		var cleanParts []string
		for _, p := range parts {
			trimmed := strings.TrimSpace(p)
			if trimmed != "" && !adKeywordRegex.MatchString(trimmed) {
				cleanParts = append(cleanParts, trimmed)
			}
		}
		if len(cleanParts) > 0 {
			s = strings.Join(cleanParts, " - ")
		}
	}

	// 4. Fallback cleanup for inline keywords and leftover URLs
	s = urlRegex.ReplaceAllString(s, "")
	s = inlineAdRegex.ReplaceAllString(s, "")
	s = trimSepRegex.ReplaceAllString(s, "")
	s = strings.TrimSpace(s)

	if s == "" {
		return strings.TrimSpace(raw)
	}
	return s
}

// MatchCountryFlag checks if a name corresponds to a known region and returns its emoji flag.
func MatchCountryFlag(name string) string {
	if name == "" || flagEmojiRegex.MatchString(name) {
		return ""
	}
	for _, rule := range regionRules {
		for _, pattern := range rule.Patterns {
			if pattern.MatchString(name) {
				return rule.Flag
			}
		}
	}
	return ""
}

// InjectCountryFlag prepends national / regional flag emoji if none exists.
func InjectCountryFlag(name string) string {
	if name == "" {
		return ""
	}
	flag := MatchCountryFlag(name)
	if flag != "" {
		return flag + " " + name
	}
	return name
}

// SanitizeAndFlagNodeName combines sanitization and flag injection.
func SanitizeAndFlagNodeName(raw string) string {
	clean := SanitizeNodeName(raw)
	return InjectCountryFlag(clean)
}

// UpdateShareURIName replaces or appends the node name in the share URI fragment or VMess ps field.
func UpdateShareURIName(shareURI, newName string) string {
	if shareURI == "" || newName == "" {
		return shareURI
	}
	lower := strings.ToLower(shareURI)
	if strings.HasPrefix(lower, "vmess://") {
		encoded := strings.TrimPrefix(shareURI, "vmess://")
		decoded, err := base64.StdEncoding.DecodeString(encoded)
		if err != nil {
			decoded, err = base64.RawStdEncoding.DecodeString(encoded)
		}
		if err != nil {
			decoded, err = base64.URLEncoding.DecodeString(encoded)
		}
		if err == nil {
			var vm map[string]any
			if json.Unmarshal(decoded, &vm) == nil {
				vm["ps"] = newName
				if updatedJSON, err := json.Marshal(vm); err == nil {
					return "vmess://" + base64.StdEncoding.EncodeToString(updatedJSON)
				}
			}
		}
		return shareURI
	}

	// Standard URIs (vless, ss, trojan, hysteria2, etc.): fragment after '#'
	parts := strings.SplitN(shareURI, "#", 2)
	return parts[0] + "#" + url.QueryEscape(newName)
}
