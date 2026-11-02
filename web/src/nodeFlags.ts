/**
 * Node Flag Emoji Detector, Region Grouping, and Formatter for External Subscriptions
 *
 * Automatically inspects node names (such as "Hong Kong | 01", "Tokyo 02", "台湾 03")
 * and prepends corresponding national / regional flag emojis if absent, groups nodes
 * by geographical region, and cleans common advertising noise.
 */

// Regex matching any existing regional indicator flag emoji (U+1F1E6 to U+1F1FF pair)
export const FLAG_EMOJI_REGEX = /[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/

export interface RegionRule {
  code: string
  name: string
  flag: string
  patterns: (string | RegExp)[]
}

export const REGION_RULES: RegionRule[] = [
  {
    code: 'HK',
    name: '香港',
    flag: '🇭🇰',
    patterns: [
      /香港/i,
      /hong\s*kong/i,
      /hongkong/i,
      /(?:^|[^a-z0-9])hkg?(?:[^a-z0-9]|$)/i,
      /深港/i,
      /沪港/i,
      /穗港/i,
      /京港/i,
    ],
  },
  {
    code: 'TW',
    name: '台湾',
    flag: '🇹🇼',
    patterns: [
      /台湾/i,
      /台灣/i,
      /taiwan/i,
      /taipei/i,
      /(?:^|[^a-z0-9])twn?(?:[^a-z0-9]|$)/i,
      /台北/i,
      /新北/i,
      /台中/i,
      /高雄/i,
      /台南/i,
    ],
  },
  {
    code: 'JP',
    name: '日本',
    flag: '🇯🇵',
    patterns: [
      /日本/i,
      /japan/i,
      /tokyo/i,
      /osaka/i,
      /(?:^|[^a-z0-9])jpn?(?:[^a-z0-9]|$)/i,
      /东京/i,
      /大阪/i,
      /川崎/i,
      /名古屋/i,
      /福冈/i,
      /冲绳/i,
      /北海道/i,
    ],
  },
  {
    code: 'SG',
    name: '新加坡',
    flag: '🇸🇬',
    patterns: [
      /新加坡/i,
      /狮城/i,
      /星加坡/i,
      /singapore/i,
      /(?:^|[^a-z0-9])sgp?(?:[^a-z0-9]|$)/i,
    ],
  },
  {
    code: 'US',
    name: '美国',
    flag: '🇺🇸',
    patterns: [
      /美国/i,
      /美國/i,
      /united\s*states/i,
      /(?:^|[^a-z0-9])usa?(?:[^a-z0-9]|$)/i,
      /america/i,
      /los\s*angeles/i,
      /san\s*jose/i,
      /silicon\s*valley/i,
      /new\s*york/i,
      /seattle/i,
      /chicago/i,
      /dallas/i,
      /miami/i,
      /phoenix/i,
      /portland/i,
      /oregon/i,
      /洛杉矶/i,
      /圣何塞/i,
      /硅谷/i,
      /西雅图/i,
      /芝加哥/i,
      /纽约/i,
      /达拉斯/i,
      /迈阿密/i,
      /波特兰/i,
      /俄勒冈/i,
      /凤凰城/i,
    ],
  },
  {
    code: 'KR',
    name: '韩国',
    flag: '🇰🇷',
    patterns: [
      /韩国/i,
      /韓國/i,
      /korea/i,
      /seoul/i,
      /(?:^|[^a-z0-9])kor?(?:[^a-z0-9]|$)/i,
      /首尔/i,
      /仁川/i,
      /釜山/i,
    ],
  },
  {
    code: 'GB',
    name: '英国',
    flag: '🇬🇧',
    patterns: [
      /英国/i,
      /英國/i,
      /united\s*kingdom/i,
      /(?:^|[^a-z0-9])(?:uk|gbr?)(?:[^a-z0-9]|$)/i,
      /london/i,
      /manchester/i,
      /伦敦/i,
      /曼彻斯特/i,
      /大不列颠/i,
    ],
  },
  {
    code: 'DE',
    name: '德国',
    flag: '🇩🇪',
    patterns: [
      /德国/i,
      /德國/i,
      /germany/i,
      /deutschland/i,
      /(?:^|[^a-z0-9])deu?(?:[^a-z0-9]|$)/i,
      /frankfurt/i,
      /berlin/i,
      /munich/i,
      /法兰克福/i,
      /柏林/i,
      /慕尼黑/i,
    ],
  },
  {
    code: 'FR',
    name: '法国',
    flag: '🇫🇷',
    patterns: [
      /法国/i,
      /法國/i,
      /france/i,
      /(?:^|[^a-z0-9])fra?(?:[^a-z0-9]|$)/i,
      /paris/i,
      /巴黎/i,
      /马赛/i,
    ],
  },
  {
    code: 'CA',
    name: '加拿大',
    flag: '🇨🇦',
    patterns: [
      /加拿大/i,
      /canada/i,
      /(?:^|[^a-z0-9])can?(?:[^a-z0-9]|$)/i,
      /toronto/i,
      /vancouver/i,
      /montreal/i,
      /多伦多/i,
      /温哥华/i,
      /蒙特利尔/i,
    ],
  },
  {
    code: 'AU',
    name: '澳大利亚',
    flag: '🇦🇺',
    patterns: [
      /澳大利亚/i,
      /澳大利亞/i,
      /澳洲/i,
      /australia/i,
      /(?:^|[^a-z0-9])aus?(?:[^a-z0-9]|$)/i,
      /sydney/i,
      /melbourne/i,
      /悉尼/i,
      /墨尔本/i,
      /布里斯班/i,
    ],
  },
  {
    code: 'RU',
    name: '俄罗斯',
    flag: '🇷🇺',
    patterns: [
      /俄罗斯/i,
      /俄羅斯/i,
      /russia/i,
      /(?:^|[^a-z0-9])rus?(?:[^a-z0-9]|$)/i,
      /moscow/i,
      /saint\s*petersburg/i,
      /莫斯科/i,
      /圣彼得堡/i,
      /海参崴/i,
    ],
  },
  {
    code: 'NL',
    name: '荷兰',
    flag: '🇳🇱',
    patterns: [
      /荷兰/i,
      /荷蘭/i,
      /netherlands/i,
      /holland/i,
      /(?:^|[^a-z0-9])nld?(?:[^a-z0-9]|$)/i,
      /amsterdam/i,
      /阿姆斯特丹/i,
    ],
  },
  {
    code: 'TR',
    name: '土耳其',
    flag: '🇹🇷',
    patterns: [
      /土耳其/i,
      /turkey/i,
      /türkiye/i,
      /(?:^|[^a-z0-9])tur?(?:[^a-z0-9]|$)/i,
      /istanbul/i,
      /伊斯坦布尔/i,
    ],
  },
  {
    code: 'IN',
    name: '印度',
    flag: '🇮🇳',
    patterns: [
      /印度/i,
      /india/i,
      /(?:^|[^a-z0-9])ind?(?:[^a-z0-9]|$)/i,
      /mumbai/i,
      /delhi/i,
      /孟买/i,
      /新德里/i,
    ],
  },
  {
    code: 'MY',
    name: '马来西亚',
    flag: '🇲🇾',
    patterns: [
      /马来西亚/i,
      /馬來西亞/i,
      /大马/i,
      /malaysia/i,
      /(?:^|[^a-z0-9])mys?(?:[^a-z0-9]|$)/i,
      /kuala\s*lumpur/i,
      /吉隆坡/i,
    ],
  },
  {
    code: 'TH',
    name: '泰国',
    flag: '🇹🇭',
    patterns: [
      /泰国/i,
      /泰國/i,
      /thailand/i,
      /(?:^|[^a-z0-9])tha?(?:[^a-z0-9]|$)/i,
      /bangkok/i,
      /曼谷/i,
    ],
  },
  {
    code: 'PH',
    name: '菲律宾',
    flag: '🇵🇭',
    patterns: [
      /菲律宾/i,
      /菲律賓/i,
      /philippines/i,
      /(?:^|[^a-z0-9])phl?(?:[^a-z0-9]|$)/i,
      /manila/i,
      /马尼拉/i,
    ],
  },
  {
    code: 'VN',
    name: '越南',
    flag: '🇻🇳',
    patterns: [
      /越南/i,
      /vietnam/i,
      /(?:^|[^a-z0-9])vnm?(?:[^a-z0-9]|$)/i,
      /ho\s*chi\s*minh/i,
      /hanoi/i,
      /胡志明/i,
      /河内/i,
    ],
  },
  {
    code: 'ID',
    name: '印尼',
    flag: '🇮🇩',
    patterns: [
      /印尼/i,
      /印度尼西亚/i,
      /indonesia/i,
      /(?:^|[^a-z0-9])idn?(?:[^a-z0-9]|$)/i,
      /jakarta/i,
      /雅加达/i,
    ],
  },
  {
    code: 'AE',
    name: '阿联酋',
    flag: '🇦🇪',
    patterns: [
      /阿联酋/i,
      /阿拉伯联合酋长国/i,
      /uae/i,
      /dubai/i,
      /迪拜/i,
    ],
  },
  {
    code: 'CH',
    name: '瑞士',
    flag: '🇨🇭',
    patterns: [
      /瑞士/i,
      /switzerland/i,
      /(?:^|[^a-z0-9])che?(?:[^a-z0-9]|$)/i,
      /zurich/i,
      /geneva/i,
      /苏黎世/i,
      /日内瓦/i,
    ],
  },
  {
    code: 'SE',
    name: '瑞典',
    flag: '🇸🇪',
    patterns: [
      /瑞典/i,
      /sweden/i,
      /(?:^|[^a-z0-9])swe?(?:[^a-z0-9]|$)/i,
      /stockholm/i,
      /斯德哥尔摩/i,
    ],
  },
  {
    code: 'NO',
    name: '挪威',
    flag: '🇳🇴',
    patterns: [
      /挪威/i,
      /norway/i,
      /(?:^|[^a-z0-9])nor?(?:[^a-z0-9]|$)/i,
      /oslo/i,
      /奥斯陆/i,
    ],
  },
  {
    code: 'FI',
    name: '芬兰',
    flag: '🇫🇮',
    patterns: [
      /芬兰/i,
      /finland/i,
      /(?:^|[^a-z0-9])fin?(?:[^a-z0-9]|$)/i,
      /helsinki/i,
      /赫尔辛基/i,
    ],
  },
  {
    code: 'ES',
    name: '西班牙',
    flag: '🇪🇸',
    patterns: [
      /西班牙/i,
      /spain/i,
      /(?:^|[^a-z0-9])esp?(?:[^a-z0-9]|$)/i,
      /madrid/i,
      /barcelona/i,
      /马德里/i,
      /巴塞罗那/i,
    ],
  },
  {
    code: 'IT',
    name: '意大利',
    flag: '🇮🇹',
    patterns: [
      /意大利/i,
      /italy/i,
      /(?:^|[^a-z0-9])ita?(?:[^a-z0-9]|$)/i,
      /milan/i,
      /rome/i,
      /米兰/i,
      /罗马/i,
    ],
  },
  {
    code: 'BR',
    name: '巴西',
    flag: '🇧🇷',
    patterns: [
      /巴西/i,
      /brazil/i,
      /(?:^|[^a-z0-9])bra?(?:[^a-z0-9]|$)/i,
      /sao\s*paulo/i,
      /圣保罗/i,
    ],
  },
  {
    code: 'AR',
    name: '阿根廷',
    flag: '🇦🇷',
    patterns: [
      /阿根廷/i,
      /argentina/i,
      /(?:^|[^a-z0-9])arg?(?:[^a-z0-9]|$)/i,
      /buenos\s*aires/i,
      /布宜诺斯艾利斯/i,
    ],
  },
  {
    code: 'ZA',
    name: '南非',
    flag: '🇿🇦',
    patterns: [
      /南非/i,
      /south\s*africa/i,
      /(?:^|[^a-z0-9])zaf?(?:[^a-z0-9]|$)/i,
      /johannesburg/i,
      /约翰内斯堡/i,
    ],
  },
  {
    code: 'CN',
    name: '中国',
    flag: '🇨🇳',
    patterns: [
      /中国/i,
      /中华/i,
      /china/i,
      /(?:^|[^a-z0-9])chn?(?:[^a-z0-9]|$)/i,
      /北京/i,
      /上海/i,
      /广州/i,
      /深圳/i,
      /杭州/i,
      /成都/i,
      /重庆/i,
      /武汉/i,
      /南京/i,
    ],
  },
]

export interface RegionInfo {
  code: string
  name: string
  flag: string
}

export interface RegionSummary {
  code: string
  name: string
  flag: string
  totalCount: number
  nodeIds: string[]
}

/**
 * Strips advertisements, promotion links, speed test restrictions, and remaining traffic noise
 * commonly embedded in commercial airport node names.
 */
export function sanitizeNodeName(raw: string): string {
  if (!raw) return ''
  let s = raw.trim()

  // 1. Remove bracketed rates like [1.5x], (2.0倍率), [1.0]
  s = s.replace(/\[\s*[0-9.]+\s*(?:x|倍率?)\s*\]/gi, '')
       .replace(/\(\s*[0-9.]+\s*(?:x|倍率?)\s*\)/gi, '')

  const adKeywords = /剩余流量|到期时间|官网|防失联|发布页|最新地址|最新网址|客服|TG群|交流群|TG频道|禁止BT|请勿测速|打卡返利|永久域名|http:\/\/|https:\/\/|www\.|t\.me/i

  // 2. Split into segments by pipe
  if (/[|｜]/.test(s)) {
    const parts = s.split(/[|｜]/).map(p => p.trim()).filter(Boolean)
    const cleanParts = parts.filter(p => !adKeywords.test(p))
    if (cleanParts.length > 0) {
      s = cleanParts.join(' | ')
    }
  }

  // 3. Clean ' - ' separated trailing ad parts
  if (s.includes(' - ')) {
    const parts = s.split(' - ').map(p => p.trim()).filter(Boolean)
    const cleanParts = parts.filter(p => !adKeywords.test(p))
    if (cleanParts.length > 0) {
      s = cleanParts.join(' - ')
    }
  }

  // 4. Fallback cleanup for remaining inline keywords
  s = s.replace(/https?:\/\/[^\s|｜)\]]+/gi, '')
       .replace(/\bwww\.[a-z0-9-]+\.[a-z]+(?::[0-9]+)?(?:\/[^\s|｜)\]]*)?/gi, '')
       .replace(/(?:剩余流量|到期时间|官网|防失联|发布页|最新地址|最新网址|客服|TG群|交流群|TG频道|禁止BT|请勿测速|打卡返利|永久域名)[^|｜\n]*/gi, '')
       .replace(/^[|｜\s\-_/]+/, '')
       .replace(/[|｜\s\-_/]+$/, '')
       .trim()

  return s || raw.trim()
}

/**
 * Matches a regional flag emoji based on keywords inside the node name.
 * If the node name already contains a flag emoji, returns an empty string.
 */
export function matchCountryFlag(name: string): string {
  if (!name || FLAG_EMOJI_REGEX.test(name)) {
    return ''
  }
  for (const rule of REGION_RULES) {
    for (const pattern of rule.patterns) {
      if (typeof pattern === 'string') {
        if (name.includes(pattern)) return rule.flag
      } else if (pattern.test(name)) {
        return rule.flag
      }
    }
  }
  return ''
}

/**
 * Detects the geographical region info of a node by checking existing emoji flags or keyword patterns.
 */
export function detectNodeRegion(name: string): RegionInfo {
  if (!name) {
    return { code: 'OTHER', name: '其他', flag: '🌐' }
  }

  // 1. If name contains a known region flag
  for (const rule of REGION_RULES) {
    if (name.includes(rule.flag)) {
      return { code: rule.code, name: rule.name, flag: rule.flag }
    }
  }

  // 2. Check patterns against sanitized name
  const clean = sanitizeNodeName(name)
  for (const rule of REGION_RULES) {
    for (const pattern of rule.patterns) {
      if (typeof pattern === 'string') {
        if (clean.includes(pattern) || name.includes(pattern)) {
          return { code: rule.code, name: rule.name, flag: rule.flag }
        }
      } else if (pattern.test(clean) || pattern.test(name)) {
        return { code: rule.code, name: rule.name, flag: rule.flag }
      }
    }
  }

  return { code: 'OTHER', name: '其他', flag: '🌐' }
}

/**
 * Extracts and aggregates regions from a list of external nodes.
 */
export function extractSubscriptionRegions(nodes: Array<{ id: string; name?: string }>): RegionSummary[] {
  if (!Array.isArray(nodes) || nodes.length === 0) {
    return []
  }

  const regionMap = new Map<string, { code: string; name: string; flag: string; nodeIds: string[] }>()

  for (const node of nodes) {
    const region = detectNodeRegion(node.name || '')
    let group = regionMap.get(region.code)
    if (!group) {
      group = { code: region.code, name: region.name, flag: region.flag, nodeIds: [] }
      regionMap.set(region.code, group)
    }
    group.nodeIds.push(node.id)
  }

  const result: RegionSummary[] = []
  // Keep order defined in REGION_RULES
  for (const rule of REGION_RULES) {
    const group = regionMap.get(rule.code)
    if (group && group.nodeIds.length > 0) {
      result.push({
        code: group.code,
        name: group.name,
        flag: group.flag,
        totalCount: group.nodeIds.length,
        nodeIds: group.nodeIds,
      })
      regionMap.delete(rule.code)
    }
  }

  // Any remaining regions (like OTHER)
  for (const group of regionMap.values()) {
    if (group.nodeIds.length > 0) {
      result.push({
        code: group.code,
        name: group.name,
        flag: group.flag,
        totalCount: group.nodeIds.length,
        nodeIds: group.nodeIds,
      })
    }
  }

  return result
}

/**
 * Returns formatted node name with sanitized advertisements and prepended country flag emoji if matched.
 */
export function formatNodeNameWithFlag(name: string): string {
  if (!name) return ''
  const clean = sanitizeNodeName(name)
  const flag = matchCountryFlag(clean)
  return flag ? `${flag} ${clean}` : clean
}

/**
 * Normalizes protocol strings (including aliases like hy2, ss, shadowsocks)
 * into standard CSS modifier class names matching the panel's theme colors.
 */
export function normalizeProtocolClass(protocol?: string): string {
  if (!protocol) return ''
  const p = protocol.toLowerCase().trim()
  if (p === 'ss' || p === 'shadowsocks' || p === 'ss2022') return 'shadowsocks'
  if (p === 'hy2' || p === 'hysteria2') return 'hysteria2'
  if (p === 'vless-ws-tunnel') return 'vless-ws-tunnel'
  if (p === 'vless') return 'vless'
  if (p === 'trojan') return 'trojan'
  if (p === 'tuic') return 'tuic'
  if (p === 'anytls') return 'anytls'
  if (p === 'vmess') return 'vmess'
  return p
}

/**
 * Formats a protocol into a concise uppercase badge label matching the deployment node cards.
 */
export function formatExternalProtocolBadge(protocol?: string): string {
  if (!protocol) return ''
  const p = protocol.toLowerCase().trim()
  if (p === 'hysteria2' || p === 'hy2') return 'HY2'
  if (p === 'shadowsocks' || p === 'ss') return 'SS'
  if (p === 'ss2022') return 'SS2022'
  if (p === 'vless-ws-tunnel') return 'VLESS · CF'
  return p.toUpperCase()
}
