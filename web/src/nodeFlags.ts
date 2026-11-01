/**
 * Node Flag Emoji Detector and Formatter for External Subscriptions
 *
 * Automatically inspects node names (such as "Hong Kong | 01", "Tokyo 02", "台湾 03")
 * and prepends corresponding national / regional flag emojis if absent.
 */

// Regex matching any existing regional indicator flag emoji (U+1F1E6 to U+1F1FF pair)
export const FLAG_EMOJI_REGEX = /[\uD83C][\uDDE6-\uDDFF][\uD83C][\uDDE6-\uDDFF]/

interface RegionRule {
  flag: string
  patterns: (string | RegExp)[]
}

const REGION_RULES: RegionRule[] = [
  {
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
 * Returns formatted node name with prepended country flag emoji if matched.
 */
export function formatNodeNameWithFlag(name: string): string {
  if (!name) return ''
  const flag = matchCountryFlag(name)
  return flag ? `${flag} ${name}` : name
}
