export function formatRelativeTime(isoString?: string, now = Date.now(), lang = 'zh-CN'): string {
  if (!isoString) return ''
  const timestamp = Date.parse(isoString)
  if (Number.isNaN(timestamp) || timestamp <= 0) return ''

  const diffMs = Math.max(0, now - timestamp)
  const diffSec = Math.floor(diffMs / 1000)
  const diffMin = Math.floor(diffSec / 60)
  const diffHour = Math.floor(diffMin / 60)
  const diffDay = Math.floor(diffHour / 24)

  const isEn = lang === 'en-US'

  if (diffSec < 45) {
    return isEn ? 'just now' : '刚刚'
  }
  if (diffMin < 60) {
    return isEn ? `${diffMin}m ago` : `${diffMin}分钟前`
  }
  if (diffHour < 24) {
    return isEn ? `${diffHour}h ago` : `${diffHour}小时前`
  }
  if (diffDay === 1) {
    const timeStr = new Date(timestamp).toLocaleTimeString(lang, { hour: '2-digit', minute: '2-digit', hour12: false })
    return isEn ? `yesterday ${timeStr}` : `昨天 ${timeStr}`
  }
  if (diffDay < 7) {
    return isEn ? `${diffDay}d ago` : `${diffDay}天前`
  }
  const date = new Date(timestamp)
  return date.toLocaleDateString(lang, { month: 'numeric', day: 'numeric' })
}

export function formatFullDateTime(isoString?: string, lang = 'zh-CN'): string {
  if (!isoString) return ''
  const timestamp = Date.parse(isoString)
  if (Number.isNaN(timestamp) || timestamp <= 0) return ''
  const date = new Date(timestamp)
  return date.toLocaleString(lang, {
    year: 'numeric',
    month: '2-digit',
    day: '2-digit',
    hour: '2-digit',
    minute: '2-digit',
    second: '2-digit',
    hour12: false
  })
}
