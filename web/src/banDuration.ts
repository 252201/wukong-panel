export const banDurationPresets = [600, 3600, 86400, 604800, 2592000, -1] as const

export function formatBanDuration(seconds: number, language: string): string {
 const en = language === 'en-US'
 if (seconds === -1) return en ? 'Permanent (no automatic expiry)' : '永久（不自动解除）'
 for (const [unit, zh, singular] of [[86400, '天', 'day'], [3600, '小时', 'hour'], [60, '分钟', 'minute'], [1, '秒', 'second']] as const) {
  if (seconds > 0 && seconds % unit === 0) {
   const count = seconds / unit
   return en ? `${count} ${singular}${count === 1 ? '' : 's'}` : `${count} ${zh}`
  }
 }
 return String(seconds)
}

// Bare numbers retain the existing seconds convention; the API still receives seconds or -1.
export function parseBanDuration(text: string, permanentSupported: boolean): number | null {
 const value = text.trim().toLowerCase()
 if (['永久', '永久（不自动解除）', 'permanent', 'permanent (no automatic expiry)'].includes(value)) return permanentSupported ? -1 : null
 const match = /^(\d+(?:\.\d+)?)\s*(秒|秒钟|s|sec|secs|second|seconds|分|分钟|m|min|mins|minute|minutes|小时|时|h|hr|hrs|hour|hours|天|d|day|days)?$/.exec(value)
 if (!match) return null
 const unit = match[2] || 's'
 const multiplier = /^(分|分钟|m|min|mins|minute|minutes)$/.test(unit) ? 60 : /^(小时|时|h|hr|hrs|hour|hours)$/.test(unit) ? 3600 : /^(天|d|day|days)$/.test(unit) ? 86400 : 1
 const seconds = Number(match[1]) * multiplier
 return Number.isSafeInteger(seconds) && seconds >= 60 && seconds <= 2592000 ? seconds : null
}
