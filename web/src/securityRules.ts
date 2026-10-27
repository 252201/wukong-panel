import type { SecurityPort, SecurityRule } from './api'

export function formatProtocol(protocol: string | null | undefined): string {
  if (!protocol) return ''
  const p = protocol.trim().toLowerCase()
  if (p === 'tcp/udp' || p === 'tcp+udp' || p === 'tcp + udp') return 'TCP+UDP'
  if (p === 'ipv6-icmp') return 'IPv6-ICMP'
  return p.toUpperCase()
}

export function formatHumanSeconds(seconds: number | null | undefined, language: string): string {
  const n = Number(seconds)
  if (!Number.isFinite(n) || n <= 0) return ''
  const en = language === 'en-US'
  const days = Math.floor(n / 86400)
  const hours = Math.floor((n % 86400) / 3600)
  const mins = Math.floor((n % 3600) / 60)
  const secs = Math.floor(n % 60)
  const parts: string[] = []
  if (days > 0) parts.push(en ? `${days}d` : `${days} 天`)
  if (hours > 0) parts.push(en ? `${hours}h` : `${hours} 小时`)
  if (mins > 0) parts.push(en ? `${mins}m` : `${mins} 分钟`)
  if (secs > 0 && days === 0 && hours === 0) parts.push(en ? `${secs}s` : `${secs} 秒`)
  return parts.join(' ')
}

export function securityRuleMatchesProtocol(rule: SecurityRule, protocol: string): boolean {
  const rp = rule.protocol?.toLowerCase()
  const p = protocol?.toLowerCase()
  if (rp === p) return true
  if ((rp === 'tcp/udp' || rp === 'tcp+udp') && (p === 'tcp' || p === 'udp')) return true
  return false
}


export function securityRuleServices(rule: SecurityRule, ports: SecurityPort[], language: string): string[] {
 if (!rule.adoptable) return []
 const last = rule.portTo || rule.portFrom
 const translate = (reason: string): string => {
  if (language !== 'en-US') return reason
  if (reason === '面板入口') return 'Panel entrance'
  if (reason === 'HTTP / 证书验证') return 'HTTP / certificate validation'
  return reason.replace(/^节点 /, 'Node ')
 }
 return [...new Set(ports.filter(port => securityRuleMatchesProtocol(rule, port.protocol) && port.port >= rule.portFrom && port.port <= last).map(port => translate(port.reason)))]
}

export function parseSecurityPorts(value: string): number[] {
 if (!value.trim()) return []
 const ports = value.split(/[ ,]+/).map(part => Number(part))
 if (ports.some(port => !Number.isInteger(port) || port < 1 || port > 65535)) throw new Error('端口需为 1–65535')
 return [...new Set(ports)].sort((a, b) => a - b)
}
export function securityStateFresh(checkedAt: string, now = Date.now()): boolean {
 const checked = Date.parse(checkedAt)
 return Number.isFinite(checked) && now >= checked - 5000 && now - checked < 90_000
}

export function securityBatchEligible(rule: SecurityRule, mode: 'adopt'|'delete'): boolean {
 return rule.adoptable && (mode === 'adopt' ? !rule.managed : rule.managed && !rule.protected)
}

export function sortFirewallRules<T extends {protected: boolean; portFrom: number; portTo: number; protocol: string}>(rules: T[]): T[] {
 return [...rules].sort((a, b) => {
  if (a.protected !== b.protected) return a.protected ? -1 : 1
  if (a.protected && b.protected) return 0
  if (a.portFrom !== b.portFrom) return a.portFrom - b.portFrom
  const aTo = a.portTo || a.portFrom
  const bTo = b.portTo || b.portFrom
  if (aTo !== bTo) return aTo - bTo
  return String(a.protocol || '').localeCompare(String(b.protocol || ''))
 })
}

export function securityRuleChange(text: string, language: string): string | null {
 const match = /^(?:(adopt|delete|add) )?(allow|deny):(tcp|udp|tcp\/udp|tcp\+udp):(\d+):(\d+):(.+):([^:]*)$/.exec(text)
 if (!match) return null
 const [,operation,action,protocol,first,last,source,zone] = match
 const en = language === 'en-US'
 const verb = !operation || operation === 'add' ? (en ? 'Add' : '添加') : operation === 'adopt' ? (en ? 'Adopt' : '接管') : (en ? 'Delete' : '删除')
 const verdict = action === 'allow' ? (en ? 'allow' : '允许') : (en ? 'deny' : '拒绝')
 const ports = first === last ? first : `${first}–${last}`
 const transport = formatProtocol(protocol)
 return `${verb} · ${verdict} ${ports}/${transport} · ${source === 'any' ? (en ? 'Any IP' : '任意 IP') : source}${zone ? ` · ${en ? 'Zone' : '区域'} ${zone}` : ''}`
}
