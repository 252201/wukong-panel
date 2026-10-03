import type { SecurityPort, SecurityRule } from './api'

export function securityRuleMatchesProtocol(rule: SecurityRule, protocol: string): boolean {
 return rule.protocol === protocol || (rule.protocol === 'tcp/udp' && (protocol === 'tcp' || protocol === 'udp'))
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

export function securityRuleChange(text: string, language: string): string | null {
 const match = /^(adopt|delete) (allow|deny):(tcp|udp|tcp\/udp):(\d+):(\d+):(.+):([^:]*)$/.exec(text)
 if (!match) return null
 const [,operation,action,protocol,first,last,source,zone] = match
 const en = language === 'en-US'
 const verb = operation === 'adopt' ? (en ? 'Adopt' : '接管') : (en ? 'Delete' : '删除')
 const verdict = action === 'allow' ? (en ? 'allow' : '允许') : (en ? 'deny' : '拒绝')
 const ports = first === last ? first : `${first}–${last}`
 const transport = protocol === 'tcp/udp' ? 'TCP + UDP' : protocol!.toUpperCase()
 return `${verb} · ${verdict} ${ports}/${transport} · ${source === 'any' ? (en ? 'Any IP' : '任意 IP') : source}${zone ? ` · ${en ? 'Zone' : '区域'} ${zone}` : ''}`
}
