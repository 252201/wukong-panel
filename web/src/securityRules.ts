import type { SecurityPort, SecurityRule } from './api'

export function securityRuleServices(rule: SecurityRule, ports: SecurityPort[], language: string): string[] {
 if (!rule.adoptable) return []
 const last = rule.portTo || rule.portFrom
 const translate = (reason: string): string => {
  if (language !== 'en-US') return reason
  if (reason === '面板入口') return 'Panel entrance'
  if (reason === 'HTTP / 证书验证') return 'HTTP / certificate validation'
  return reason.replace(/^节点 /, 'Node ')
 }
 return [...new Set(ports.filter(port => port.protocol === rule.protocol && port.port >= rule.portFrom && port.port <= last).map(port => translate(port.reason)))]
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
