import type { FleetHost, NetworkGroupHealth, NetworkHealth } from './api'
import { historySlotsFor } from './networkHistory.ts'

export type NetworkGroupName = 'international' | 'domestic'
const networkGroups: NetworkGroupName[] = ['international', 'domestic']
const staleAfterMs = 150_000
const alertLossPct = 5

export function networkGroupFrom(health: NetworkHealth | undefined, group: NetworkGroupName): NetworkGroupHealth | undefined {
  if (!health) return undefined
  if (group === 'domestic') return health.domestic
  if (health.international) return health.international
  // Only label a legacy flat result as international when its targets are known.
  return health.targets?.length && health.targets.every(target => target === '1.1.1.1' || target === '8.8.8.8') ? health : undefined
}

export function recentNetworkLossPct(health: NetworkGroupHealth | undefined, now = Date.now()): number | null {
  if (!health) return null
  const totals = historySlotsFor(health, now).reduce((total, sample) => {
    if (sample && sample.packetsSent > 0) {
      total.sent += sample.packetsSent
      total.received += sample.packetsReceived
    }
    return total
  }, { sent: 0, received: 0 })
  return totals.sent > 0 ? (totals.sent - totals.received) * 100 / totals.sent : null
}

function hasNetworkAlert(health: NetworkGroupHealth, now: number): boolean {
  const checkedAt = Date.parse(health.checkedAt)
  if (!Number.isFinite(checkedAt) || now - checkedAt > staleAfterMs) return true
  const samples = historySlotsFor(health, now).filter(sample => sample !== null)
  if (health.status === 'error' || samples.some(sample => sample.status === 'error')) return true
  return (recentNetworkLossPct(health, now) ?? 0) >= alertLossPct
}

export function summarizeFleet(hosts: FleetHost[], now = Date.now()) {
  const result = {
    online: 0,
    total: hosts.length,
    runningNodes: 0,
    knownNodes: 0,
    networkAlerts: 0,
    networkPending: 0,
    rx: 0,
    tx: 0,
  }
  for (const host of hosts) {
    const overview = host.snapshot?.overview
    result.knownNodes += overview?.nodeCount || 0
    if (!host.online) continue

    result.online++
    result.runningNodes += overview?.onlineNodes || 0
    result.rx += overview?.now?.rxBps || 0
    result.tx += overview?.now?.txBps || 0

    const groups = networkGroups.map(group => networkGroupFrom(overview?.network, group))
    if (groups.some(health => health && hasNetworkAlert(health, now))) result.networkAlerts++
    else if (groups.some(health => !health)) result.networkPending++
  }
  return result
}

export function formatBytes(value = 0, fractionDigits?: number) {
  if (!Number.isFinite(value)) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = Math.max(0, value); let index = 0
  while (size >= 1000 && index < units.length - 1) { size /= 1000; index++ }
  return `${size.toFixed(fractionDigits ?? (index < 2 ? 0 : 2))} ${units[index]}`
}

export function formatRate(value = 0) {
  return `${formatBytes(value)}/s`
}

export function fleetHostLiveRates(host: FleetHost) {
  if (!host?.online) {
    return { rx: 0, tx: 0, rxFormatted: '0 B/s', txFormatted: '0 B/s' }
  }
  const rx = host.snapshot?.overview?.now?.rxBps || 0
  const tx = host.snapshot?.overview?.now?.txBps || 0
  return {
    rx,
    tx,
    rxFormatted: formatRate(rx),
    txFormatted: formatRate(tx),
  }
}

export function fleetHostRateHint(host: FleetHost, locale: 'zh-CN' | 'en-US' = 'zh-CN') {
  const isEn = locale === 'en-US'
  if (!host?.online) return isEn ? 'Host offline' : '主机离线'
  const rx = host.snapshot?.overview?.now?.rxBps || 0
  const tx = host.snapshot?.overview?.now?.txBps || 0
  const iface = host.snapshot?.overview?.now?.interface
  if (isEn) {
    return `Download: ${formatRate(rx)} · Upload: ${formatRate(tx)}${iface ? ` · Interface: ${iface}` : ''}`
  }
  return `实时下载: ${formatRate(rx)} · 实时上传: ${formatRate(tx)}${iface ? ` · 出口网卡: ${iface}` : ''}`
}
