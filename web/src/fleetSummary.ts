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

export function sortFleetHostsByOrder(hosts: FleetHost[], order?: string[]): FleetHost[] {
  const local = hosts.find(h => h.id === 'local')
  const remote = hosts.filter(h => h.id !== 'local')
  if (!order || !order.length) {
    return local ? [local, ...remote] : remote
  }
  const orderMap = new Map<string, number>()
  order.forEach((id, idx) => {
    if (id && id !== 'local' && !orderMap.has(id)) {
      orderMap.set(id, idx)
    }
  })
  const sortedRemote = [...remote].sort((a, b) => {
    const idxA = orderMap.has(a.id) ? orderMap.get(a.id)! : 999999
    const idxB = orderMap.has(b.id) ? orderMap.get(b.id)! : 999999
    if (idxA !== idxB) return idxA - idxB
    return a.id.localeCompare(b.id)
  })
  return local ? [local, ...sortedRemote] : sortedRemote
}

export function sortRemoteHostsByPreset(
  hosts: FleetHost[],
  preset: 'latency' | 'expiry' | 'traffic' | 'name' | 'default'
): FleetHost[] {
  const list = [...hosts]
  if (preset === 'latency') {
    list.sort((a, b) => {
      const latA = a.online ? (networkGroupFrom(a.snapshot?.overview?.network, 'domestic')?.latencyMs ?? 999990) : 999999
      const latB = b.online ? (networkGroupFrom(b.snapshot?.overview?.network, 'domestic')?.latencyMs ?? 999990) : 999999
      return latA - latB
    })
  } else if (preset === 'expiry') {
    list.sort((a, b) => {
      if (!a.expiresAt && !b.expiresAt) return 0
      if (!a.expiresAt) return 1
      if (!b.expiresAt) return -1
      return a.expiresAt.localeCompare(b.expiresAt)
    })
  } else if (preset === 'traffic') {
    list.sort((a, b) => (b.snapshot?.overview?.trafficUsed || 0) - (a.snapshot?.overview?.trafficUsed || 0))
  } else if (preset === 'name') {
    list.sort((a, b) => a.name.localeCompare(b.name, undefined, { sensitivity: 'base' }))
  } else if (preset === 'default') {
    list.sort((a, b) => (a.createdAt || '').localeCompare(b.createdAt || ''))
  }
  return list
}
