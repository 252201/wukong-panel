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

function hasNetworkAlert(health: NetworkGroupHealth, now: number): boolean {
  const checkedAt = Date.parse(health.checkedAt)
  if (!Number.isFinite(checkedAt) || now - checkedAt > staleAfterMs) return true
  const samples = historySlotsFor(health, now).filter(sample => sample !== null)
  if (health.status === 'error' || samples.some(sample => sample.status === 'error')) return true
  const totals = samples.reduce((total, sample) => {
    if (sample.packetsSent > 0) {
      total.sent += sample.packetsSent
      total.received += sample.packetsReceived
    }
    return total
  }, { sent: 0, received: 0 })
  return totals.sent > 0 && (totals.sent - totals.received) * 100 >= alertLossPct * totals.sent
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
