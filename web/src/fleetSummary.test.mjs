import assert from 'node:assert/strict'
import test from 'node:test'
import { recentNetworkLossPct, summarizeFleet, fleetHostLiveRates, fleetHostRateHint, sortFleetHostsByOrder, sortRemoteHostsByPreset } from './fleetSummary.ts'

const now = Date.parse('2026-09-27T10:00:00Z')
const sample = (checkedAt, packetsSent = 10, packetsReceived = packetsSent, status = 'ok') => ({
  checkedAt: new Date(checkedAt).toISOString(), packetsSent, packetsReceived,
  packetLossPct: packetsSent ? (packetsSent - packetsReceived) * 100 / packetsSent : 0, status,
})
const host = (id, online, nodeCount, onlineNodes, network) => ({
  id, online, snapshot: { overview: {
    nodeCount, onlineNodes, now: { rxBps: 100, txBps: 50 }, network,
  } },
})

test('offline nodes stay in the known total without appearing as running or adding stale traffic', () => {
  const fresh = sample(now)
  const hosts = [host('local', true, 3, 2, { international: fresh, domestic: fresh }),
    host('remote', false, 2, 2, { international: fresh, domestic: fresh })]
  const summary = summarizeFleet(hosts, now)
  assert.deepEqual([summary.runningNodes, summary.knownNodes, summary.rx, summary.tx], [2, 5, 100, 50])
  assert.equal(summary.networkAlerts, 0)
})

test('one lost packet among 30 full probe minutes does not alert', () => {
  const fresh = sample(now)
  const history = Array.from({ length: 30 }, (_, index) => sample(now - (29 - index) * 60_000, 10, index === 0 ? 9 : 10))
  const network = { international: fresh, domestic: { ...fresh, history } }
  assert.equal(summarizeFleet([host('local', true, 3, 3, network)], now).networkAlerts, 0)
})

test('card loss uses the 30-minute packet total instead of the latest sample', () => {
  const history = Array.from({ length: 30 }, (_, index) => sample(now - (29 - index) * 60_000, 10, index >= 22 ? 9 : 10))
  const health = { ...history.at(-1), history }
  assert.equal(health.packetLossPct, 10)
  assert.equal(recentNetworkLossPct(health, now)?.toFixed(1), '2.7')
  assert.equal(recentNetworkLossPct(sample(now, 0, 0), now), null)
})

test('a 30-minute total loss of at least 5% in either region alerts once per host', () => {
  const fresh = sample(now)
  const history = Array.from({ length: 30 }, (_, index) => sample(now - (29 - index) * 60_000, 10, index < 15 ? 9 : 10))
  const network = { international: { ...fresh, history }, domestic: { ...fresh, history } }
  assert.equal(summarizeFleet([host('local', true, 3, 3, network)], now).networkAlerts, 1)
  const tooOld = sample(now - 31 * 60_000, 10, 0)
  const clear = { international: { ...fresh, history: [tooOld, fresh] }, domestic: fresh }
  assert.equal(summarizeFleet([host('local', true, 3, 3, clear)], now).networkAlerts, 0)
})

test('regional loss rates are not combined to manufacture an alert', () => {
  const mildLoss = sample(now, 100, 97)
  assert.equal(summarizeFleet([host('local', true, 1, 1, { international: mildLoss, domestic: mildLoss })], now).networkAlerts, 0)
})

test('total loss is weighted by packets sent, not averaged across probe minutes', () => {
  const fresh = sample(now, 90)
  const history = [sample(now - 60_000, 10, 9), fresh]
  assert.equal(summarizeFleet([host('local', true, 1, 1, {
    international: { ...fresh, history }, domestic: fresh,
  })], now).networkAlerts, 0)
})

test('stale or failed probes alert, including historical outages; a host awaiting its first probe is pending', () => {
  const fresh = sample(now)
  const stale = sample(now - 151_000)
  const failed = sample(now, 0, 0, 'error')
  const hosts = [host('stale', true, 1, 1, { international: stale, domestic: fresh }),
    host('failed', true, 1, 1, { international: failed, domestic: fresh }),
    host('historical-failure', true, 1, 1, { international: { ...fresh, history: [sample(now - 60_000, 0, 0, 'error'), fresh] }, domestic: fresh }),
    host('pending', true, 1, 1, { international: fresh }),
    host('offline', false, 1, 1, { international: failed, domestic: failed })]
  const summary = summarizeFleet(hosts, now)
  assert.equal(summary.networkAlerts, 3)
  assert.equal(summary.networkPending, 1)
})

test('fleetHostLiveRates computes rates for online hosts and zeroes out offline hosts', () => {
  const onlineHost = {
    id: 'h1', online: true,
    snapshot: { overview: { now: { rxBps: 1250000, txBps: 54000 } } },
  }
  const offlineHost = {
    id: 'h2', online: false,
    snapshot: { overview: { now: { rxBps: 9999999, txBps: 8888888 } } },
  }
  const emptyHost = { id: 'h3', online: true }

  const onlineRates = fleetHostLiveRates(onlineHost)
  assert.equal(onlineRates.rx, 1250000)
  assert.equal(onlineRates.tx, 54000)
  assert.equal(onlineRates.rxFormatted, '1.25 MB/s')
  assert.equal(onlineRates.txFormatted, '54 KB/s')

  const offlineRates = fleetHostLiveRates(offlineHost)
  assert.equal(offlineRates.rx, 0)
  assert.equal(offlineRates.tx, 0)
  assert.equal(offlineRates.rxFormatted, '0 B/s')
  assert.equal(offlineRates.txFormatted, '0 B/s')

  const emptyRates = fleetHostLiveRates(emptyHost)
  assert.equal(emptyRates.rx, 0)
  assert.equal(emptyRates.tx, 0)
  assert.equal(emptyRates.rxFormatted, '0 B/s')
  assert.equal(emptyRates.txFormatted, '0 B/s')
})

test('fleetHostRateHint formats Chinese and English tooltips correctly', () => {
  const onlineHost = {
    id: 'h1', online: true,
    snapshot: { overview: { now: { rxBps: 1250000, txBps: 54000, interface: 'eth0' } } },
  }
  const offlineHost = { id: 'h2', online: false }

  assert.equal(fleetHostRateHint(onlineHost, 'zh-CN'), '实时下载: 1.25 MB/s · 实时上传: 54 KB/s · 出口网卡: eth0')
  assert.equal(fleetHostRateHint(onlineHost, 'en-US'), 'Download: 1.25 MB/s · Upload: 54 KB/s · Interface: eth0')

  assert.equal(fleetHostRateHint(offlineHost, 'zh-CN'), '主机离线')
  assert.equal(fleetHostRateHint(offlineHost, 'en-US'), 'Host offline')
})

test('sortFleetHostsByOrder keeps central local host pinned at index 0 and orders remote hosts', () => {
  const localHost = { id: 'local', name: '中央本机', online: true }
  const h1 = { id: 'h1', name: 'HK Host', online: true }
  const h2 = { id: 'h2', name: 'JP Host', online: true }
  const h3 = { id: 'h3', name: 'US Host', online: true }
  const h4 = { id: 'h4', name: 'SG Host', online: true }

  // 1. Order specified: h3, h1, h2 (h4 unmentioned)
  const sorted = sortFleetHostsByOrder([h1, localHost, h2, h4, h3], ['h3', 'h1', 'h2'])
  assert.deepEqual(sorted.map(h => h.id), ['local', 'h3', 'h1', 'h2', 'h4'])

  // 2. Order mentions 'local' (must be ignored and remain first)
  const sortedWithLocal = sortFleetHostsByOrder([h2, h1, localHost], ['h1', 'local', 'h2'])
  assert.deepEqual(sortedWithLocal.map(h => h.id), ['local', 'h1', 'h2'])

  // 3. Empty or undefined order preserves existing order with local at index 0
  const sortedEmpty = sortFleetHostsByOrder([h2, localHost, h1], [])
  assert.deepEqual(sortedEmpty.map(h => h.id), ['local', 'h2', 'h1'])
})

test('sortRemoteHostsByPreset correctly orders remote hosts by preset criteria', () => {
  const hosts = [
    {
      id: 'h1', name: 'Charlie', online: true, createdAt: '2026-01-03',
      expiresAt: '2026-11-20',
      snapshot: { overview: { trafficUsed: 500, network: { domestic: { latencyMs: 120 } } } }
    },
    {
      id: 'h2', name: 'Alice', online: true, createdAt: '2026-01-01',
      expiresAt: '2026-11-05',
      snapshot: { overview: { trafficUsed: 800, network: { domestic: { latencyMs: 45 } } } }
    },
    {
      id: 'h3', name: 'Bob', online: false, createdAt: '2026-01-02',
      expiresAt: '', // no expiry
      snapshot: { overview: { trafficUsed: 200, network: { domestic: { latencyMs: 30 } } } }
    },
    {
      id: 'h4', name: 'Delta', online: true, createdAt: '2026-01-04',
      expiresAt: '2026-11-10',
      snapshot: { overview: { trafficUsed: 1200, network: { domestic: { latencyMs: 80 } } } }
    },
  ]

  // Latency: h2 (45ms), h4 (80ms), h1 (120ms), h3 (offline -> end)
  const byLatency = sortRemoteHostsByPreset(hosts, 'latency')
  assert.deepEqual(byLatency.map(h => h.id), ['h2', 'h4', 'h1', 'h3'])

  // Expiry: h2 (11-05), h4 (11-10), h1 (11-20), h3 (no expiry -> end)
  const byExpiry = sortRemoteHostsByPreset(hosts, 'expiry')
  assert.deepEqual(byExpiry.map(h => h.id), ['h2', 'h4', 'h1', 'h3'])

  // Traffic: h4 (1200), h2 (800), h1 (500), h3 (200)
  const byTraffic = sortRemoteHostsByPreset(hosts, 'traffic')
  assert.deepEqual(byTraffic.map(h => h.id), ['h4', 'h2', 'h1', 'h3'])

  // Name: Alice (h2), Bob (h3), Charlie (h1), Delta (h4)
  const byName = sortRemoteHostsByPreset(hosts, 'name')
  assert.deepEqual(byName.map(h => h.id), ['h2', 'h3', 'h1', 'h4'])

  // Default (createdAt): h2 (01-01), h3 (01-02), h1 (01-03), h4 (01-04)
  const byDefault = sortRemoteHostsByPreset(hosts, 'default')
  assert.deepEqual(byDefault.map(h => h.id), ['h2', 'h3', 'h1', 'h4'])
})

test('fleet-order-modal layout is wide and flags are constrained to prevent distortion', async () => {
  const fs = await import('node:fs')
  const path = await import('node:path')
  const appVuePath = path.resolve(process.cwd(), 'src/App.vue')
  const stylesCssPath = path.resolve(process.cwd(), 'src/styles.css')

  const appVue = fs.readFileSync(appVuePath, 'utf8')
  const stylesCss = fs.readFileSync(stylesCssPath, 'utf8')

  // 1. App.vue should not use 'compact' class for fleet-order modal
  assert.match(appVue, /modal === 'fleet-order'" class="modal-card fleet-order-modal"/)
  assert.doesNotMatch(appVue, /modal === 'fleet-order'" class="modal-card compact fleet-order-modal"/)

  // 2. styles.css should set wide dimensions for fleet-order-modal
  assert.match(stylesCss, /\.fleet-order-modal\s*\{[^}]*width:\s*min\(920px,\s*94vw\)/)
  assert.match(stylesCss, /\.fleet-order-modal\s*\{[^}]*max-width:\s*940px/)

  // 3. Global .fleet-host-flag should be defined with width and height constraints
  assert.match(stylesCss, /\.fleet-host-flag\s*\{[^}]*width:\s*16px;\s*height:\s*11px;\s*object-fit:\s*cover;/)
  assert.match(stylesCss, /\.fleet-order-modal \.fleet-host-flag\s*\{[^}]*width:\s*18px;\s*height:\s*12px;\s*object-fit:\s*cover;/)

  // 4. Central host in pinned box has #1 badge and central styling
  assert.match(appVue, /class="fleet-order-pinned-box"/)
  assert.match(appVue, /class="order-index-badge">#1<\/span>/)
})
