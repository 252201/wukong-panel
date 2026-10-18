import assert from 'node:assert/strict'
import test from 'node:test'
import { fleetHostLiveRates, fleetHostRateHint, recentNetworkLossPct, summarizeFleet } from './fleetSummary.ts'

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
