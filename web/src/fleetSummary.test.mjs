import assert from 'node:assert/strict'
import test from 'node:test'
import { summarizeFleet } from './fleetSummary.ts'

const now = Date.parse('2026-09-27T10:00:00Z')
const sample = (checkedAt, packetLossPct = 0, status = 'ok') => ({
  checkedAt: new Date(checkedAt).toISOString(), packetLossPct, status,
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

test('one host with loss in either region counts once, including earlier loss within the last 30 minutes', () => {
  const fresh = sample(now)
  const oldLoss = sample(now - 12 * 60_000, 10, 'partial')
  const network = { international: { ...fresh, history: [oldLoss, fresh] }, domestic: { ...fresh, history: [oldLoss, fresh] } }
  assert.equal(summarizeFleet([host('local', true, 3, 3, network)], now).networkAlerts, 1)
  const tooOld = sample(now - 31 * 60_000, 10, 'partial')
  const clear = { international: { ...fresh, history: [tooOld, fresh] }, domestic: fresh }
  assert.equal(summarizeFleet([host('local', true, 3, 3, clear)], now).networkAlerts, 0)
})

test('stale or failed probes alert; a host awaiting its first probe is pending', () => {
  const fresh = sample(now)
  const stale = sample(now - 151_000)
  const failed = sample(now, 0, 'error')
  const hosts = [host('stale', true, 1, 1, { international: stale, domestic: fresh }),
    host('failed', true, 1, 1, { international: failed, domestic: fresh }),
    host('pending', true, 1, 1, { international: fresh }),
    host('offline', false, 1, 1, { international: failed, domestic: failed })]
  const summary = summarizeFleet(hosts, now)
  assert.equal(summary.networkAlerts, 2)
  assert.equal(summary.networkPending, 1)
})
