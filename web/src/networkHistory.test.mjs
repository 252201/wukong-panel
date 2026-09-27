import assert from 'node:assert/strict'
import test from 'node:test'
import { historySlotsFor } from './networkHistory.ts'

const base = Date.parse('2026-09-27T10:00:10Z')
const sample = (time) => ({ checkedAt: new Date(time).toISOString(), status: 'ok' })
const health = (samples) => ({ checkedAt: samples.at(-1).checkedAt, history: samples })

test('small probe delays do not create an empty bar between consecutive samples', () => {
  const samples = [sample(base - 130_000), sample(base - 70_000), sample(base)]
  const slots = historySlotsFor(health(samples), base + 50_000)
  assert.deepEqual(slots.slice(-3), samples)
  assert.equal(slots.filter(Boolean).length, 3)
})

test('a genuinely missed probe minute stays empty', () => {
  const samples = [sample(base - 120_000), sample(base)]
  const slots = historySlotsFor(health(samples), base + 10_000)
  assert.equal(slots.at(-1), samples[1])
  assert.equal(slots.at(-2), null)
  assert.equal(slots.at(-3), samples[0])
})

test('a stopped probe leaves empty bars at the live end of the timeline', () => {
  const samples = [sample(base - 60_000), sample(base)]
  const slots = historySlotsFor(health(samples), base + 180_000)
  assert.deepEqual(slots.slice(-4), [samples[0], samples[1], null, null])
})

test('thirty regular samples fill thirty bars until the next probe is due', () => {
  const samples = Array.from({ length: 30 }, (_, index) => sample(base - (29 - index) * 60_000))
  const slots = historySlotsFor(health(samples), base + 50_000)
  assert.deepEqual(slots, samples)
})
