import type { NetworkGroupHealth, NetworkSample } from './api'

const slotCount = 30
const minuteMs = 60_000

// Anchor a healthy timeline to its newest probe, so polling between probes
// does not turn the newest bar into a false gap. Keep advancing when probes stop.
export function historySlotsFor(health: NetworkGroupHealth | undefined, now = Date.now()): (NetworkSample | null)[] {
  const slots: (NetworkSample | null)[] = Array(slotCount).fill(null)
  if (!health) return slots

  const samples = health.history?.length ? health.history : [health]
  const newest = Math.max(...samples.map(sample => Date.parse(sample.checkedAt)).filter(timestamp => Number.isFinite(timestamp) && timestamp <= now))
  if (!Number.isFinite(newest)) return slots
  const anchor = Math.max(newest, now - minuteMs)

  for (const sample of samples) {
    const checkedAt = Date.parse(sample.checkedAt)
    if (!Number.isFinite(checkedAt) || checkedAt > now) continue
    // Rounding tolerates a few seconds of ICMP and scheduler jitter, while a
    // genuinely missed minute (roughly 90 seconds or more) remains empty.
    const index = slotCount - 1 - Math.round((anchor - checkedAt) / minuteMs)
    if (index >= 0 && index < slotCount) slots[index] = sample
  }
  return slots
}
