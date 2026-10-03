import type { FirewallState, Fail2banState } from './api'

type SecurityStates = {firewall: FirewallState; fail2ban: Fail2banState}
export type SecurityKind = keyof SecurityStates
type Entry = {host: string; kind: SecurityKind; value?: SecurityStates[SecurityKind]; pending?: Promise<SecurityStates[SecurityKind]>}
// Memory only: cached samples are for display. Every visit still requests the
// Agent, and the component separately tracks whether each sample was verified.
export function createSecurityStatusCache(limit = 32) {
 const entries = new Map<string, Entry>()
 const keyFor = (host: string, kind: SecurityKind, zone: string) => JSON.stringify([host,kind,kind === 'firewall' ? zone : ''])
 const copy = <T>(value: T): T => JSON.parse(JSON.stringify(value))
 function clear(host?: string) {
  for (const [key,entry] of entries) if (host === undefined || entry.host === host) entries.delete(key)
 }
 function read<K extends SecurityKind>(host: string, kind: K, zone?: string): SecurityStates[K] | null {
  const entry = zone === undefined
   ? [...entries.values()].reverse().find(item => item.host === host && item.kind === kind && item.value)
   : entries.get(keyFor(host,kind,zone))
  return entry?.value ? copy(entry.value as SecurityStates[K]) : null
 }
 function refresh<K extends SecurityKind>(host: string, kind: K, zone: string, request: () => Promise<SecurityStates[K]>): Promise<SecurityStates[K]> {
  const key = keyFor(host,kind,zone)
  let entry = entries.get(key)
  if (entry?.pending) return entry.pending.then(value => copy(value as SecurityStates[K]))
  entry ||= {host,kind}
  entries.delete(key)
  entries.set(key,entry)
  while (entries.size > limit) entries.delete(entries.keys().next().value!)
  const current = entry
  current.pending = Promise.resolve().then(request).then(value => {
   // A mutation or logout can invalidate an outstanding request. Its late
   // response must never repopulate the cache with a pre-change sample.
   if (entries.get(key) === current) current.value = copy(value)
   return value
  }).finally(() => {current.pending = undefined})
  return current.pending.then(value => copy(value as SecurityStates[K]))
 }
 return {read,refresh,clear}
}
export const securityStatusCache = createSecurityStatusCache()
