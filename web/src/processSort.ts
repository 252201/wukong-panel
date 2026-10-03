import type { Overview } from './api'
export type ProcessSortKey = 'cpu'|'memory'
type Process = Overview['processes'][number]
// Copy the snapshot so refreshes, labels and other views keep their original data.
export function sortProcesses(processes: Process[], key: ProcessSortKey, ascending = false): Process[] {
 const finite = (value: number) => Number.isFinite(value) ? value : 0
 return [...processes].sort((a,b) => {
  const cpu = finite(b.cpu) - finite(a.cpu)
  const memory = finite(b.rssBytes) - finite(a.rssBytes)
  const delta = key === 'memory' ? memory || cpu : cpu || memory
  return (ascending ? -delta : delta) || a.pid - b.pid
 })
}
