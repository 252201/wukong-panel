import type { Job } from './api'
const jobs = new Map<string, { job: Job; at: number }>()
const key = (hostId: string, component: string) => `${encodeURIComponent(hostId)}:${component}`
const running = (job: Job) => job.status === 'queued' || job.status === 'running'
export function startComponentUpdateJob(hostId: string, component: string, job: Job) {
 const id = key(hostId, component)
 jobs.delete(id)
 jobs.set(id, { job, at: Date.now() })
 while (jobs.size > 128) jobs.delete(jobs.keys().next().value!)
}
export function refreshComponentUpdateJob(hostId: string, component: string, job: Job) {
 const id = key(hostId, component)
 if (jobs.get(id)?.job.id !== job.id) return
 if (!running(job)) jobs.delete(id)
 else jobs.set(id, { job, at: Date.now() })
}
export function pendingComponentUpdateJob(hostId: string, component: string): Job | undefined {
 const id = key(hostId, component), saved = jobs.get(id)
 if (!saved) return
 if (Date.now() - saved.at > 15 * 60 * 1000 || !running(saved.job)) { jobs.delete(id); return }
 return saved.job
}
