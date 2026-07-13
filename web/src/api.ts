export type NodeStatus = 'active' | 'inactive' | 'unknown'

export interface NodeItem {
  id: string
  name: string
  protocol: string
  mode: 'prefer_v6' | 'v4only' | 'v6only'
  listenPort: number
  server: string
  domain: string
  ipv4Bind?: string
  ipv6Bind?: string
  autoBind: boolean
  serviceName: string
  serviceManager: string
  configPath: string
  configVersion: string
  ownership: string
  sharedGroup?: string
  status: NodeStatus
  probeStatus?: 'running' | 'success' | 'failed'
  probeLatencyMs?: number
  probeExitIp?: string
  probeTarget?: string
  probeError?: string
  probeCheckedAt?: string
}

export interface Metric {
  timestamp: number
  interface: string
  rxBytes: number
  txBytes: number
  rxBps: number
  txBps: number
  cpu: number
  memory: number
  memoryUsedBytes: number
  memoryTotalBytes: number
  disk: number
  diskUsedBytes: number
  diskTotalBytes: number
  load1: number
  uptime: number
}

export interface Overview {
  now: Metric
  history: Metric[]
  devices: DeviceTraffic[]
  processes: ProcessStat[]
  processCount: number
  nodeCount: number
  onlineNodes: number
  trafficUsed: number
  trafficQuota: number
  billingStart: string
  billingEnd: string
  singBoxVersion: string
  panelVersion: string
}

export interface ProcessStat { pid: number; name: string; cpu: number; rssBytes: number; memoryPercent: number }

export interface DeviceTraffic { nodeId: string; nodeName: string; bytes: number; rateBps: number }
export interface TrafficBucket { label: string; startedAt: number; rxBytes: number; txBytes: number }
export interface TrafficTimeline {
  today: TrafficBucket[]
  billing: TrafficBucket[]
  todayRx: number
  todayTx: number
  billingRx: number
  billingTx: number
  timezone: string
  billingStart: string
  billingEnd: string
}

export interface Job {
  id: string
  kind: string
  target: string
  status: 'queued' | 'running' | 'success' | 'failed'
  progress: number
  message: string
  error?: string
  createdAt: string
  updatedAt: string
}

export interface Candidate {
  fingerprint: string
  name: string
  protocol: string
  mode: string
  listenPort: number
  domain: string
  serviceName: string
  serviceManager: string
  configPath: string
  configVersion: string
  sharedGroup?: string
}

export interface BindAddress { address: string; interface: string }
export interface NodeDeploymentDefaults { panelDomain: string; ipv4: BindAddress[]; ipv6: BindAddress[] }

export interface Settings {
  language: string
  timezone: string
  interface: string
  trafficQuotaBytes: number
  billingResetDay: number
  collectEndpoints: boolean
  subscriptionToken?: string
}

export interface EndpointStat { nodeId: string; nodeName: string; endpoint: string; bytes: number }
export interface SingBoxMigrationFile { path: string; changes: string[]; warnings: string[]; errors: string[]; interfaces?: string[] }
export interface SingBoxMigrationPlan {
  target: string
  compatible: boolean
  requiresMigration: boolean
  files: SingBoxMigrationFile[]
  changes: number
  warnings: number
  errors: number
}

function normalizeMigrationPlan(plan: SingBoxMigrationPlan): SingBoxMigrationPlan {
  return {
    ...plan,
    files: (plan.files || []).map(file => ({
      ...file,
      changes: file.changes || [],
      warnings: file.warnings || [],
      errors: file.errors || [],
      interfaces: file.interfaces || [],
    })),
  }
}

let csrf = ''
export function setCSRF(value: string) { csrf = value }

async function request<T>(path: string, options: RequestInit = {}): Promise<T> {
  const headers = new Headers(options.headers)
  if (options.body) headers.set('Content-Type', 'application/json')
  if (csrf && options.method && options.method !== 'GET') headers.set('X-CSRF-Token', csrf)
  const response = await fetch(`api/v1/${path}`, { ...options, headers, credentials: 'same-origin' })
  const body = await response.json().catch(() => ({}))
  if (!response.ok) throw new Error(body.error || `HTTP ${response.status}`)
  return body as T
}

export const api = {
  login: (username: string, password: string) => request<{username: string; csrf: string; mustChange: boolean}>('auth/login', { method: 'POST', body: JSON.stringify({ username, password }) }),
  me: () => request<{username: string; csrf: string; mustChange: boolean; version: string}>('auth/me'),
  logout: () => request<{ok: boolean}>('auth/logout', { method: 'POST', body: '{}' }),
  changePassword: (password: string) => request<{ok: boolean}>('auth/password', { method: 'POST', body: JSON.stringify({ password }) }),
  overview: () => request<Overview>('overview'),
  endpoints: () => request<EndpointStat[]>('metrics/endpoints'),
  timeline: () => request<TrafficTimeline>('metrics/timeline'),
  singBoxMigration: async (target = '1.13.14') => normalizeMigrationPlan(await request<SingBoxMigrationPlan>(`system/sing-box/migration?target=${encodeURIComponent(target)}`)),
  nodes: () => request<NodeItem[]>('nodes'),
  nodeDeploymentDefaults: () => request<NodeDeploymentDefaults>('nodes/deployment-defaults'),
  createNode: (data: Record<string, unknown>) => request<{jobId: string}>('nodes', { method: 'POST', body: JSON.stringify(data) }),
  renameNode: (id: string, name: string) => request<{jobId: string}>(`nodes/${id}`, { method: 'PATCH', body: JSON.stringify({ name }) }),
  nodeAction: (id: string, action: string, confirmName = '') => request<{jobId: string}>(`nodes/${id}/actions`, { method: 'POST', body: JSON.stringify({ action, confirmName }) }),
  share: (id: string) => request<{uri: string; expiresAt: string}>(`nodes/${id}/share`),
  scan: () => request<Candidate[]>('imports/scan'),
  importNodes: (fingerprints: string[]) => request<{jobId: string}>('imports/confirm', { method: 'POST', body: JSON.stringify({ fingerprints }) }),
  jobs: () => request<Job[]>('jobs'),
  job: (id: string) => request<Job>(`jobs/${id}`),
  settings: () => request<Settings>('settings'),
  saveSettings: (data: Settings) => request<{ok: boolean}>('settings', { method: 'PUT', body: JSON.stringify(data) }),
  rotateSubscription: () => request<{token: string}>('settings/subscription-token', { method: 'POST', body: '{}' }),
}
