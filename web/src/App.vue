<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import QRCode from 'qrcode'
import { api, componentUpdateAPI, getIPReputation, hostSecurityAPI, setCSRF, setFleetHost, type Candidate, type ComponentUpdateState, type EndpointStat, type FirewallState, type FleetHost, type FleetProbeNode, type FleetStatus, type FleetSubscriptionProbe, type IPReputationReport, type Job, type NetworkGroupHealth, type NodeDeploymentDefaults, type NodeItem, type NodeStatus, type Overview, type ResidentialExit, type Settings, type SingBoxMigrationPlan, type SOCKSExit, type TrafficBucket, type TrafficTimeline } from './api'
import { startComponentUpdateJob, refreshComponentUpdateJob, pendingComponentUpdateJob } from './componentUpdateJobs'
import { formatRelativeTime, formatFullDateTime } from './timeFormat'
import { securityRuleMatchesProtocol } from './securityRules'
import ThemePicker from './ThemePicker.vue'
import SecurityPanel from './SecurityPanel.vue'
import ComponentUpdatePanel from './ComponentUpdatePanel.vue'
import { securityStatusCache } from './securityStatus'
import NetworkHistoryBars from './NetworkHistoryBars.vue'
import { applyThemePreference, effectiveTheme, nextToggledThemePreference, observeSystemTheme, readThemePreference, type EffectiveTheme, type ThemePreference } from './theme'
import { applyLocale, createDocumentLocalizer, readLocalePreference, refreshDocumentLocale, translateText, type Locale } from './i18n'
import { sortProcesses, type ProcessSortKey } from './processSort'
import { historySlotsFor } from './networkHistory'
import { countryFlagURL } from './countryFlags'
import {
  fleetHostRateHint,
  networkGroupFrom,
  recentNetworkLossPct,
  summarizeFleet,
  sortFleetHostsByOrder,
  sortRemoteHostsByPreset,
  type NetworkGroupName,
} from './fleetSummary'
import { realityPresets, flattenRealityPresets, findRealityPreset } from './realityPresets'
import {
  fetchLatestRelease,
  isNewerVersion,
  hostUpdateOnlineSupported,
  getProbeUpdateCommand,
  getPanelUpdateCommand,
  getSingBoxUpdateCommand,
  type ReleaseInfo
} from './versionCheck'

type Page = 'fleet' | 'overview' | 'nodes' | 'traffic' | 'system' | 'security' | 'jobs' | 'settings'
type DeviceDraft = { key: number; name: string; listenPort: number; server: string; preferredServer: string; webSocketPath: string }

const processServiceLabels: Record<string, string> = {
  cloudflared: 'Cloudflare 隧道',
  'systemd-journal': '系统日志服务 · 内存含可回收日志缓存',
  fail2ban: '登录防护服务 · Fail2ban',
  'fail2ban-client': '登录防护管理工具 · Fail2ban',
  firewalld: '防火墙服务 · firewalld',
  'firewalld-client': '防火墙管理工具 · firewalld',
  ufw: '防火墙规则管理工具 · UFW',
  nftables: '防火墙规则管理工具 · nftables',
  iptables: '防火墙规则管理工具 · iptables',
  ip6tables: '防火墙规则管理工具 · ip6tables',
  'security-recovery': '悟空安全自动恢复',
  'security-firewall': '悟空防火墙规则加载',
}
function processServiceLabel(service?: string, name?: string): string {
  const key = service && Object.hasOwn(processServiceLabels, service)
    ? service
    : (name === 'systemd-journal' || name === 'systemd-journald' ? 'systemd-journal' : '')
  return key ? translateText(processServiceLabels[key], language.value) : ''
}

const authenticated = ref(false)
const loading = ref(true)
const username = ref('admin')
const password = ref('')
const loginError = ref('')
const mustChange = ref(false)
const newPassword = ref('')
const page = ref<Page>('overview')
const fleetStatus = ref<FleetStatus | null>(null)
const selectedHostId = ref('local')
const fleetEnabledDraft = ref(false)
const fleetPublicURL = ref('')
const fleetSubscriptionPublicURL = ref('')
const fleetSubscriptionProbe = ref<FleetSubscriptionProbe | null>(null)
const fleetSubscriptionProbeError = ref('')
const fleetSubscriptionProbeBusy = ref(false)
const enrollmentCommand = ref('')
const enrollmentMode = ref<'panel' | 'probe'>('panel')
const enrollmentExpiresAt = ref('')
const fleetLeaveCommand = computed(() => enrollmentMode.value === 'probe' ? 'curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/probe-install.sh | sudo sh -s -- --uninstall' : 'curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- --leave-controller')
const fleetSelectedHosts = ref<string[]>([])
const fleetSelectedNodes = ref<Record<string, string[]>>({})
const fleetDraftDirty = ref(false)
const settingsDraftDirty = ref(false)
const confirmRotateGlobalToken = ref(false)
const confirmRotateHostToken = ref(false)
let syncingFleetDraft = false
let syncingSettingsDraft = false
const overview = ref<Overview | null>(null)
const processSortKey = ref<ProcessSortKey>('cpu')
const processSortAscending = ref(false)
const sortedProcesses = computed(() => sortProcesses(overview.value?.processes || [], processSortKey.value, processSortAscending.value))
function changeProcessSort(key: ProcessSortKey) {
  processSortAscending.value = processSortKey.value === key ? !processSortAscending.value : false
  processSortKey.value = key
}
const nodes = ref<NodeItem[]>([])
const jobs = ref<Job[]>([])
const settings = ref<Settings>({ language: 'zh-CN', timezone: 'Asia/Shanghai', interface: 'auto', trafficQuotaBytes: 0, billingResetDay: 1, expiresAt: '', collectEndpoints: true })
const endpoints = ref<EndpointStat[]>([])
const timeline = ref<TrafficTimeline | null>(null)
const singBoxMigrationPlan = ref<SingBoxMigrationPlan | null>(null)
const singBoxMigrationLoading = ref(false)
const singBoxMigrationDetailsOpen = ref(false)
const residentialExit = ref<ResidentialExit | null>(null)
const residentialForm = reactive({ endpoint: '', listenPort: 51820, peerPublicKey: '', expectedExitIp: '' })
const residentialFormHydrated = ref(false)
const residentialBusy = ref(false)
const socksExit = ref<SOCKSExit | null>(null)
const socksForm = reactive({ server: '', port: 1080, version: '5', username: '', password: '', clearPassword: false, network: 'both', expectedExitIp: '' })
const socksFormHydrated = ref(false)
const socksBusy = ref(false)
const activeEgressTab = ref<'residential' | 'socks'>('residential')
const timelineRange = ref<'today' | 'billing'>('today')
const activeTimelineBucket = ref<number | null>(null)
const deviceLimit = ref(3)
const busy = ref(false)
const toast = ref('')
const language = ref<Locale>(readLocalePreference())
const themePreference = ref<ThemePreference>(readThemePreference())
const activeEffectiveTheme = ref<EffectiveTheme>(effectiveTheme(themePreference.value))
const topbarThemeTitle = computed(() => {
  const isDark = activeEffectiveTheme.value === 'dark'
  if (language.value === 'en-US') {
    return isDark ? 'Switch to light theme (Bright orange)' : 'Switch to dark theme (Midnight gold)'
  }
  return isDark ? '切换为亮色主题（明净橙白）' : '切换为暗色主题（墨夜金阙）'
})
const modal = ref<'create' | 'device-create' | 'edit' | 'import' | 'share' | 'delete' | 'residential-remove' | 'socks-remove' | 'fleet-host-action' | 'fleet-host-settings' | 'probe-nodes' | 'ip-reputation' | 'host-update' | 'singbox-update' | 'fleet-order' | 'diagnostic' | null>(null)
const hostUpdateTarget = ref<FleetHost | null>(null)
const hostUpdating = ref(false)
const hostUpdateJob = ref<Job | null>(null)
const hostUpdateError = ref('')
const hostReconnecting = ref(false)
const hostReconnectAttempts = ref(0)
const hostReloadCountdown = ref(0)
let hostReloadCountdownTimer: number | undefined
let hostPollTimer: ReturnType<typeof setTimeout> | undefined
let hostReconnectTimer: ReturnType<typeof setTimeout> | undefined
const latestRelease = ref<ReleaseInfo | null>(null)
const latestReleaseVersion = computed(() => latestRelease.value?.version || '')
const latestReleaseNotes = computed(() => latestRelease.value?.body || '')
const latestReleaseUrl = computed(() => latestRelease.value?.htmlUrl || '')
const latestSingBoxVersion = computed(() => latestRelease.value?.singBoxVersion || '1.14.4')
const latestSingBoxUrl = computed(() => latestRelease.value?.singBoxUrl || 'https://github.com/SagerNet/sing-box/releases')
const singBoxUpdateTarget = ref<FleetHost | null>(null)
const singBoxUpdateState = ref<ComponentUpdateState | null>(null)
const singBoxUpdating = ref(false)
const singBoxUpdateJob = ref<Job | null>(null)
const singBoxUpdateError = ref('')
let singBoxPollTimer: ReturnType<typeof setTimeout> | undefined
type FleetHostAction = 'rename' | 'remove' | 'purge'
const fleetHostAction = ref<FleetHostAction | null>(null)
const fleetHostTarget = ref<FleetHost | null>(null)
const fleetHostSettingsTarget = ref<FleetHost | null>(null)
const probeNodesTarget = ref<FleetHost | null>(null)
const probeNodesList = ref<FleetProbeNode[]>([])
const probeNodesLoading = ref(false)
const probeNodeRenameId = ref<string | null>(null)
const probeNodeRenameDraft = ref('')
const probeNodeAddShareURI = ref('')
const probeNodeAddBusy = ref(false)
const fleetHostSettingsDraft = ref({
  billingResetDay: 1,
  trafficQuotaGB: 0,
  trafficCalcMode: 'both',
  expiresAt: '',
})
const fleetHostNameDraft = ref('')
const fleetHostConfirm = ref('')
const candidates = ref<Candidate[]>([])
const selectedCandidates = ref<string[]>([])
const candidateDeleteTarget = ref<Candidate | null>(null)
const candidateDeleteConfirm = ref('')
const selectedNode = ref<NodeItem | null>(null)
const shareURI = ref('')
const shareQR = ref('')
const deleteConfirm = ref('')
const residentialRemoveConfirm = ref('')
const socksRemoveConfirm = ref('')
const createForm = reactive({ protocol: 'hysteria2', name: '', mode: 'prefer_v6', egress: 'direct', listenPort: 0, autoAllowPort: true, server: '', domain: '', preferredServer: '', webSocketPath: '', tunnelToken: '', ipv4Bind: '', ipv6Bind: '', autoBind: false, v6OnlyDomains: 'chatgpt.com,claude.ai,anthropic.com', certificatePath: '', keyPath: '' })
const deviceMode = computed(() => modal.value === 'device-create')
const isEditing = computed(() => modal.value === 'edit')
const deviceSequence = ref(0)
const deviceNodes = reactive<DeviceDraft[]>([])
const deploymentDefaults = ref<NodeDeploymentDefaults>({ panelDomain: '', ipv4: [], ipv6: [], residentialExitReady: false, socksExitReady: false })
const bindChoice = reactive({ ipv4: '', ipv6: '' })
const defaultsLoading = ref(false)
const formHydrating = ref(false)
const probeJobs = reactive<Record<string, string>>({})
const hostFirewall = ref<FirewallState | null>(null)
const diagnosticNode = ref<NodeItem | null>(null)

interface DeploymentProgress {
  jobId: string
  targetName: string
  progress: number
  message: string
}
interface DeploymentReadyNotice {
  jobId: string
  title: string
  message: string
  node?: NodeItem
}
const deploymentProgress = ref<DeploymentProgress | null>(null)
const deploymentReady = ref<DeploymentReadyNotice | null>(null)
let deploymentReadyTimer: number | null = null

watch(nodes, (newNodes) => {
  if (diagnosticNode.value) {
    const updated = newNodes.find(n => n.id === diagnosticNode.value?.id)
    if (updated) diagnosticNode.value = updated
  }
})

const words = {
  'zh-CN': { fleet: '舰队', overview: '总览', nodes: '节点', traffic: '流量', system: '系统', security: '安全', jobs: '任务日志', settings: '设置', deploy: '部署节点', import: '接管节点', online: '在线', offline: '离线' },
  'en-US': { fleet: 'Fleet', overview: 'Overview', nodes: 'Nodes', traffic: 'Traffic', system: 'System', security: 'Security', jobs: 'Jobs', settings: 'Settings', deploy: 'Deploy node', import: 'Import nodes', online: 'Online', offline: 'Offline' },
}
const t = (key: keyof typeof words['zh-CN']) => words[language.value][key]
const navItems = computed(() => [
  ...(fleetStatus.value?.enabled ? [{ id: 'fleet' as Page, seal: '舰', label: t('fleet') }] : []),
  { id: 'overview' as Page, seal: '总', label: t('overview') },
  { id: 'nodes' as Page, seal: '节', label: t('nodes') },
  { id: 'traffic' as Page, seal: '流', label: t('traffic') },
  { id: 'system' as Page, seal: '系', label: t('system') },
  { id: 'security' as Page, seal: language.value === 'en-US' ? 'S' : '安', label: t('security') },
  { id: 'jobs' as Page, seal: '任', label: t('jobs') },
  { id: 'settings' as Page, seal: '设', label: t('settings') },
])
const currentFleetHost = computed<FleetHost | null>(() => fleetStatus.value?.hosts.find(host => host.id === selectedHostId.value) || null)
const remoteHost = computed(() => selectedHostId.value !== 'local')
const mutationsDisabled = computed(() => remoteHost.value && (!currentFleetHost.value?.online || !currentFleetHost.value?.compatible))
const fleetHosts = computed(() => fleetStatus.value?.hosts || [])
const remoteFleetHosts = computed(() => fleetHosts.value.filter(host => host.id !== 'local'))
const centralFleetHost = computed<FleetHost | null>(() => fleetHosts.value.find(host => host.id === 'local') || null)
const isProbeHost = (host: FleetHost) => host.capabilities?.includes('probe') || false
function fleetHostNodeSummary(host: FleetHost): string {
  if (isProbeHost(host)) {
    const total = (host.snapshot?.nodes || []).length || host.snapshot?.overview?.nodeCount || 0
    const online = host.online ? ((host.snapshot?.nodes || []).length || host.snapshot?.overview?.onlineNodes || 0) : 0
    return `${online}/${total}`
  }
  return `${host.snapshot?.overview?.onlineNodes || 0}/${host.snapshot?.overview?.nodeCount || 0}`
}
const fleetAggregate = computed(() => summarizeFleet(fleetHosts.value))

const trafficPercent = computed(() => {
  const data = overview.value
  if (!data?.trafficQuota) return 0
  return Math.min(100, data.trafficUsed / data.trafficQuota * 100)
})
const quotaRing = computed(() => ({ '--progress': `${trafficPercent.value * 3.6}deg` }))
const networkHealth = computed(() => overview.value?.network)
const networkGroups: NetworkGroupName[] = ['international', 'domestic']
const networkMetrics = ['latency', 'loss'] as const
function networkGroup(group: NetworkGroupName): NetworkGroupHealth | undefined {
  return networkGroupFrom(networkHealth.value, group)
}
function networkGroupLabel(group: NetworkGroupName) {
  return group === 'international' ? (language.value === 'en-US' ? 'International' : '国际') : (language.value === 'en-US' ? 'Domestic' : '国内')
}
function networkState(group: NetworkGroupName) {
  if (remoteHost.value && !currentFleetHost.value?.online) return 'offline'
  const health = networkGroup(group)
  if (!health) return 'pending'
  const checkedAt = Date.parse(health.checkedAt)
  if (!Number.isFinite(checkedAt) || Date.now() - checkedAt > 150_000) return 'stale'
  return health.status
}
function networkReadable(group: NetworkGroupName) { return networkState(group) === 'ok' || networkState(group) === 'partial' }
function networkLatency(group: NetworkGroupName) {
  const health = networkGroup(group)
  if (!networkReadable(group) || !health) return '—'
  return health.packetsReceived ? health.latencyMs.toFixed(1) : (language.value === 'en-US' ? 'No reply' : '无响应')
}
function networkLoss(group: NetworkGroupName) {
  const loss = networkReadable(group) ? recentNetworkLossPct(networkGroup(group)) : null
  return loss === null ? '—' : loss.toFixed(1)
}
function networkHistoryLabel(group: NetworkGroupName) {
  const english = language.value === 'en-US'
  if (networkState(group) === 'offline') return english ? 'Host offline' : '主机离线'
  if (networkState(group) === 'pending') return english ? 'Waiting for probe' : '等待首次采样'
  if (networkState(group) === 'stale') return english ? 'Stale sample' : '采样已过期'
  if (networkState(group) === 'error') return english ? 'ICMP unavailable' : 'ICMP 不可用'
  return english ? 'Last 30 minutes' : '近 30 分钟'
}
function networkHistorySlots(group: NetworkGroupName) { return historySlotsFor(networkGroup(group)) }
function networkHistoryCount(group: NetworkGroupName) { return networkHistorySlots(group).filter(Boolean).length }
function networkLatencyTone(group: NetworkGroupName) {
  const health = networkGroup(group)
  if (!networkReadable(group)) return 'muted'
  if (!health?.packetsReceived) return 'bad'
  return health.latencyMs >= 200 ? 'bad' : health.latencyMs >= 100 ? 'warn' : 'good'
}
function networkLossTone(group: NetworkGroupName) {
  const loss = networkReadable(group) ? recentNetworkLossPct(networkGroup(group)) : null
  if (loss === null) return 'muted'
  return loss >= 5 ? 'bad' : loss > 0 ? 'warn' : 'good'
}
function fleetNetworkGroup(host: FleetHost, group: NetworkGroupName) {
  return networkGroupFrom(host.snapshot?.overview?.network, group)
}
function fleetNetworkState(host: FleetHost, group: NetworkGroupName) {
  if (!host.online) return 'offline'
  const health = fleetNetworkGroup(host, group)
  if (!health) return 'pending'
  const checkedAt = Date.parse(health.checkedAt)
  if (!Number.isFinite(checkedAt) || Date.now() - checkedAt > 150_000) return 'stale'
  return health.status
}
function fleetNetworkReadable(host: FleetHost, group: NetworkGroupName) {
  const state = fleetNetworkState(host, group)
  return state === 'ok' || state === 'partial'
}
function fleetNetworkValue(host: FleetHost, group: NetworkGroupName, metric: 'latency' | 'loss') {
  const health = fleetNetworkGroup(host, group)
  if (!fleetNetworkReadable(host, group) || !health) return '—'
  if (metric === 'loss') {
    const loss = recentNetworkLossPct(health)
    return loss === null ? '—' : `${loss.toFixed(1)}%`
  }
  return health.packetsReceived ? `${health.latencyMs.toFixed(1)} ms` : (language.value === 'en-US' ? 'No reply' : '无响应')
}
function fleetNetworkTone(host: FleetHost, group: NetworkGroupName, metric: 'latency' | 'loss') {
  const health = fleetNetworkGroup(host, group)
  if (!fleetNetworkReadable(host, group) || !health) return 'muted'
  if (metric === 'loss') {
    const loss = recentNetworkLossPct(health)
    return loss === null ? 'muted' : loss >= 5 ? 'bad' : loss > 0 ? 'warn' : 'good'
  }
  if (!health.packetsReceived || health.latencyMs >= 200) return 'bad'
  return health.latencyMs >= 100 ? 'warn' : 'good'
}
function fleetNetworkHistorySlots(host: FleetHost, group: NetworkGroupName) {
  return historySlotsFor(fleetNetworkGroup(host, group))
}
function fleetNetworkHistoryCount(host: FleetHost, group: NetworkGroupName) {
  return fleetNetworkHistorySlots(host, group).filter(Boolean).length
}
function fleetNetworkStateLabel(host: FleetHost, group: NetworkGroupName) {
  const english = language.value === 'en-US'
  switch (fleetNetworkState(host, group)) {
    case 'offline': return english ? 'Offline' : '离线'
    case 'pending': return english ? 'No sample' : '未采样'
    case 'stale': return english ? 'Stale' : '已过期'
    case 'error': return english ? 'Unavailable' : '不可用'
    default: return `${fleetNetworkHistoryCount(host, group)}/30`
  }
}
function fleetNetworkHint(host: FleetHost, group: NetworkGroupName) {
  const health = fleetNetworkGroup(host, group)
  const state = fleetNetworkState(host, group)
  if (state === 'offline') return language.value === 'en-US' ? 'Host offline' : '主机离线'
  if (state === 'pending') return language.value === 'en-US' ? 'Waiting for probe' : '等待首次采样'
  if (state === 'stale') return language.value === 'en-US' ? 'Stale sample' : '采样已过期'
  return health?.error || health?.targets?.join(' / ') || 'ICMP'
}
function fleetRateHint(host: FleetHost) {
  return fleetHostRateHint(host, language.value)
}
const chartPeak = computed(() => Math.max(0, ...(overview.value?.history || []).flatMap(row => [row.rxBps, row.txBps])))
function makeChartPath(field: 'rxBps' | 'txBps') {
  const rows = overview.value?.history || []
  if (rows.length < 2) return 'M 0 70 L 1000 70'
  const scale = Math.max(1, chartPeak.value)
  return rows.map((row, index) => `${index ? 'L' : 'M'} ${(index / (rows.length - 1)) * 1000} ${125 - (row[field] / scale) * 105}`).join(' ')
}
const rxChartPath = computed(() => makeChartPath('rxBps'))
const txChartPath = computed(() => makeChartPath('txBps'))
const rxAreaPath = computed(() => `${rxChartPath.value} L 1000 140 L 0 140 Z`)
const activeDevices = computed(() => overview.value?.devices || [])
const visibleDevices = computed(() => activeDevices.value.slice(0, deviceLimit.value))
const hiddenDeviceCount = computed(() => Math.max(0, activeDevices.value.length - deviceLimit.value))
const vitalItems = computed(() => [
  { name: 'CPU', value: overview.value?.now.cpu || 0, meta: `负载 ${overview.value?.now.load1.toFixed(2) || 0}`, usage: '' },
  { name: '内存', value: overview.value?.now.memory || 0, meta: 'MemAvailable 口径', usage: `${bytes(overview.value?.now.memoryUsedBytes)} / ${bytes(overview.value?.now.memoryTotalBytes)}` },
  { name: '磁盘', value: overview.value?.now.disk || 0, meta: '根分区 /', usage: `${bytes(overview.value?.now.diskUsedBytes)} / ${bytes(overview.value?.now.diskTotalBytes)}` },
])
const timelineBuckets = computed(() => timelineRange.value === 'today' ? timeline.value?.today || [] : timeline.value?.billing || [])
const timelineTotals = computed(() => timelineRange.value === 'today'
  ? { rx: timeline.value?.todayRx || 0, tx: timeline.value?.todayTx || 0 }
  : { rx: timeline.value?.billingRx || 0, tx: timeline.value?.billingTx || 0 })
const timelineMax = computed(() => Math.max(1, ...timelineBuckets.value.map(item => item.rxBytes + item.txBytes)))
const timelineAverage = computed(() => {
  const rows = timelineBuckets.value
  return rows.length ? rows.reduce((sum, item) => sum + item.rxBytes + item.txBytes, 0) / rows.length : 0
})
const selectedTimelineBucket = computed<TrafficBucket | null>(() => {
  if (activeTimelineBucket.value === null) return null
  const item = timelineBuckets.value[activeTimelineBucket.value]
  return item && item.rxBytes + item.txBytes > 0 ? item : null
})
const timelineTooltipLeft = computed(() => {
  const index = activeTimelineBucket.value ?? 0
  return `${Math.min(86, Math.max(14, (index + .5) / Math.max(1, timelineBuckets.value.length) * 100))}%`
})
const activeJobs = computed(() => jobs.value.filter(job => job.status === 'running' || job.status === 'queued').length)
const residentialNodesInUse = computed(() => nodes.value.filter(node => node.egress === 'residential'))
const socksNodesInUse = computed(() => nodes.value.filter(node => node.egress === 'socks'))
function outboundLabel(node: NodeItem) {
  if (node.egress === 'residential') return '落地出口'
  if (node.egress === 'socks') return 'SOCKS 出站'
  return modeLabel(node.mode)
}
const protocolCatalog = {
  hysteria2: { badge: 'HY2', label: 'Hysteria2', transport: 'UDP', domainLabel: 'TLS 域名', note: 'QUIC 高速节点，适合弱网与高延迟链路。' },
  vless: { badge: 'VLESS', label: 'VLESS + REALITY', transport: 'TCP', domainLabel: 'REALITY 伪装域名', note: 'TCP 备用线路；域名必须是本机可访问的真实 TLS 站点。' },
  'vless-ws-tunnel': { badge: 'VLESS · CF', label: 'VLESS + WebSocket + Cloudflare Tunnel', transport: 'WS · CF', domainLabel: 'Cloudflare 节点域名', note: 'Cloudflare 边缘 443 入站；VPS 仅监听本机 Origin，不开放代理端口。' },
  shadowsocks: { badge: 'SS2022', label: 'Shadowsocks 2022', transport: 'TCP + UDP', domainLabel: '', note: '轻量双栈节点，使用 2022 AES-128-GCM。' },
  tuic: { badge: 'TUIC', label: 'TUIC v5', transport: 'UDP', domainLabel: 'TLS 域名', note: 'QUIC 低延迟节点，使用 BBR 拥塞控制。' },
  trojan: { badge: 'TROJAN', label: 'Trojan TLS', transport: 'TCP', domainLabel: 'TLS 域名', note: '基于标准 TLS 的 TCP 兼容节点。' },
  anytls: { badge: 'ANYTLS', label: 'AnyTLS', transport: 'TCP', domainLabel: 'TLS 域名', note: '基于标准 TLS 的复用与填充协议，适合 UDP 受限网络。' },
} as const
const protocolList = [
  { key: 'hysteria2', badge: 'HY2', label: 'Hysteria2', transport: 'UDP', highlight: 'QUIC 极速抗丢包' },
  { key: 'vless', badge: 'VLESS', label: 'VLESS + REALITY', transport: 'TCP', highlight: '真实 TLS 免证书' },
  { key: 'vless-ws-tunnel', badge: 'VLESS · CF', label: 'CF Tunnel', transport: 'WS · CF', highlight: '免公网端口·穿透' },
  { key: 'shadowsocks', badge: 'SS2022', label: 'Shadowsocks 2022', transport: 'TCP+UDP', highlight: '轻量极简双栈' },
  { key: 'tuic', badge: 'TUIC', label: 'TUIC v5', transport: 'UDP', highlight: '低延迟 BBR 拥塞' },
  { key: 'trojan', badge: 'TROJAN', label: 'Trojan TLS', transport: 'TCP', highlight: '标准 TLS 兼容' },
  { key: 'anytls', badge: 'ANYTLS', label: 'AnyTLS', transport: 'TCP', highlight: '流量填充与复用' },
] as const
const protocolInfo = (protocol: string) => protocolCatalog[protocol as keyof typeof protocolCatalog] || protocolCatalog.hysteria2
const selectedProtocolInfo = computed(() => protocolInfo(createForm.protocol))
const isTunnelProtocol = computed(() => createForm.protocol === 'vless-ws-tunnel')

const flattenedRealityPresets = computed(() => flattenRealityPresets(realityPresets))
const activeRealityPreset = computed(() => findRealityPreset(createForm.domain, realityPresets))
const realityPickerOpen = ref(false)
function chooseRealityPreset(domain: string) {
  createForm.domain = domain
  realityPickerOpen.value = false
}
watch(() => [modal.value, createForm.protocol], () => {
  realityPickerOpen.value = false
})

function bytes(value = 0, fractionDigits?: number) {
  if (!Number.isFinite(value)) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = Math.max(0, value); let index = 0
  while (size >= 1000 && index < units.length - 1) { size /= 1000; index++ }
  return `${size.toFixed(fractionDigits ?? (index < 2 ? 0 : 2))} ${units[index]}`
}
function resourceUsage(used = 0, total = 0, fractionDigits?: number) {
  if (!Number.isFinite(used) || !Number.isFinite(total) || total <= 0) return '— / —'
  return `${bytes(used, fractionDigits)} / ${bytes(total, fractionDigits)}`
}
function resourcePercent(used = 0, total = 0, fallback = 0, fractionDigits = 1) {
  const percent = total > 0 ? used / total * 100 : fallback
  return `${Math.max(0, percent).toFixed(fractionDigits)}% 已用`
}
function fleetBillingUsage(data?: Overview) {
  if (!data) return '—'
  return `${bytes(data.trafficUsed)} / ${data.trafficQuota ? bytes(data.trafficQuota) : '不限量'}`
}
function fleetBillingPercent(data?: Overview) {
  if (!data) return '—'
  if (!data.trafficQuota) return '不限量'
  return `${Math.min(100, Math.max(0, data.trafficUsed / data.trafficQuota * 100)).toFixed(1)}% 已用`
}
function rate(value = 0) { return `${bytes(value)}/s` }
function axisRate(value = 0) {
  if (!Number.isFinite(value) || value <= 0) return '0 B/s'
  const units = ['B/s', 'KB/s', 'MB/s', 'GB/s', 'TB/s']
  let size = value; let index = 0
  while (size >= 1000 && index < units.length - 1) { size /= 1000; index++ }
  const digits = index === 0 ? 0 : index === 1 ? 1 : 2
  return `${size.toFixed(digits)} ${units[index]}`
}
function uptime(value?: number) {
  if (typeof value !== 'number' || !Number.isFinite(value) || value < 0) return '—'
  const seconds = Math.floor(value)
  const days = Math.floor(seconds / 86400)
  const hours = Math.floor(seconds % 86400 / 3600)
  const minutes = Math.floor(seconds % 3600 / 60)
  if (days) return `${days}天 ${hours}小时`
  if (hours) return `${hours}小时 ${minutes}分`
  return `${minutes}分`
}
function hostCountryName(code: string) {
  try {
    return new Intl.DisplayNames([language.value], { type: 'region' }).of(code.toUpperCase()) || code
  } catch {
    return code.toUpperCase()
  }
}
function modeLabel(mode: string) { return ({ prefer_v6: 'IPv6 优先', v4only: '纯 IPv4', v6only: '纯 IPv6' } as Record<string, string>)[mode] || mode }
function jobLabel(kind: string) { return ({ 'node.create': '部署节点', 'node.create_batch': '部署设备节点', 'node.edit': '编辑节点', 'node.rename': '重命名节点', 'node.start': '启动节点', 'node.stop': '停止节点', 'node.restart': '重启节点', 'node.check': '校验配置', 'node.probe': '连通性检测', 'node.delete': '删除节点', 'nodes.import': '接管节点', 'candidate.delete': '彻底删除接管节点' } as Record<string, string>)[kind] || kind }
function notify(message: string) { toast.value = message; window.setTimeout(() => { if (toast.value === message) toast.value = '' }, 3200) }
function probeState(node: NodeItem) { return probeJobs[node.id] ? 'running' : node.probeStatus || 'idle' }
function probeTime(value?: string) {
  if (!value) return ''
  const date = new Date(value)
  return Number.isNaN(date.getTime()) ? '' : date.toLocaleTimeString(language.value, { hour: '2-digit', minute: '2-digit' })
}
function probeDetail(node: NodeItem) {
  const state = probeState(node)
  if (state === 'running') return node.protocol === 'vless-ws-tunnel' ? '正在验证 Cloudflare TLS、WebSocket、认证与代理出站' : '正在验证握手、认证与代理出站'
  const relTime = formatRelativeTime(node.probeCheckedAt, Date.now(), language.value)
  if (state === 'success') return `${node.probeLatencyMs || 0} ms${node.probeExitIp ? ` · ${node.probeExitIp}` : ''}${relTime ? ` · ${relTime}` : ''}`
  if (state === 'failed') return `${node.probeError || '完整代理请求未通过'}${relTime ? ` · ${relTime}` : ''}`
  return node.protocol === 'vless-ws-tunnel' ? 'CF TLS · WebSocket · 认证 · 出站' : '握手 · 认证 · 出站'
}
function nodePublicPort(node: NodeItem) { return node.protocol === 'vless-ws-tunnel' ? 443 : node.listenPort }
function tunnelOrigin(node: NodeItem) { return `http://127.0.0.1:${node.listenPort}` }
function nodeDialServer(node: NodeItem) { return node.protocol === 'vless-ws-tunnel' && node.preferredServer ? node.preferredServer : node.server || node.domain }
function nodeRate(nodeId: string): number {
  const dev = overview.value?.devices?.find(d => d.nodeId === nodeId)
  return dev?.rateBps || 0
}
function nodeTrafficTooltip(node: NodeItem): string {
  const current = bytes(node.trafficBytes || 0)
  const total = bytes(node.totalTrafficBytes || 0)
  if (language.value === 'en-US') {
    if (node.totalTrafficBytes && node.totalTrafficBytes !== node.trafficBytes) {
      return `Current billing cycle: ${current} · 90-day total: ${total}`
    }
    return `Cumulative traffic: ${current}`
  }
  if (node.totalTrafficBytes && node.totalTrafficBytes !== node.trafficBytes) {
    return `本账期累计: ${current} · 90天历史总计: ${total}`
  }
  return `当前节点累计传输流量: ${current}`
}
function openDiagnostic(node: NodeItem) {
  diagnosticNode.value = node
  modal.value = 'diagnostic'
}
async function fetchFirewallStatus() {
  try {
    const cached = securityStatusCache.read(selectedHostId.value, 'firewall')
    if (cached) {
      hostFirewall.value = cached
      return
    }
    const client = hostSecurityAPI(selectedHostId.value)
    const fw = await securityStatusCache.refresh(selectedHostId.value, 'firewall', '', () => client.firewall())
    hostFirewall.value = fw
  } catch {
    // Graceful fallback if security/firewall endpoint is unavailable
  }
}
function nodeFirewallStatus(node: NodeItem) {
  const isEn = language.value === 'en-US'
  if (node.protocol === 'vless-ws-tunnel') {
    return {
      status: 'tunnel',
      label: isEn ? 'Tunnel Loopback' : '免开公网端口',
      class: 'tunnel',
      clickable: false,
      title: isEn
        ? 'Cloudflare Tunnel connects via outbound WebSocket, requiring no open public inbound ports.'
        : 'Cloudflare Tunnel 走本地回环出站连接，无需在 VPS 主机或安全组开放公网入站端口。'
    }
  }

  const fw = hostFirewall.value
  if (!fw) {
    return {
      status: 'unknown',
      label: isEn ? 'Firewall: —' : '防火墙检测',
      class: 'unknown',
      clickable: true,
      title: isEn
        ? 'Click to manage firewall rules in Security tab.'
        : '点击前往安全板块查看主机防火墙规则与配置。'
    }
  }

  if (!fw.active) {
    return {
      status: 'disabled',
      label: isEn ? 'Firewall Off' : '防火墙未启用',
      class: 'idle',
      clickable: true,
      title: isEn
        ? 'Host firewall is inactive. Inbound ports are open directly (ensure cloud security group allows traffic).'
        : '主机未启用系统防火墙，所有入站端口直通（仍需确保云厂商安全组放行）。'
    }
  }

  const transport = protocolInfo(node.protocol).transport.toLowerCase()
  const port = node.listenPort
  const isAllowed = fw.rules && fw.rules.some(rule =>
    rule.action === 'allow' &&
    (rule.source === 'any' || !rule.source) &&
    securityRuleMatchesProtocol(rule, transport) &&
    rule.portFrom <= port &&
    rule.portTo >= port
  )

  if (isAllowed) {
    return {
      status: 'allowed',
      label: isEn ? 'Port Allowed' : '端口已放行',
      class: 'allowed',
      clickable: true,
      title: isEn
        ? `Host firewall allows inbound traffic to ${port}/${transport.toUpperCase()}.`
        : `主机防火墙已放行 ${port}/${transport.toUpperCase()} 入站端口。`
    }
  }

  return {
    status: 'blocked',
    label: isEn ? 'Port Not Allowed' : '端口待放行',
    class: 'warning',
    clickable: true,
    title: isEn
      ? `Host firewall has not allowed port ${port}/${transport.toUpperCase()}. External clients may be blocked. Click to manage.`
      : `主机防火墙尚未放行 ${port}/${transport.toUpperCase()}，外部客户端可能无法连接。点击前往安全板块一键放行。`
  }
}
function setTimelineRange(range: 'today' | 'billing') {
  timelineRange.value = range
  activeTimelineBucket.value = null
}
function showTimelineBucket(index: number) {
  const item = timelineBuckets.value[index]
  activeTimelineBucket.value = item && item.rxBytes + item.txBytes > 0 ? index : null
}
function clearTimelineBucket(index?: number) {
  if (index === undefined || activeTimelineBucket.value === index) activeTimelineBucket.value = null
}
function bucketHeight(item: TrafficBucket) { return Math.max(item.rxBytes + item.txBytes > 0 ? 3 : 0, (item.rxBytes + item.txBytes) / timelineMax.value * 100) }
function bucketSegment(value: number, item: TrafficBucket) { const total = item.rxBytes + item.txBytes; return total ? value / total * 100 : 0 }
function timelineLabel(item: TrafficBucket) { return timelineRange.value === 'today' ? `${item.label}:00` : item.label }
function updateDeviceLimit() { deviceLimit.value = window.innerWidth < 720 ? 2 : window.innerWidth < 1100 ? 3 : 4 }
function navigateTo(nextPage: Page) {
  deployMenuOpen.value = false
  window.scrollTo({ top: 0, left: 0, behavior: 'auto' })
  page.value = nextPage
}

async function refreshFleetStatus() {
  const status = await api.fleetStatus()
  fleetStatus.value = status
  if (!fleetDraftDirty.value) applyFleetDraft(status)
  if (!status.hosts.some(host => host.id === selectedHostId.value)) {
    selectedHostId.value = 'local'
    setFleetHost('local')
  }
}

function sameStringArray(a: readonly string[], b: readonly string[]): boolean {
  if (a.length !== b.length) return false
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false
  }
  return true
}

function sameSelectedNodesMap(a: Record<string, string[]>, b: Record<string, string[]>): boolean {
  const aKeys = Object.keys(a)
  const bKeys = Object.keys(b)
  if (aKeys.length !== bKeys.length) return false
  for (const key of aKeys) {
    if (!Object.hasOwn(b, key) || !sameStringArray(a[key] || [], b[key] || [])) return false
  }
  return true
}

function applyFleetDraft(status: FleetStatus) {
  const selectedNodes: Record<string, string[]> = {}
  for (const host of status.hosts) {
    const snapshotNodes = host.snapshot?.nodes
    const activeNodeIds = (snapshotNodes || []).filter(node => node.status === 'active').map(node => node.id)
    const rawSelected = status.selectedNodeIds?.[host.id]
    if (!Array.isArray(rawSelected)) {
      selectedNodes[host.id] = activeNodeIds
    } else if (Array.isArray(snapshotNodes)) {
      const activeSet = new Set(activeNodeIds)
      selectedNodes[host.id] = rawSelected.filter(id => activeSet.has(id))
    } else {
      selectedNodes[host.id] = [...rawSelected]
    }
  }
  const nextSelectedHosts = status.selectedHostIds?.length ? status.selectedHostIds.filter(id => {
    const h = status.hosts.find(item => item.id === id)
    return Boolean(h && (!isProbeHost(h) || (h.snapshot?.nodes || []).length > 0))
  }) : status.hosts.filter(host => !isProbeHost(host) || (host.snapshot?.nodes || []).length > 0).map(host => host.id)
  syncingFleetDraft = true
  try {
    fleetEnabledDraft.value = status.enabled
    fleetPublicURL.value = status.publicUrl || `${window.location.origin}${window.location.pathname.replace(/[^/]*$/, '')}`
    fleetSubscriptionPublicURL.value = status.subscriptionPublicUrl || ''
    if (!sameStringArray(fleetSelectedHosts.value, nextSelectedHosts)) {
      fleetSelectedHosts.value = nextSelectedHosts
    }
    if (!sameSelectedNodesMap(fleetSelectedNodes.value, selectedNodes)) {
      fleetSelectedNodes.value = selectedNodes
    }
  } finally { syncingFleetDraft = false }
}

async function switchFleetHost(hostId: string) {
  deployMenuOpen.value = false
  if (fleetHosts.value.some(host => host.id === hostId && isProbeHost(host))) return
  selectedHostId.value = hostId
  setFleetHost(hostId)
  hostFirewall.value = null
  void fetchFirewallStatus()
  if (page.value === 'settings') settingsDraftDirty.value = false
  residentialFormHydrated.value = false
  socksFormHydrated.value = false
  if (page.value === 'fleet') navigateTo('overview')
  if (page.value !== 'security') await refreshAll()
}

async function saveFleetController(rotateGlobalToken = false) {
  busy.value = true
  try {
    fleetStatus.value = await api.saveFleetStatus({ enabled: fleetEnabledDraft.value, publicUrl: fleetPublicURL.value, subscriptionPublicUrl: fleetSubscriptionPublicURL.value, selectedHostIds: fleetSelectedHosts.value, selectedNodeIds: fleetSelectedNodes.value, rotateGlobalToken })
    applyFleetDraft(fleetStatus.value)
    fleetDraftDirty.value = false
    notify(rotateGlobalToken ? '全局订阅令牌已轮换' : '中央控制设置已保存')
  } catch (error) { notify(error instanceof Error ? error.message : '中央控制设置保存失败') }
  finally { busy.value = false }
}

async function saveFleetSubscriptionSelection() {
	busy.value = true
	try {
		fleetStatus.value = await api.saveFleetStatus({ enabled: true, publicUrl: fleetPublicURL.value, subscriptionPublicUrl: fleetSubscriptionPublicURL.value, selectedHostIds: fleetSelectedHosts.value, selectedNodeIds: fleetSelectedNodes.value })
		applyFleetDraft(fleetStatus.value)
		fleetDraftDirty.value = false
		notify('全局订阅范围已保存，旧缓存已失效')
	} catch (error) { notify(error instanceof Error ? error.message : '订阅范围保存失败') }
	finally { busy.value = false }
}

async function probeFleetSubscription() {
  fleetSubscriptionProbeBusy.value = true
  fleetSubscriptionProbe.value = null
  fleetSubscriptionProbeError.value = ''
  try {
    fleetSubscriptionProbe.value = await api.probeFleetSubscription(fleetSubscriptionPublicURL.value)
  } catch (error) {
    fleetSubscriptionProbeError.value = error instanceof Error ? error.message : '订阅入口检测失败'
  } finally { fleetSubscriptionProbeBusy.value = false }
}

function toggleFleetNode(hostId: string, nodeId: string, enabled: boolean) {
	const selected = new Set(fleetSelectedNodes.value[hostId] || [])
	if (enabled) selected.add(nodeId); else selected.delete(nodeId)
	fleetSelectedNodes.value = { ...fleetSelectedNodes.value, [hostId]: [...selected] }
}

async function createFleetEnrollment(mode: 'panel' | 'probe' = 'panel') {
  busy.value = true
  try {
    const result = await api.createFleetEnrollment(mode)
    enrollmentMode.value = mode
    enrollmentCommand.value = result.command
    enrollmentExpiresAt.value = result.expiresAt
    navigateTo('fleet')
    await nextTick()
    document.getElementById('fleet-enrollment')?.scrollIntoView({ behavior: 'smooth', block: 'center' })
    notify('已生成 10 分钟一次性接入命令')
  } catch (error) { notify(error instanceof Error ? error.message : '接入令牌生成失败') }
  finally { busy.value = false }
}

function stageFleetHostAction(action: FleetHostAction, host: FleetHost) {
  fleetHostAction.value = action
  fleetHostTarget.value = host
  fleetHostNameDraft.value = action === 'rename' ? host.name : ''
  fleetHostConfirm.value = ''
  modal.value = 'fleet-host-action'
}
function closeFleetHostAction() {
  modal.value = null
  fleetHostAction.value = null
  fleetHostTarget.value = null
  fleetHostNameDraft.value = ''
  fleetHostConfirm.value = ''
}
async function submitFleetHostAction() {
  const host = fleetHostTarget.value
  const action = fleetHostAction.value
  if (!host || !action) return
  const name = fleetHostNameDraft.value.trim()
  const confirmName = fleetHostConfirm.value.trim()
  if (action === 'rename' && (!name || name === host.name)) return
  if (action !== 'rename' && confirmName !== host.name) return
  busy.value = true
  try {
    if (action === 'rename') {
      await api.renameFleetHost(host.id, name)
      closeFleetHostAction()
      await refreshFleetStatus()
      notify('主机已重命名')
    } else if (action === 'remove') {
      await api.removeFleetHost(host.id, confirmName)
      closeFleetHostAction()
      if (selectedHostId.value === host.id) await switchFleetHost('local')
      await refreshFleetStatus()
      notify('主机凭据已撤销，指标进入 30 天归档期')
    } else {
      await api.purgeFleetHost(host.id, confirmName)
      closeFleetHostAction()
      await refreshFleetStatus()
      notify('主机归档数据已永久清除')
    }
  } catch (error) { notify(error instanceof Error ? error.message : action === 'rename' ? '重命名失败' : action === 'remove' ? '移除失败' : '永久清除失败') }
  finally { busy.value = false }
}

function expiryDays(dateStr?: string) {
  if (!dateStr) return null
  const parts = dateStr.split('-').map(Number)
  if (parts.length < 3 || !parts[0] || !parts[1] || !parts[2]) return null
  const target = new Date(parts[0], parts[1] - 1, parts[2])
  const today = new Date()
  const todayDate = new Date(today.getFullYear(), today.getMonth(), today.getDate())
  const diffMs = target.getTime() - todayDate.getTime()
  return Math.round(diffMs / 86400000)
}

function expiryLabel(dateStr?: string) {
  const days = expiryDays(dateStr)
  if (days === null) return ''
  if (days < 0) return language.value === 'en-US' ? `⚠️ Expired (${-days}d ago)` : `⚠️ 已过期 ${-days} 天`
  if (days === 0) return language.value === 'en-US' ? '⚠️ Expires today' : '⚠️ 今日到期'
  if (days <= 7) return language.value === 'en-US' ? `⚠️ Expires in ${days}d` : `⚠️ 剩余 ${days} 天到期`
  return language.value === 'en-US' ? `${dateStr} (${days}d left)` : `${dateStr} 到期 (${days}天)`
}

function expiryTone(dateStr?: string) {
  const days = expiryDays(dateStr)
  if (days === null) return ''
  if (days < 0) return 'danger'
  if (days <= 7) return 'warning'
  return 'info'
}

function openFleetHostSettings(host: FleetHost) {
  fleetHostSettingsTarget.value = host
  const quotaBytes = host.trafficQuotaBytes || host.snapshot?.overview?.trafficQuota || 0
  fleetHostSettingsDraft.value = {
    billingResetDay: host.billingResetDay || 1,
    trafficQuotaGB: quotaBytes > 0 ? Number((quotaBytes / 1_000_000_000).toFixed(2)) : 0,
    trafficCalcMode: host.trafficCalcMode || 'both',
    expiresAt: host.expiresAt || '',
  }
  modal.value = 'fleet-host-settings'
}

async function submitFleetHostSettings() {
  const host = fleetHostSettingsTarget.value
  if (!host) return
  busy.value = true
  try {
    const quotaBytes = Math.max(0, Math.round(Number(fleetHostSettingsDraft.value.trafficQuotaGB || 0) * 1_000_000_000))
    await api.updateFleetHostSettings(host.id, {
      billingResetDay: Number(fleetHostSettingsDraft.value.billingResetDay) || 1,
      trafficQuotaBytes: quotaBytes,
      trafficCalcMode: fleetHostSettingsDraft.value.trafficCalcMode || 'both',
      expiresAt: (fleetHostSettingsDraft.value.expiresAt || '').trim(),
    })
    modal.value = null
    fleetHostSettingsTarget.value = null
    await refreshFleetStatus()
    notify(language.value === 'en-US' ? 'Host settings updated' : '主机配额与设置已保存')
  } catch (error) {
    notify(error instanceof Error ? error.message : '保存主机设置失败')
  } finally {
    busy.value = false
  }
}

// Custom Fleet Host Ordering (excluding central local host and fleet companion card)
const draggedHostId = ref<string | null>(null)
const dragOverHostId = ref<string | null>(null)
const modalDraggedIndex = ref<number | null>(null)
const modalDragOverIndex = ref<number | null>(null)
const fleetOrderList = ref<FleetHost[]>([])
const fleetOrderSaving = ref(false)

function openFleetOrderModal() {
  fleetOrderList.value = remoteFleetHosts.value.map(h => ({ ...h }))
  modal.value = 'fleet-order'
}

function moveFleetHostInList(fromIndex: number, toIndex: number) {
  if (fromIndex < 0 || fromIndex >= fleetOrderList.value.length || toIndex < 0 || toIndex >= fleetOrderList.value.length || fromIndex === toIndex) return
  const item = fleetOrderList.value.splice(fromIndex, 1)[0]
  fleetOrderList.value.splice(toIndex, 0, item)
}

function applyHostPresetSort(preset: 'latency' | 'expiry' | 'traffic' | 'name' | 'default') {
  fleetOrderList.value = sortRemoteHostsByPreset(fleetOrderList.value, preset)
}

async function applyFleetHostOrder(order: string[]) {
  if (!fleetStatus.value) return
  fleetStatus.value.hosts = sortFleetHostsByOrder(fleetStatus.value.hosts, order)
  fleetStatus.value.hostOrder = order
  await api.saveFleetHostOrder(order)
}

async function saveFleetOrderModal() {
  fleetOrderSaving.value = true
  const order = fleetOrderList.value.map(h => h.id)
  try {
    await applyFleetHostOrder(order)
    modal.value = null
    notify(language.value === 'en-US' ? 'Host order updated' : '主机卡片排序已保存')
  } catch (error) {
    notify(error instanceof Error ? error.message : (language.value === 'en-US' ? 'Failed to save order' : '保存排序失败'))
  } finally {
    fleetOrderSaving.value = false
  }
}

function onHostDragStart(e: DragEvent, host: FleetHost) {
  if (host.id === 'local') {
    e.preventDefault()
    return
  }
  draggedHostId.value = host.id
  if (e.dataTransfer) {
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('text/plain', host.id)
  }
}

function onHostDragOver(e: DragEvent, host: FleetHost) {
  if (!draggedHostId.value || host.id === 'local' || draggedHostId.value === host.id) return
  dragOverHostId.value = host.id
  if (e.dataTransfer) {
    e.dataTransfer.dropEffect = 'move'
  }
}

function onHostDragLeave(_e: DragEvent, host: FleetHost) {
  if (dragOverHostId.value === host.id) {
    dragOverHostId.value = null
  }
}

async function onHostDrop(_e: DragEvent, targetHost: FleetHost) {
  const fromId = draggedHostId.value
  const toId = targetHost.id
  draggedHostId.value = null
  dragOverHostId.value = null
  if (!fromId || !toId || fromId === toId || toId === 'local' || fromId === 'local') return

  const currentRemote = remoteFleetHosts.value.map(h => h.id)
  const fromIndex = currentRemote.indexOf(fromId)
  const toIndex = currentRemote.indexOf(toId)
  if (fromIndex === -1 || toIndex === -1) return

  currentRemote.splice(fromIndex, 1)
  currentRemote.splice(toIndex, 0, fromId)

  try {
    await applyFleetHostOrder(currentRemote)
    notify(language.value === 'en-US' ? 'Host order updated' : '主机卡片顺序已调整')
  } catch (error) {
    notify(error instanceof Error ? error.message : (language.value === 'en-US' ? 'Failed to update order' : '更新排序失败'))
  }
}

function onHostDragEnd() {
  draggedHostId.value = null
  dragOverHostId.value = null
}

function onModalDragStart(e: DragEvent, index: number) {
  modalDraggedIndex.value = index
  if (e.dataTransfer) {
    e.dataTransfer.effectAllowed = 'move'
    e.dataTransfer.setData('text/plain', String(index))
  }
}

function onModalDragOver(e: DragEvent, index: number) {
  if (modalDraggedIndex.value === null || modalDraggedIndex.value === index) return
  modalDragOverIndex.value = index
  if (e.dataTransfer) {
    e.dataTransfer.dropEffect = 'move'
  }
}

function onModalDrop(_e: DragEvent, toIndex: number) {
  if (modalDraggedIndex.value === null) return
  moveFleetHostInList(modalDraggedIndex.value, toIndex)
  modalDraggedIndex.value = null
  modalDragOverIndex.value = null
}

function onModalDragEnd() {
  modalDraggedIndex.value = null
  modalDragOverIndex.value = null
}

function hostVersionString(host: FleetHost): string {
  if (isProbeHost(host)) {
    return host.panelVersion || ''
  }
  return host.panelVersion || host.snapshot?.overview?.panelVersion || ''
}

function hasHostUpdate(host: FleetHost): boolean {
  if (!latestReleaseVersion.value) return false
  const current = hostVersionString(host)
  return isNewerVersion(current, latestReleaseVersion.value)
}

function hostUpdateCurrentVersion(host: FleetHost): string {
  const v = hostVersionString(host)
  if (!v) return '—'
  return v.startsWith('v') || v.startsWith('V') ? v : `v${v}`
}

function hostUpdateCommand(host: FleetHost): string {
  return isProbeHost(host) ? getProbeUpdateCommand() : getPanelUpdateCommand()
}

function openHostUpdateModal(host: FleetHost) {
  hostUpdateTarget.value = host
  hostUpdating.value = false
  hostUpdateJob.value = null
  hostUpdateError.value = ''
  hostReconnecting.value = false
  hostReconnectAttempts.value = 0
  hostReloadCountdown.value = 0
  if (hostReloadCountdownTimer) {
    clearInterval(hostReloadCountdownTimer)
    hostReloadCountdownTimer = undefined
  }
  if (hostPollTimer) {
    clearTimeout(hostPollTimer)
    hostPollTimer = undefined
  }
  if (hostReconnectTimer) {
    clearTimeout(hostReconnectTimer)
    hostReconnectTimer = undefined
  }
  modal.value = 'host-update'

  const comp = isProbeHost(host) ? 'probe' : 'panel'
  const pending = pendingComponentUpdateJob(host.id, comp)
  if (pending) {
    hostUpdateJob.value = pending
    hostUpdating.value = true
    void pollHostJob(host, pending.id)
  }
}

async function startHostUpgrade(host: FleetHost) {
  if (hostUpdating.value || hostReconnecting.value || hostReloadCountdown.value > 0) return
  hostUpdating.value = true
  hostUpdateError.value = ''
  hostReconnecting.value = false
  hostReconnectAttempts.value = 0
  hostReloadCountdown.value = 0
  if (hostReloadCountdownTimer) {
    clearInterval(hostReloadCountdownTimer)
    hostReloadCountdownTimer = undefined
  }
  try {
    const comp = isProbeHost(host) ? 'probe' : 'panel'
    const client = componentUpdateAPI(host.id, comp)
    const currentVer = hostUpdateCurrentVersion(host).replace(/^v/i, '')
    const targetVer = latestReleaseVersion.value
    const res = await client.update(currentVer, targetVer)
    const queued: Job = {
      id: res.jobId,
      kind: isProbeHost(host) ? 'probe.update' : 'panel.update',
      target: host.id,
      status: 'queued',
      progress: 0,
      message: `等待更新${isProbeHost(host) ? '轻量探针' : '面板服务'}…`,
      createdAt: '',
      updatedAt: '',
    }
    startComponentUpdateJob(host.id, comp, queued)
    hostUpdateJob.value = queued
    void pollHostJob(host, res.jobId)
  } catch (err) {
    hostUpdating.value = false
    const errMsg = err instanceof Error ? err.message : '启动更新失败'
    hostUpdateError.value = errMsg
    hostUpdateJob.value = {
      id: '',
      kind: isProbeHost(host) ? 'probe.update' : 'panel.update',
      target: host.id,
      status: 'failed',
      progress: 0,
      message: '启动更新失败',
      error: errMsg,
      createdAt: '',
      updatedAt: '',
    }
  }
}

async function pollHostJob(host: FleetHost, jobId: string) {
  const comp = isProbeHost(host) ? 'probe' : 'panel'
  try {
    const client = componentUpdateAPI(host.id, comp)
    const job = await client.job(jobId)
    refreshComponentUpdateJob(host.id, comp, job)
    hostUpdateJob.value = job
    if (job.status === 'success') {
      hostUpdating.value = false
      if (host.id === 'local') {
        hostReconnecting.value = true
        hostReconnectAttempts.value = 0
        void startPanelReconnect()
      } else {
        const targetVer = latestReleaseVersion.value
        host.panelVersion = targetVer
        if (host.snapshot?.overview) {
          host.snapshot.overview.panelVersion = targetVer
        }
        notify(`${isProbeHost(host) ? '轻量探针' : '面板服务'}升级成功，已更新至 v${targetVer}`)
      }
      return
    }
    if (job.status === 'failed') {
      hostUpdating.value = false
      hostUpdateError.value = job.error || job.message || '更新执行失败'
      return
    }
    hostPollTimer = setTimeout(() => void pollHostJob(host, jobId), host.id === 'local' ? 1000 : 1500)
  } catch {
    if (host.id === 'local' && hostUpdateJob.value && (hostUpdateJob.value.progress >= 80 || hostUpdateJob.value.status === 'running')) {
      hostUpdating.value = false
      hostReconnecting.value = true
      hostReconnectAttempts.value = 0
      void startPanelReconnect()
      return
    }
    hostPollTimer = setTimeout(() => void pollHostJob(host, jobId), 1500)
  }
}

function startPanelReconnect() {
  if (!hostReconnecting.value) return
  hostReconnectAttempts.value++
  api.overview()
    .then(() => {
      hostReconnecting.value = false
      if (hostUpdateJob.value) {
        hostUpdateJob.value.status = 'success'
        hostUpdateJob.value.progress = 100
      } else {
        hostUpdateJob.value = {
          id: '',
          kind: 'panel.update',
          target: 'local',
          status: 'success',
          progress: 100,
          message: '升级完成',
          createdAt: '',
          updatedAt: '',
        }
      }
      hostReloadCountdown.value = 2
      notify(`面板已成功升级至 v${latestReleaseVersion.value}！将在 2 秒后自动刷新页面…`)
      if (hostReloadCountdownTimer) {
        clearInterval(hostReloadCountdownTimer)
      }
      hostReloadCountdownTimer = window.setInterval(() => {
        hostReloadCountdown.value--
        if (hostReloadCountdown.value > 0) {
          notify(`面板已成功升级至 v${latestReleaseVersion.value}！将在 ${hostReloadCountdown.value} 秒后自动刷新页面…`)
        } else {
          clearInterval(hostReloadCountdownTimer)
          hostReloadCountdownTimer = undefined
          modal.value = null
          window.location.reload()
        }
      }, 1000)
    })
    .catch(() => {
      if (hostReconnectAttempts.value >= 60) {
        hostReconnecting.value = false
        hostUpdateError.value = '面板服务重启超时，请登录终端检查状态'
        return
      }
      hostReconnectTimer = setTimeout(() => void startPanelReconnect(), 2000)
    })
}

async function copyHostUpdateCommand(host: FleetHost) {
  const cmd = hostUpdateCommand(host)
  await copy(cmd)
  notify(isProbeHost(host) ? '已复制探针升级命令' : '已复制面板升级命令')
}

function hostSingBoxVersion(host: FleetHost): string {
  return host.singBoxVersion || host.snapshot?.overview?.singBoxVersion || ''
}

function hasSingBoxUpdate(host: FleetHost): boolean {
  if (isProbeHost(host)) return false
  if (!latestSingBoxVersion.value) return false
  const current = hostSingBoxVersion(host)
  if (!current) return false
  return isNewerVersion(current, latestSingBoxVersion.value)
}

const fleetNexus = computed(() => {
  const hosts = fleetHosts.value
  let totalTrafficUsed = 0
  let totalTrafficQuota = 0
  let quotaHostCount = 0
  let topHost: FleetHost | null = null
  let topUsed = -1
  let nearestExpiryHost: FleetHost | null = null
  let nearestExpiryDays: number | null = null
  let updatableHostCount = 0
  let pendingUpdateItems = 0

  for (const host of hosts) {
    const used = host.snapshot?.overview?.trafficUsed || 0
    const quota = host.trafficQuotaBytes || host.snapshot?.overview?.trafficQuota || 0
    totalTrafficUsed += used
    if (quota > 0) {
      totalTrafficQuota += quota
      quotaHostCount++
    }
    if (used > topUsed) {
      topUsed = used
      topHost = host
    }
    const days = expiryDays(host.expiresAt)
    if (days !== null && (nearestExpiryDays === null || days < nearestExpiryDays)) {
      nearestExpiryDays = days
      nearestExpiryHost = host
    }
    const hostUpd = hasHostUpdate(host)
    const sbUpd = hasSingBoxUpdate(host)
    if (hostUpd || sbUpd) {
      updatableHostCount++
      pendingUpdateItems += (hostUpd ? 1 : 0) + (sbUpd ? 1 : 0)
    }
  }

  const topTrafficHostName = topHost && topUsed > 0 ? (topHost.id === 'local' ? '中央本机' : topHost.name) : '暂无消耗'
  const topTrafficShare = totalTrafficUsed > 0 && topUsed > 0 ? Math.round((topUsed / totalTrafficUsed) * 100) : 0
  const selectedHostSet = new Set(fleetSelectedHosts.value)
  const validSelectedHosts = hosts.filter(host => selectedHostSet.has(host.id) && (!isProbeHost(host) || (host.snapshot?.nodes || []).length > 0))
  const selectedHostCount = validSelectedHosts.length
  const selectedNodeCount = validSelectedHosts.reduce((sum, host) => {
    const activeIds = new Set((host.snapshot?.nodes || []).filter(node => node.status === 'active').map(node => node.id))
    const chosen = (fleetSelectedNodes.value[host.id] || []).filter(id => activeIds.has(id))
    return sum + chosen.length
  }, 0)

  return {
    totalTrafficUsed,
    totalTrafficQuota,
    quotaHostCount,
    topTrafficHostName,
    topTrafficHostUsed: Math.max(0, topUsed),
    topTrafficShare,
    nearestExpiryHost,
    nearestExpiryDays,
    updatableHostCount,
    pendingUpdateItems,
    upToDateHostCount: Math.max(0, hosts.length - updatableHostCount),
    selectedHostCount,
    selectedNodeCount,
  }
})

function singBoxUpdateSupported(host: FleetHost): boolean {
  if (isProbeHost(host)) return false
  return host.id === 'local' || (host.capabilities || []).includes('sing-box.update')
}

async function openSingBoxUpdateModal(host: FleetHost) {
  singBoxUpdateTarget.value = host
  singBoxUpdateState.value = null
  singBoxUpdating.value = false
  singBoxUpdateJob.value = null
  singBoxUpdateError.value = ''
  singBoxMigrationPlan.value = null
  singBoxMigrationLoading.value = false
  singBoxMigrationDetailsOpen.value = false
  if (singBoxPollTimer) {
    clearTimeout(singBoxPollTimer)
    singBoxPollTimer = undefined
  }
  modal.value = 'singbox-update'

  const pending = pendingComponentUpdateJob(host.id, 'sing-box')
  if (pending) {
    singBoxUpdateJob.value = pending
    singBoxUpdating.value = true
    void pollSingBoxJob(host, pending.id)
  }

  if (singBoxUpdateSupported(host) && host.online) {
    const targetVer = latestSingBoxVersion.value || '1.14.4'
    void loadSingBoxMigration(host, targetVer)
    try {
      const client = componentUpdateAPI(host.id, 'sing-box')
      singBoxUpdateState.value = await client.status()
    } catch {
      // ignore
    }
  }
}

async function copySingBoxUpdateCommand() {
  const cmd = getSingBoxUpdateCommand()
  await copy(cmd)
  notify('已复制 sing-box 内核升级命令')
}

async function startSingBoxUpgrade(host: FleetHost) {
  if (singBoxUpdating.value) return
  if (singBoxMigrationPlan.value && !singBoxMigrationPlan.value.compatible) {
    notify('节点配置存在阻断项，请先人工排查修复后再升级')
    return
  }
  singBoxUpdating.value = true
  singBoxUpdateError.value = ''
  try {
    const client = componentUpdateAPI(host.id, 'sing-box')
    const currentVer = hostSingBoxVersion(host) || singBoxUpdateState.value?.currentVersion || '1.14.3'
    const targetVer = latestSingBoxVersion.value || singBoxUpdateState.value?.latestVersion || '1.14.4'
    const res = await client.update(currentVer, targetVer)
    const queued: Job = {
      id: res.jobId,
      kind: 'sing-box.update',
      target: host.id,
      status: 'queued',
      progress: 0,
      message: '等待更新 sing-box…',
      createdAt: '',
      updatedAt: ''
    }
    startComponentUpdateJob(host.id, 'sing-box', queued)
    singBoxUpdateJob.value = queued
    void pollSingBoxJob(host, res.jobId)
  } catch (err) {
    singBoxUpdating.value = false
    singBoxUpdateError.value = err instanceof Error ? err.message : '启动更新失败'
  }
}

async function pollSingBoxJob(host: FleetHost, jobId: string) {
  try {
    const client = componentUpdateAPI(host.id, 'sing-box')
    const job = await client.job(jobId)
    refreshComponentUpdateJob(host.id, 'sing-box', job)
    singBoxUpdateJob.value = job
    if (job.status === 'success') {
      singBoxUpdating.value = false
      const targetVer = latestSingBoxVersion.value || '1.14.4'
      host.singBoxVersion = targetVer
      if (host.snapshot?.overview) {
        host.snapshot.overview.singBoxVersion = targetVer
      }
      if (host.id === 'local' && overview.value) {
        overview.value.singBoxVersion = targetVer
      }
      notify(`sing-box 已成功升级至 ${targetVer}`)
      try {
        singBoxUpdateState.value = await client.status()
      } catch {
        // ignore
      }
      return
    }
    if (job.status === 'failed') {
      singBoxUpdating.value = false
      singBoxUpdateError.value = job.error || job.message || '更新失败'
      return
    }
  } catch (err) {
    singBoxUpdateError.value = err instanceof Error ? err.message : '查询更新进度失败'
  }
  if (modal.value === 'singbox-update') {
    singBoxPollTimer = setTimeout(() => pollSingBoxJob(host, jobId), 1000)
  }
}

async function checkLatestRelease() {
  try {
    const res = await fetchLatestRelease()
    if (res && res.version) {
      latestRelease.value = res
    }
  } catch {
    // Ignore error
  }
}

async function openProbeNodesModal(host: FleetHost) {
  probeNodesTarget.value = host
  probeNodeRenameId.value = null
  probeNodeRenameDraft.value = ''
  probeNodeAddShareURI.value = ''
  modal.value = 'probe-nodes'
  await loadProbeNodes(host.id)
}

async function loadProbeNodes(hostId: string) {
  probeNodesLoading.value = true
  try {
    const list = await api.getFleetProbeNodes(hostId)
    probeNodesList.value = list
    const host = fleetHosts.value.find(h => h.id === hostId)
    if (host) {
      if (!host.snapshot) {
        host.snapshot = { overview: {} as Overview, nodes: [] }
      }
      host.snapshot.probeNodes = list
      host.snapshot.nodes = list.map(n => ({
        id: n.id,
        name: n.name,
        protocol: n.protocol,
        domain: n.domain,
        server: n.server,
        listenPort: n.port,
        status: 'active' as NodeStatus,
        mode: 'prefer_v6',
        egress: 'direct',
        autoBind: false,
        serviceName: '',
        serviceManager: '',
        configPath: '',
        configVersion: '',
        ownership: 'probe',
      }))
      host.snapshot.overview.nodeCount = list.length
      host.snapshot.overview.onlineNodes = list.length
      if (fleetSelectedHosts.value.includes(hostId)) {
        const curNodes = fleetSelectedNodes.value[hostId] || []
        const allNodeIds = list.map(n => n.id)
        fleetSelectedNodes.value = { ...fleetSelectedNodes.value, [hostId]: Array.from(new Set([...curNodes, ...allNodeIds])) }
      }
    }
  } catch (e: any) {
    notify(e.message || (language.value === 'en-US' ? 'Failed to load probe nodes' : '加载探针节点失败'))
  } finally {
    probeNodesLoading.value = false
  }
}

function startRenameProbeNode(node: FleetProbeNode) {
  probeNodeRenameId.value = node.id
  probeNodeRenameDraft.value = node.name
}

function cancelRenameProbeNode() {
  probeNodeRenameId.value = null
  probeNodeRenameDraft.value = ''
}

async function submitRenameProbeNode(node: FleetProbeNode) {
  const newName = probeNodeRenameDraft.value.trim()
  if (!newName) {
    notify(language.value === 'en-US' ? 'Node name cannot be empty' : '节点名称不能为空')
    return
  }
  if (!probeNodesTarget.value) return
  try {
    await api.renameFleetProbeNode(probeNodesTarget.value.id, node.id, newName)
    notify(language.value === 'en-US' ? 'Node name updated' : '节点名称已更新')
    probeNodeRenameId.value = null
    await loadProbeNodes(probeNodesTarget.value.id)
  } catch (e: any) {
    notify(e.message || (language.value === 'en-US' ? 'Failed to rename node' : '重命名失败'))
  }
}

async function deleteProbeNode(node: FleetProbeNode) {
  if (!probeNodesTarget.value) return
  if (!confirm(language.value === 'en-US' ? `Delete node "${node.name}"?` : `确定要删除节点 "${node.name}" 吗？`)) return
  try {
    await api.deleteFleetProbeNode(probeNodesTarget.value.id, node.id)
    notify(language.value === 'en-US' ? 'Node deleted' : '节点已删除')
    await loadProbeNodes(probeNodesTarget.value.id)
  } catch (e: any) {
    notify(e.message || (language.value === 'en-US' ? 'Failed to delete node' : '删除失败'))
  }
}

async function addProbeNode() {
  const text = probeNodeAddShareURI.value.trim()
  if (!text) {
    notify(language.value === 'en-US' ? 'Please paste share URIs or config' : '请粘贴节点分享链接或配置')
    return
  }
  if (!probeNodesTarget.value) return
  probeNodeAddBusy.value = true
  try {
    await api.createFleetProbeNode(probeNodesTarget.value.id, { shareUri: text })
    notify(language.value === 'en-US' ? 'Nodes added successfully' : '节点添加成功')
    probeNodeAddShareURI.value = ''
    await loadProbeNodes(probeNodesTarget.value.id)
  } catch (e: any) {
    notify(e.message || (language.value === 'en-US' ? 'Failed to add node' : '添加节点失败'))
  } finally {
    probeNodeAddBusy.value = false
  }
}

interface IPRepState {
  loading: boolean
  report?: IPReputationReport
  error?: string
  fetchedAt: number
}
const ipReputationCache = reactive<Record<string, IPRepState>>({})
const reputationModalHost = ref<FleetHost | null>(null)
const reputationModalIPv4 = ref('')
const reputationModalIPv6 = ref('')

function isIPv4(ip: string): boolean {
  return /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip.trim().replace(/^\[|\]$/g, ''))
}

function isIPv6(ip: string): boolean {
  const clean = ip.trim().replace(/^\[|\]$/g, '')
  return clean.includes(':') && /^[0-9a-fA-F:]+$/.test(clean)
}

function isPublicIP(ip: string): boolean {
  const clean = ip.trim().replace(/^\[|\]$/g, '')
  if (isIPv4(clean)) {
    const parts = clean.split('.').map(Number)
    if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return false
    if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
    if (parts[0] === 192 && parts[1] === 168) return false
    if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false
    if (parts[0] >= 224) return false
    return true
  }
  if (isIPv6(clean)) {
    const lower = clean.toLowerCase()
    if (lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc00:') || lower.startsWith('fd00:')) return false
    return true
  }
  return false
}

function getHostDualStackIPs(host: FleetHost | null) {
  let v4 = ''
  let v6 = ''
  if (!host) return { v4, v6 }

  const loc = host.snapshot?.location
  if (loc?.ipv4 && isIPv4(loc.ipv4)) v4 = loc.ipv4
  if (loc?.ipv6 && isIPv6(loc.ipv6)) v6 = loc.ipv6
  if (!v4 && loc?.publicIP && isIPv4(loc.publicIP)) v4 = loc.publicIP
  if (!v6 && loc?.publicIP && isIPv6(loc.publicIP)) v6 = loc.publicIP

  if (!v4 && host.snapshot?.deploymentDefaults?.ipv4) {
    for (const item of host.snapshot.deploymentDefaults.ipv4) {
      if (item.address && isIPv4(item.address) && isPublicIP(item.address)) {
        v4 = item.address
        break
      }
    }
  }
  if (!v6 && host.snapshot?.deploymentDefaults?.ipv6) {
    for (const item of host.snapshot.deploymentDefaults.ipv6) {
      if (item.address && isIPv6(item.address) && isPublicIP(item.address)) {
        v6 = item.address
        break
      }
    }
  }

  if (host.snapshot?.nodes) {
    for (const n of host.snapshot.nodes) {
      if (!v4 && n.server && isIPv4(n.server) && isPublicIP(n.server)) v4 = n.server
      if (!v4 && n.ipv4Bind && isIPv4(n.ipv4Bind) && isPublicIP(n.ipv4Bind)) v4 = n.ipv4Bind
      if (!v4 && n.probeExitIp && isIPv4(n.probeExitIp) && isPublicIP(n.probeExitIp)) v4 = n.probeExitIp
      if (!v4 && n.preferredServer && isIPv4(n.preferredServer) && isPublicIP(n.preferredServer)) v4 = n.preferredServer
      if (!v6 && n.server && isIPv6(n.server) && isPublicIP(n.server)) v6 = n.server
      if (!v6 && n.ipv6Bind && isIPv6(n.ipv6Bind) && isPublicIP(n.ipv6Bind)) v6 = n.ipv6Bind
      if (!v6 && n.probeExitIp && isIPv6(n.probeExitIp) && isPublicIP(n.probeExitIp)) v6 = n.probeExitIp
      if (!v6 && n.preferredServer && isIPv6(n.preferredServer) && isPublicIP(n.preferredServer)) v6 = n.preferredServer
    }
  }

  if (host.snapshot?.probeNodes) {
    for (const p of host.snapshot.probeNodes) {
      if (!v4 && p.server && isIPv4(p.server) && isPublicIP(p.server)) v4 = p.server
      if (!v4 && p.domain && isIPv4(p.domain) && isPublicIP(p.domain)) v4 = p.domain
      if (!v6 && p.server && isIPv6(p.server) && isPublicIP(p.server)) v6 = p.server
      if (!v6 && p.domain && isIPv6(p.domain) && isPublicIP(p.domain)) v6 = p.domain
    }
  }

  return { v4, v6 }
}

function getHostCandidateIPs(host: FleetHost | null) {
  if (!host) return []
  const list: { ip: string; label: string; kind: 'public' | 'node' | 'probe'; family: 'v4' | 'v6' }[] = []
  const seen = new Set<string>()

  const addIP = (raw: string | undefined, label: string, kind: 'public' | 'node' | 'probe') => {
    if (!raw) return
    const clean = raw.trim().replace(/^\[|\]$/g, '')
    if (!clean || !isPublicIP(clean) || seen.has(clean)) return
    seen.add(clean)
    list.push({ ip: clean, label, kind, family: isIPv6(clean) ? 'v6' : 'v4' })
  }

  if (host.snapshot?.location?.publicIP) {
    const raw = host.snapshot.location.publicIP
    addIP(raw, isIPv6(raw) ? '出口公网 IPv6' : '出口公网 IPv4', 'public')
  }
  if (host.snapshot?.location?.ipv4) {
    addIP(host.snapshot.location.ipv4, '出口公网 IPv4', 'public')
  }
  if (host.snapshot?.location?.ipv6) {
    addIP(host.snapshot.location.ipv6, '出口公网 IPv6', 'public')
  }
  if (host.snapshot?.deploymentDefaults?.ipv4) {
    for (const item of host.snapshot.deploymentDefaults.ipv4) {
      addIP(item.address, `本机 IPv4 (${item.interface})`, 'public')
    }
  }
  if (host.snapshot?.deploymentDefaults?.ipv6) {
    for (const item of host.snapshot.deploymentDefaults.ipv6) {
      addIP(item.address, `本机 IPv6 (${item.interface})`, 'public')
    }
  }
  if (host.snapshot?.nodes) {
    for (const n of host.snapshot.nodes) {
      if (n.server) addIP(n.server, `节点: ${n.name}`, 'node')
      if (n.ipv4Bind) addIP(n.ipv4Bind, `绑定: ${n.name}`, 'node')
      if (n.ipv6Bind) addIP(n.ipv6Bind, `绑定: ${n.name}`, 'node')
      if (n.probeExitIp) addIP(n.probeExitIp, `节点出口: ${n.name}`, 'node')
      if (n.preferredServer) addIP(n.preferredServer, `节点解析: ${n.name}`, 'node')
    }
  }
  if (host.snapshot?.probeNodes) {
    for (const p of host.snapshot.probeNodes) {
      if (p.server) addIP(p.server, `轻量节点: ${p.name || p.rawName || '节点'}`, 'probe')
      if (p.domain) addIP(p.domain, `轻量解析: ${p.name || p.rawName || '节点'}`, 'probe')
    }
  }
  const v4List = list.filter(item => item.family === 'v4')
  const v6List = list.filter(item => item.family === 'v6')
  return [...v4List, ...v6List]
}

const reputationCandidateIPs = computed(() => getHostCandidateIPs(reputationModalHost.value))
const reputationStateIPv4 = computed(() => {
  const ip = reputationModalIPv4.value.trim().replace(/^\[|\]$/g, '')
  return ip ? ipReputationCache[ip] : undefined
})
const reputationStateIPv6 = computed(() => {
  const ip = reputationModalIPv6.value.trim().replace(/^\[|\]$/g, '')
  return ip ? ipReputationCache[ip] : undefined
})

const IP_REPUTATION_CACHE_TTL = 24 * 3600_000 // 自动检测周期与本地缓存有效期设为 24 小时

function getCachedReputation(ip: string): IPReputationReport | null {
  const clean = ip.trim().replace(/^\[|\]$/g, '')
  if (!clean) return null
  try {
    const raw = localStorage.getItem(`wukong_ip_rep_${clean}`)
    if (raw) {
      const data = JSON.parse(raw)
      if (data && typeof data === 'object' && Date.now() - (data._savedAt || 0) < IP_REPUTATION_CACHE_TTL) {
        return data.report as IPReputationReport
      }
    }
  } catch {
    // Ignore storage read errors
  }
  return null
}

function saveCachedReputation(ip: string, report: IPReputationReport) {
  const clean = ip.trim().replace(/^\[|\]$/g, '')
  if (!clean) return
  try {
    localStorage.setItem(`wukong_ip_rep_${clean}`, JSON.stringify({
      report,
      _savedAt: Date.now(),
    }))
  } catch {
    // Ignore storage quota errors
  }
}

async function loadReputation(ip: string, force = false): Promise<IPReputationReport | undefined> {
  const clean = ip.trim().replace(/^\[|\]$/g, '')
  if (!clean) return undefined

  const existing = ipReputationCache[clean]
  if (!force) {
    if (existing?.report && Date.now() - existing.fetchedAt < IP_REPUTATION_CACHE_TTL) {
      return existing.report
    }
    const local = getCachedReputation(clean)
    if (local) {
      ipReputationCache[clean] = {
        loading: false,
        report: local,
        fetchedAt: Date.now(),
      }
      return local
    }
  }

  if (existing?.loading) return undefined

  ipReputationCache[clean] = {
    loading: true,
    report: existing?.report,
    fetchedAt: Date.now(),
  }

  try {
    const report = await getIPReputation(clean)
    ipReputationCache[clean] = {
      loading: false,
      report,
      fetchedAt: Date.now(),
    }
    saveCachedReputation(clean, report)
    return report
  } catch (err: any) {
    ipReputationCache[clean] = {
      loading: false,
      report: existing?.report,
      error: err?.message || '获取信誉分失败',
      fetchedAt: Date.now(),
    }
    return undefined
  }
}

function hostReputationDual(host: FleetHost) {
  const { v4, v6 } = getHostDualStackIPs(host)
  const state4 = v4 ? ipReputationCache[v4] : undefined
  const state6 = v6 ? ipReputationCache[v6] : undefined
  return { v4, v6, state4, state6 }
}

function prefetchHostReputation(host: FleetHost) {
  const { v4, v6 } = getHostDualStackIPs(host)
  if (v4) {
    const local = getCachedReputation(v4)
    if (local && !ipReputationCache[v4]) {
      ipReputationCache[v4] = { loading: false, report: local, fetchedAt: Date.now() }
    } else if (!local) {
      loadReputation(v4)
    }
  }
  if (v6) {
    const local = getCachedReputation(v6)
    if (local && !ipReputationCache[v6]) {
      ipReputationCache[v6] = { loading: false, report: local, fetchedAt: Date.now() }
    } else if (!local) {
      loadReputation(v6)
    }
  }
}

function reputationBadgeClass(host: FleetHost): string {
  const { v4, v6, state4, state6 } = hostReputationDual(host)
  if (!v4 && !v6) return 'score-none'
  if ((state4?.loading && !state4?.report) || (state6?.loading && !state6?.report)) return 'loading'

  const scores: number[] = []
  if (state4?.report?.trust_score !== undefined) scores.push(state4.report.trust_score)
  if (state6?.report?.trust_score !== undefined) scores.push(state6.report.trust_score)

  if (scores.length > 0) {
    const minScore = Math.min(...scores)
    if (minScore >= 80) return 'score-high'
    if (minScore >= 50) return 'score-medium'
    return 'score-low'
  }
  if (state4?.error || state6?.error) return 'score-error'
  return 'score-idle'
}

function reputationBadgeTitle(host: FleetHost): string {
  const { v4, v6, state4, state6 } = hostReputationDual(host)
  if (!v4 && !v6) return '未检测到公网 IP，点击手动检测'
  const lines: string[] = ['IP 双栈信誉与威胁情报（点击打开详情）：']
  if (v4) {
    const s = state4?.report?.trust_score !== undefined ? `${state4.report.trust_score}分` : (state4?.loading ? '检测中' : '待检测')
    lines.push(`IPv4: ${v4} (${s})`)
  }
  if (v6) {
    const s = state6?.report?.trust_score !== undefined ? `${state6.report.trust_score}分` : (state6?.loading ? '检测中' : '待检测')
    lines.push(`IPv6: ${v6} (${s})`)
  }
  return lines.join('\n')
}

interface ReputationBadgePart {
  mode: 'dual' | 'single' | 'text'
  tag4?: string
  score4?: string
  class4?: string
  tag6?: string
  score6?: string
  class6?: string
  singleTag?: string
  singleScore?: string
  singleClass?: string
  text?: string
}

function scoreColorClass(score: number | undefined): string {
  if (score === undefined) return ''
  if (score >= 80) return 'score-high'
  if (score >= 50) return 'score-medium'
  return 'score-low'
}

function reputationBadgeParts(host: FleetHost): ReputationBadgePart {
  const { v4, v6, state4, state6 } = hostReputationDual(host)
  if (!v4 && !v6) return { mode: 'text', text: 'IP检测' }

  const score4 = state4?.report?.trust_score
  const score6 = state6?.report?.trust_score

  const s4Text = score4 !== undefined ? `${score4}分` : (v4 && state4?.loading && !state4?.report ? '...' : (v4 && state4?.error ? '--分' : ''))
  const s6Text = score6 !== undefined ? `${score6}分` : (v6 && state6?.loading && !state6?.report ? '...' : (v6 && state6?.error ? '--分' : ''))

  if (s4Text && s6Text) {
    return {
      mode: 'dual',
      tag4: 'V4：',
      score4: s4Text,
      class4: scoreColorClass(score4),
      tag6: 'V6：',
      score6: s6Text,
      class6: scoreColorClass(score6)
    }
  }
  if (s4Text) {
    return {
      mode: 'single',
      singleTag: 'V4：',
      singleScore: s4Text,
      singleClass: scoreColorClass(score4)
    }
  }
  if (s6Text) {
    return {
      mode: 'single',
      singleTag: 'V6：',
      singleScore: s6Text,
      singleClass: scoreColorClass(score6)
    }
  }

  if ((state4?.loading && !state4?.report) || (state6?.loading && !state6?.report)) return { mode: 'text', text: '...' }
  if (state4?.error || state6?.error) return { mode: 'text', text: '--分' }
  return { mode: 'text', text: 'IP分' }
}

function reputationBadgeText(host: FleetHost): string {
  const { v4, v6, state4, state6 } = hostReputationDual(host)
  if (!v4 && !v6) return 'IP检测'

  const score4 = state4?.report?.trust_score
  const score6 = state6?.report?.trust_score

  if (score4 !== undefined && score6 !== undefined) {
    return `V4：${score4}分 / V6：${score6}分`
  }
  if (score4 !== undefined) {
    if (v6 && state6?.loading && !state6?.report) {
      return `V4：${score4}分 / V6：...`
    }
    return `V4：${score4}分`
  }
  if (score6 !== undefined) {
    if (v4 && state4?.loading && !state4?.report) {
      return `V4：... / V6：${score6}分`
    }
    return `V6：${score6}分`
  }

  if ((state4?.loading && !state4?.report) || (state6?.loading && !state6?.report)) return '...'
  if (state4?.error || state6?.error) return '--分'
  return 'IP分'
}

function openReputationModal(host?: FleetHost, initialIP?: string) {
  reputationModalHost.value = host || null
  const dual = getHostDualStackIPs(host || null)
  reputationModalIPv4.value = dual.v4
  reputationModalIPv6.value = dual.v6

  if (initialIP) {
    if (isIPv4(initialIP)) reputationModalIPv4.value = initialIP
    else if (isIPv6(initialIP)) reputationModalIPv6.value = initialIP
  }

  modal.value = 'ip-reputation'

  if (reputationModalIPv4.value) loadReputation(reputationModalIPv4.value)
  if (reputationModalIPv6.value) loadReputation(reputationModalIPv6.value)
}

function checkReputationBoth(force = false) {
  if (reputationModalIPv4.value.trim()) {
    loadReputation(reputationModalIPv4.value.trim(), force)
  }
  if (reputationModalIPv6.value.trim()) {
    loadReputation(reputationModalIPv6.value.trim(), force)
  }
}

function selectCandidateIP(cand: { ip: string; family: 'v4' | 'v6' }) {
  if (cand.family === 'v4') {
    reputationModalIPv4.value = cand.ip
    loadReputation(cand.ip)
  } else {
    reputationModalIPv6.value = cand.ip
    loadReputation(cand.ip)
  }
}

function ensureHostWritable() {
  if (!mutationsDisabled.value) return true
  notify(currentFleetHost.value?.compatible ? '该主机离线，修改操作已禁用' : '舰队协议版本不兼容，修改操作已禁用')
  return false
}

async function bootstrap() {
  loading.value = true
  try {
    const me = await api.me(); setCSRF(me.csrf); authenticated.value = true; username.value = me.username; mustChange.value = me.mustChange
    if (!me.mustChange) { await refreshFleetStatus(); await refreshAll(); checkLatestRelease().catch(() => {}) }
  } catch { authenticated.value = false }
  finally { loading.value = false }
}
async function login() {
  busy.value = true; loginError.value = ''
  try { const result = await api.login(username.value, password.value); setCSRF(result.csrf); mustChange.value = result.mustChange; authenticated.value = true; password.value = ''; if (!result.mustChange) { await refreshFleetStatus(); await refreshAll(); checkLatestRelease().catch(() => {}) } }
  catch (error) { loginError.value = error instanceof Error ? error.message : '登录失败' }
  finally { busy.value = false }
}
async function changePassword() {
  busy.value = true
  try { await api.changePassword(newPassword.value); mustChange.value = false; authenticated.value = false; newPassword.value = ''; loginError.value = ''; notify('密码已更新，请重新登录') }
  catch (error) { notify(error instanceof Error ? error.message : '修改失败') }
  finally { busy.value = false }
}
async function logout() { try { await api.logout() } finally { securityStatusCache.clear(); authenticated.value = false; overview.value = null } }
function setThemePreference(preference: ThemePreference) {
  themePreference.value = preference
  activeEffectiveTheme.value = effectiveTheme(preference)
  applyThemePreference(preference)
}
function toggleThemePreference() {
  setThemePreference(nextToggledThemePreference(themePreference.value))
}
async function refreshAll() {
  const [overviewData, nodeData, jobData, settingData, endpointData, timelineData, exitData, socksData] = await Promise.all([api.overview(), api.nodes(), api.jobs(), api.settings(), api.endpoints(), api.timeline(), api.residentialExit().catch(() => null), api.socksExit().catch(() => null)])
  overview.value = overviewData; nodes.value = nodeData; jobs.value = jobData; endpoints.value = endpointData; timeline.value = timelineData
  void fetchFirewallStatus()
  if (!settingsDraftDirty.value) {
    syncingSettingsDraft = true
    try { settings.value = { ...settingData, expiresAt: settingData.expiresAt || '' }; language.value = settingData.language === 'en-US' ? 'en-US' : 'zh-CN' }
    finally { syncingSettingsDraft = false }
  }
  residentialExit.value = exitData
  if (exitData && !residentialFormHydrated.value) {
    Object.assign(residentialForm, { endpoint: exitData.endpoint || '', listenPort: exitData.listenPort || 51820, peerPublicKey: exitData.peerPublicKey || '', expectedExitIp: exitData.expectedExitIp || '' })
    residentialFormHydrated.value = true
  }
  socksExit.value = socksData
  if (socksData && !socksFormHydrated.value) {
    Object.assign(socksForm, {
      server: socksData.server || '', port: socksData.port || 1080, version: socksData.version || '5',
      username: socksData.username || '', password: '', clearPassword: false, network: socksData.network || 'both',
      expectedExitIp: socksData.expectedExitIp || '',
    })
    socksFormHydrated.value = true
    if (!exitData?.configured && !exitData?.installScript && socksData.configured) {
      activeEgressTab.value = 'socks'
    }
  }
}
async function showJobLog() {
  navigateTo('jobs')
  await refreshAll()
}
async function createNode() {
	if (!ensureHostWritable()) return
  busy.value = true
  try {
    const creatingDeviceBatch = deviceMode.value
    const common = { ...createForm, v6OnlyDomains: createForm.v6OnlyDomains.split(',').map(item => item.trim()).filter(Boolean) }
    if (modal.value === 'edit' && selectedNode.value) {
      const editTarget = selectedNode.value
      const targetName = common.name.trim() || editTarget.name
      const result = await api.editNode(editTarget.id, {
        name: common.name.trim(), mode: common.mode, egress: common.egress, listenPort: common.listenPort,
        server: common.server.trim(), domain: common.domain.trim(), preferredServer: common.preferredServer.trim(),
        webSocketPath: common.webSocketPath.trim(), ipv4Bind: common.ipv4Bind.trim(), ipv6Bind: common.ipv6Bind.trim(),
        autoBind: common.autoBind, autoAllowPort: common.autoAllowPort, v6OnlyDomains: common.v6OnlyDomains,
      })
      if (!isTunnelProtocol.value && common.autoAllowPort) {
        securityStatusCache.clear(selectedHostId.value)
        void fetchFirewallStatus()
      }
      modal.value = null
      notify(language.value === 'en-US' ? `Updating ${targetName}...` : `正在更新 ${targetName}...`)
      void watchActionJob(result.jobId, targetName, 'edit')
      return
    }
    let deployRes: { jobId: string }
    if (creatingDeviceBatch) {
      const requests = deviceNodes.map(device => ({
        ...common,
        name: device.name.trim(),
        listenPort: device.listenPort,
        autoAllowPort: common.autoAllowPort,
        ...(isTunnelProtocol.value ? {
          server: device.server.trim(),
          domain: device.server.trim(),
          preferredServer: device.preferredServer.trim(),
          webSocketPath: device.webSocketPath.trim(),
        } : {}),
      }))
      deployRes = await api.createNodeBatch(requests)
    } else {
      deployRes = await api.createNode(common)
    }
    if (!isTunnelProtocol.value && common.autoAllowPort) {
      securityStatusCache.clear(selectedHostId.value)
      void fetchFirewallStatus()
    }
    modal.value = null
    const deployTargetLabel = creatingDeviceBatch ? `${deviceNodes.length} 台设备编队` : (common.name.trim() || '节点')
    notify(creatingDeviceBatch ? `${deviceNodes.length} 台设备的部署任务已启动...` : `${deployTargetLabel} 部署任务已启动...`)
    void watchDeploymentJob(deployRes.jobId, deployTargetLabel)
  } catch (error) { notify(error instanceof Error ? error.message : '部署失败') }
  finally { busy.value = false }
}
async function quickCopyShare(node: NodeItem) {
  try {
    const share = await api.share(node.id)
    await copy(share.uri)
    notify(language.value === 'en-US' ? 'Node share link copied' : '节点分享链接已复制到剪贴板')
  } catch (error) {
    notify(error instanceof Error ? error.message : (language.value === 'en-US' ? 'Failed to get share link' : '无法获取分享链接'))
  }
}
async function watchDeploymentJob(jobId: string, targetName: string, hostId = selectedHostId.value) {
  const previousNodeIds = new Set(nodes.value.map(n => n.id))
  deploymentProgress.value = { jobId, targetName, progress: 10, message: language.value === 'en-US' ? 'Initializing...' : '初始化部署...' }
  let delay = 300
  try {
    for (let attempt = 0; attempt < 80; attempt++) {
      if (!authenticated.value) return
      await new Promise(resolve => window.setTimeout(resolve, delay))
      if (!authenticated.value) return
      delay = 800
      let job: Job
      try {
        job = await api.job(jobId)
      } catch {
        continue
      }
      const existingIdx = jobs.value.findIndex(j => j.id === jobId)
      if (existingIdx >= 0) {
        jobs.value[existingIdx] = job
      } else {
        jobs.value.unshift(job)
      }
      if (deploymentProgress.value && deploymentProgress.value.jobId === jobId) {
        deploymentProgress.value.progress = job.progress
        deploymentProgress.value.message = job.message || (language.value === 'en-US' ? 'Deploying...' : '正在部署...')
      }
      if (job.status === 'success') {
        const [nodeData, jobData, overviewData] = await Promise.all([
          api.nodes(),
          api.jobs(),
          api.overview().catch(() => null),
        ])
        if (selectedHostId.value === hostId) {
          nodes.value = nodeData
          jobs.value = jobData
          if (overviewData) overview.value = overviewData
        }
        void refreshFleetStatus()

        const newlyAdded = nodeData.find(n => !previousNodeIds.has(n.id)) || nodeData[0]
        const successMsg = language.value === 'en-US'
          ? `${targetName} deployed successfully and is ready!`
          : `${targetName} 部署完成并已就绪！已更新节点列表`
        notify(successMsg)

        deploymentReady.value = {
          jobId,
          title: language.value === 'en-US' ? `${targetName} Ready` : `${targetName} 部署就绪`,
          message: language.value === 'en-US' ? 'Node started and passed inbound verification.' : '节点服务已启动并完成闭环校验，可直接使用。',
          node: newlyAdded,
        }
        if (deploymentReadyTimer) window.clearTimeout(deploymentReadyTimer)
        deploymentReadyTimer = window.setTimeout(() => {
          if (deploymentReady.value?.jobId === jobId) {
            deploymentReady.value = null
          }
        }, 15000)
        return
      } else if (job.status === 'failed') {
        const failMsg = language.value === 'en-US'
          ? `${targetName} deployment failed: ${job.error || job.message || 'unknown error'}`
          : `${targetName} 部署失败：${job.error || job.message || '未知错误'}`
        notify(failMsg)
        if (selectedHostId.value === hostId) {
          const jobData = await api.jobs().catch(() => null)
          if (jobData) jobs.value = jobData
        }
        return
      }
    }
    notify(language.value === 'en-US' ? 'Deployment still running in background, check Jobs log.' : '部署任务仍在后台运行，可前往任务日志查看进度')
  } catch (error) {
    notify(error instanceof Error ? error.message : (language.value === 'en-US' ? 'Failed to track deployment' : '轮询任务状态失败'))
  } finally {
    if (deploymentProgress.value?.jobId === jobId) {
      deploymentProgress.value = null
    }
  }
}
async function watchActionJob(jobId: string, targetName: string, action: 'delete' | 'edit' | 'import' | 'delete_candidate', hostId = selectedHostId.value) {
  let delay = 300
  try {
    for (let attempt = 0; attempt < 80; attempt++) {
      if (!authenticated.value) return
      await new Promise(resolve => window.setTimeout(resolve, delay))
      if (!authenticated.value) return
      delay = 800
      let job: Job
      try {
        job = await api.job(jobId)
      } catch {
        continue
      }
      const existingIdx = jobs.value.findIndex(j => j.id === jobId)
      if (existingIdx >= 0) {
        jobs.value[existingIdx] = job
      } else {
        jobs.value.unshift(job)
      }
      if (job.status === 'success') {
        const [nodeData, jobData, overviewData] = await Promise.all([
          api.nodes(),
          api.jobs(),
          api.overview().catch(() => null),
        ])
        if (selectedHostId.value === hostId) {
          nodes.value = nodeData
          jobs.value = jobData
          if (overviewData) overview.value = overviewData
        }
        void refreshFleetStatus()

        let successMsg = ''
        if (action === 'delete') {
          successMsg = language.value === 'en-US' ? `${targetName} deleted successfully` : `${targetName} 已成功删除`
        } else if (action === 'edit') {
          successMsg = language.value === 'en-US' ? `${targetName} updated successfully` : `${targetName} 配置已更新`
        } else if (action === 'import') {
          successMsg = language.value === 'en-US' ? 'Nodes adopted successfully' : '节点接管完成'
        } else if (action === 'delete_candidate') {
          successMsg = language.value === 'en-US' ? `${targetName} completely deleted` : `${targetName} 已彻底删除`
        }
        notify(successMsg)
        return
      } else if (job.status === 'failed') {
        let actionLabel = action === 'delete' ? '删除' : action === 'edit' ? '更新' : action === 'import' ? '接管' : '删除'
        if (language.value === 'en-US') {
          actionLabel = action === 'delete' ? 'Delete' : action === 'edit' ? 'Update' : action === 'import' ? 'Adopt' : 'Delete'
        }
        const failMsg = language.value === 'en-US'
          ? `${actionLabel} ${targetName} failed: ${job.error || job.message || 'unknown error'}`
          : `${actionLabel} ${targetName} 失败：${job.error || job.message || '未知错误'}`
        notify(failMsg)
        if (selectedHostId.value === hostId) {
          const jobData = await api.jobs().catch(() => null)
          if (jobData) jobs.value = jobData
        }
        return
      }
    }
    notify(language.value === 'en-US' ? 'Task still running in background, check Jobs log.' : '任务仍在后台运行，可前往任务日志查看进度')
  } catch (error) {
    notify(error instanceof Error ? error.message : (language.value === 'en-US' ? 'Failed to track task status' : '轮询任务状态失败'))
  }
}
function newDeviceDraft(index: number): DeviceDraft {
  deviceSequence.value += 1
  return { key: deviceSequence.value, name: `设备 ${index + 1}`, listenPort: 0, server: '', preferredServer: '', webSocketPath: '' }
}
function resetDeviceDrafts() {
  deviceNodes.splice(0, deviceNodes.length, newDeviceDraft(0), newDeviceDraft(1))
}
function addDevice() {
  if (deviceNodes.length < 20) deviceNodes.push(newDeviceDraft(deviceNodes.length))
}
function removeDevice(index: number) {
  if (deviceNodes.length > 2) deviceNodes.splice(index, 1)
}
function switchDeployKind(kind: 'create' | 'device-create') {
  if (isEditing.value) return
  modal.value = kind
  if (kind === 'device-create' && deviceNodes.length === 0) {
    resetDeviceDrafts()
  }
}
const conflictingNodeName = computed(() => {
  const port = createForm.listenPort
  if (!port || port <= 0 || port > 65535) return ''
  const match = nodes.value.find(n => n.listenPort === port && (!isEditing.value || n.id !== selectedNode.value?.id))
  return match ? match.name : ''
})
function pickRandomAvailablePort() {
  const occupied = new Set(nodes.value.map(n => n.listenPort).filter(p => p > 0))
  for (let attempt = 0; attempt < 100; attempt++) {
    const port = Math.floor(Math.random() * (62000 - 15000 + 1)) + 15000
    if (!occupied.has(port)) {
      createForm.listenPort = port
      return
    }
  }
  createForm.listenPort = 52333
}
function autoAssignSequentialPorts() {
  const occupied = new Set(nodes.value.map(n => n.listenPort).filter(p => p > 0))
  let base = 52100
  for (const dev of deviceNodes) {
    while (occupied.has(base)) base++
    dev.listenPort = base
    occupied.add(base)
    base++
  }
}
function batchRenameDevices(prefix = '设备') {
  deviceNodes.forEach((dev, idx) => {
    dev.name = `${prefix} ${String(idx + 1).padStart(2, '0')}`
  })
}
const hasDevicePortDuplicate = computed(() => {
  const ports = deviceNodes.map(d => d.listenPort).filter(p => p > 0)
  return new Set(ports).size !== ports.length
})
function applyBindChoice(family: 'ipv4' | 'ipv6') {
  const field = family === 'ipv4' ? 'ipv4Bind' : 'ipv6Bind'
  createForm[field] = bindChoice[family] === '__manual__' ? '' : bindChoice[family]
}
function syncBindingsToMode() {
  if (createForm.mode === 'v6only') createForm.ipv4Bind = ''
  else if (bindChoice.ipv4 !== '__manual__') createForm.ipv4Bind = bindChoice.ipv4
  if (createForm.mode === 'v4only') createForm.ipv6Bind = ''
  else if (bindChoice.ipv6 !== '__manual__') createForm.ipv6Bind = bindChoice.ipv6
}
watch(() => createForm.mode, syncBindingsToMode)
watch(() => createForm.egress, egress => {
  if (egress !== 'residential' && egress !== 'socks') return
  createForm.mode = 'v4only'
  createForm.ipv4Bind = ''; createForm.ipv6Bind = ''; createForm.autoBind = false
  bindChoice.ipv4 = ''; bindChoice.ipv6 = ''
})
watch(() => socksForm.version, version => {
  if (version === '5') {
    socksForm.clearPassword = false
    return
  }
  socksForm.network = 'tcp'
  socksForm.password = ''
  socksForm.clearPassword = true
})
watch(() => createForm.protocol, (protocol, previous) => {
  if (formHydrating.value) return
  const panelDomain = deploymentDefaults.value.panelDomain
  if (protocol === 'vless-ws-tunnel') {
    if (createForm.server === panelDomain) createForm.server = ''
    createForm.domain = ''
  } else if (protocol === 'vless' && (createForm.domain === panelDomain || !createForm.domain)) createForm.domain = 's0.awsstatic.com'
  else if (protocol === 'shadowsocks') createForm.domain = ''
  else if (previous === 'vless' || previous === 'vless-ws-tunnel' || !createForm.domain) createForm.domain = panelDomain
  if (protocol !== 'vless-ws-tunnel' && !createForm.server) createForm.server = panelDomain
  if (protocol !== 'vless-ws-tunnel') createForm.preferredServer = ''
})
watch([fleetEnabledDraft, fleetPublicURL, fleetSubscriptionPublicURL, fleetSelectedHosts, fleetSelectedNodes], () => {
  if (!syncingFleetDraft) {
    fleetDraftDirty.value = true
    fleetSubscriptionProbe.value = null
    fleetSubscriptionProbeError.value = ''
  }
}, { deep: true, flush: 'sync' })
watch(settings, () => {
  if (!syncingSettingsDraft) settingsDraftDirty.value = true
}, { deep: true, flush: 'sync' })
watch(() => settings.value.language, value => {
  const next: Locale = value === 'en-US' ? 'en-US' : 'zh-CN'
  if (language.value !== next) language.value = next
}, { flush: 'sync' })
watch(language, locale => {
  applyLocale(locale)
  refreshDocumentLocale(locale)
}, { flush: 'post' })
watch(page, (next, previous) => {
  if (next === previous) return
  if (previous === 'fleet') {
    fleetDraftDirty.value = false
    refreshFleetStatus().catch(() => {})
  }
  if (previous === 'settings') {
    settingsDraftDirty.value = false
    confirmRotateGlobalToken.value = false
    confirmRotateHostToken.value = false
  }
  if (next !== 'security' && next !== 'fleet' && (previous === 'settings' || previous === 'security')) {
    refreshAll().catch(() => {})
  }
}, { flush: 'sync' })
watch(fleetHosts, (hosts) => {
  for (const host of hosts) {
    prefetchHostReputation(host)
  }
}, { immediate: true })
async function openNodeForm(kind: 'create' | 'device-create') {
	if (!ensureHostWritable()) return
  Object.assign(createForm, { protocol: 'hysteria2', name: '', mode: 'prefer_v6', egress: 'direct', listenPort: 0, autoAllowPort: true, server: '', domain: '', preferredServer: '', webSocketPath: '', tunnelToken: '', ipv4Bind: '', ipv6Bind: '', autoBind: false, v6OnlyDomains: 'chatgpt.com,claude.ai,anthropic.com', certificatePath: '', keyPath: '' })
  if (kind === 'device-create') resetDeviceDrafts()
  bindChoice.ipv4 = ''; bindChoice.ipv6 = ''
  modal.value = kind; defaultsLoading.value = true
  try {
    const defaults = await api.nodeDeploymentDefaults()
    if (modal.value !== kind) return
    deploymentDefaults.value = { panelDomain: defaults.panelDomain || '', ipv4: defaults.ipv4 || [], ipv6: defaults.ipv6 || [], residentialExitReady: !!defaults.residentialExitReady, socksExitReady: !!defaults.socksExitReady }
    if (!createForm.server) {
      createForm.server = deploymentDefaults.value.panelDomain
    }
    if (!createForm.domain) {
      createForm.domain = deploymentDefaults.value.panelDomain
    }
    if (!bindChoice.ipv4 && deploymentDefaults.value.ipv4.length === 1) { bindChoice.ipv4 = deploymentDefaults.value.ipv4[0].address; applyBindChoice('ipv4') }
    if (!bindChoice.ipv6 && deploymentDefaults.value.ipv6.length === 1) { bindChoice.ipv6 = deploymentDefaults.value.ipv6[0].address; applyBindChoice('ipv6') }
  } catch (error) {
    if (modal.value !== kind) return
    deploymentDefaults.value = { panelDomain: '', ipv4: [], ipv6: [], residentialExitReady: false, socksExitReady: false }
    notify(error instanceof Error ? `无法读取部署默认值：${error.message}` : '无法读取部署默认值，请手动填写')
  } finally { defaultsLoading.value = false }
}
function openCreate() { return openNodeForm('create') }
function openDeviceCreate() { return openNodeForm('device-create') }
const deployMenuOpen = ref(false)
function toggleDeployMenu() {
  if (mutationsDisabled.value) return
  deployMenuOpen.value = !deployMenuOpen.value
}
function selectDeployOption(type: 'standard' | 'device') {
  deployMenuOpen.value = false
  if (type === 'standard') {
    openCreate()
  } else {
    openDeviceCreate()
  }
}
function onDocumentClick(e: MouseEvent) {
  if (deployMenuOpen.value) {
    const target = e.target as HTMLElement | null
    if (!target?.closest('.deploy-dropdown-wrap')) {
      deployMenuOpen.value = false
    }
  }
}
function onDocumentKeydown(e: KeyboardEvent) {
  if (e.key === 'Escape' && deployMenuOpen.value) {
    deployMenuOpen.value = false
  }
}
async function openEdit(node: NodeItem) {
	if (!ensureHostWritable()) return
  if (node.ownership !== 'managed') return
  selectedNode.value = node
  modal.value = 'edit'
  defaultsLoading.value = true
  formHydrating.value = true
  try {
    const [defaults, details] = await Promise.all([api.nodeDeploymentDefaults(), api.nodeEditDetails(node.id)])
    deploymentDefaults.value = { panelDomain: defaults.panelDomain || '', ipv4: defaults.ipv4 || [], ipv6: defaults.ipv6 || [], residentialExitReady: !!defaults.residentialExitReady, socksExitReady: !!defaults.socksExitReady }
    const current = details.node
    Object.assign(createForm, {
      protocol: current.protocol, name: current.name, mode: current.mode, egress: current.egress || 'direct', listenPort: current.listenPort,
      autoAllowPort: true,
      server: current.server || '', domain: current.domain || '', preferredServer: current.preferredServer || '',
      webSocketPath: current.webSocketPath || '', tunnelToken: '', ipv4Bind: current.ipv4Bind || '', ipv6Bind: current.ipv6Bind || '',
      autoBind: false, v6OnlyDomains: (details.v6OnlyDomains || []).join(','), certificatePath: '', keyPath: '',
    })
    bindChoice.ipv4 = deploymentDefaults.value.ipv4.some(item => item.address === createForm.ipv4Bind) ? createForm.ipv4Bind : createForm.ipv4Bind ? '__manual__' : ''
    bindChoice.ipv6 = deploymentDefaults.value.ipv6.some(item => item.address === createForm.ipv6Bind) ? createForm.ipv6Bind : createForm.ipv6Bind ? '__manual__' : ''
    await nextTick()
  } catch (error) {
    modal.value = null
    notify(error instanceof Error ? `无法读取节点配置：${error.message}` : '无法读取节点配置')
  } finally {
    formHydrating.value = false
    defaultsLoading.value = false
  }
}
async function nodeAction(node: NodeItem, action: string) {
	if (!ensureHostWritable()) return
  if (action === 'delete') { selectedNode.value = node; deleteConfirm.value = ''; modal.value = 'delete'; return }
  try { await api.nodeAction(node.id, action); notify(`${node.sharedGroup && ['start', 'stop', 'restart'].includes(action) ? '设备编队整组' : ''}${jobLabel(`node.${action}`)}任务已创建`); await refreshAll() }
  catch (error) { notify(error instanceof Error ? error.message : '操作失败') }
}
async function probeNode(node: NodeItem) {
  if (node.status !== 'active' || probeJobs[node.id]) return
  try {
    const result = await api.nodeAction(node.id, 'probe')
    probeJobs[node.id] = result.jobId
    notify(`正在检测 ${node.name} 的完整代理链路`)
    void watchProbeJob(node.id, result.jobId)
  } catch (error) { notify(error instanceof Error ? error.message : '无法创建检测任务') }
}
async function watchProbeJob(nodeId: string, jobId: string) {
  try {
    for (let attempt = 0; attempt < 65; attempt++) {
      await new Promise(resolve => window.setTimeout(resolve, 1000))
      const job = await api.job(jobId)
      if (job.status !== 'success' && job.status !== 'failed') continue
      const [nodeData, jobData] = await Promise.all([api.nodes(), api.jobs()])
      nodes.value = nodeData; jobs.value = jobData
      const node = nodeData.find(item => item.id === nodeId)
      if (job.status === 'success') notify(`${node?.name || '节点'}闭环检测通过${node?.probeLatencyMs ? ` · ${node.probeLatencyMs} ms` : ''}`)
      else notify(`${node?.name || '节点'}检测失败，请查看卡片或任务日志`)
      return
    }
    notify('检测仍在运行，可在任务日志查看进度')
  } catch (error) { notify(error instanceof Error ? error.message : '无法读取检测结果') }
  finally { if (probeJobs[nodeId] === jobId) delete probeJobs[nodeId] }
}
async function deleteNode() {
	if (!ensureHostWritable()) return
  if (!selectedNode.value) return
  const nodeToDelete = selectedNode.value
  const targetName = nodeToDelete.name
  busy.value = true
  try {
    const res = await api.nodeAction(nodeToDelete.id, 'delete', deleteConfirm.value)
    modal.value = null
    deleteConfirm.value = ''
    notify(language.value === 'en-US' ? `Deleting ${targetName}...` : `正在删除 ${targetName}...`)
    void watchActionJob(res.jobId, targetName, 'delete')
  } catch (error) {
    notify(error instanceof Error ? error.message : '删除失败')
  } finally {
    busy.value = false
  }
}
async function revealShare(node: NodeItem) {
  selectedNode.value = node; shareURI.value = ''; shareQR.value = ''; modal.value = 'share'
  try { const share = await api.share(node.id); shareURI.value = share.uri; shareQR.value = await QRCode.toDataURL(share.uri, { margin: 1, width: 224, color: { dark: '#15120b', light: '#f5e9c8' } }) }
  catch (error) { notify(error instanceof Error ? error.message : '无法生成分享链接') }
}
async function openImport() {
	if (!ensureHostWritable()) return
  modal.value = 'import'; candidates.value = []; selectedCandidates.value = []; candidateDeleteTarget.value = null; candidateDeleteConfirm.value = ''
  try { candidates.value = await api.scan(); selectedCandidates.value = candidates.value.map(item => item.fingerprint) }
  catch (error) { notify(error instanceof Error ? error.message : '扫描失败') }
}
async function importSelected() {
	if (!ensureHostWritable()) return
  busy.value = true
  try {
    const res = await api.importNodes(selectedCandidates.value)
    modal.value = null
    const targetLabel = `${selectedCandidates.value.length} 个节点`
    notify(language.value === 'en-US' ? 'Adopting nodes...' : '正在接管选中节点...')
    void watchActionJob(res.jobId, targetLabel, 'import')
  } catch (error) {
    notify(error instanceof Error ? error.message : '接管失败')
  } finally {
    busy.value = false
  }
}
function stageCandidateDelete(candidate: Candidate) {
  candidateDeleteTarget.value = candidate
  candidateDeleteConfirm.value = ''
  selectedCandidates.value = selectedCandidates.value.filter(id => id !== candidate.fingerprint)
}
function cancelCandidateDelete() {
  candidateDeleteTarget.value = null
  candidateDeleteConfirm.value = ''
}
async function deleteCandidate() {
	if (!ensureHostWritable()) return
  const candidate = candidateDeleteTarget.value
  if (!candidate || candidateDeleteConfirm.value !== candidate.name) return
  const targetName = candidate.name
  busy.value = true
  try {
    const res = await api.deleteCandidate(candidate.fingerprint, candidateDeleteConfirm.value)
    modal.value = null; candidateDeleteTarget.value = null; candidateDeleteConfirm.value = ''
    notify(language.value === 'en-US' ? `Deleting candidate ${targetName}...` : `正在彻底删除 ${targetName}...`)
    void watchActionJob(res.jobId, targetName, 'delete_candidate')
  } catch (error) {
    notify(error instanceof Error ? error.message : '无法创建彻底删除任务')
  } finally {
    busy.value = false
  }
}
async function saveSettings() {
	if (!ensureHostWritable()) return
	busy.value = true
  try { await api.saveSettings(settings.value); settingsDraftDirty.value = false; language.value = settings.value.language === 'en-US' ? 'en-US' : 'zh-CN'; notify('设置已保存') }
  catch (error) { notify(error instanceof Error ? error.message : '保存失败') }
	finally { busy.value = false }
}
async function rotateSubscription() {
	if (!ensureHostWritable()) return
	try { const result = await api.rotateSubscription(); settings.value.subscriptionToken = `${result.token.slice(0, 4)}••••${result.token.slice(-4)}`; settingsDraftDirty.value = false; notify('订阅令牌已轮换') }
	catch (error) { notify(error instanceof Error ? error.message : '轮换失败') }
}
async function loadSingBoxMigration(host: FleetHost, targetVersion: string) {
  singBoxMigrationLoading.value = true
  try {
    singBoxMigrationPlan.value = await api.singBoxMigration(targetVersion, host.id)
  } catch {
    singBoxMigrationPlan.value = null
  } finally {
    singBoxMigrationLoading.value = false
  }
}
async function configureResidentialExit() {
	if (!ensureHostWritable()) return
  residentialBusy.value = true
  try {
    const result = await api.configureResidentialExit({
      endpoint: residentialForm.endpoint.trim(),
      listenPort: residentialForm.listenPort,
      peerPublicKey: residentialForm.peerPublicKey.trim(),
      expectedExitIp: residentialForm.expectedExitIp.trim(),
    })
    residentialExit.value = result
    deploymentDefaults.value.residentialExitReady = result.configured
    notify(result.configured ? '落地出口已配置并启动' : 'A 机密钥已生成，请在 B 机运行安装脚本')
  } catch (error) { notify(error instanceof Error ? error.message : '落地出口配置失败') }
  finally { residentialBusy.value = false }
}
function stageResidentialExitRemoval() {
  residentialRemoveConfirm.value = ''
  modal.value = 'residential-remove'
}
async function removeResidentialExit() {
	if (!ensureHostWritable()) return
  if (residentialRemoveConfirm.value !== 'REMOVE' || residentialNodesInUse.value.length) return
  residentialBusy.value = true
  try {
    await api.removeResidentialExit('REMOVE')
    residentialExit.value = await api.residentialExit()
    Object.assign(residentialForm, { endpoint: '', listenPort: 51820, peerPublicKey: '', expectedExitIp: '' })
    deploymentDefaults.value.residentialExitReady = false
    modal.value = null
    residentialRemoveConfirm.value = ''
    notify('落地出口已移除')
  } catch (error) { notify(error instanceof Error ? error.message : '落地出口移除失败') }
  finally { residentialBusy.value = false }
}
async function configureSOCKSExit() {
	if (!ensureHostWritable()) return
  socksBusy.value = true
  try {
    const result = await api.configureSOCKSExit({
      server: socksForm.server.trim(),
      port: socksForm.port,
      version: socksForm.version,
      username: socksForm.username.trim(),
      password: socksForm.password,
      clearPassword: socksForm.clearPassword,
      network: socksForm.network,
      expectedExitIp: socksForm.expectedExitIp.trim(),
    })
    socksExit.value = result
    socksForm.password = ''
    socksForm.clearPassword = false
    deploymentDefaults.value.socksExitReady = result.configured
    notify(`SOCKS 出站预检通过${result.probeExitIp ? ` · 出口 ${result.probeExitIp}` : ''}`)
  } catch (error) { notify(error instanceof Error ? error.message : 'SOCKS 出站配置失败') }
  finally { socksBusy.value = false }
}
function stageSOCKSExitRemoval() {
  socksRemoveConfirm.value = ''
  modal.value = 'socks-remove'
}
async function removeSOCKSExit() {
	if (!ensureHostWritable()) return
  if (socksRemoveConfirm.value !== 'REMOVE' || socksNodesInUse.value.length) return
  socksBusy.value = true
  try {
    await api.removeSOCKSExit('REMOVE')
    socksExit.value = await api.socksExit()
    Object.assign(socksForm, { server: '', port: 1080, version: '5', username: '', password: '', clearPassword: false, network: 'both', expectedExitIp: '' })
    deploymentDefaults.value.socksExitReady = false
    modal.value = null
    socksRemoveConfirm.value = ''
    notify('SOCKS 出站已移除')
  } catch (error) { notify(error instanceof Error ? error.message : 'SOCKS 出站移除失败') }
  finally { socksBusy.value = false }
}
async function copy(value: string) { await navigator.clipboard.writeText(value); notify('已复制到剪贴板') }

let timer = 0
let releaseCheckTick = 0
let stopObservingTheme = () => {}
let stopLocalizing = () => {}
const onWindowFocus = () => { if (authenticated.value && !mustChange.value) checkLatestRelease().catch(() => {}) }
onMounted(async () => { applyLocale(language.value, false); stopLocalizing = createDocumentLocalizer(() => language.value); applyThemePreference(themePreference.value, false); activeEffectiveTheme.value = effectiveTheme(themePreference.value); stopObservingTheme = observeSystemTheme(() => themePreference.value, next => { activeEffectiveTheme.value = next }); updateDeviceLimit(); window.addEventListener('resize', updateDeviceLimit); window.addEventListener('focus', onWindowFocus); window.addEventListener('click', onDocumentClick); window.addEventListener('keydown', onDocumentKeydown); await bootstrap(); void fetchFirewallStatus(); setTimelineRange('today'); timer = window.setInterval(() => { if (authenticated.value && !mustChange.value && !busy.value) { refreshFleetStatus().catch(() => {}); if (page.value !== 'fleet' && page.value !== 'security') refreshAll().catch(() => {}); releaseCheckTick++; if (releaseCheckTick % 30 === 0) checkLatestRelease().catch(() => {}) } }, 10_000) })
onBeforeUnmount(() => { stopLocalizing(); stopObservingTheme(); window.clearInterval(timer); if (singBoxPollTimer) clearTimeout(singBoxPollTimer); window.removeEventListener('resize', updateDeviceLimit); window.removeEventListener('focus', onWindowFocus); window.removeEventListener('click', onDocumentClick); window.removeEventListener('keydown', onDocumentKeydown) })
</script>

<template>
  <div v-if="loading" class="boot-screen"><div class="orbit-mark"><i></i><b>悟</b></div><p>正在唤醒悟空面板</p></div>

  <main v-else-if="!authenticated" class="login-stage">
    <div class="cloud cloud-a"></div><div class="cloud cloud-b"></div>
    <section class="login-brand">
      <div class="brand-kicker">WUKONG CONTROL PLANE · 01</div>
      <h1>驭云端<br><em>定乾坤</em></h1>
      <p>从一束流量，到一方节点。部署、管理与观测，在同一座控制台完成。</p>
      <div class="brand-stats"><span><b>7</b> 种协议驱动</span><span><b>10s</b> 实时采样</span><span><b>1</b> 单机自治</span></div>
    </section>
    <form class="login-panel" @submit.prevent="login">
      <div class="panel-seal">悟</div><p class="eyebrow">悟空面板</p><h2>进入控制台</h2><p class="subtle">使用安装时生成的管理员凭据</p>
      <label>管理员账号<input v-model="username" autocomplete="username" required /></label>
      <label>访问密码<input v-model="password" type="password" autocomplete="current-password" required /></label>
      <p v-if="loginError" class="form-error">{{ loginError }}</p>
      <button class="primary wide" :disabled="busy">{{ busy ? '验证中…' : '登录面板' }}<span>→</span></button>
      <div class="login-theme-control"><span>界面主题</span><ThemePicker :model-value="themePreference" compact aria-label="登录页界面主题" @update:model-value="setThemePreference" /></div>
      <small>HTTPS 加密 · 单管理员 · 操作留痕</small>
    </form>
  </main>

  <div v-else class="app-shell">
    <aside class="sidebar">
      <button class="brand-button" @click="navigateTo('overview')"><span class="mini-orbit">悟</span><span><strong>悟空面板</strong><small>WUKONG PANEL</small></span></button>
      <nav><button v-for="item in navItems" :key="item.id" :class="{ active: page === item.id }" @click="navigateTo(item.id)"><i>{{ item.seal }}</i><span>{{ item.label }}</span><b v-if="item.id === 'jobs' && activeJobs">{{ activeJobs }}</b></button></nav>
      <div class="sidebar-foot"><div class="server-pulse" :class="{ muted: mutationsDisabled }"><i></i><span><b>{{ currentFleetHost?.name || '本机' }} Agent</b><small>{{ currentFleetHost?.online === false ? '最后快照 · 当前离线' : '安全通道已连接' }}</small></span></div><button class="ghost-icon" title="退出" @click="logout">↪</button></div>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div><p class="breadcrumb">天宫 / {{ navItems.find(item => item.id === page)?.label }}</p><h1>{{ navItems.find(item => item.id === page)?.label }}</h1></div>
        <div class="top-actions">
          <label v-if="fleetStatus?.enabled" class="host-switcher">
            <select aria-label="当前主机" :value="selectedHostId" @change="switchFleetHost(($event.target as HTMLSelectElement).value)">
              <option v-for="host in fleetHosts.filter(item => !isProbeHost(item))" :key="host.id" :value="host.id">{{ host.name }}</option>
            </select>
          </label>
          <span class="clock">{{ new Date().toLocaleDateString(language, { month: 'short', day: 'numeric' }) }}</span>
          <button type="button" class="secondary ip-rep-topbar-btn" title="检测 IP 信誉分与威胁情报" @click="openReputationModal(currentFleetHost || undefined)">🛡️ IP 信誉</button>
          <button v-if="page !== 'fleet'" class="secondary import-topbar-btn" :disabled="mutationsDisabled" :title="language === 'en-US' ? 'Import existing nodes' : '接管已有节点'" @click="openImport">↳ {{ t('import') }}</button>
          <div v-if="page !== 'fleet'" class="deploy-dropdown-wrap">
            <button
              type="button"
              class="primary deploy-btn-main"
              :class="{ open: deployMenuOpen }"
              :disabled="mutationsDisabled"
              :aria-expanded="deployMenuOpen"
              aria-haspopup="menu"
              :title="language === 'en-US' ? 'Deploy proxy node or device fleet' : '部署新节点或设备专用编队'"
              @click.stop="toggleDeployMenu"
            >
              <span>＋ {{ t('deploy') }}</span>
              <i class="deploy-caret" :class="{ open: deployMenuOpen }" aria-hidden="true">▾</i>
            </button>
            <transition name="dropdown">
              <div
                v-if="deployMenuOpen"
                class="deploy-dropdown-menu"
                role="menu"
                aria-orientation="vertical"
                @click.stop
              >
                <button
                  type="button"
                  class="deploy-menu-item"
                  role="menuitem"
                  @click="selectDeployOption('standard')"
                >
                  <span class="menu-item-icon standard">＋</span>
                  <div class="menu-item-text">
                    <div class="menu-item-title-row">
                      <b>{{ language === 'en-US' ? 'Standard Proxy Node' : '标准代理节点' }}</b>
                      <span class="menu-item-tag gold">{{ language === 'en-US' ? '7 Protocols' : '七协议' }}</span>
                    </div>
                    <small>{{ language === 'en-US' ? 'Hysteria2 / VLESS / TUIC / SS · Standalone or shared core' : 'Hysteria2 / VLESS / TUIC / SS 等原生托管 · 自动生成安全凭据' }}</small>
                  </div>
                </button>
                <button
                  type="button"
                  class="deploy-menu-item"
                  role="menuitem"
                  @click="selectDeployOption('device')"
                >
                  <span class="menu-item-icon device">器</span>
                  <div class="menu-item-text">
                    <div class="menu-item-title-row">
                      <b>{{ language === 'en-US' ? 'Device Dedicated Fleet' : '设备专用编队' }}</b>
                      <span class="menu-item-tag jade">{{ language === 'en-US' ? 'Fleet Group' : '设备编队' }}</span>
                    </div>
                    <small>{{ language === 'en-US' ? 'Independent inbound per device · Shared sing-box process & tunnel' : '多设备独立入站隔离 · 共享 sing-box 进程与隧道 · 聚合监控' }}</small>
                  </div>
                </button>
              </div>
            </transition>
          </div>
          <button type="button" class="topbar-theme-toggle" :title="topbarThemeTitle" :aria-label="topbarThemeTitle" @click="toggleThemePreference"><i class="theme-swatch" :class="`theme-swatch-${activeEffectiveTheme}`" aria-hidden="true"><b></b><em></em></i></button>
        </div>
      </header>

      <div v-if="mutationsDisabled && page !== 'fleet'" class="fleet-readonly-banner"><b>{{ currentFleetHost?.compatible ? '远端主机离线' : '协议版本不兼容' }}</b><span>当前展示最后同步快照，所有修改操作已禁用。{{ currentFleetHost?.lastSeenAt ? `最后心跳 ${new Date(currentFleetHost.lastSeenAt).toLocaleString(language)}` : '' }}</span></div>

      <div v-if="page === 'fleet'" class="page-content fleet-page">
        <div class="page-intro">
          <div><p>CELESTIAL FLEET</p><h2>中央多机控制台</h2><small class="page-caption">每台远端保持本机自治；中央停机不会影响现有节点。</small></div>
          <div class="fleet-enroll-actions">
            <button v-if="remoteFleetHosts.length >= 2" type="button" class="secondary fleet-sort-btn" title="自定义远端主机卡片排列顺序" @click="openFleetOrderModal"><span class="fleet-sort-icon">⇅</span> 自定义排序</button>
            <button class="primary" @click="createFleetEnrollment('panel')">＋ 接入面板</button>
            <button class="secondary" @click="createFleetEnrollment('probe')">＋ 接入轻量探针</button>
          </div>
        </div>
        <section class="fleet-summary-grid"><article><small>主机在线</small><strong>{{ fleetAggregate.online }}<span>/{{ fleetAggregate.total }}</span></strong><em>30 秒在线窗口</em></article><article><small>运行节点</small><strong>{{ fleetAggregate.runningNodes }}<span>/{{ fleetAggregate.knownNodes }}</span></strong><em>在线运行 / 已知节点</em></article><article><small>网络探测异常</small><strong>{{ fleetAggregate.online ? fleetAggregate.networkAlerts : '—' }}<span v-if="fleetAggregate.online"> {{ language === 'en-US' ? 'hosts' : '台' }}</span></strong><em>{{ language === 'en-US' ? `30-min total loss ≥5% or probe outage${fleetAggregate.networkPending ? ` · ${fleetAggregate.networkPending} awaiting samples` : ''}` : `近 30 分钟总丢包率 ≥5% / 探测中断${fleetAggregate.networkPending ? ` · ${fleetAggregate.networkPending} 台待采样` : ''}` }}</em></article><article class="fleet-summary-traffic-card"><small>实时流量</small><strong>↓ <b>{{ rate(fleetAggregate.rx) }}</b></strong><em>↑ <b>{{ rate(fleetAggregate.tx) }}</b></em></article></section>
        <section class="fleet-host-grid">
          <article
            v-for="host in fleetHosts"
            :key="host.id"
            class="panel-card fleet-host-card"
            :class="{
              offline: !host.online,
              incompatible: !host.compatible,
              'is-draggable': host.id !== 'local',
              'is-dragging': draggedHostId === host.id,
              'drag-over': dragOverHostId === host.id
            }"
            :draggable="host.id !== 'local'"
            @dragstart="onHostDragStart($event, host)"
            @dragover.prevent="onHostDragOver($event, host)"
            @dragleave="onHostDragLeave($event, host)"
            @drop.prevent="onHostDrop($event, host)"
            @dragend="onHostDragEnd"
          >
            <span v-if="host.id !== 'local'" class="fleet-drag-handle" title="按住拖拽以调整卡片顺序" aria-label="按住拖拽调整顺序">⠿</span>
            <header>
              <div>
                <i></i>
                <span><span class="fleet-host-title"><b>{{ host.id === 'local' ? '中央本机' : host.name }}</b><span v-if="host.snapshot?.location?.countryCode" class="fleet-host-country" :title="host.snapshot.location.publicIP"><img class="fleet-host-flag" :src="countryFlagURL(host.snapshot.location.countryCode)" alt="" aria-hidden="true"> {{ hostCountryName(host.snapshot.location.countryCode) }}</span><span v-if="host.expiresAt" class="fleet-host-expiry fleet-host-expiry-header" :class="expiryTone(host.expiresAt)" :title="`到期时间: ${host.expiresAt}`">{{ expiryLabel(host.expiresAt) }}</span></span><small>{{ host.os || 'Linux' }} · {{ host.arch || 'unknown' }}</small></span>
              </div>
              <aside class="fleet-header-aside">
                <div class="fleet-header-rates" :title="fleetRateHint(host)">
                  <span class="fleet-rate-down">↓ <b>{{ host.online ? rate(host.snapshot?.overview?.now?.rxBps || 0) : '0 B/s' }}</b></span>
                  <span class="fleet-rate-up">↑ <b>{{ host.online ? rate(host.snapshot?.overview?.now?.txBps || 0) : '0 B/s' }}</b></span>
                </div>
                <em><span class="fleet-host-status"><span class="fleet-node-summary">{{ `节点 ${fleetHostNodeSummary(host)}` }}</span><span class="fleet-online-state">· {{ host.online ? '在线' : '离线' }}</span></span><span class="fleet-uptime">运行：{{ uptime(host.snapshot?.overview?.now?.uptime) }}</span></em>
              </aside>
            </header>
            <div class="fleet-host-body">
              <section class="fleet-resource-grid" aria-label="主机资源">
                <div class="fleet-resource"><small>CPU</small><b>{{ (host.snapshot?.overview?.now?.cpu || 0).toFixed(1) }}%</b><em>负载 {{ (host.snapshot?.overview?.now?.load1 || 0).toFixed(2) }}</em></div>
                <div class="fleet-resource"><small>内存</small><b :title="resourceUsage(host.snapshot?.overview?.now?.memoryUsedBytes || 0, host.snapshot?.overview?.now?.memoryTotalBytes || 0, 0)">{{ resourceUsage(host.snapshot?.overview?.now?.memoryUsedBytes || 0, host.snapshot?.overview?.now?.memoryTotalBytes || 0, 0) }}</b><em>{{ resourcePercent(host.snapshot?.overview?.now?.memoryUsedBytes || 0, host.snapshot?.overview?.now?.memoryTotalBytes || 0, host.snapshot?.overview?.now?.memory || 0, 0) }}</em></div>
                <div class="fleet-resource"><small>磁盘</small><b :title="resourceUsage(host.snapshot?.overview?.now?.diskUsedBytes || 0, host.snapshot?.overview?.now?.diskTotalBytes || 0)">{{ resourceUsage(host.snapshot?.overview?.now?.diskUsedBytes || 0, host.snapshot?.overview?.now?.diskTotalBytes || 0) }}</b><em>{{ resourcePercent(host.snapshot?.overview?.now?.diskUsedBytes || 0, host.snapshot?.overview?.now?.diskTotalBytes || 0, host.snapshot?.overview?.now?.disk || 0) }}</em></div>
                <div v-if="isProbeHost(host)" class="fleet-resource fleet-resource-clickable" :title="language === 'en-US' ? 'Click to configure quota and VPS expiry' : '点击配置配额与到期时间'" @click="openFleetHostSettings(host)"><small>本账期流量</small><b :title="fleetBillingUsage(host.snapshot?.overview)">{{ fleetBillingUsage(host.snapshot?.overview) }}</b><em>{{ fleetBillingPercent(host.snapshot?.overview) }} · {{ host.snapshot?.overview?.now?.interface || '—' }}</em></div><div v-else class="fleet-resource"><small>本账期流量</small><b :title="fleetBillingUsage(host.snapshot?.overview)">{{ fleetBillingUsage(host.snapshot?.overview) }}</b><em>{{ fleetBillingPercent(host.snapshot?.overview) }}</em></div>
              </section>
              <section class="fleet-host-network" aria-label="网络质量">
                <div class="fleet-network-heading"><div class="fleet-network-title-wrap"><strong>网络质量</strong><button type="button" class="fleet-host-reputation-badge" :class="reputationBadgeClass(host)" :title="reputationBadgeTitle(host)" @click.stop="openReputationModal(host)"><i class="reputation-dot" aria-hidden="true"></i><span v-if="reputationBadgeParts(host).mode === 'dual'" class="rep-badge-content"><span class="rep-lbl">{{ reputationBadgeParts(host).tag4 }}</span><span class="rep-val" :class="reputationBadgeParts(host).class4">{{ reputationBadgeParts(host).score4 }}</span><span class="rep-slash">/</span><span class="rep-lbl">{{ reputationBadgeParts(host).tag6 }}</span><span class="rep-val" :class="reputationBadgeParts(host).class6">{{ reputationBadgeParts(host).score6 }}</span></span><span v-else-if="reputationBadgeParts(host).mode === 'single'" class="rep-badge-content"><span class="rep-lbl">{{ reputationBadgeParts(host).singleTag }}</span><span class="rep-val" :class="reputationBadgeParts(host).singleClass">{{ reputationBadgeParts(host).singleScore }}</span></span><span v-else>{{ reputationBadgeParts(host).text }}</span></button></div><small>ICMP · 近 30 分钟</small></div>
                <div v-for="group in networkGroups" :key="group" class="fleet-network-group">
                  <div class="fleet-network-summary" :title="fleetNetworkHint(host, group)">
                    <div class="fleet-network-region"><strong>{{ networkGroupLabel(group) }}</strong><small>{{ fleetNetworkStateLabel(host, group) }}</small></div>
                    <dl><div v-for="metric in networkMetrics" :key="metric"><dt>{{ metric === 'latency' ? '延迟' : '总丢包' }}</dt><dd :class="fleetNetworkTone(host, group, metric)">{{ fleetNetworkValue(host, group, metric) }}</dd></div></dl>
                  </div>
                  <div v-for="metric in networkMetrics" :key="metric" class="fleet-network-track"><span>{{ metric === 'latency' ? '延迟' : '丢包' }}</span><NetworkHistoryBars :samples="fleetNetworkHistorySlots(host, group)" :metric="metric" :group-label="networkGroupLabel(group)" :language="language" :history-label="`${networkGroupLabel(group)}${metric === 'latency' ? '延迟' : '丢包'}近 30 分钟历史`" /></div>
                </div>
              </section>
            </div>
            <footer><div class="fleet-host-version-meta"><template v-if="isProbeHost(host)"><span class="fleet-host-version-text">Probe {{ host.panelVersion || '—' }} · {{ language === 'en-US' ? 'Monitoring only' : '轻量探针' }}</span><button v-if="hasHostUpdate(host)" type="button" class="fleet-update-pill" :title="`发现新版本 v${latestReleaseVersion}，点击更新`" @click.stop="openHostUpdateModal(host)"><i class="fleet-update-icon" aria-hidden="true">⬆</i><span><span class="fleet-update-lead">可</span>更新 v{{ latestReleaseVersion }}</span></button></template><template v-else><span class="fleet-host-version-text">Panel {{ host.panelVersion || host.snapshot?.overview?.panelVersion || '—' }}</span><button v-if="hasHostUpdate(host)" type="button" class="fleet-update-pill" :title="`发现新版本 v${latestReleaseVersion}，点击更新`" @click.stop="openHostUpdateModal(host)"><i class="fleet-update-icon" aria-hidden="true">⬆</i><span><span class="fleet-update-lead">可</span>更新 v{{ latestReleaseVersion }}</span></button><span class="fleet-version-dot">·</span><span class="fleet-host-version-text">sing-box {{ host.singBoxVersion || '—' }}</span><button v-if="hasSingBoxUpdate(host)" type="button" class="fleet-update-pill singbox-update-pill" :title="`发现新版本 ${latestSingBoxVersion}，点击更新`" @click.stop="openSingBoxUpdateModal(host)"><i class="fleet-update-icon" aria-hidden="true">⬆</i><span><span class="fleet-update-lead">可</span>更新 {{ latestSingBoxVersion }}</span></button></template></div><div class="fleet-footer-actions"><div class="fleet-footer-buttons"><button v-if="!isProbeHost(host)" @click="switchFleetHost(host.id)">进入主机</button><button v-if="isProbeHost(host)" @click="openProbeNodesModal(host)">节点</button><button v-if="isProbeHost(host)" @click="openFleetHostSettings(host)">设置</button><button v-if="host.id !== 'local'" @click="stageFleetHostAction('rename', host)">重命名</button><button v-if="host.id !== 'local'" class="danger" @click="stageFleetHostAction('remove', host)">移除</button></div><span v-if="host.expiresAt" class="fleet-host-expiry fleet-host-expiry-footer" :class="expiryTone(host.expiresAt)" :title="`到期时间: ${host.expiresAt}`">{{ expiryLabel(host.expiresAt) }}</span></div></footer>
            <p v-if="!host.compatible" class="fleet-protocol-warning">fleetProtocolVersion {{ host.protocolVersion }} 与中央 v1 不兼容，仅显示状态。</p>
          </article>
          <article v-if="fleetHosts.length % 2 === 1" class="panel-card fleet-host-card fleet-companion-card" aria-label="舰队全局与扩容舱">
            <header>
              <div>
                <span class="fleet-companion-seal" aria-hidden="true">阵</span>
                <span>
                  <span class="fleet-host-title">
                    <b>舰队全局</b>
                    <span class="fleet-host-country fleet-nexus-badge">FLEET NEXUS</span>
                  </span>
                  <small>账期汇总、租期预警与主机扩容</small>
                </span>
              </div>
              <aside class="fleet-header-aside">
                <div class="fleet-header-rates" title="全舰队实时总吞吐速率">
                  <span class="fleet-rate-down">↓ <b>{{ rate(fleetAggregate.rx) }}</b></span>
                  <span class="fleet-rate-up">↑ <b>{{ rate(fleetAggregate.tx) }}</b></span>
                </div>
                <em>
                  <span class="fleet-node-summary">在线 {{ fleetAggregate.online }}/{{ fleetAggregate.total }}</span>
                  <span class="fleet-online-state">运行节点 {{ fleetAggregate.runningNodes }}</span>
                </em>
              </aside>
            </header>
            <div class="fleet-host-body">
              <section class="fleet-resource-grid" aria-label="舰队全局汇总">
                <div class="fleet-resource">
                  <small>全舰队月流量</small>
                  <b :title="bytes(fleetNexus.totalTrafficUsed)">{{ bytes(fleetNexus.totalTrafficUsed) }}</b>
                  <em>{{ fleetNexus.totalTrafficQuota > 0 ? (fleetNexus.quotaHostCount === fleetHosts.length ? `总配额 ${bytes(fleetNexus.totalTrafficQuota)}` : `${fleetNexus.quotaHostCount} 台设限 ${bytes(fleetNexus.totalTrafficQuota)}`) : '全部主机不限流量' }}</em>
                </div>
                <div class="fleet-resource">
                  <small>流量榜首主机</small>
                  <b :title="fleetNexus.topTrafficHostName">{{ fleetNexus.topTrafficHostName }}</b>
                  <em>{{ fleetNexus.totalTrafficUsed > 0 ? `${bytes(fleetNexus.topTrafficHostUsed)} · 占 ${fleetNexus.topTrafficShare}%` : '本账期暂无消耗' }}</em>
                </div>
                <div class="fleet-resource">
                  <small>最近到期租期</small>
                  <b v-if="fleetNexus.nearestExpiryHost" :class="`nexus-expiry-${expiryTone(fleetNexus.nearestExpiryHost.expiresAt)}`" :title="`${fleetNexus.nearestExpiryHost.id === 'local' ? '中央本机' : fleetNexus.nearestExpiryHost.name} · ${fleetNexus.nearestExpiryHost.expiresAt}`">{{ fleetNexus.nearestExpiryDays! < 0 ? `已过期 ${-fleetNexus.nearestExpiryDays!} 天` : fleetNexus.nearestExpiryDays === 0 ? '今日到期' : `剩余 ${fleetNexus.nearestExpiryDays} 天` }}</b>
                  <b v-else>未登记租期</b>
                  <em v-if="fleetNexus.nearestExpiryHost" :title="`${fleetNexus.nearestExpiryHost.id === 'local' ? '中央本机' : fleetNexus.nearestExpiryHost.name} (${fleetNexus.nearestExpiryHost.expiresAt})`">{{ fleetNexus.nearestExpiryHost.id === 'local' ? '中央本机' : fleetNexus.nearestExpiryHost.name }} · {{ fleetNexus.nearestExpiryHost.expiresAt }}</em>
                  <em v-else>可在主机设置中登记</em>
                </div>
                <div class="fleet-resource">
                  <small>组件版本态势</small>
                  <b :class="{ 'nexus-version-ok': fleetNexus.updatableHostCount === 0, 'nexus-version-warn': fleetNexus.updatableHostCount > 0 }">{{ fleetNexus.updatableHostCount === 0 ? '全员最新' : `${fleetNexus.upToDateHostCount}/${fleetHosts.length} 台最新` }}</b>
                  <em>{{ fleetNexus.pendingUpdateItems > 0 ? `${fleetNexus.pendingUpdateItems} 项组件可在线升级` : 'Panel 与内核均最新' }}</em>
                </div>
              </section>
              <section class="fleet-host-network fleet-companion-enroll" aria-label="接入新远端主机">
                <div class="fleet-network-heading">
                  <div class="fleet-network-title-wrap">
                    <strong>接入新远端主机</strong>
                    <span class="fleet-companion-pill">10 分钟一次性令牌</span>
                  </div>
                  <small>HTTPS 双向鉴权 · 远端自治</small>
                </div>
                <div class="fleet-network-group fleet-enroll-col">
                  <div class="fleet-network-region">
                    <strong>完整面板主机</strong>
                    <small>Panel · Nginx · sing-box</small>
                  </div>
                  <p class="fleet-enroll-col-desc">支持中央切换纳管、远程部署节点与全局订阅聚合。</p>
                  <button type="button" class="fleet-enroll-card-btn primary-accent" :disabled="busy" @click="createFleetEnrollment('panel')"><span>＋</span> 生成完整面板接入命令</button>
                </div>
                <div class="fleet-network-group fleet-enroll-col">
                  <div class="fleet-network-region">
                    <strong>轻量监控探针</strong>
                    <small>Probe Agent · 零侵入</small>
                  </div>
                  <p class="fleet-enroll-col-desc">仅采集系统负载、网络质量与已有节点，不改现有业务。</p>
                  <button type="button" class="fleet-enroll-card-btn" :disabled="busy" @click="createFleetEnrollment('probe')"><span>＋</span> 生成轻量探针接入命令</button>
                </div>
              </section>
            </div>
            <footer>
              <div class="fleet-host-version-meta">
                <span v-if="enrollmentCommand" class="fleet-host-version-text fleet-enroll-active-hint"><i class="enroll-ready-dot" aria-hidden="true"></i>已就绪：{{ enrollmentMode === 'probe' ? '轻量探针一次性接入命令' : '完整面板一次性接入命令' }}</span>
                <span v-else class="fleet-host-version-text">全局订阅纳入 {{ fleetNexus.selectedHostCount }}/{{ fleetHosts.length }} 台主机 · {{ fleetNexus.selectedNodeCount }} 个节点</span>
              </div>
              <div class="fleet-footer-actions">
                <div class="fleet-footer-buttons">
                  <button v-if="enrollmentCommand" type="button" class="enroll-copy-inline-btn" @click="copy(enrollmentCommand)">复制接入命令</button>
                  <button type="button" @click="navigateTo('settings')">主控设置</button>
                </div>
              </div>
            </footer>
          </article>
          <template v-else-if="fleetHosts.length > 0">
            <article class="panel-card fleet-host-card fleet-companion-card fleet-companion-split-card" aria-label="舰队全局">
              <header>
                <div>
                  <span class="fleet-companion-seal" aria-hidden="true">阵</span>
                  <span>
                    <span class="fleet-host-title">
                      <b>舰队全局</b>
                      <span class="fleet-host-country fleet-nexus-badge">FLEET NEXUS</span>
                    </span>
                    <small>全舰队本账期流量汇总、租期预警与组件版本态势</small>
                  </span>
                </div>
                <aside class="fleet-header-aside">
                  <div class="fleet-header-rates" title="全舰队实时总吞吐速率">
                    <span class="fleet-rate-down">↓ <b>{{ rate(fleetAggregate.rx) }}</b></span>
                    <span class="fleet-rate-up">↑ <b>{{ rate(fleetAggregate.tx) }}</b></span>
                  </div>
                  <em>
                    <span class="fleet-node-summary">在线 {{ fleetAggregate.online }}/{{ fleetAggregate.total }}</span>
                    <span class="fleet-online-state">运行节点 {{ fleetAggregate.runningNodes }}</span>
                  </em>
                </aside>
              </header>
              <div class="fleet-host-body fleet-split-body">
                <section class="fleet-resource-grid" aria-label="舰队全局汇总">
                  <div class="fleet-resource">
                    <small>全舰队月流量</small>
                    <b :title="bytes(fleetNexus.totalTrafficUsed)">{{ bytes(fleetNexus.totalTrafficUsed) }}</b>
                    <em>{{ fleetNexus.totalTrafficQuota > 0 ? (fleetNexus.quotaHostCount === fleetHosts.length ? `总配额 ${bytes(fleetNexus.totalTrafficQuota)}` : `${fleetNexus.quotaHostCount} 台设限 ${bytes(fleetNexus.totalTrafficQuota)}`) : '全部主机不限流量' }}</em>
                  </div>
                  <div class="fleet-resource">
                    <small>流量榜首主机</small>
                    <b :title="fleetNexus.topTrafficHostName">{{ fleetNexus.topTrafficHostName }}</b>
                    <em>{{ fleetNexus.totalTrafficUsed > 0 ? `${bytes(fleetNexus.topTrafficHostUsed)} · 占 ${fleetNexus.topTrafficShare}%` : '本账期暂无消耗' }}</em>
                  </div>
                  <div class="fleet-resource">
                    <small>最近到期租期</small>
                    <b v-if="fleetNexus.nearestExpiryHost" :class="`nexus-expiry-${expiryTone(fleetNexus.nearestExpiryHost.expiresAt)}`" :title="`${fleetNexus.nearestExpiryHost.id === 'local' ? '中央本机' : fleetNexus.nearestExpiryHost.name} · ${fleetNexus.nearestExpiryHost.expiresAt}`">{{ fleetNexus.nearestExpiryDays! < 0 ? `已过期 ${-fleetNexus.nearestExpiryDays!} 天` : fleetNexus.nearestExpiryDays === 0 ? '今日到期' : `剩余 ${fleetNexus.nearestExpiryDays} 天` }}</b>
                    <b v-else>未登记租期</b>
                    <em v-if="fleetNexus.nearestExpiryHost" :title="`${fleetNexus.nearestExpiryHost.id === 'local' ? '中央本机' : fleetNexus.nearestExpiryHost.name} (${fleetNexus.nearestExpiryHost.expiresAt})`">{{ fleetNexus.nearestExpiryHost.id === 'local' ? '中央本机' : fleetNexus.nearestExpiryHost.name }} · {{ fleetNexus.nearestExpiryHost.expiresAt }}</em>
                    <em v-else>可在主机设置中登记</em>
                  </div>
                  <div class="fleet-resource">
                    <small>组件版本态势</small>
                    <b :class="{ 'nexus-version-ok': fleetNexus.updatableHostCount === 0, 'nexus-version-warn': fleetNexus.updatableHostCount > 0 }">{{ fleetNexus.updatableHostCount === 0 ? '全员最新' : `${fleetNexus.upToDateHostCount}/${fleetHosts.length} 台最新` }}</b>
                    <em>{{ fleetNexus.pendingUpdateItems > 0 ? `${fleetNexus.pendingUpdateItems} 项组件可在线升级` : 'Panel 与内核均最新' }}</em>
                  </div>
                </section>
              </div>
              <footer>
                <div class="fleet-host-version-meta">
                  <span class="fleet-host-version-text">全局订阅纳入 {{ fleetNexus.selectedHostCount }}/{{ fleetHosts.length }} 台主机 · {{ fleetNexus.selectedNodeCount }} 个节点</span>
                </div>
                <div class="fleet-footer-actions">
                  <div class="fleet-footer-buttons">
                    <button type="button" @click="navigateTo('settings')">主控设置</button>
                  </div>
                </div>
              </footer>
            </article>
            <article class="panel-card fleet-host-card fleet-companion-card fleet-companion-split-card fleet-companion-enroll-card" aria-label="接入新远端主机">
              <header>
                <div>
                  <span class="fleet-companion-seal jade-seal" aria-hidden="true">拓</span>
                  <span>
                    <span class="fleet-host-title">
                      <b>接入新远端主机</b>
                      <span class="fleet-companion-pill">10 分钟一次性令牌</span>
                    </span>
                    <small>HTTPS 双向鉴权 · 远端本机自治，中央停机不影响现有节点</small>
                  </span>
                </div>
                <aside class="fleet-header-aside">
                  <div class="fleet-header-rates">
                    <span class="fleet-rate-down">模式 <b>完整面板</b></span>
                    <span class="fleet-rate-up">或 <b>轻量探针</b></span>
                  </div>
                  <em>
                    <span class="fleet-node-summary">支持 2–10 台协同</span>
                    <span class="fleet-online-state">单次有效</span>
                  </em>
                </aside>
              </header>
              <div class="fleet-host-body fleet-split-body">
                <section class="fleet-host-network fleet-companion-enroll fleet-companion-enroll-split" aria-label="接入新远端主机">
                  <div class="fleet-network-group fleet-enroll-col">
                    <div class="fleet-network-region">
                      <strong>完整面板主机</strong>
                      <small>Panel · Nginx · sing-box</small>
                    </div>
                    <p class="fleet-enroll-col-desc">支持中央切换纳管、远程部署节点与全局订阅聚合。</p>
                    <button type="button" class="fleet-enroll-card-btn primary-accent" :disabled="busy" @click="createFleetEnrollment('panel')"><span>＋</span> 生成完整面板接入命令</button>
                  </div>
                  <div class="fleet-network-group fleet-enroll-col">
                    <div class="fleet-network-region">
                      <strong>轻量监控探针</strong>
                      <small>Probe Agent · 零侵入</small>
                    </div>
                    <p class="fleet-enroll-col-desc">仅采集系统负载、网络质量与已有节点，不改现有业务。</p>
                    <button type="button" class="fleet-enroll-card-btn" :disabled="busy" @click="createFleetEnrollment('probe')"><span>＋</span> 生成轻量探针接入命令</button>
                  </div>
                </section>
              </div>
              <footer>
                <div class="fleet-host-version-meta">
                  <span v-if="enrollmentCommand" class="fleet-host-version-text fleet-enroll-active-hint"><i class="enroll-ready-dot" aria-hidden="true"></i>已就绪：{{ enrollmentMode === 'probe' ? '轻量探针一次性接入命令' : '完整面板一次性接入命令' }}</span>
                  <span v-else class="fleet-host-version-text">点击上方按钮生成一次性安装脚本，在远端 VPS 以 root 执行</span>
                </div>
                <div class="fleet-footer-actions">
                  <div class="fleet-footer-buttons">
                    <button v-if="enrollmentCommand" type="button" class="enroll-copy-inline-btn" @click="copy(enrollmentCommand)">复制接入命令</button>
                    <button type="button" :disabled="busy" @click="createFleetEnrollment('panel')">＋ 面板令牌</button>
                    <button type="button" :disabled="busy" @click="createFleetEnrollment('probe')">＋ 探针令牌</button>
                  </div>
                </div>
              </footer>
            </article>
          </template>
        </section>
        <section v-if="fleetStatus?.archivedHosts?.length" class="panel-card fleet-archive"><header><div><span class="section-mark red">档</span><div><h3>已移除主机</h3><p>凭据已撤销；归档指标保留 30 天，远端节点不受影响</p></div></div></header><div><article v-for="host in fleetStatus.archivedHosts" :key="host.id"><span><b>{{ host.name }}</b><small>{{ host.hostname }} · 最后心跳 {{ host.lastSeenAt ? new Date(host.lastSeenAt).toLocaleString(language) : '从未连接' }}</small></span><button class="danger-button" @click="stageFleetHostAction('purge', host)">永久清除</button></article></div></section>
        <section class="panel-card fleet-subscription-scope"><header><div><span class="section-mark jade">订</span><div><h3>全局订阅范围</h3><p>默认纳入所有在线 active 节点；离线主机继续使用加密缓存</p></div></div><div class="fleet-scope-actions"><button type="button" class="secondary" :disabled="!fleetStatus?.globalSubscription" @click="copy(fleetStatus?.globalSubscription || '')">复制全局订阅</button><button class="primary" :disabled="!fleetSelectedHosts.length" @click="saveFleetSubscriptionSelection">保存范围</button></div></header><div class="fleet-scope-hosts"><article v-for="host in fleetHosts.filter(item => !isProbeHost(item) || (item.snapshot?.nodes || []).length > 0)" :key="`scope-${host.id}`"><label><input v-model="fleetSelectedHosts" type="checkbox" :value="host.id"><span><b>{{ host.name }}</b><small>{{ host.online ? '在线' : host.subscriptionCachedAt ? `离线 · 缓存 ${new Date(host.subscriptionCachedAt).toLocaleString(language)}` : isProbeHost(host) ? '离线 · 节点已就绪' : '离线 · 尚无缓存' }}</small></span></label><div v-if="fleetSelectedHosts.includes(host.id)"><label v-for="node in (host.snapshot?.nodes || []).filter(item => item.status === 'active')" :key="node.id"><input type="checkbox" :checked="(fleetSelectedNodes[host.id] || []).includes(node.id)" @change="toggleFleetNode(host.id, node.id, ($event.target as HTMLInputElement).checked)"><span>{{ node.name }}</span></label><small v-if="!(host.snapshot?.nodes || []).some(item => item.status === 'active')">暂无 active 节点</small></div></article></div></section>
        <section v-if="enrollmentCommand" id="fleet-enrollment" class="panel-card enrollment-card"><div class="enrollment-col enrollment-join"><div class="enrollment-col-head"><div class="enrollment-col-title"><span class="section-mark">令</span><div><h3>{{ enrollmentMode === 'probe' ? '轻量探针一次性接入命令' : '完整面板一次性接入命令' }}</h3><p>{{ new Date(enrollmentExpiresAt).toLocaleString(language) }} 过期 · 仅能成功使用一次</p></div></div><button type="button" @click="copy(enrollmentCommand)">复制命令</button></div><code>{{ enrollmentCommand }}</code><small>{{ enrollmentMode === 'probe' ? '在远端 VPS 以 root 执行；仅安装探针，不安装面板、Nginx 或 sing-box。探针只主动连接可信 HTTPS 主控。' : '在远端 VPS 以 root 执行；将安装完整面板、Nginx 与 sing-box，Agent 主动连接可信 HTTPS 主控。' }}</small></div><div class="enrollment-col enrollment-leave"><div class="enrollment-leave-head enrollment-col-head"><div class="enrollment-leave-title enrollment-col-title"><span class="section-mark red">撤</span><div><h4>{{ enrollmentMode === 'probe' ? '卸载轻量探针' : '取消中央接入' }}</h4><p>{{ enrollmentMode === 'probe' ? '停止服务并删除探针文件；中央记录需在舰队卡片中另行移除。' : '仅移除远端与中央主控的连接，不会卸载本机面板、数据库或节点。' }}</p></div></div><button type="button" class="secondary" @click="copy(fleetLeaveCommand)">复制卸载命令</button></div><code>{{ fleetLeaveCommand }}</code><small>在远端 VPS 以 root 执行；完成后 Agent 将停止向中央汇报。</small></div></section>
      </div>

      <div v-else-if="page === 'overview'" class="page-content overview-page">
        <section class="hero-grid">
          <article class="traffic-oracle panel-card">
            <div class="card-caption"><span>本账期流量</span><em>{{ overview?.billingStart }} — {{ overview?.billingEnd }}</em></div>
            <div class="quota-ring" :style="quotaRing"><div><small>已使用</small><strong>{{ trafficPercent.toFixed(1) }}<sup>%</sup></strong><span>{{ bytes(overview?.trafficUsed) }} / {{ overview?.trafficQuota ? bytes(overview?.trafficQuota) : '不限量' }}</span></div></div>
            <div class="oracle-meta"><span>距离重置 <b>{{ overview?.billingEnd || '—' }}</b></span><span>出口网卡 <b>{{ overview?.now.interface || '—' }}</b></span></div>
          </article>
          <div class="stat-column">
            <article class="metric-card">
              <div class="metric-row down"><span>↓</span><div><small>实时下载</small><strong>{{ rate(overview?.now.rxBps) }}</strong></div></div>
              <div class="metric-row up"><span>↑</span><div><small>实时上传</small><strong>{{ rate(overview?.now.txBps) }}</strong></div></div>
            </article>
            <article class="node-balance"><div><small>节点阵列</small><strong>{{ overview?.onlineNodes || 0 }}<span>/{{ overview?.nodeCount || 0 }}</span></strong></div><div class="node-dots"><i v-for="node in nodes" :key="node.id" :class="node.status"></i></div><p>{{ overview?.onlineNodes === overview?.nodeCount ? '阵列稳定，诸节点皆在位' : '存在离线节点，请检查任务日志' }}</p></article>
            <article class="panel-card overview-slot network-card">
              <div class="network-card-head"><span>网络延迟</span><small>{{ networkHealth?.demo ? 'DEMO · ' : '' }}ICMP</small></div>
              <div class="network-card-values"><div v-for="group in networkGroups" :key="group" class="network-card-metric" :title="networkGroup(group)?.error || networkGroup(group)?.targets?.join(' / ') || networkHistoryLabel(group)"><small>{{ networkGroupLabel(group) }}</small><div class="network-card-value" :class="networkLatencyTone(group)"><strong>{{ networkLatency(group) }}</strong><em v-if="networkReadable(group) && !!networkGroup(group)?.packetsReceived">ms</em></div></div></div>
              <div class="network-card-history"><div class="network-history-head"><span>{{ language === 'en-US' ? 'Last 30 minutes' : '近 30 分钟' }}</span></div><div v-for="group in networkGroups" :key="group" class="network-history-row"><span class="network-history-label">{{ networkGroupLabel(group) }}</span><NetworkHistoryBars :samples="networkHistorySlots(group)" metric="latency" :group-label="networkGroupLabel(group)" :language="language" :history-label="`${networkGroupLabel(group)}${language === 'en-US' ? ' latency history for the last 30 minutes' : '近 30 分钟延迟历史'}`" /><small :title="networkHistoryLabel(group)">{{ networkHistoryCount(group) }}/30</small></div></div>
            </article>
            <article class="panel-card overview-slot network-card">
              <div class="network-card-head"><span>近 30 分钟总丢包率</span><small>{{ networkHealth?.demo ? 'DEMO · ' : '' }}ICMP</small></div>
              <div class="network-card-values"><div v-for="group in networkGroups" :key="group" class="network-card-metric" :title="networkGroup(group)?.error || networkGroup(group)?.targets?.join(' / ') || networkHistoryLabel(group)"><small>{{ networkGroupLabel(group) }}</small><div class="network-card-value" :class="networkLossTone(group)"><strong>{{ networkLoss(group) }}</strong><em v-if="networkLoss(group) !== '—'">%</em></div></div></div>
              <div class="network-card-history"><div class="network-history-head"><span>{{ language === 'en-US' ? 'Last 30 minutes' : '近 30 分钟' }}</span></div><div v-for="group in networkGroups" :key="group" class="network-history-row"><span class="network-history-label">{{ networkGroupLabel(group) }}</span><NetworkHistoryBars :samples="networkHistorySlots(group)" metric="loss" :group-label="networkGroupLabel(group)" :language="language" :history-label="`${networkGroupLabel(group)}${language === 'en-US' ? ' packet loss history for the last 30 minutes' : '近 30 分钟丢包历史'}`" /><small :title="networkHistoryLabel(group)">{{ networkHistoryCount(group) }}/30</small></div></div>
            </article>
          </div>
        </section>

        <section class="panel-card trend-card">
          <div class="card-head flow-head"><div><span class="section-mark">流</span><div><h3>流量脉络</h3><p>最近 80 个采样点 · 每 10 秒刷新</p></div></div><div v-if="activeDevices.length" class="device-rack" aria-label="当前活跃设备"><span v-for="device in visibleDevices" :key="device.nodeId" class="device-chip" :title="`${device.nodeName} · 节点最近窗口下行 ${rate(device.rateBps)}`"><i></i><b>{{ device.nodeName }}</b><em>{{ rate(device.rateBps) }}</em></span><span v-if="hiddenDeviceCount" class="device-overflow" :title="`另有 ${hiddenDeviceCount} 个活跃设备`">+{{ hiddenDeviceCount }}</span></div><div v-else class="device-silent"><i></i>设备静默</div></div>
          <div class="flow-metrics"><span class="flow-rx"><small>下载</small><b>{{ rate(overview?.now.rxBps) }}</b></span><span class="flow-tx"><small>上传</small><b>{{ rate(overview?.now.txBps) }}</b></span><em>设备速率来自 UDP/TCP 节点采集器最近完成窗口</em></div>
          <div class="chart-wrap"><div class="chart-plot"><svg viewBox="0 0 1000 150" preserveAspectRatio="none" aria-label="实时下载与上传趋势"><defs><linearGradient id="jadeArea" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#52b690" stop-opacity=".28"/><stop offset="1" stop-color="#52b690" stop-opacity="0"/></linearGradient></defs><path :d="rxAreaPath" fill="url(#jadeArea)"/><path :d="rxChartPath" class="chart-line rx-line"/><path :d="txChartPath" class="chart-line tx-line"/></svg><div class="chart-grid"></div></div><div class="chart-axis" aria-label="流量速率刻度"><span>{{ axisRate(chartPeak) }}</span><span>{{ axisRate(chartPeak / 2) }}</span><span>0 B/s</span></div></div>
        </section>

        <section class="overview-lower">
          <article class="panel-card node-preview"><div class="card-head"><div><span class="section-mark red">阵</span><div><h3>节点兵器谱</h3><p>按服务状态实时排列</p></div></div><button class="text-button" @click="navigateTo('nodes')">查看全部 →</button></div><div class="compact-nodes"><div v-for="node in nodes.slice(0, 4)" :key="node.id"><i :class="node.status"></i><span><b>{{ node.name }}</b><small>{{ protocolInfo(node.protocol).badge }} · {{ nodePublicPort(node) }}/{{ protocolInfo(node.protocol).transport }}</small></span><em>{{ node.status === 'active' ? t('online') : t('offline') }}</em></div><p v-if="!nodes.length" class="empty">尚无节点，点击右上角部署第一座节点。</p></div></article>
          <article class="panel-card system-glance"><div class="card-head"><div><span class="section-mark jade">脉</span><div><h3>主机气脉</h3><p>资源水位</p></div></div><span class="uptime">运行 {{ uptime(overview?.now.uptime) }}</span></div><div class="resource-row"><span>CPU</span><div><i :style="{ width: `${overview?.now.cpu || 0}%` }"></i></div><b>{{ overview?.now.cpu.toFixed(1) || 0 }}%</b></div><div class="resource-row"><span>内存</span><div><i :style="{ width: `${overview?.now.memory || 0}%` }"></i></div><b>{{ overview?.now.memory.toFixed(1) || 0 }}%</b></div><div class="resource-row"><span>磁盘</span><div><i :style="{ width: `${overview?.now.disk || 0}%` }"></i></div><b>{{ overview?.now.disk.toFixed(1) || 0 }}%</b></div><div class="version-strip"><div class="fleet-host-version-meta"><span class="fleet-host-version-text">Panel {{ overview?.panelVersion || '—' }}</span><button v-if="currentFleetHost && hasHostUpdate(currentFleetHost)" type="button" class="fleet-update-pill" :title="`发现新版本 v${latestReleaseVersion}，点击更新`" @click.stop="openHostUpdateModal(currentFleetHost)"><i class="fleet-update-icon" aria-hidden="true">⬆</i><span><span class="fleet-update-lead">可</span>更新 v{{ latestReleaseVersion }}</span></button><span class="fleet-version-dot">·</span><span class="fleet-host-version-text">sing-box {{ overview?.singBoxVersion || '—' }}</span><button v-if="currentFleetHost && hasSingBoxUpdate(currentFleetHost)" type="button" class="fleet-update-pill singbox-update-pill" :title="`发现新版本 ${latestSingBoxVersion}，点击更新`" @click.stop="openSingBoxUpdateModal(currentFleetHost)"><i class="fleet-update-icon" aria-hidden="true">⬆</i><span><span class="fleet-update-lead">可</span>更新 {{ latestSingBoxVersion }}</span></button></div></div></article>
        </section>
      </div>

      <div v-else-if="page === 'nodes'" class="page-content">
        <div class="page-intro">
          <div><p>NODE ARSENAL</p><h2>管理所有代理入站</h2><small class="page-caption">“检测”执行本机完整代理闭环；公网防火墙与 NAT 可达性仍需异地验证。</small></div>
          <div class="summary-pills">
            <span><i class="active"></i>{{ overview?.onlineNodes || 0 }} 在线</span>
            <span>{{ nodes.filter(n => n.ownership === 'imported').length }} 已接管</span>
          </div>
        </div>
        <section class="node-grid">
          <article v-for="node in nodes" :key="node.id" class="node-card" :class="[node.status, { tunnel: node.protocol === 'vless-ws-tunnel', preferred: !!node.preferredServer }]">
            <div class="node-top">
              <div class="node-top-left">
                <span class="protocol-badge">{{ protocolInfo(node.protocol).badge }}</span>
                <span
                  v-if="node.status === 'active'"
                  class="node-rate-badge"
                  :class="{ active: nodeRate(node.id) > 0 }"
                  :title="nodeRate(node.id) > 0 ? (language === 'en-US' ? `Real-time rate: ${rate(nodeRate(node.id))}` : `当前窗口下行速率: ${rate(nodeRate(node.id))}`) : (language === 'en-US' ? 'Idle: No active traffic' : '当前节点无实时流量')"
                >
                  <i class="rate-dot"></i>
                  <span class="rate-val">{{ nodeRate(node.id) > 0 ? rate(nodeRate(node.id)) : '0 B/s' }}</span>
                </span>
              </div>
              <div class="node-state"><i></i>{{ node.status === 'active' ? (language === 'en-US' ? 'Running' : '运行中') : node.status === 'inactive' ? (language === 'en-US' ? 'Stopped' : '已停止') : (language === 'en-US' ? 'Unknown' : '未知') }}</div>
            </div>
            <div class="node-title-row"><h3>{{ node.name }}</h3><button v-if="node.ownership === 'managed'" type="button" title="重新编辑节点" :aria-label="`重新编辑节点 ${node.name}`" :disabled="mutationsDisabled" @click="openEdit(node)">编辑</button></div>
            <div class="endpoint-row">
              <p class="endpoint">{{ nodeDialServer(node) || '未设置出口域名' }}<b>:{{ nodePublicPort(node) }}</b><small> / {{ protocolInfo(node.protocol).transport }}</small></p>
              <span
                class="node-fw-badge"
                :class="nodeFirewallStatus(node).class"
                :title="nodeFirewallStatus(node).title"
                :role="nodeFirewallStatus(node).clickable ? 'button' : undefined"
                :tabindex="nodeFirewallStatus(node).clickable ? 0 : undefined"
                @click="nodeFirewallStatus(node).clickable ? navigateTo('security') : null"
              >
                <i class="fw-dot"></i>
                <span>{{ nodeFirewallStatus(node).label }}</span>
              </span>
            </div>
            <div v-if="node.protocol === 'vless-ws-tunnel'" class="tunnel-route-box">
              <div v-if="node.preferredServer" class="tunnel-route-row">
                <div class="route-item"><small>{{ language === 'en-US' ? 'Preferred' : '优选' }}</small><code :title="node.preferredServer">{{ node.preferredServer }}</code></div>
                <span class="route-arrow" aria-hidden="true">→</span>
                <div class="route-item"><small>SNI</small><code :title="node.server">{{ node.server }}</code></div>
              </div>
              <div class="tunnel-origin-row">
                <div class="origin-item"><small>{{ language === 'en-US' ? 'Origin' : 'CF 回源' }}</small><code :title="tunnelOrigin(node)">{{ tunnelOrigin(node) }}</code></div>
                <button type="button" class="tunnel-copy-btn" :title="language === 'en-US' ? 'Copy Cloudflare Service URL' : '复制 Cloudflare Service URL'" @click="copy(tunnelOrigin(node))">{{ language === 'en-US' ? 'Copy' : '复制' }}</button>
              </div>
            </div>
            <div class="node-specs">
              <span><small>{{ language === 'en-US' ? 'Outbound' : '出站策略' }}</small><b>{{ outboundLabel(node) }}</b></span>
              <span :title="nodeTrafficTooltip(node)"><small>{{ language === 'en-US' ? 'Cumulative' : '累计流量' }}</small><b>{{ bytes(node.trafficBytes || 0) }}</b></span>
              <span :title="language === 'en-US' ? `Service: ${node.serviceManager} · Core: sing-box ${overview?.singBoxVersion || node.configVersion || '—'}` : `服务管理: ${node.serviceManager} · 核心版本: sing-box ${overview?.singBoxVersion || node.configVersion || '—'}`"><small>{{ language === 'en-US' ? 'Ownership' : '管理归属' }}</small><b>{{ node.ownership === 'imported' ? (language === 'en-US' ? 'Imported' : '外部接管') : (language === 'en-US' ? 'Managed' : '原生托管') }}</b></span>
            </div>
            <p v-if="node.sharedGroup" class="shared-note">⌁ {{ node.ownership === 'managed' ? (node.protocol === 'vless-ws-tunnel' ? '设备编队 · 独立入站，共享 sing-box 与 Tunnel 连接器' : '设备编队 · 独立入站，共享一个 sing-box 进程') : '与同配置内其他端点共享生命周期' }}</p>
            <div
              class="probe-strip clickable"
              :class="probeState(node)"
              :title="`${probeDetail(node)}（点击查看详细闭环诊断）`"
              role="button"
              tabindex="0"
              aria-label="查看闭环诊断详情"
              @click="openDiagnostic(node)"
              @keydown.enter.prevent="openDiagnostic(node)"
              @keydown.space.prevent="openDiagnostic(node)"
            >
              <i></i>
              <span>
                <b>{{ probeState(node) === 'running' ? '闭环检测中' : probeState(node) === 'success' ? '闭环正常' : probeState(node) === 'failed' ? '检测失败' : '尚未检测' }}</b>
                <small>{{ probeDetail(node) }}</small>
              </span>
              <em class="probe-diag-hint" aria-hidden="true">诊断 ↗</em>
            </div>
            <div class="node-actions"><button :disabled="mutationsDisabled" @click="revealShare(node)">分享</button><button class="probe-button" :disabled="mutationsDisabled || node.status !== 'active' || probeState(node) === 'running'" :title="node.status !== 'active' ? '请先启动节点' : node.protocol === 'vless-ws-tunnel' ? '验证 Cloudflare TLS、WebSocket、认证和代理出站' : '验证握手、认证和代理出站'" @click="probeNode(node)">{{ probeState(node) === 'running' ? '检测中' : '检测' }}</button><button :disabled="mutationsDisabled" @click="nodeAction(node, 'check')">校验</button><button v-if="node.status === 'active'" :disabled="mutationsDisabled" @click="nodeAction(node, 'restart')">重启</button><button v-else :disabled="mutationsDisabled" @click="nodeAction(node, 'start')">启动</button><button class="danger" :disabled="mutationsDisabled" @click="nodeAction(node, 'delete')">删除</button></div>
          </article>
          <button class="add-node-card" :disabled="mutationsDisabled" @click="openCreate"><span>＋</span><b>部署新节点</b><small>七协议 · 自动生成安全凭据</small></button>
        </section>
      </div>

      <div v-else-if="page === 'traffic'" class="page-content">
        <div class="page-intro"><div><p>TRAFFIC OBSERVATORY</p><h2>整机流量与账期观测</h2></div><span class="live-badge"><i></i>10 秒实时刷新</span></div>
        <section class="traffic-stat-grid"><article><small>下载速率</small><strong>{{ rate(overview?.now.rxBps) }}</strong><span>当前出口</span></article><article><small>上传速率</small><strong>{{ rate(overview?.now.txBps) }}</strong><span>当前出口</span></article><article><small>本账期使用</small><strong>{{ bytes(overview?.trafficUsed) }}</strong><span>{{ trafficPercent.toFixed(1) }}% 配额</span></article><article><small>账期重置</small><strong>{{ overview?.billingEnd || '—' }}</strong><span>{{ settings.timezone }}</span></article></section>
        <section class="panel-card timeline-card">
          <div class="timeline-head"><div class="timeline-title"><span class="section-mark">时</span><div><h3>流量时间轴</h3><p>{{ timelineRange === 'today' ? `今日 00:00 — 24:00 · ${timeline?.timezone || settings.timezone}` : `${timeline?.billingStart} — ${timeline?.billingEnd} · 本账期逐日` }}</p></div></div><div class="timeline-switch" role="tablist" aria-label="时间轴范围"><button :class="{ active: timelineRange === 'today' }" role="tab" :aria-selected="timelineRange === 'today'" @click="setTimelineRange('today')"><b>今日</b><small>{{ bytes((timeline?.todayRx || 0) + (timeline?.todayTx || 0)) }}</small></button><button :class="{ active: timelineRange === 'billing' }" role="tab" :aria-selected="timelineRange === 'billing'" @click="setTimelineRange('billing')"><b>本账期</b><small>{{ bytes((timeline?.billingRx || 0) + (timeline?.billingTx || 0)) }}</small></button></div></div>
          <div class="timeline-summary"><span class="rx"><i></i><small>下载</small><b>{{ bytes(timelineTotals.rx) }}</b></span><span class="tx"><i></i><small>上传</small><b>{{ bytes(timelineTotals.tx) }}</b></span><span class="total"><small>合计</small><b>{{ bytes(timelineTotals.rx + timelineTotals.tx) }}</b></span></div>
          <div class="timeline-viewport" @mouseleave="clearTimelineBucket()">
            <div class="timeline-plot" :class="timelineRange">
              <div class="timeline-grid"><i></i><i></i><i></i></div>
              <div class="timeline-y"><span>{{ bytes(timelineMax) }}</span><span>{{ bytes(timelineMax / 2) }}</span><span>0 B</span></div>
              <div v-if="timelineAverage" class="average-line" :style="{ bottom: `${timelineAverage / timelineMax * 100}%` }"><span>Avg {{ bytes(timelineAverage) }}</span></div>
              <div class="timeline-bars" :style="{ gridTemplateColumns: `repeat(${Math.max(1, timelineBuckets.length)}, minmax(10px, 1fr))` }">
                <button v-for="(item,index) in timelineBuckets" :key="item.startedAt" class="timeline-bar" :class="{ selected: index === activeTimelineBucket }" :aria-label="`${timelineLabel(item)}，下载 ${bytes(item.rxBytes)}，上传 ${bytes(item.txBytes)}`" @mouseenter="showTimelineBucket(index)" @focus="showTimelineBucket(index)" @blur="clearTimelineBucket(index)" @click="showTimelineBucket(index)">
                  <span class="bar-stack" :style="{ height: `${bucketHeight(item)}%` }"><i class="bar-rx" :style="{ height: `${bucketSegment(item.rxBytes, item)}%` }"></i><i class="bar-tx" :style="{ height: `${bucketSegment(item.txBytes, item)}%` }"></i></span>
                  <em v-if="timelineRange === 'today' ? index % 6 === 0 : index % 5 === 0">{{ timelineRange === 'billing' ? item.label.slice(3) : item.label }}</em>
                </button>
              </div>
              <div v-if="selectedTimelineBucket" class="timeline-tooltip" :style="{ left: timelineTooltipLeft }"><strong>{{ timelineLabel(selectedTimelineBucket) }} <small>{{ timeline?.timezone }}</small></strong><span><i class="rx"></i>下载 <b>{{ bytes(selectedTimelineBucket.rxBytes) }}</b></span><span><i class="tx"></i>上传 <b>{{ bytes(selectedTimelineBucket.txBytes) }}</b></span><em>总计 <b>{{ bytes(selectedTimelineBucket.rxBytes + selectedTimelineBucket.txBytes) }}</b></em></div>
            </div>
          </div>
        </section>
        <section class="endpoint-section panel-card"><div class="card-head"><div><span class="section-mark red">端</span><div><h3>近 24 小时客户端端点</h3><p>仅展示脱敏地址 · 按下行包长度聚合</p></div></div></div><div class="endpoint-list"><div v-for="(item,index) in endpoints" :key="`${item.nodeId}-${item.endpoint}`"><b>{{ String(index + 1).padStart(2, '0') }}</b><span><strong>{{ item.nodeName }}</strong><small>{{ item.endpoint }}</small></span><em>{{ bytes(item.bytes) }}</em></div><p v-if="!endpoints.length" class="empty">等待端点采样；未安装 tcpdump 时整机流量仍正常统计。</p></div></section>
        <div class="privacy-banner"><span>隐</span><div><b>端点隐私策略</b><p>客户端 IP 默认脱敏；原始端点保留 24 小时，设备聚合保留 90 天。</p></div><label class="switch"><input v-model="settings.collectEndpoints" type="checkbox" :disabled="mutationsDisabled" @change="saveSettings"><i></i></label></div>
      </div>

      <SecurityPanel v-else-if="page === 'security'" :key="selectedHostId" :host-id="selectedHostId" :host-name="currentFleetHost?.name || '本机'" :online="!remoteHost || !!currentFleetHost?.online" :compatible="!remoteHost || !!currentFleetHost?.compatible" :capabilities="currentFleetHost?.capabilities || []" :language="language" />
      <div v-else-if="page === 'system'" class="page-content">
        <div class="page-intro"><div><p>HOST VITALS</p><h2>主机资源与运行态势</h2></div><span class="live-badge"><i></i>Agent 正常</span></div>
        <section class="vital-grid"><article v-for="item in vitalItems" :key="item.name"><div class="vital-dial" :style="{ '--vital': `${item.value * 3.6}deg` }"><b>{{ item.value.toFixed(1) }}<small>%</small></b></div><h3>{{ item.name }}</h3><p>{{ item.meta }}</p><strong v-if="item.usage" class="vital-usage">{{ item.usage }}</strong></article></section>
        <section class="panel-card host-table"><div class="card-head"><div><span class="section-mark jade">机</span><div><h3>系统信息</h3><p>不展示进程完整命令行</p></div></div></div><dl><div><dt>操作系统</dt><dd>{{ currentFleetHost?.os || '—' }}</dd></div><div><dt>架构</dt><dd>{{ currentFleetHost?.arch || '—' }}</dd></div><div><dt>出口网卡</dt><dd>{{ overview?.now.interface || '—' }}</dd></div><div><dt>运行时间</dt><dd>{{ uptime(overview?.now.uptime) }}</dd></div><div><dt>sing-box</dt><dd>{{ overview?.singBoxVersion }}</dd></div><div><dt>悟空面板</dt><dd>{{ overview?.panelVersion }}</dd></div><div><dt>服务模式</dt><dd>Web / Root Agent 分权</dd></div><div><dt>指标保留</dt><dd>90 天</dd></div></dl></section>
        <section class="component-update-grid" :aria-label="language === 'en-US' ? 'Runtime updates' : '组件更新'">
          <ComponentUpdatePanel v-for="component in (['sing-box', 'cloudflared'] as const)" :key="`${selectedHostId}:${component}`" :component="component" :host-id="selectedHostId" :online="!remoteHost || !!currentFleetHost?.online" :compatible="!remoteHost || !!currentFleetHost?.compatible" :capabilities="currentFleetHost?.capabilities || []" :language="language" />
        </section>
        <section class="panel-card residential-panel egress-hub-panel">
          <div class="card-head">
            <div>
              <span class="section-mark jade">出</span>
              <div>
                <h3>出站分流与落地出口</h3>
                <p>为节点提供 B 机 WireGuard 落地 IP 或上游 SOCKS 代理分流 · 断线严格阻断不回退直连</p>
              </div>
            </div>
            <div class="egress-head-badges">
              <span class="live-badge" :class="{ muted: !residentialExit?.active }"><i></i>WG · {{ residentialExit?.active ? '隧道在线' : residentialExit?.configured ? '等待握手' : '未配置' }}</span>
              <span class="live-badge" :class="{ muted: !socksExit?.configured }"><i></i>SOCKS · {{ socksExit?.configured ? '预检通过' : '未配置' }}</span>
            </div>
          </div>
          <div class="egress-channel-tabs" role="tablist" aria-label="出站通道选择">
            <button type="button" role="tab" class="egress-channel-card" :class="{ active: activeEgressTab === 'residential' }" :aria-selected="activeEgressTab === 'residential'" @click="activeEgressTab = 'residential'">
              <div class="egress-channel-top">
                <div class="egress-channel-title">
                  <span class="egress-channel-icon jade">落</span>
                  <div>
                    <b>落地 IP 出口</b>
                    <span class="egress-proto-tag">WireGuard · NAT</span>
                  </div>
                </div>
                <span class="egress-state-pill" :class="residentialExit?.active ? 'is-online' : residentialExit?.configured ? 'is-pending' : 'is-idle'">{{ residentialExit?.active ? '隧道在线' : residentialExit?.configured ? '等待 B 机握手' : '未配置' }}</span>
              </div>
              <div class="egress-channel-meta">
                <span>{{ residentialExit?.configured ? `${residentialExit.endpoint}:${residentialExit.listenPort} · ${residentialExit.peerAddress || '10.77.0.2'}` : 'A 机接入 · WireGuard 到 B 机 NAT · 断线拒绝回退' }}</span>
                <em v-if="residentialNodesInUse.length" class="egress-node-count">{{ residentialNodesInUse.length }} 个节点使用中</em>
              </div>
            </button>
            <button type="button" role="tab" class="egress-channel-card" :class="{ active: activeEgressTab === 'socks' }" :aria-selected="activeEgressTab === 'socks'" @click="activeEgressTab = 'socks'">
              <div class="egress-channel-top">
                <div class="egress-channel-title">
                  <span class="egress-channel-icon">袜</span>
                  <div>
                    <b>自定义 SOCKS 出站</b>
                    <span class="egress-proto-tag">SOCKS{{ socksExit?.configured ? socksExit.version : socksForm.version }}</span>
                  </div>
                </div>
                <span class="egress-state-pill" :class="socksExit?.configured ? 'is-online' : 'is-idle'">{{ socksExit?.configured ? '预检通过' : '未配置' }}</span>
              </div>
              <div class="egress-channel-meta">
                <span>{{ socksExit?.configured ? `${socksExit.server}:${socksExit.port} · 出口 ${socksExit.probeExitIp || '已连通'}${socksExit.probeLatencyMs !== undefined ? ` (${socksExit.probeLatencyMs} ms)` : ''}` : '节点流量经上游 SOCKS 代理 · 密码加密保存 · 失败不回退直连' }}</span>
                <em v-if="socksNodesInUse.length" class="egress-node-count">{{ socksNodesInUse.length }} 个节点使用中</em>
              </div>
            </button>
          </div>
          <div v-if="activeEgressTab === 'residential'" class="egress-tab-body" role="tabpanel">
            <div v-if="residentialExit?.configured || residentialNodesInUse.length" class="egress-telemetry-strip">
              <div class="egress-telemetry-item">
                <small>隧道网卡与内网</small>
                <b><code>{{ residentialExit?.interface || 'wg-exit0' }}</code> · {{ residentialExit?.tunnelAddress || '10.77.0.1' }} → {{ residentialExit?.peerAddress || '10.77.0.2' }}</b>
              </div>
              <div class="egress-telemetry-item">
                <small>最近握手时间</small>
                <b>{{ residentialExit?.latestHandshake ? new Date(residentialExit.latestHandshake).toLocaleString(language) : '等待 B 机握手' }}</b>
              </div>
              <div class="egress-telemetry-item">
                <small>隧道累计流量</small>
                <b>↓ {{ bytes(residentialExit?.rxBytes) }} · ↑ {{ bytes(residentialExit?.txBytes) }}</b>
              </div>
              <div class="egress-telemetry-item">
                <small>当前引用节点</small>
                <div v-if="residentialNodesInUse.length" class="egress-bound-nodes">
                  <span v-for="n in residentialNodesInUse" :key="n.id" class="egress-node-chip">{{ n.name }}</span>
                </div>
                <b v-else class="egress-muted">暂未绑定节点</b>
              </div>
            </div>
            <div class="residential-grid">
              <label>
                <span class="egress-field-head"><span>A 机公网 IP / 域名</span><small class="egress-step-tag">步骤 1 · 必填</small></span>
                <input v-model="residentialForm.endpoint" placeholder="a.example.com">
              </label>
              <label>
                <span class="egress-field-head"><span>WireGuard UDP 端口</span><small class="egress-step-tag">步骤 1</small></span>
                <input v-model.number="residentialForm.listenPort" type="number" min="1" max="65535">
              </label>
              <label>
                <span class="egress-field-head"><span>B 机公钥</span><small class="egress-step-tag">步骤 2 · 脚本输出</small></span>
                <input v-model="residentialForm.peerPublicKey" placeholder="先留空生成 B 机脚本">
              </label>
              <label>
                <span class="egress-field-head"><span>预期落地 IPv4（可选）</span><small class="egress-step-hint">人工核对</small></span>
                <input v-model="residentialForm.expectedExitIp" placeholder="用于人工核对出口">
              </label>
            </div>
            <div v-if="residentialExit?.installScript" class="residential-script">
              <div><b>B 机一键安装命令</b><button type="button" class="secondary" @click="copy(residentialExit?.installScript || '')">复制脚本</button></div>
              <textarea :value="residentialExit.installScript" readonly spellcheck="false" wrap="off"></textarea>
              <p>在 B 机以 root 运行后，只把输出的 <code>B_PUBLIC_KEY</code> 粘贴到上方“B 机公钥”并保存。A/B 私钥只在各自本机生成，面板不会接收。</p>
            </div>
            <div class="egress-footer-bar">
              <p class="help-text">选用落地出口的节点被强制为 IPv4，并通过 fwmark {{ 102 }} 进入独立路由表；隧道中断时策略表保留 unreachable 默认路由，不会泄漏到 A 机公网。</p>
              <div class="egress-footer-actions">
                <button v-if="residentialExit?.configured" type="button" class="danger-button" :disabled="mutationsDisabled || residentialBusy" @click="stageResidentialExitRemoval">移除落地出口</button>
                <button type="button" class="primary" :disabled="mutationsDisabled || residentialBusy || !residentialForm.endpoint" @click="configureResidentialExit">{{ residentialBusy ? '处理中…' : residentialForm.peerPublicKey ? '保存并启动隧道' : '生成 B 机安装脚本' }}</button>
              </div>
            </div>
          </div>
          <div v-else class="egress-tab-body" role="tabpanel">
            <div v-if="socksExit?.configured || socksNodesInUse.length" class="egress-telemetry-strip">
              <div class="egress-telemetry-item">
                <small>实测出口 IP</small>
                <b><code>{{ socksExit?.probeExitIp || '已连通' }}</code></b>
              </div>
              <div class="egress-telemetry-item">
                <small>预检闭环延迟</small>
                <b>{{ socksExit?.probeLatencyMs !== undefined ? `${socksExit.probeLatencyMs} ms` : '—' }}</b>
              </div>
              <div class="egress-telemetry-item">
                <small>最近预检时间</small>
                <b>{{ socksExit?.probeCheckedAt ? new Date(socksExit.probeCheckedAt).toLocaleString(language) : '—' }}</b>
              </div>
              <div class="egress-telemetry-item">
                <small>当前引用节点</small>
                <div v-if="socksNodesInUse.length" class="egress-bound-nodes">
                  <span v-for="n in socksNodesInUse" :key="n.id" class="egress-node-chip">{{ n.name }}</span>
                </div>
                <b v-else class="egress-muted">暂未绑定节点</b>
              </div>
            </div>
            <div v-if="socksNodesInUse.length" class="egress-inuse-banner">
              <b>配置正被节点引用锁定：</b>
              <span>当前节点（{{ socksNodesInUse.map(node => node.name).join('、') }}）正在使用此 SOCKS 出站；为避免业务中断，修改或移除前请先将引用节点切回其他出口。</span>
            </div>
            <div class="socks-grid">
              <label>
                <span class="egress-field-head"><span>SOCKS 服务器</span><small class="egress-step-tag">必填</small></span>
                <input v-model="socksForm.server" placeholder="proxy.example.com">
              </label>
              <label>
                <span class="egress-field-head"><span>端口</span><small class="egress-step-hint">1–65535</small></span>
                <input v-model.number="socksForm.port" type="number" min="1" max="65535">
              </label>
              <label>
                <span class="egress-field-head"><span>版本</span></span>
                <select v-model="socksForm.version"><option value="5">SOCKS5</option><option value="4a">SOCKS4a</option><option value="4">SOCKS4</option></select>
              </label>
              <label>
                <span class="egress-field-head"><span>承载网络</span><small v-if="socksForm.version !== '5'" class="egress-step-hint">仅支持 TCP</small></span>
                <select v-model="socksForm.network" :disabled="socksForm.version !== '5'"><option value="both">TCP + UDP</option><option value="tcp">仅 TCP</option></select>
              </label>
            </div>
            <div class="socks-auth-grid" :class="{ 'is-v4': socksForm.version !== '5' }">
              <label>
                <span class="egress-field-head"><span>用户名（可选）</span><small class="egress-step-hint">认证账户</small></span>
                <input v-model="socksForm.username" autocomplete="off" placeholder="无认证可留空">
              </label>
              <label v-if="socksForm.version === '5'">
                <span class="egress-field-head">
                  <span>密码（可选）</span>
                  <button v-if="socksExit?.hasPassword" type="button" class="egress-clear-pwd-chip" :class="{ active: socksForm.clearPassword }" @click="socksForm.clearPassword = !socksForm.clearPassword">{{ socksForm.clearPassword ? '✓ 保存后清除已存密码' : '清除已保存密码' }}</button>
                  <small v-else class="egress-step-hint">加密保存</small>
                </span>
                <input v-model="socksForm.password" type="password" autocomplete="new-password" :disabled="socksForm.clearPassword" :placeholder="socksForm.clearPassword ? '保存后将改为无密码认证' : socksExit?.hasPassword ? '已保存；留空保持不变' : '无认证可留空'">
              </label>
              <label>
                <span class="egress-field-head"><span>预期出口 IP（可选）</span><small class="egress-step-hint">代理核对</small></span>
                <input v-model="socksForm.expectedExitIp" placeholder="用于真实代理核对">
              </label>
            </div>
            <div class="egress-footer-bar">
              <p class="help-text">保存前会通过上游 SOCKS 完成真实 HTTPS 闭环。配置正被节点使用时禁止修改或删除；SOCKS4/4a 只承载 TCP，SOCKS5 的 UDP 流量要求上游支持 UDP ASSOCIATE。</p>
              <div class="egress-footer-actions">
                <button v-if="socksExit?.configured" type="button" class="danger-button" :disabled="mutationsDisabled || socksBusy" @click="stageSOCKSExitRemoval">移除 SOCKS 出站</button>
                <button type="button" class="primary" :disabled="mutationsDisabled || socksBusy || !socksForm.server" @click="configureSOCKSExit">{{ socksBusy ? '正在真实代理预检…' : socksExit?.configured ? '重新预检并保存' : '预检并保存' }}</button>
              </div>
            </div>
          </div>
        </section>
        <section class="panel-card process-panel"><div class="card-head"><div><span class="section-mark">程</span><div><h3>进程</h3><p>按 CPU 与内存排序 · 不采集完整命令行</p></div></div><span class="process-count">{{ overview?.processCount || 0 }} 个</span></div><div class="process-table"><div class="process-row process-header"><span>PID</span><span>进程</span><span role="columnheader" :aria-sort="processSortKey === 'cpu' ? (processSortAscending ? 'ascending' : 'descending') : 'none'"><button type="button" class="process-sort" :class="{active:processSortKey === 'cpu'}" :aria-label="translateText('按 CPU 排序', language)" @click="changeProcessSort('cpu')">CPU {{processSortKey === 'cpu' ? (processSortAscending ? '↑' : '↓') : '↕'}}</button></span><span role="columnheader" :aria-sort="processSortKey === 'memory' ? (processSortAscending ? 'ascending' : 'descending') : 'none'"><button type="button" class="process-sort" :class="{active:processSortKey === 'memory'}" :aria-label="translateText('按内存排序', language)" @click="changeProcessSort('memory')">{{translateText('内存',language)}} {{processSortKey === 'memory' ? (processSortAscending ? '↑' : '↓') : '↕'}}</button></span></div><div class="process-scroll"><div v-for="process in sortedProcesses" :key="process.pid" class="process-row"><code>{{ process.pid }}</code><b :title="[process.name, processServiceLabel(process.service, process.name), ...(process.nodes || [])].filter(Boolean).join(' · ')"><span>{{ process.name }}</span><small v-if="processServiceLabel(process.service, process.name)">{{ process.service === 'cloudflared' ? [processServiceLabel(process.service, process.name), ...(process.nodes || [])].filter(Boolean).join(' · ') : processServiceLabel(process.service, process.name) }}</small><small v-if="process.nodes?.length && process.service !== 'cloudflared'">{{ process.nodes.join(' · ') }}</small></b><strong>{{ process.cpu.toFixed(1) }}%</strong><span class="process-memory"><em>{{ bytes(process.rssBytes) }}</em><small>{{ process.memoryPercent.toFixed(1) }}%</small></span></div><p v-if="!overview?.processes?.length" class="empty">等待 Agent 完成进程采样。</p></div></div><p v-if="(overview?.processCount || 0) > sortedProcesses.length" class="process-help">{{translateText('排序范围为已采集的进程，采样保留 CPU 与内存占用最高的进程。',language)}} {{sortedProcesses.length}} / {{overview?.processCount}}</p><p v-if="sortedProcesses.some(p => p.name === 'systemd-journal' || p.name === 'systemd-journald' || p.service === 'systemd-journal')" class="process-help">{{translateText('systemd-journal 的常驻内存（RSS）主要为 mmap 映射的日志文件页缓存，系统内存紧张时由内核自动回收。',language)}}</p><p class="process-help">UFW / nftables 通常没有常驻进程；防护是否生效请查看安全页。</p></section>
      </div>

      <div v-else-if="page === 'jobs'" class="page-content">
        <div class="page-intro"><div><p>MISSION LOG</p><h2>任务进度与操作留痕</h2></div><span>{{ jobs.length }} 条最近任务</span></div>
        <section class="job-list panel-card"><div v-for="job in jobs" :key="job.id" class="job-row"><span class="job-icon" :class="job.status">{{ job.status === 'success' ? '✓' : job.status === 'failed' ? '!' : '↻' }}</span><div class="job-copy"><b>{{ jobLabel(job.kind) }}</b><small>{{ job.target }} · {{ new Date(job.createdAt).toLocaleString(language) }}</small><p v-if="job.error">{{ job.error }}</p></div><div class="job-progress"><span>{{ job.message }}</span><div><i :class="job.status" :style="{ width: `${job.progress}%` }"></i></div></div></div><p v-if="!jobs.length" class="empty">暂无任务记录。</p></section>
      </div>

      <div v-else-if="page === 'settings'" class="page-content settings-page">
        <div class="page-intro">
          <div><p>CONTROL SETTINGS</p><h2>账期、隐私与访问设置</h2></div>
          <div class="settings-intro-actions">
            <span v-if="settingsDraftDirty" class="settings-dirty-pill">有未保存的主机设置</span>
            <button class="primary" :disabled="mutationsDisabled" @click="saveSettings">保存更改</button>
          </div>
        </div>
        <section v-if="selectedHostId === 'local'" class="panel-card fleet-controller-settings">
          <div class="setting-title fleet-head-row">
            <div class="setting-title-main">
              <span>舰</span>
              <div>
                <div class="setting-title-inline">
                  <h3>中央多机控制</h3>
                  <span class="settings-state-badge" :class="{ active: fleetStatus?.enabled }">{{ fleetStatus?.enabled ? '已启用' : '未启用' }}</span>
                  <span v-if="fleetDraftDirty" class="settings-dirty-pill">未保存修改</span>
                </div>
                <p>控制流与订阅流可使用各自独立的可信 HTTPS 入口</p>
              </div>
            </div>
            <label class="fleet-header-switch">
              <span><b>启用中央控制</b></span>
              <span class="switch"><input v-model="fleetEnabledDraft" type="checkbox"><i></i></span>
            </label>
          </div>
          <div v-if="fleetEnabledDraft" class="fleet-url-grid">
            <label class="fleet-url-field">
              <span><b>01 · 主控通信地址</b><em>CONTROL PLANE</em></span>
              <input v-model="fleetPublicURL" type="url" placeholder="https://panel.example.com/wukong/">
              <small>供远端 Agent 接入和心跳使用，必须包含面板随机路径。</small>
            </label>
            <label class="fleet-url-field subscription">
              <span><b>02 · 订阅公开地址</b><em>SUBSCRIPTION · 443</em></span>
              <input v-model="fleetSubscriptionPublicURL" type="url" placeholder="https://sub.example.com/">
              <small>可留空以复用主控地址；建议使用独立标准 HTTPS 443 域名，只反代 <code>/fleet-sub/</code>。</small>
            </label>
          </div>
          <div v-if="fleetStatus?.enabled && fleetStatus?.globalSubscription" class="fleet-global-sub-box">
            <div class="fleet-sub-box-head">
              <div class="fleet-sub-box-title">
                <b>全局聚合订阅入口</b>
                <span class="settings-scope-tag jade">Clash / Mihomo</span>
              </div>
              <div class="fleet-sub-box-actions">
                <button type="button" class="secondary mini-action probe" :disabled="fleetSubscriptionProbeBusy" @click="probeFleetSubscription">{{ fleetSubscriptionProbeBusy ? '正在检测…' : '检测订阅入口' }}</button>
                <button v-if="!confirmRotateGlobalToken" type="button" class="secondary mini-action warn-hover" :disabled="busy" @click="confirmRotateGlobalToken = true">轮换全局订阅 Token</button>
                <span v-else class="inline-confirm-bar">
                  <small>旧全局订阅将失效：</small>
                  <button type="button" class="danger-mini-btn" :disabled="busy" @click="confirmRotateGlobalToken = false; saveFleetController(true)">确认轮换</button>
                  <button type="button" class="secondary mini-action" @click="confirmRotateGlobalToken = false">取消</button>
                </span>
              </div>
            </div>
            <div v-if="fleetSubscriptionProbeBusy || fleetSubscriptionProbe || fleetSubscriptionProbeError" class="fleet-probe-result" :class="fleetSubscriptionProbeError ? 'error' : fleetSubscriptionProbe ? 'success' : 'running'">
              <i></i><span v-if="fleetSubscriptionProbeBusy">正从主控服务器验证 TLS、HTTP 状态与订阅内容…</span><span v-else-if="fleetSubscriptionProbe"><b>入口可用</b> · HTTP {{ fleetSubscriptionProbe.status }} · {{ fleetSubscriptionProbe.nodeCount }} 个节点 · {{ fleetSubscriptionProbe.latencyMs }} ms</span><span v-else>{{ fleetSubscriptionProbeError }}</span>
            </div>
            <div class="token-box"><code>{{ fleetStatus.globalSubscription }}</code><button type="button" @click="copy(fleetStatus?.globalSubscription || '')">复制全局订阅</button></div>
          </div>
          <div class="fleet-setting-actions">
            <button class="primary" :disabled="busy" @click="saveFleetController(false)">保存中央设置</button>
            <div v-if="fleetStatus?.enabled" class="fleet-enroll-btn-group">
              <button class="secondary" :disabled="busy" @click="createFleetEnrollment('panel')">生成面板接入命令</button>
              <button class="secondary" :disabled="busy" @click="createFleetEnrollment('probe')">生成探针接入命令</button>
            </div>
          </div>
        </section>
        <section class="settings-grid">
          <article class="panel-card localization-settings">
            <div class="setting-title"><span>时</span><div><h3>本地化与账期</h3><p>用于流量归档和面板时间</p></div></div>
            <div class="settings-row-split">
              <label>
                <span>界面语言</span>
                <select v-model="settings.language" :disabled="mutationsDisabled"><option value="zh-CN">简体中文</option><option value="en-US">English</option></select>
              </label>
              <label>
                <span>时区</span>
                <input v-model="settings.timezone" :disabled="mutationsDisabled" placeholder="Asia/Shanghai">
                <span class="settings-chip-row">
                  <button v-for="tz in ['Asia/Shanghai', 'UTC', 'Asia/Tokyo', 'America/Los_Angeles']" :key="tz" type="button" class="settings-preset-chip" :class="{ active: settings.timezone === tz }" :disabled="mutationsDisabled" @click="settings.timezone = tz">{{ tz }}</button>
                </span>
              </label>
            </div>
            <div class="settings-row-split">
              <label>
                <span>账期重置日</span>
                <input v-model.number="settings.billingResetDay" type="number" min="1" max="28" :disabled="mutationsDisabled">
                <small>{{ language === 'en-US' ? 'Days 1-28 each month' : '每月 1～28 日' }}</small>
              </label>
              <label>
                <span>到期时间</span>
                <input v-model="settings.expiresAt" type="date" :disabled="mutationsDisabled">
                <small>{{ settings.expiresAt ? expiryLabel(settings.expiresAt) : (language === 'en-US' ? 'Leave empty for no expiry' : '留空表示长期有效') }}</small>
              </label>
            </div>
            <label>
              <span class="settings-label-head">
                <span>月流量额度（GB）</span>
                <span class="settings-chip-row">
                  <button v-for="quota in [0, 500, 1000, 2000, 5000]" :key="quota" type="button" class="settings-preset-chip" :class="{ active: Math.round(settings.trafficQuotaBytes / 1_000_000_000) === quota }" :disabled="mutationsDisabled" @click="settings.trafficQuotaBytes = quota * 1_000_000_000">{{ quota === 0 ? '不限' : `${quota}G` }}</button>
                </span>
              </span>
              <input :value="settings.trafficQuotaBytes / 1_000_000_000" type="number" min="0" :disabled="mutationsDisabled" @input="settings.trafficQuotaBytes = Number(($event.target as HTMLInputElement).value) * 1_000_000_000">
              <small>0 表示不限量</small>
            </label>
          </article>
          <article class="panel-card host-composite-settings">
            <div class="composite-section network-settings-section">
              <div class="setting-title composite-head-row">
                <div class="setting-title-main">
                  <span>网</span>
                  <div><h3>网络采集</h3><p>自动识别默认出口网卡</p></div>
                </div>
                <button type="button" class="primary composite-save-btn" :disabled="mutationsDisabled" @click="saveSettings">保存更改</button>
              </div>
              <div class="settings-row-split network-split-row">
                <label>
                  <span class="settings-label-head">
                    <span>监控网卡</span>
                    <span class="settings-chip-row">
                      <button v-for="nic in ['auto', 'eth0', 'ens3']" :key="nic" type="button" class="settings-preset-chip" :class="{ active: settings.interface === nic }" :disabled="mutationsDisabled" @click="settings.interface = nic">{{ nic }}</button>
                    </span>
                  </span>
                  <input v-model="settings.interface" placeholder="auto" :disabled="mutationsDisabled">
                </label>
                <div class="network-endpoint-field">
                  <span class="settings-label-head"><span>采集客户端端点</span></span>
                  <label class="toggle-row compact-toggle-box">
                    <span><small>关闭后仍保留整机流量统计</small></span>
                    <span class="switch"><input v-model="settings.collectEndpoints" type="checkbox" :disabled="mutationsDisabled"><i></i></span>
                  </label>
                </div>
              </div>
            </div>
            <div class="composite-section subscription-settings-section">
              <div class="setting-title">
                <span>令</span>
                <div>
                  <div class="setting-title-inline">
                    <h3>订阅令牌</h3>
                    <span class="settings-scope-tag">单机独立</span>
                  </div>
                  <p>与管理入口完全隔离</p>
                </div>
              </div>
              <div class="token-box">
                <code>{{ settings.subscriptionToken || '尚未生成' }}</code>
                <button v-if="!confirmRotateHostToken" type="button" :disabled="mutationsDisabled" @click="confirmRotateHostToken = true">轮换</button>
                <template v-else>
                  <button type="button" class="danger-token-btn" :disabled="mutationsDisabled" @click="confirmRotateHostToken = false; rotateSubscription()">确认轮换</button>
                  <button type="button" class="cancel-token-btn" @click="confirmRotateHostToken = false">取消</button>
                </template>
              </div>
              <p class="help-text">令牌轮换后旧订阅地址立即失效。节点密码仅在生成订阅或短时分享时由 Root Agent 解密。</p>
            </div>
            <div class="composite-section danger-zone-section">
              <div class="setting-title"><span>险</span><div><h3>危险区域</h3><p>首版不会修改 SSH、防火墙或系统更新</p></div></div>
              <p class="danger-desc">卸载与版本回滚请通过服务器上的 <code>wukongctl</code> 执行，避免浏览器会话误操作。</p>
              <div class="cli-ref-list">
                <div class="cli-ref-item">
                  <span>重置管理员密码</span>
                  <div class="cli-cmd-row">
                    <code>install.sh --reset-password</code>
                    <button type="button" class="mini-copy-btn" @click="copy('curl -fsSL https://github.com/252201/wukong-panel/releases/latest/download/install.sh | sudo sh -s -- --reset-password')">复制</button>
                  </div>
                </div>
                <div class="cli-ref-item">
                  <span>终端运维工具</span>
                  <div class="cli-cmd-row">
                    <code>sudo wukongctl --help</code>
                    <button type="button" class="mini-copy-btn" @click="copy('sudo wukongctl --help')">复制</button>
                  </div>
                </div>
              </div>
            </div>
          </article>
        </section>
      </div>
    </section>
  </div>

  <div v-if="mustChange && authenticated" class="modal-backdrop locked"><form class="modal-card compact" @submit.prevent="changePassword"><span class="modal-seal">钥</span><p class="eyebrow">首次登录安全检查</p><h2>设置新的管理员密码</h2><p>密码至少 12 位。提交后所有会话将失效，需要重新登录。</p><label>新密码<input v-model="newPassword" type="password" minlength="12" autocomplete="new-password" required></label><button class="primary wide" :disabled="busy">保存并重新登录</button></form></div>

  <div v-if="modal" class="modal-backdrop" @click.self="modal === 'fleet-host-action' ? closeFleetHostAction() : modal = null">
    <form v-if="modal === 'create' || modal === 'device-create' || modal === 'edit'" class="modal-card node-form" @click="realityPickerOpen = false" @submit.prevent="createNode">
      <header class="node-form-top">
        <div class="node-form-title-area">
          <span class="modal-seal" :class="{ jade: deviceMode, gold: !deviceMode && !isEditing, amber: isEditing }">{{ deviceMode ? '器' : isEditing ? '更' : '署' }}</span>
          <div class="node-form-headings">
            <p class="eyebrow">{{ deviceMode ? 'DEPLOY DEVICE FLEET' : isEditing ? 'EDIT MANAGED NODE' : 'DEPLOY PROXY NODE' }}</p>
            <h2>{{ deviceMode ? '部署设备专用节点' : isEditing ? `重新编辑 ${selectedNode?.name}` : '部署一座新节点' }}</h2>
            <p v-if="isEditing" class="form-hint edit-safety-hint">保存前会建立配置快照并校验；重启失败自动恢复原配置。协议与凭据不会在编辑中改变。</p>
          </div>
        </div>

        <div v-if="!isEditing" class="deploy-mode-tabs" role="tablist">
          <button
            type="button"
            class="deploy-mode-tab"
            :class="{ active: !deviceMode }"
            role="tab"
            :aria-selected="!deviceMode"
            @click="switchDeployKind('create')"
          >
            <span class="tab-icon">＋</span>
            <div class="tab-text">
              <b>标准代理节点</b>
              <span class="tab-tag gold">七协议</span>
            </div>
          </button>
          <button
            type="button"
            class="deploy-mode-tab"
            :class="{ active: deviceMode }"
            role="tab"
            :aria-selected="deviceMode"
            @click="switchDeployKind('device-create')"
          >
            <span class="tab-icon jade">器</span>
            <div class="tab-text">
              <b>设备专用编队</b>
              <span class="tab-tag jade">设备编队</span>
            </div>
          </button>
        </div>
        <button type="button" class="modal-close" @click="modal = null">×</button>
      </header>

      <!-- Seven Protocols Matrix Deck -->
      <div class="protocol-selection-area">
        <div class="protocol-matrix">
          <button
            v-for="item in protocolList"
            :key="item.key"
            type="button"
            class="protocol-matrix-card"
            :class="{
              active: createForm.protocol === item.key,
              locked: isEditing && createForm.protocol === item.key,
              disabled: isEditing && createForm.protocol !== item.key
            }"
            :disabled="isEditing"
            @click="createForm.protocol = item.key"
          >
            <div class="card-tag-row">
              <span class="matrix-badge" :class="item.key">{{ item.badge }}</span>
              <span class="matrix-transport">{{ item.transport }}</span>
            </div>
            <b class="matrix-title">{{ item.label }}</b>
            <small class="matrix-highlight">{{ item.highlight }}</small>
          </button>
        </div>
        <div class="protocol-note-strip">
          <span class="strip-icon">💡</span>
          <div class="strip-text">
            <strong>{{ selectedProtocolInfo.label }}（{{ selectedProtocolInfo.transport }}）</strong>：
            <span>{{ isEditing ? '已部署节点不能原地切换协议；如需换协议请新建节点' : selectedProtocolInfo.note }}</span>
          </div>
        </div>
      </div>

      <!-- Mode A: Standard Node Dual-Column Form Grid -->
      <div v-if="!deviceMode" class="node-form-dual-grid">
        <!-- Left Column: Inbound & Service Exposure -->
        <section class="form-section-card inbound-section">
          <div class="section-card-head">
            <span class="section-idx">01</span>
            <div class="section-head-title">
              <b>入站服务与网络暴露</b>
              <small>配置监听端口、外部连接地址及 TLS 伪装域名</small>
            </div>
          </div>

          <div class="section-card-body">
            <label class="field-item">
              <span class="field-label-text">节点名称 <em class="req-star">*</em></span>
              <input v-model="createForm.name" placeholder="例如：花果山 · iPhone" required>
            </label>

            <div class="field-grid-2">
              <div class="field-item">
                <div class="field-label-row">
                  <span class="field-label-text">{{ isTunnelProtocol ? '本地 Origin 端口 (TCP)' : `监听端口 (${selectedProtocolInfo.transport})` }}</span>
                  <button v-if="!isTunnelProtocol" type="button" class="mini-dice-btn" title="随机生成 15000~62000 可用端口" @click="pickRandomAvailablePort">🎲 随机端口</button>
                </div>
                <input v-model.number="createForm.listenPort" type="number" min="0" max="65535" placeholder="0 = 自动分配">
                <div class="field-foot-row">
                  <small v-if="isTunnelProtocol">仅监听 127.0.0.1 本地；客户端连接 Cloudflare 443</small>
                  <small v-else-if="conflictingNodeName" class="port-conflict-hint">⚠️ 端口 {{ createForm.listenPort }} 已被节点「{{ conflictingNodeName }}」占用</small>
                  <small v-else>填 0 由系统自动分配高位空闲端口</small>
                  <label v-if="!isTunnelProtocol" class="port-auto-allow-label" :title="language === 'en-US' ? 'Automatically allow inbound port in host firewall' : '创建或更新节点时，自动在主机系统防火墙放行该端口'">
                    <input v-model="createForm.autoAllowPort" type="checkbox" class="mini-checkbox">
                    <span>{{ language === 'en-US' ? 'Auto-allow' : '自动放行' }}</span>
                  </label>
                </div>
              </div>

              <div class="field-item">
                <div class="field-label-row">
                  <span class="field-label-text">{{ isTunnelProtocol ? 'Cloudflare 节点域名' : '公网域名 / IP' }} <em class="req-star">*</em></span>
                </div>
                <input v-model="createForm.server" :placeholder="isTunnelProtocol ? 'edge.example.com' : 'node.example.com'" required>
                <div class="field-foot-row">
                  <small v-if="isTunnelProtocol">填写 Published application 对应的公开主机名</small>
                  <small v-else-if="deploymentDefaults.panelDomain">默认已采用面板域名，可按需修改</small>
                </div>
              </div>
            </div>

            <!-- Domain / REALITY / TLS -->
            <div v-if="createForm.protocol !== 'shadowsocks' && !isTunnelProtocol" class="field-item domain-input-group">
              <span v-if="createForm.protocol !== 'vless'" class="field-label-text">{{ selectedProtocolInfo.domainLabel }}</span>
              <div v-else class="field-title-row">
                <span class="field-label-text">{{ selectedProtocolInfo.domainLabel }}</span>
                <div class="reality-picker-wrap" @keydown.esc.stop="realityPickerOpen = false">
                  <button
                    type="button"
                    class="reality-quick-select"
                    :class="{ open: realityPickerOpen }"
                    :aria-expanded="realityPickerOpen"
                    title="快速选用推荐伪装域名"
                    @click.prevent.stop="realityPickerOpen = !realityPickerOpen"
                  >
                    <span>快捷选用推荐域名</span>
                    <i class="reality-caret" aria-hidden="true">▾</i>
                  </button>
                  <div v-if="realityPickerOpen" class="reality-quick-menu" role="listbox" aria-label="快捷选用推荐域名" @click.stop>
                    <div class="reality-menu-head">快捷选用推荐域名</div>
                    <div v-for="cat in realityPresets" :key="cat.category" class="reality-menu-group">
                      <div class="reality-menu-category">{{ cat.category }}</div>
                      <button
                        v-for="item in cat.items"
                        :key="item.domain"
                        type="button"
                        role="option"
                        class="reality-menu-option"
                        :class="{ active: activeRealityPreset?.domain === item.domain }"
                        :aria-selected="activeRealityPreset?.domain === item.domain"
                        @click.prevent.stop="chooseRealityPreset(item.domain)"
                      >
                        <span class="reality-opt-title">
                          <i class="reality-opt-check" aria-hidden="true">{{ activeRealityPreset?.domain === item.domain ? '✓' : '' }}</i>
                          <span>{{ item.title }}</span>
                        </span>
                        <code class="reality-opt-domain">{{ item.domain }}</code>
                      </button>
                    </div>
                  </div>
                </div>
              </div>
              <input
                v-model="createForm.domain"
                :placeholder="createForm.protocol === 'vless' ? 's0.awsstatic.com' : 'node.example.com'"
                autocomplete="off"
                spellcheck="false"
              >
              <small v-if="createForm.protocol === 'vless'" class="reality-desc">
                <template v-if="activeRealityPreset">
                  <span class="reality-badge">{{ activeRealityPreset.category }}</span>
                  {{ activeRealityPreset.desc }}
                </template>
                <template v-else-if="createForm.domain">
                  <span class="reality-badge custom">自定义</span>
                  客户端与 VPS 均可达的 TLS 1.3 站点（已填入自定义域名）
                </template>
                <template v-else>
                  默认使用 AWS 静态资源 TLS 站点；也可改为客户端与 VPS 均可达的 TLS 1.3 站点
                </template>
              </small>
              <small v-else-if="deploymentDefaults.panelDomain">与面板证书域名保持一致</small>
            </div>

            <!-- Tunnel specific fields -->
            <template v-if="isTunnelProtocol">
              <div class="field-grid-2">
                <label class="field-item">
                  <div class="field-label-row">
                    <span class="field-label-text">WebSocket 路径</span>
                  </div>
                  <input v-model="createForm.webSocketPath" placeholder="留空自动生成随机路径" maxlength="128" autocomplete="off">
                  <small>自定义时必须以 / 开头</small>
                </label>

                <label class="field-item">
                  <div class="field-label-row">
                    <span class="field-label-text">优选连接域名 / IP</span>
                  </div>
                  <input v-model="createForm.preferredServer" placeholder="例如：cf-best.example.com 或 104.16.0.1" autocomplete="off" spellcheck="false">
                  <small>替换客户端 server；SNI 与 Tunnel 仍使用节点域名。留空保持标准 Anycast。</small>
                </label>
              </div>

              <label v-if="!isEditing" class="field-item tunnel-token-field">
                <span class="field-label-text">Tunnel Token <em class="req-star">*</em></span>
                <input v-model="createForm.tunnelToken" type="password" autocomplete="new-password" spellcheck="false" placeholder="粘贴 Cloudflare Tunnel 的运行 Token" required>
                <small>仅接受运行 Token；不会要求或保存 Cloudflare API Key</small>
              </label>
              <div v-if="!isEditing" class="tunnel-guide">
                <span>隧</span>
                <div>
                  <b>Cloudflare 侧配置步骤</b>
                  <ol>
                    <li>在 Zero Trust 创建 remotely-managed Tunnel，并复制运行 Token。</li>
                    <li>在 Published application 把 Service URL 设为 <code>http://127.0.0.1:端口</code>。</li>
                  </ol>
                  <p>VPS 无需开放 Origin 端口；由 cloudflared 连接器建立出站安全隧道。</p>
                </div>
              </div>
              <div v-if="isEditing" class="edit-impact-note">
                <b>Cloudflare 路由需要同步</b>
                <p>若修改公开主机名或 Origin 端口，请同步更新 Zero Trust 的 Published application。</p>
              </div>
            </template>
          </div>
        </section>

        <!-- Right Column: 02 出口路由与网络策略 -->
        <section class="form-section-card egress-section">
          <div class="section-card-head">
            <span class="section-idx">02</span>
            <div class="section-head-title">
              <b>出口网络与路由策略</b>
              <small>定义节点流量真实落地点与双栈出站偏好</small>
            </div>
          </div>

          <div class="section-card-body">
            <div class="field-grid-2">
              <label class="field-item">
                <span class="field-label-text">出口位置</span>
                <select v-model="createForm.egress">
                  <option value="direct">A 机本地直出</option>
                  <option value="residential" :disabled="!deploymentDefaults.residentialExitReady">B 机落地 IP{{ deploymentDefaults.residentialExitReady ? '' : '（请先配置）' }}</option>
                  <option value="socks" :disabled="!deploymentDefaults.socksExitReady">自定义 SOCKS{{ deploymentDefaults.socksExitReady ? '' : '（请先配置）' }}</option>
                </select>
                <small v-if="createForm.egress === 'residential'">WireGuard 断线时拒绝联网，不回退到 A 机</small>
                <small v-else-if="createForm.egress === 'socks'">全部流量只经 SOCKS 出站；代理不可用时连接失败</small>
                <small v-else>使用本机当前网络接口直连出站</small>
              </label>

              <label class="field-item">
                <span class="field-label-text">出站策略</span>
                <input v-if="createForm.egress === 'socks'" value="由 SOCKS 代理接管" disabled>
                <select v-else v-model="createForm.mode" :disabled="createForm.egress === 'residential'">
                  <option value="prefer_v6">IPv6 优先 + IPv4 兜底</option>
                  <option value="v4only">纯 IPv4</option>
                  <option value="v6only">纯 IPv6</option>
                </select>
                <small v-if="createForm.egress === 'residential'">落地出口固定使用策略路由</small>
                <small v-else>目标同时拥有双栈时的出站偏好</small>
              </label>
            </div>

            <!-- Advanced Network Settings Box -->
            <div class="advanced-network-box">
              <div class="adv-box-header">
                <b>高级出站网络绑定</b>
                <small>多网卡 / 专属公网 IP 绑定与动态 IP 跟随</small>
              </div>

              <div class="field-grid-2">
                <label class="field-item" :class="{ 'disabled-field': createForm.mode === 'v6only' || createForm.egress !== 'direct' }">
                  <span class="field-label-text">IPv4 出站绑定</span>
                  <input v-if="createForm.egress === 'residential'" value="落地出口使用策略路由" disabled>
                  <input v-else-if="createForm.egress === 'socks'" value="SOCKS 出站不使用本机绑定" disabled>
                  <input v-else-if="createForm.mode === 'v6only'" value="纯 IPv6 模式不使用 IPv4" disabled>
                  <template v-else>
                    <select v-if="deploymentDefaults.ipv4.length" v-model="bindChoice.ipv4" @change="applyBindChoice('ipv4')">
                      <option value="">自动路由（不固定地址）</option>
                      <option v-for="item in deploymentDefaults.ipv4" :key="item.address" :value="item.address">{{ item.address }} · {{ item.interface }}</option>
                      <option value="__manual__">手动填写…</option>
                    </select>
                    <input v-if="!deploymentDefaults.ipv4.length || bindChoice.ipv4 === '__manual__'" v-model="createForm.ipv4Bind" placeholder="自动或 192.0.2.10">
                  </template>
                  <small v-if="createForm.mode === 'v6only' && createForm.egress === 'direct'">已清空，不会写入节点配置</small>
                  <small v-else-if="deploymentDefaults.ipv4.length && createForm.egress === 'direct'">已识别 {{ deploymentDefaults.ipv4.length }} 个本机可绑定 IPv4</small>
                </label>

                <label class="field-item" :class="{ 'disabled-field': createForm.mode === 'v4only' || createForm.egress !== 'direct' }">
                  <span class="field-label-text">IPv6 出站绑定</span>
                  <input v-if="createForm.egress === 'socks'" value="SOCKS 出站不使用本机绑定" disabled>
                  <input v-else-if="createForm.mode === 'v4only' || createForm.egress === 'residential'" value="当前出口不使用 IPv6" disabled>
                  <template v-else>
                    <select v-if="deploymentDefaults.ipv6.length" v-model="bindChoice.ipv6" @change="applyBindChoice('ipv6')">
                      <option value="">自动路由（不固定地址）</option>
                      <option v-for="item in deploymentDefaults.ipv6" :key="item.address" :value="item.address">{{ item.address }} · {{ item.interface }}</option>
                      <option value="__manual__">手动填写…</option>
                    </select>
                    <input v-if="!deploymentDefaults.ipv6.length || bindChoice.ipv6 === '__manual__'" v-model="createForm.ipv6Bind" placeholder="2001:db8::10">
                  </template>
                  <small v-if="createForm.mode === 'v4only' && createForm.egress === 'direct'">已清空，不会写入节点配置</small>
                  <small v-else-if="deploymentDefaults.ipv6.length && createForm.egress === 'direct'">已识别 {{ deploymentDefaults.ipv6.length }} 个本机可绑定 IPv6 地址</small>
                </label>
              </div>

              <label v-if="createForm.egress === 'direct'" class="field-item">
                <span class="field-label-text">强制 IPv6 域名名单</span>
                <input v-model="createForm.v6OnlyDomains" placeholder="例如：chatgpt.com,claude.ai,anthropic.com">
                <small>列表中的域名将强制使用 IPv6 建立直连连接（以英文逗号分隔）</small>
              </label>
            </div>

            <div v-if="isEditing && selectedNode?.sharedGroup" class="edit-impact-note shared">
              <b>共享进程影响范围</b>
              <p>节点名称、端口与入站参数只修改当前设备；出站策略、IPv4/IPv6 绑定和强制 IPv6 域名会同步应用到整个设备编队。</p>
            </div>
          </div>
        </section>
      </div>

      <!-- Mode B: Device Fleet Mode Grid -->
      <div v-else class="fleet-deploy-grid">
        <!-- Shared Settings Row -->
        <section class="form-section-card fleet-shared-card">
          <div class="section-card-head">
            <span class="section-idx">器</span>
            <div class="section-head-title">
              <b>编队共享网络与出口设置</b>
              <small>整组设备共享一个 sing-box 进程与出站配置，降低系统资源开销</small>
            </div>
          </div>
          <div class="section-card-body">
            <div class="field-grid-4">
              <label class="field-item">
                <span class="field-label-text">出口位置</span>
                <select v-model="createForm.egress">
                  <option value="direct">A 机本地直出</option>
                  <option value="residential" :disabled="!deploymentDefaults.residentialExitReady">B 机落地 IP{{ deploymentDefaults.residentialExitReady ? '' : '（请先配置）' }}</option>
                  <option value="socks" :disabled="!deploymentDefaults.socksExitReady">自定义 SOCKS{{ deploymentDefaults.socksExitReady ? '' : '（请先配置）' }}</option>
                </select>
              </label>
              <label class="field-item">
                <span class="field-label-text">出站策略</span>
                <input v-if="createForm.egress === 'socks'" value="由 SOCKS 代理接管" disabled>
                <select v-else v-model="createForm.mode" :disabled="createForm.egress === 'residential'">
                  <option value="prefer_v6">IPv6 优先 + IPv4 兜底</option>
                  <option value="v4only">纯 IPv4</option>
                  <option value="v6only">纯 IPv6</option>
                </select>
              </label>
              <template v-if="!isTunnelProtocol">
                <label class="field-item" :class="{ 'span-2': createForm.protocol === 'shadowsocks' }">
                  <span class="field-label-text">公网域名 / IP <em class="req-star">*</em></span>
                  <input v-model="createForm.server" placeholder="node.example.com" required>
                </label>
                <label v-if="createForm.protocol !== 'shadowsocks'" class="field-item">
                  <span class="field-label-text">{{ selectedProtocolInfo.domainLabel }}</span>
                  <input v-model="createForm.domain" :placeholder="createForm.protocol === 'vless' ? 's0.awsstatic.com' : 'node.example.com'">
                </label>
              </template>
              <label v-else class="field-item tunnel-token-field span-2">
                <span class="field-label-text">共享 Tunnel Token <em class="req-star">*</em></span>
                <input v-model="createForm.tunnelToken" type="password" autocomplete="new-password" placeholder="粘贴 Cloudflare Tunnel 的运行 Token" required>
                <small>整组设备共用一个 cloudflared 连接器；每台设备使用独立主机名和 Origin 端口</small>
              </label>
            </div>
          </div>
        </section>

        <!-- Fleet Devices Section -->
        <section class="form-section-card fleet-devices-card">
          <div class="section-card-head fleet-device-head">
            <div class="fleet-head-left">
              <span class="section-idx">阵</span>
              <div class="section-head-title">
                <b>设备清单</b>
                <small class="fleet-counter-pill">当前 {{ deviceNodes.length }} / 20 台 · 最少 2 台 · 独立入站隔离</small>
              </div>
            </div>
            <div class="fleet-head-actions">
              <button type="button" class="mini-tool-btn" title="为设备批量命名为：设备 01、设备 02…" @click="batchRenameDevices()">🪄 批量命名</button>
              <button type="button" class="mini-tool-btn" title="按连续递增方式分配端口" @click="autoAssignSequentialPorts()">⚡ 连续端口</button>
              <button type="button" class="add-device-btn" :disabled="deviceNodes.length >= 20" @click="addDevice">＋ 添加设备</button>
            </div>
          </div>

          <!-- Tunnel Route Guide Banner in Fleet Devices Card -->
          <div v-if="isTunnelProtocol" class="tunnel-guide tunnel-fleet-banner">
            <span>隧</span>
            <div>
              <b>一个 Tunnel，多条设备路由</b>
              <ol>
                <li>在 Zero Trust 创建 remotely-managed Tunnel，并复制运行 Token 填入上方共享配置。</li>
                <li>为下方每台设备添加一条 Published application，把独立主机名路由到对应 <code>http://127.0.0.1:端口</code>。</li>
              </ol>
            </div>
          </div>

          <div class="device-fleet-grid">
            <article v-for="(device, index) in deviceNodes" :key="device.key" class="device-draft-card">
              <header class="device-card-header">
                <span class="device-idx-badge">{{ String(index + 1).padStart(2, '0') }}</span>
                <b class="device-card-name">{{ device.name || `设备 ${index + 1}` }}</b>
                <button type="button" class="device-remove-btn" :disabled="deviceNodes.length <= 2" title="移除设备" @click="removeDevice(index)">×</button>
              </header>
              <div class="device-card-grid">
                <label class="field-item">
                  <span class="field-label-text">设备名称 <em class="req-star">*</em></span>
                  <input v-model="device.name" maxlength="80" placeholder="例如：iPhone" required>
                </label>
                <label class="field-item">
                  <span class="field-label-text">{{ isTunnelProtocol ? '本地 Origin 端口' : '监听端口' }}</span>
                  <input v-model.number="device.listenPort" type="number" min="0" max="65535" placeholder="0 = 自动分配">
                </label>
                <label v-if="isTunnelProtocol" class="field-item">
                  <span class="field-label-text">公开主机名 <em class="req-star">*</em></span>
                  <input v-model="device.server" placeholder="iphone.example.com" required>
                </label>
                <label v-if="isTunnelProtocol" class="field-item">
                  <span class="field-label-text">优选连接域名 / IP <em>可选</em></span>
                  <input v-model="device.preferredServer" placeholder="cf-best.example.com">
                </label>
                <label v-if="isTunnelProtocol" class="field-item span-full">
                  <span class="field-label-text">WebSocket 路径 <em>可选</em></span>
                  <input v-model="device.webSocketPath" placeholder="留空自动生成随机路径" maxlength="128">
                </label>
              </div>
            </article>
          </div>
        </section>

        <!-- Fleet Shared Advanced Network -->
        <section class="form-section-card fleet-adv-card">
          <div class="section-card-head">
            <span class="section-idx">绑</span>
            <div class="section-head-title">
              <b>编队出站多网卡与动态容灾设置</b>
              <small>应用于整个编队进程的出站 IP 绑定与动态 IP 跟随</small>
            </div>
          </div>
          <div class="section-card-body">
            <div class="field-grid-2">
              <label class="field-item" :class="{ 'disabled-field': createForm.mode === 'v6only' || createForm.egress !== 'direct' }">
                <span class="field-label-text">IPv4 出站绑定</span>
                <input v-if="createForm.egress === 'residential'" value="落地出口使用策略路由" disabled>
                <input v-else-if="createForm.egress === 'socks'" value="SOCKS 出站不使用本机绑定" disabled>
                <input v-else-if="createForm.mode === 'v6only'" value="纯 IPv6 模式不使用 IPv4" disabled>
                <template v-else>
                  <select v-if="deploymentDefaults.ipv4.length" v-model="bindChoice.ipv4" @change="applyBindChoice('ipv4')">
                    <option value="">自动路由（不固定地址）</option>
                    <option v-for="item in deploymentDefaults.ipv4" :key="item.address" :value="item.address">{{ item.address }} · {{ item.interface }}</option>
                    <option value="__manual__">手动填写…</option>
                  </select>
                  <input v-if="!deploymentDefaults.ipv4.length || bindChoice.ipv4 === '__manual__'" v-model="createForm.ipv4Bind" placeholder="自动或 192.0.2.10">
                </template>
              </label>
              <label class="field-item" :class="{ 'disabled-field': createForm.mode === 'v4only' || createForm.egress !== 'direct' }">
                <span class="field-label-text">IPv6 出站绑定</span>
                <input v-if="createForm.egress === 'socks'" value="SOCKS 出站不使用本机绑定" disabled>
                <input v-else-if="createForm.mode === 'v4only' || createForm.egress === 'residential'" value="当前出口不使用 IPv6" disabled>
                <template v-else>
                  <select v-if="deploymentDefaults.ipv6.length" v-model="bindChoice.ipv6" @change="applyBindChoice('ipv6')">
                    <option value="">自动路由（不固定地址）</option>
                    <option v-for="item in deploymentDefaults.ipv6" :key="item.address" :value="item.address">{{ item.address }} · {{ item.interface }}</option>
                    <option value="__manual__">手动填写…</option>
                  </select>
                  <input v-if="!deploymentDefaults.ipv6.length || bindChoice.ipv6 === '__manual__'" v-model="createForm.ipv6Bind" placeholder="2001:db8::10">
                </template>
              </label>
            </div>
          </div>
        </section>
      </div>

      <!-- Footer Action Bar -->
      <footer class="node-form-foot">
        <div class="node-form-status-bar">
          <span class="status-chip proto-chip">{{ selectedProtocolInfo.badge }}</span>
          <span class="status-chip mode-chip">{{ modeLabel(createForm.mode) }}</span>
          <span class="status-chip egress-chip">{{ createForm.egress === 'direct' ? 'A 机直出' : createForm.egress === 'residential' ? 'B 机落地' : 'SOCKS' }}</span>
          <span v-if="conflictingNodeName" class="status-chip danger-chip">⚠️ 端口 {{ createForm.listenPort }} 冲突</span>
          <span v-else-if="deviceMode && hasDevicePortDuplicate" class="status-chip danger-chip">⚠️ 编队设备间端口冲突</span>
        </div>
        <div class="modal-actions">
          <button type="button" class="secondary" @click="modal = null">取消</button>
          <button class="primary" :disabled="busy || defaultsLoading || !!conflictingNodeName || (deviceMode && hasDevicePortDuplicate)">
            {{ busy ? '正在创建任务…' : isEditing ? '保存并安全重启' : '确认部署' }}
          </button>
        </div>
      </footer>
    </form>
    <section v-else-if="modal === 'import'" class="modal-card import-modal"><button class="modal-close" @click="modal = null">×</button><p class="eyebrow">DISCOVER EXISTING NODES</p><h2>扫描并接管现有节点</h2><p>接管不会重写配置或升级 sing-box；未知字段将原样保留。彻底删除会先建立校验快照。</p><div class="candidate-list"><div v-for="item in candidates" :key="item.fingerprint" class="candidate-row" :class="{ deleting: candidateDeleteTarget?.fingerprint === item.fingerprint }"><label class="candidate-select"><input v-model="selectedCandidates" type="checkbox" :value="item.fingerprint"><span><b>{{ item.name }} · {{ protocolInfo(item.protocol).badge }}</b><small>{{ item.configPath }} · {{ item.serviceName }}</small></span><em>{{ item.listenPort }}/{{ protocolInfo(item.protocol).transport }}</em></label><button type="button" class="candidate-purge" title="从服务器彻底删除此候选节点" @click="stageCandidateDelete(item)">彻底删除</button></div><p v-if="!candidates.length" class="empty">未发现可接管的代理节点</p></div><section v-if="candidateDeleteTarget" class="candidate-delete-confirm" role="alert"><header><span>险</span><div><b>彻底删除 {{ candidateDeleteTarget.name }}？</b><small>{{ candidateDeleteTarget.configPath }}</small></div></header><p v-if="candidateDeleteTarget.sharedGroup">系统会先建立 SHA-256 快照，只从共享配置移除端口 {{ candidateDeleteTarget.listenPort }} 的 inbound；其他节点与共享服务会保留。配置校验或重启失败将自动恢复。</p><p v-else>系统会先建立 SHA-256 快照，再停止并删除 {{ candidateDeleteTarget.serviceName === 'unknown' ? '对应配置文件' : '对应服务与配置文件' }}。此操作不可从面板撤销。</p><label>输入完整节点名称确认<input v-model="candidateDeleteConfirm" autocomplete="off" :placeholder="candidateDeleteTarget.name"></label><div><button type="button" class="secondary" @click="cancelCandidateDelete">保留节点</button><button type="button" class="danger-button" :disabled="busy || candidateDeleteConfirm !== candidateDeleteTarget.name" @click="deleteCandidate">{{ busy ? '正在创建任务…' : '确认彻底删除' }}</button></div></section><div class="modal-actions"><button class="secondary" @click="modal = null">取消</button><button class="primary" :disabled="busy || !selectedCandidates.length" @click="importSelected">接管 {{ selectedCandidates.length }} 个端点</button></div></section>
    <section v-else-if="modal === 'share'" class="modal-card share-modal"><button class="modal-close" @click="modal = null">×</button><p class="eyebrow">EPHEMERAL SHARE</p><h2>{{ selectedNode?.name }}</h2><p>敏感链接仅在当前会话短时显示。</p><img v-if="shareQR" :src="shareQR" alt="节点二维码"><div class="share-code"><code>{{ shareURI || '正在向 Root Agent 请求密钥…' }}</code><button :disabled="!shareURI" @click="copy(shareURI)">复制</button></div></section>
    <form v-else-if="modal === 'fleet-host-action'" class="modal-card compact fleet-host-action-modal" :class="{ 'danger-modal': fleetHostAction !== 'rename' }" role="dialog" aria-modal="true" @submit.prevent="submitFleetHostAction" @keydown.esc.prevent="closeFleetHostAction">
      <button type="button" class="modal-close" :disabled="busy" @click="closeFleetHostAction">×</button>
      <span class="modal-seal" :class="{ red: fleetHostAction !== 'rename' }">{{ fleetHostAction === 'rename' ? '改' : fleetHostAction === 'purge' ? '清' : '撤' }}</span>
      <p class="eyebrow">{{ fleetHostAction === 'rename' ? 'FLEET HOST RENAME' : fleetHostAction === 'purge' ? 'FLEET ARCHIVE PURGE' : 'FLEET HOST REMOVAL' }}</p>
      <h2>{{ fleetHostAction === 'rename' ? '重命名主机' : fleetHostAction === 'purge' ? '永久清除归档？' : '移除远端主机？' }}</h2>
      <p v-if="fleetHostAction === 'rename'">只修改中央控制台显示名称，不会改变远端 VPS 的主机名或本机配置。</p>
      <p v-else-if="fleetHostAction === 'purge'">将永久删除中央保存的指标、命令回执和订阅缓存；远端面板、节点与运行状态不受影响。</p>
      <p v-else>中央会立即撤销 Agent 凭据，并将指标保留 30 天归档；远端面板与节点继续运行。</p>
      <div v-if="fleetHostTarget" class="fleet-host-action-target"><small>操作目标</small><b>{{ fleetHostTarget.name }}</b><span v-if="fleetHostAction !== 'rename'">{{ fleetHostTarget.hostname || fleetHostTarget.id }}</span></div>
      <label v-if="fleetHostAction === 'rename'">新的主机名称<input v-model="fleetHostNameDraft" maxlength="120" autocomplete="off" required autofocus></label>
      <label v-else>输入完整主机名 <code>{{ fleetHostTarget?.name }}</code> 确认<input v-model="fleetHostConfirm" autocomplete="off" spellcheck="false" :placeholder="fleetHostTarget?.name" required autofocus></label>
      <div class="modal-actions"><button type="button" class="secondary" :disabled="busy" @click="closeFleetHostAction">取消</button><button :class="fleetHostAction === 'rename' ? 'primary' : 'danger-button'" :disabled="busy || (fleetHostAction === 'rename' ? !fleetHostNameDraft.trim() || fleetHostNameDraft.trim() === fleetHostTarget?.name : fleetHostConfirm.trim() !== fleetHostTarget?.name)">{{ busy ? '处理中…' : fleetHostAction === 'rename' ? '保存名称' : fleetHostAction === 'purge' ? '永久清除' : '确认移除' }}</button></div>
    </form>
    <form v-else-if="modal === 'fleet-host-settings'" class="modal-card compact fleet-host-settings-modal" role="dialog" aria-modal="true" @submit.prevent="submitFleetHostSettings" @keydown.esc.prevent="modal = null">
      <button type="button" class="modal-close" :disabled="busy" @click="modal = null">×</button>
      <span class="modal-seal">设</span>
      <p class="eyebrow">FLEET HOST SETTINGS</p>
      <h2>{{ fleetHostSettingsTarget?.name }} · 配额与设置</h2>
      <p>由中央主控统一托管主机的账期流量配额与 VPS 到期时间。</p>
      <div v-if="fleetHostSettingsTarget" class="fleet-host-action-target">
        <small>目标主机</small><b>{{ fleetHostSettingsTarget.name }}</b>
        <span>{{ fleetHostSettingsTarget.hostname || fleetHostSettingsTarget.id }} · {{ isProbeHost(fleetHostSettingsTarget) ? '轻量探针' : '完整面板' }}</span>
      </div>
      <div class="form-grid">
        <label>每月重置日
          <input v-model.number="fleetHostSettingsDraft.billingResetDay" type="number" min="1" max="31" required>
          <small>每月流量归零日（1~31）</small>
        </label>
        <label>月流量额度（GB）
          <input v-model.number="fleetHostSettingsDraft.trafficQuotaGB" type="number" min="0" step="any" required>
          <small>0 表示不限量</small>
        </label>
      </div>
      <label>流量计费规则
        <select v-model="fleetHostSettingsDraft.trafficCalcMode">
          <option value="both">双向计费（入站 + 出站）</option>
          <option value="tx">仅计出站（绝大多数云厂商）</option>
          <option value="rx">仅计入站</option>
          <option value="max">出入取大值（部分美西/欧机）</option>
        </select>
      </label>
      <label>VPS 到期时间
        <input v-model="fleetHostSettingsDraft.expiresAt" type="date">
        <small>{{ fleetHostSettingsDraft.expiresAt ? expiryLabel(fleetHostSettingsDraft.expiresAt) : '留空表示长期有效 / 未设置' }}</small>
      </label>
      <div class="modal-actions">
        <button type="button" class="secondary" :disabled="busy" @click="modal = null">取消</button>
        <button class="primary" :disabled="busy">{{ busy ? '保存中…' : '保存设置' }}</button>
      </div>
    </form>
    <div v-else-if="modal === 'probe-nodes' && probeNodesTarget" class="modal-card compact probe-nodes-modal" role="dialog" aria-modal="true" @keydown.esc.prevent="modal = null">
      <button type="button" class="modal-close" @click="modal = null">×</button>
      <span class="modal-seal blue">探</span>
      <p class="eyebrow">PROBE NODES MANAGEMENT</p>
      <h2>{{ probeNodesTarget.name }} · 节点管理</h2>
      <p>管理轻量探针上的代理节点，修改节点名称，或手动录入节点。这些节点均可纳入全局订阅范围。</p>
      <div class="fleet-host-action-target">
        <small>目标主机</small><b>{{ probeNodesTarget.name }}</b>
        <span>{{ probeNodesTarget.hostname || probeNodesTarget.id }} · <span class="host-online-tag" :class="{ online: probeNodesTarget.online }">{{ probeNodesTarget.online ? '● 在线' : '○ 离线' }}</span> · 节点数：{{ probeNodesList.length }}</span>
      </div>

      <div class="probe-nodes-list-section">
        <div class="probe-nodes-list-head">
          <h4>已识别节点</h4>
          <button type="button" class="mini-btn secondary" :disabled="probeNodesLoading" @click="loadProbeNodes(probeNodesTarget.id)">
            {{ probeNodesLoading ? '刷新中…' : '↻ 刷新列表' }}
          </button>
        </div>

        <div v-if="probeNodesLoading && !probeNodesList.length" class="probe-nodes-hint-box">
          正在读取探针节点…
        </div>
        <div v-else-if="!probeNodesList.length" class="probe-nodes-hint-box">
          暂未发现节点。探针会自动扫描本地 <code>/etc/s-box</code>、<code>/etc/sing-box</code>、<code>/etc/xray</code> 中的配置；您也可以在下方手动粘贴分享链接添加。
        </div>
        <div v-else class="probe-nodes-items">
          <article v-for="node in probeNodesList" :key="node.id" class="probe-node-item">
            <div class="probe-node-info">
              <div class="probe-node-title-row">
                <span class="protocol-badge" :class="node.protocol">{{ node.protocol.toUpperCase() }}</span>
                <div v-if="probeNodeRenameId === node.id" class="inline-rename-wrap">
                  <input v-model="probeNodeRenameDraft" type="text" class="inline-rename-input" maxlength="60" @keyup.enter="submitRenameProbeNode(node)" @keyup.esc="cancelRenameProbeNode" autofocus />
                  <button type="button" class="mini-btn primary" @click="submitRenameProbeNode(node)">保存</button>
                  <button type="button" class="mini-btn secondary" @click="cancelRenameProbeNode">取消</button>
                </div>
                <b v-else class="probe-node-name" :title="node.name">{{ node.name }}</b>
                <span class="source-tag" :class="node.source === 'scan' ? 'source-scan' : 'source-manual'">{{ node.source === 'scan' ? '自动扫描' : '手动' }}</span>
              </div>
              <div class="probe-node-detail-row">
                <code>:{{ node.port }}</code>
                <span v-if="node.domain && node.domain !== node.server">{{ node.domain }}</span>
                <span v-else>{{ node.server }}</span>
              </div>
            </div>
            <div class="probe-node-actions">
              <button v-if="probeNodeRenameId !== node.id" type="button" class="mini-btn" @click="startRenameProbeNode(node)">重命名</button>
              <button v-if="node.source === 'manual'" type="button" class="mini-btn danger" @click="deleteProbeNode(node)">删除</button>
            </div>
          </article>
        </div>
      </div>

      <div class="probe-nodes-add-section">
        <label>
          <b>手动添加节点</b>
          <small>支持粘贴 VLESS / Hysteria2 / Shadowsocks / TUIC / Trojan / AnyTLS / VMess 分享链接，支持每行一个批量粘贴。</small>
        </label>
        <textarea
          v-model="probeNodeAddShareURI"
          class="probe-share-input"
          rows="3"
          placeholder="vless://... 或 hysteria2://... 或 ss://... (可粘贴多行)"
          spellcheck="false"
        ></textarea>
        <div class="probe-nodes-add-btn-wrap">
          <button type="button" class="primary" :disabled="probeNodeAddBusy || !probeNodeAddShareURI.trim()" @click="addProbeNode">
            {{ probeNodeAddBusy ? '解析添加中…' : '＋ 添加到此探针' }}
          </button>
        </div>
      </div>

      <div class="modal-actions">
        <button type="button" class="secondary" @click="modal = null">完成</button>
      </div>
    </div>
    <div v-else-if="modal === 'ip-reputation'" class="modal-card ip-reputation-modal" role="dialog" aria-modal="true" @keydown.esc.prevent="modal = null">
      <button type="button" class="modal-close" @click="modal = null">×</button>
      <span class="modal-seal blue">信</span>
      <p class="eyebrow">DUAL-STACK IP THREAT & REPUTATION INTELLIGENCE</p>
      <h2>IP 双栈信誉与威胁情报检测</h2>
      <p>同时并行检测主机的 IPv4 与 IPv6 公网信誉评分、机房/家宽属性、恶意行为风险及主流服务风控拦截状态。</p>

      <div v-if="reputationModalHost" class="fleet-host-action-target">
        <small>关联主机</small><b>{{ reputationModalHost.name }}</b>
        <span>{{ reputationModalHost.hostname || reputationModalHost.id }} · <span class="host-online-tag" :class="{ online: reputationModalHost.online }">{{ reputationModalHost.online ? '● 在线' : '○ 离线' }}</span> · {{ reputationModalHost.os || 'Linux' }}</span>
      </div>

      <!-- Quick Chips: Detected Host IPs -->
      <div v-if="reputationCandidateIPs.length" class="ip-rep-candidates">
        <small class="ip-rep-label">主机已识别双栈 IP（点击快速填入对应通道）：</small>
        <div class="ip-rep-chips">
          <button
            v-for="cand in reputationCandidateIPs"
            :key="cand.ip"
            type="button"
            class="ip-chip"
            :class="{
              active: cand.ip === reputationModalIPv4 || cand.ip === reputationModalIPv6,
              'chip-v4': cand.family === 'v4',
              'chip-v6': cand.family === 'v6'
            }"
            @click="selectCandidateIP(cand)"
          >
            <div class="ip-chip-title">
              <span class="family-tag" :class="cand.family">{{ cand.family.toUpperCase() }}</span>
              <b>{{ cand.ip }}</b>
            </div>
            <small>{{ cand.label }}</small>
          </button>
        </div>
      </div>

      <!-- Dual search/input bar -->
      <form class="ip-rep-dual-search" @submit.prevent="checkReputationBoth(false)">
        <div class="ip-search-group">
          <label>IPv4 地址</label>
          <div class="input-with-tag">
            <span class="input-family-tag v4">IPv4</span>
            <input
              v-model="reputationModalIPv4"
              type="text"
              class="ip-rep-input"
              placeholder="输入或粘贴 IPv4 地址..."
              spellcheck="false"
            >
          </div>
        </div>
        <div class="ip-search-group">
          <label>IPv6 地址</label>
          <div class="input-with-tag">
            <span class="input-family-tag v6">IPv6</span>
            <input
              v-model="reputationModalIPv6"
              type="text"
              class="ip-rep-input"
              placeholder="输入或粘贴 IPv6 地址..."
              spellcheck="false"
            >
          </div>
        </div>
        <div class="ip-search-actions">
          <button type="submit" class="primary" :disabled="(reputationStateIPv4?.loading || reputationStateIPv6?.loading)">
            {{ (reputationStateIPv4?.loading || reputationStateIPv6?.loading) ? '分析中…' : '同时检测' }}
          </button>
          <button
            type="button"
            class="secondary"
            :disabled="(reputationStateIPv4?.loading || reputationStateIPv6?.loading)"
            title="强制刷新（绕过本地缓存）"
            @click="checkReputationBoth(true)"
          >
            ↻ 刷新
          </button>
        </div>
      </form>

      <!-- Side-by-Side Dual-Stack Columns -->
      <div class="ip-rep-dual-columns">
        <!-- LEFT: IPv4 Column -->
        <section class="ip-rep-stack-column">
          <header class="stack-column-header">
            <div class="column-title">
              <span class="protocol-pill ipv4">IPv4 通道</span>
              <code v-if="reputationModalIPv4">{{ reputationModalIPv4 }}</code>
              <span v-else class="text-muted">未配置</span>
            </div>
            <button
              v-if="reputationModalIPv4"
              type="button"
              class="mini-btn secondary"
              @click="copy(reputationModalIPv4)"
            >
              复制
            </button>
          </header>

          <div v-if="!reputationModalIPv4.trim()" class="ip-rep-empty-column">
            <p>当前主机未检测到公网 IPv4 地址。<br>你可以在上方输入框填入任意 IPv4 进行检测。</p>
          </div>

          <div v-else-if="reputationStateIPv4?.loading && !reputationStateIPv4?.report" class="ip-rep-loading">
            <div class="ip-rep-spinner"></div>
            <span>正在分析 IPv4 威胁情报与信誉分…</span>
          </div>

          <div v-else-if="reputationStateIPv4?.error && !reputationStateIPv4?.report" class="ip-rep-error-box">
            <b>查询失败</b>
            <p>{{ reputationStateIPv4.error }}</p>
            <button type="button" class="secondary" @click="loadReputation(reputationModalIPv4, true)">重试</button>
          </div>

          <div v-else-if="reputationStateIPv4?.report" class="ip-rep-result">
            <div
              class="ip-rep-banner"
              :class="{
                'score-high': (reputationStateIPv4.report.trust_score ?? 0) >= 80,
                'score-medium': (reputationStateIPv4.report.trust_score ?? 0) >= 50 && (reputationStateIPv4.report.trust_score ?? 0) < 80,
                'score-low': (reputationStateIPv4.report.trust_score ?? 0) < 50
              }"
            >
              <div class="ip-rep-score-ring">
                <strong>{{ reputationStateIPv4.report.trust_score ?? '—' }}</strong>
                <small>/ 100</small>
              </div>
              <div class="ip-rep-verdict">
                <div class="ip-rep-verdict-title">
                  <h3>{{ (reputationStateIPv4.report.trust_score ?? 0) >= 80 ? '高信誉优质 IP' : ((reputationStateIPv4.report.trust_score ?? 0) >= 50 ? '中等信誉 IP' : '低信誉 / 风险 IP') }}</h3>
                  <span class="ip-rep-verdict-tag">{{ reputationStateIPv4.report.is_datacenter ? 'IDC 机房' : (reputationStateIPv4.report.isResidential ? '住宅家宽' : '标准网络') }}</span>
                </div>
                <p v-if="reputationStateIPv4.report.ai_verdict?.reasoning" class="ip-rep-reasoning">
                  <b>AI 研判：</b>{{ reputationStateIPv4.report.ai_verdict.reasoning }}
                </p>
              </div>
            </div>

            <div class="ip-rep-grid">
              <div class="ip-rep-card">
                <small>滥用评分</small>
                <b>{{ reputationStateIPv4.report.abuser_score || '0 (极低)' }}</b>
                <em>{{ reputationStateIPv4.report.intelligence?.abuser_level ? `等级: ${reputationStateIPv4.report.intelligence.abuser_level}` : '未见滥用记录' }}</em>
              </div>
              <div class="ip-rep-card">
                <small>Reddit 访问</small>
                <b :class="reputationStateIPv4.report.reddit_blocked ? 'text-danger' : 'text-success'">
                  {{ reputationStateIPv4.report.reddit_blocked ? '已屏蔽' : '正常访问' }}
                </b>
                <em>{{ reputationStateIPv4.report.reddit_blocked ? '可能受严格风控拦截' : '无特殊限制' }}</em>
              </div>
              <div class="ip-rep-card">
                <small>网络属性</small>
                <b>{{ reputationStateIPv4.report.is_datacenter ? '数据中心 (IDC)' : (reputationStateIPv4.report.isResidential ? '原生住宅' : '常规网络') }}</b>
                <em>{{ reputationStateIPv4.report.is_proxy ? '代理' : '' }} {{ reputationStateIPv4.report.is_vpn ? 'VPN' : '' }} {{ reputationStateIPv4.report.is_tor ? 'Tor' : '' }} {{ (!reputationStateIPv4.report.is_proxy && !reputationStateIPv4.report.is_vpn && !reputationStateIPv4.report.is_tor) ? '非公开代理' : '' }}</em>
              </div>
              <div class="ip-rep-card">
                <small>RPKI 路由安全</small>
                <b>{{ (reputationStateIPv4.report.rpki_status || 'valid').toUpperCase() }}</b>
                <em>BGP 路由原语验证</em>
              </div>
            </div>

            <div class="ip-rep-meta-list">
              <div v-if="reputationStateIPv4.report.cidr" class="ip-rep-meta-item">
                <span>广播 CIDR</span>
                <code>{{ reputationStateIPv4.report.cidr }}</code>
              </div>
              <div class="ip-rep-meta-item">
                <span>自治系统 (ASN)</span>
                <span>AS{{ reputationStateIPv4.report.asn }} · {{ reputationStateIPv4.report.asOrganization || reputationStateIPv4.report.asname || '—' }}</span>
              </div>
              <div class="ip-rep-meta-item">
                <span>运营商 / ISP</span>
                <span>{{ reputationStateIPv4.report.isp || reputationStateIPv4.report.company_name || '—' }}</span>
              </div>
              <div class="ip-rep-meta-item">
                <span>归属地理位置</span>
                <span>
                  <img
                    v-if="reputationStateIPv4.report.countryCode"
                    class="fleet-host-flag"
                    :src="countryFlagURL(reputationStateIPv4.report.countryCode)"
                    alt=""
                    aria-hidden="true"
                  >
                  {{ reputationStateIPv4.report.country || '' }} {{ reputationStateIPv4.report.region ? `· ${reputationStateIPv4.report.region}` : '' }} {{ reputationStateIPv4.report.city ? `· ${reputationStateIPv4.report.city}` : '' }}
                </span>
              </div>
            </div>
          </div>
        </section>

        <!-- RIGHT: IPv6 Column -->
        <section class="ip-rep-stack-column">
          <header class="stack-column-header">
            <div class="column-title">
              <span class="protocol-pill ipv6">IPv6 通道</span>
              <code v-if="reputationModalIPv6">{{ reputationModalIPv6 }}</code>
              <span v-else class="text-muted">未配置</span>
            </div>
            <button
              v-if="reputationModalIPv6"
              type="button"
              class="mini-btn secondary"
              @click="copy(reputationModalIPv6)"
            >
              复制
            </button>
          </header>

          <div v-if="!reputationModalIPv6.trim()" class="ip-rep-empty-column">
            <p>当前主机未检测到公网 IPv6 地址。<br>你可以在上方输入框填入任意 IPv6 进行检测。</p>
          </div>

          <div v-else-if="reputationStateIPv6?.loading && !reputationStateIPv6?.report" class="ip-rep-loading">
            <div class="ip-rep-spinner"></div>
            <span>正在分析 IPv6 威胁情报与信誉分…</span>
          </div>

          <div v-else-if="reputationStateIPv6?.error && !reputationStateIPv6?.report" class="ip-rep-error-box">
            <b>查询失败</b>
            <p>{{ reputationStateIPv6.error }}</p>
            <button type="button" class="secondary" @click="loadReputation(reputationModalIPv6, true)">重试</button>
          </div>

          <div v-else-if="reputationStateIPv6?.report" class="ip-rep-result">
            <div
              class="ip-rep-banner"
              :class="{
                'score-high': (reputationStateIPv6.report.trust_score ?? 0) >= 80,
                'score-medium': (reputationStateIPv6.report.trust_score ?? 0) >= 50 && (reputationStateIPv6.report.trust_score ?? 0) < 80,
                'score-low': (reputationStateIPv6.report.trust_score ?? 0) < 50
              }"
            >
              <div class="ip-rep-score-ring">
                <strong>{{ reputationStateIPv6.report.trust_score ?? '—' }}</strong>
                <small>/ 100</small>
              </div>
              <div class="ip-rep-verdict">
                <div class="ip-rep-verdict-title">
                  <h3>{{ (reputationStateIPv6.report.trust_score ?? 0) >= 80 ? '高信誉优质 IP' : ((reputationStateIPv6.report.trust_score ?? 0) >= 50 ? '中等信誉 IP' : '低信誉 / 风险 IP') }}</h3>
                  <span class="ip-rep-verdict-tag">{{ reputationStateIPv6.report.is_datacenter ? 'IDC 机房' : (reputationStateIPv6.report.isResidential ? '住宅家宽' : '标准网络') }}</span>
                </div>
                <p v-if="reputationStateIPv6.report.ai_verdict?.reasoning" class="ip-rep-reasoning">
                  <b>AI 研判：</b>{{ reputationStateIPv6.report.ai_verdict.reasoning }}
                </p>
              </div>
            </div>

            <div class="ip-rep-grid">
              <div class="ip-rep-card">
                <small>滥用评分</small>
                <b>{{ reputationStateIPv6.report.abuser_score || '0 (极低)' }}</b>
                <em>{{ reputationStateIPv6.report.intelligence?.abuser_level ? `等级: ${reputationStateIPv6.report.intelligence.abuser_level}` : '未见滥用记录' }}</em>
              </div>
              <div class="ip-rep-card">
                <small>Reddit 访问</small>
                <b :class="reputationStateIPv6.report.reddit_blocked ? 'text-danger' : 'text-success'">
                  {{ reputationStateIPv6.report.reddit_blocked ? '已屏蔽' : '正常访问' }}
                </b>
                <em>{{ reputationStateIPv6.report.reddit_blocked ? '可能受严格风控拦截' : '无特殊限制' }}</em>
              </div>
              <div class="ip-rep-card">
                <small>网络属性</small>
                <b>{{ reputationStateIPv6.report.is_datacenter ? '数据中心 (IDC)' : (reputationStateIPv6.report.isResidential ? '原生住宅' : '常规网络') }}</b>
                <em>{{ reputationStateIPv6.report.is_proxy ? '代理' : '' }} {{ reputationStateIPv6.report.is_vpn ? 'VPN' : '' }} {{ reputationStateIPv6.report.is_tor ? 'Tor' : '' }} {{ (!reputationStateIPv6.report.is_proxy && !reputationStateIPv6.report.is_vpn && !reputationStateIPv6.report.is_tor) ? '非公开代理' : '' }}</em>
              </div>
              <div class="ip-rep-card">
                <small>RPKI 路由安全</small>
                <b>{{ (reputationStateIPv6.report.rpki_status || 'valid').toUpperCase() }}</b>
                <em>BGP 路由原语验证</em>
              </div>
            </div>

            <div class="ip-rep-meta-list">
              <div v-if="reputationStateIPv6.report.cidr" class="ip-rep-meta-item">
                <span>广播 CIDR</span>
                <code>{{ reputationStateIPv6.report.cidr }}</code>
              </div>
              <div class="ip-rep-meta-item">
                <span>自治系统 (ASN)</span>
                <span>AS{{ reputationStateIPv6.report.asn }} · {{ reputationStateIPv6.report.asOrganization || reputationStateIPv6.report.asname || '—' }}</span>
              </div>
              <div class="ip-rep-meta-item">
                <span>运营商 / ISP</span>
                <span>{{ reputationStateIPv6.report.isp || reputationStateIPv6.report.company_name || '—' }}</span>
              </div>
              <div class="ip-rep-meta-item">
                <span>归属地理位置</span>
                <span>
                  <img
                    v-if="reputationStateIPv6.report.countryCode"
                    class="fleet-host-flag"
                    :src="countryFlagURL(reputationStateIPv6.report.countryCode)"
                    alt=""
                    aria-hidden="true"
                  >
                  {{ reputationStateIPv6.report.country || '' }} {{ reputationStateIPv6.report.region ? `· ${reputationStateIPv6.report.region}` : '' }} {{ reputationStateIPv6.report.city ? `· ${reputationStateIPv6.report.city}` : '' }}
                </span>
              </div>
            </div>
          </div>
        </section>
      </div>

      <div class="modal-actions ip-rep-actions">
        <small class="ip-rep-source">数据来源：Net.Coffee IP 威胁情报引擎 · 双栈结果自动本地缓存 24 小时</small>
        <button type="button" class="secondary" @click="modal = null">关闭</button>
      </div>
    </div>
    <div v-else-if="modal === 'host-update' && hostUpdateTarget" class="modal-card host-update-modal" role="dialog" aria-modal="true" @keydown.esc.prevent="modal = null">
      <button type="button" class="modal-close" @click="modal = null">×</button>
      <span class="modal-seal jade">升</span>
      <p class="eyebrow">VERSION UPGRADE</p>
      <h2>{{ isProbeHost(hostUpdateTarget) ? '轻量探针升级' : '面板服务升级' }}</h2>
      <p>{{ isProbeHost(hostUpdateTarget) ? '探针运行在远端 VPS 上，升级将自动替换二进制并保留全部连接凭据与节点配置。' : '面板运行在控制中心，升级将自动备份当前数据与配置，无缝升级二进制与前端资源。' }}</p>

      <div class="fleet-host-action-target">
        <div class="target-host-main">
          <small>目标主机</small>
          <img v-if="hostUpdateTarget.snapshot?.location?.countryCode" class="fleet-host-flag" :src="countryFlagURL(hostUpdateTarget.snapshot.location.countryCode)" alt="" aria-hidden="true">
          <b>{{ hostUpdateTarget.name }}</b>
        </div>
        <div class="target-host-sub">
          <span>{{ hostUpdateTarget.hostname || hostUpdateTarget.id }} · {{ isProbeHost(hostUpdateTarget) ? '轻量探针' : '面板主控' }}</span>
        </div>
      </div>

      <div v-if="hostUpdateJob?.status === 'success' && !hostReconnecting" class="version-diff-card version-diff-card-success">
        <div class="version-success-banner">
          <span class="version-success-check">✓</span>
          <div class="version-success-text">
            <b>{{ isProbeHost(hostUpdateTarget) ? '轻量探针升级成功' : '面板服务升级成功' }}</b>
            <span>当前运行版本：<strong>v{{ latestReleaseVersion }}</strong> · {{ hostUpdateTarget?.id === 'local' ? '本机进程已平滑重启并恢复正常，正在载入最新界面' : '远端进程已平滑重启并恢复正常通讯' }}</span>
          </div>
        </div>
      </div>
      <!-- 在线一键升级就绪：合并版本对比与操作按钮为单行卡片 -->
      <div v-else-if="!hostUpdating && !hostUpdateJob && !hostReconnecting && hostUpdateOnlineSupported(hostUpdateTarget)" class="version-update-merged-card">
        <div class="merged-diff-group">
          <div class="version-diff-box current">
            <span class="diff-label">当前运行版本</span>
            <span class="diff-val">{{ hostUpdateCurrentVersion(hostUpdateTarget) }}</span>
          </div>
          <div class="version-diff-arrow">➔</div>
          <div class="version-diff-box latest">
            <span class="diff-label">可升级至版本</span>
            <div class="diff-val-wrap">
              <span class="diff-val latest">v{{ latestReleaseVersion }}</span>
              <span class="diff-tag">最新发布</span>
            </div>
          </div>
        </div>

        <div class="merged-divider"></div>

        <div class="merged-action-group">
          <div class="merged-action-desc">
            <h4>在线一键升级</h4>
            <small>{{ isProbeHost(hostUpdateTarget) ? '由中央控制台向远端探针下发安全自更新指令' : '自动备份当前数据库与配置，无需登录终端无缝升级' }}</small>
            <p v-if="hostUpdateError && !hostUpdating && !hostUpdateJob" class="singbox-update-err-msg" style="margin-top: 4px;">{{ hostUpdateError }}</p>
          </div>
          <button type="button" class="primary singbox-start-btn merged-action-btn" :disabled="hostUpdating || !hostUpdateTarget.online" @click="startHostUpgrade(hostUpdateTarget)">
            🚀 立即升级{{ isProbeHost(hostUpdateTarget) ? '探针' : '面板' }}至 v{{ latestReleaseVersion }}
          </button>
        </div>
      </div>
      <div v-else class="version-diff-card">
        <div class="version-diff-box current">
          <span class="diff-label">当前运行版本</span>
          <span class="diff-val">{{ hostUpdateCurrentVersion(hostUpdateTarget) }}</span>
        </div>
        <div class="version-diff-arrow">➔</div>
        <div class="version-diff-box latest">
          <span class="diff-label">可升级至版本</span>
          <span class="diff-val">v{{ latestReleaseVersion }}</span>
          <span class="diff-tag">最新发布</span>
        </div>
      </div>

      <!-- 在线一键升级进行中进度条 -->
      <div v-if="hostUpdateOnlineSupported(hostUpdateTarget) && (hostUpdating || hostUpdateJob || hostReconnecting)" class="host-online-update-section">
        <div class="singbox-update-progress-card" :class="{ 'update-success-card': hostUpdateJob?.status === 'success' && !hostReconnecting }">
          <div class="progress-header">
            <span class="progress-status">
              <i :class="hostReconnecting ? 'status-icon spinning' : (hostUpdateJob?.status === 'success' ? 'status-icon success' : (hostUpdateJob?.status === 'failed' ? 'status-icon failed' : 'status-icon spinning'))"></i>
              <b>{{ hostReconnecting ? `面板服务正在平滑重启，正在等待重新连接 (第 ${hostReconnectAttempts} 次重试)…` : (hostReloadCountdown > 0 ? `面板服务升级成功，将在 ${hostReloadCountdown} 秒后自动刷新页面…` : (hostUpdateJob?.status === 'success' ? (isProbeHost(hostUpdateTarget) ? '轻量探针升级成功，已平滑重启' : '面板服务升级成功，已平滑重启') : (hostUpdateJob?.message || (hostUpdating ? '正在执行更新…' : '更新完成')))) }}</b>
            </span>
            <span class="progress-pct">{{ hostReconnecting ? 100 : (hostUpdateJob?.progress ?? 0) }}%</span>
          </div>
          <div class="progress-bar-track">
            <div class="progress-bar-fill" :style="{ width: `${hostReconnecting ? 100 : (hostUpdateJob?.progress ?? 0)}%` }" :class="{ success: hostUpdateJob?.status === 'success' || hostReconnecting, failed: hostUpdateJob?.status === 'failed' }"></div>
          </div>
          <p v-if="hostUpdateJob?.status === 'success' && !hostReconnecting" class="update-success-subhint">
            ✓ {{ hostUpdateTarget?.id === 'local' ? '中央本机已平滑加载新版本二进制，保留现有数据库与凭据，即将自动刷新。' : '远端服务已平滑加载新版本二进制，保留现有认证凭据与网络配置，已恢复正常通讯。' }}
          </p>
          <p v-if="hostUpdateError" class="singbox-update-err-msg">{{ hostUpdateError }}</p>
          <div v-if="hostUpdateJob?.status === 'failed' || hostUpdateError" class="progress-retry-action">
            <button type="button" class="mini-btn" @click="startHostUpgrade(hostUpdateTarget)">重新尝试升级</button>
          </div>
        </div>
      </div>
      <div v-else-if="!hostUpdateOnlineSupported(hostUpdateTarget) && isProbeHost(hostUpdateTarget)" class="host-update-warning-banner">
        <p><b>提示：</b>当前探针版本（{{ hostUpdateCurrentVersion(hostUpdateTarget) }}）尚未包含在线升级管道。请登录该机器终端执行下方升级命令，更新后将自动启用面板在线一键更新支持。</p>
      </div>
      <div v-else-if="!hostUpdateOnlineSupported(hostUpdateTarget)" class="host-update-warning-banner">
        <p><b>提示：</b>该远端面板主控当前运行版本（{{ hostUpdateCurrentVersion(hostUpdateTarget) }}）尚未包含跨机在线升级管道。更新至新版本后，将自动启用中央控制台在线一键升级支持。本次可直接登录该机自身 Web 面板在线更新，或在终端执行下方升级命令。</p>
      </div>

      <div v-if="hostUpdateJob?.status !== 'success' || hostReconnecting" class="host-update-command-section">
        <div class="update-command-header">
          <h4>{{ isProbeHost(hostUpdateTarget) ? '远端终端升级命令（备选）' : '服务器终端升级命令（备选）' }}</h4>
          <small>如需在终端手动执行，请登录目标机器以 <code>root</code> 执行：</small>
        </div>
        <div class="update-command-box">
          <code>{{ hostUpdateCommand(hostUpdateTarget) }}</code>
          <button type="button" class="mini-btn primary" @click="copyHostUpdateCommand(hostUpdateTarget)">
            📋 复制命令
          </button>
        </div>
      </div>

      <div v-if="latestReleaseNotes" class="host-update-notes-section">
        <h4>更新日志摘要 (v{{ latestReleaseVersion }})</h4>
        <div class="update-notes-body">
          <pre>{{ latestReleaseNotes }}</pre>
        </div>
      </div>

      <div class="modal-actions host-update-modal-actions">
        <a v-if="latestReleaseUrl" :href="latestReleaseUrl" target="_blank" rel="noopener noreferrer" class="release-external-link">
          查看 GitHub Release ↗
        </a>
        <div class="actions-right">
          <button v-if="hostUpdateJob?.status === 'success' && !hostReconnecting" type="button" class="primary" @click="modal = null">
            ✓ 升级完成{{ hostReloadCountdown > 0 ? `（${hostReloadCountdown} 秒后刷新）` : '（关闭）' }}
          </button>
          <template v-else>
            <button type="button" class="secondary" @click="modal = null">关闭</button>
            <button v-if="!hostUpdating && !hostReconnecting && hostUpdateOnlineSupported(hostUpdateTarget)" type="button" class="primary" @click="startHostUpgrade(hostUpdateTarget)">
              立即在线升级
            </button>
            <button v-else type="button" class="primary" @click="copyHostUpdateCommand(hostUpdateTarget)">
              复制升级命令
            </button>
          </template>
        </div>
      </div>
    </div>
    <div v-else-if="modal === 'singbox-update' && singBoxUpdateTarget" class="modal-card host-update-modal singbox-update-modal" role="dialog" aria-modal="true" @keydown.esc.prevent="modal = null">
      <button type="button" class="modal-close" @click="modal = null">×</button>
      <span class="modal-seal jade">核</span>
      <p class="eyebrow">RUNTIME UPGRADE</p>
      <h2>sing-box 代理内核升级</h2>
      <p>更新将自动校验并安全迁移托管节点配置、备份当前程序并平滑重启运行中的节点；更新后执行本地代理探测，失败将自动回滚。</p>

      <div class="fleet-host-action-target">
        <div class="target-host-main">
          <small>目标主机</small>
          <img v-if="singBoxUpdateTarget.snapshot?.location?.countryCode" class="fleet-host-flag" :src="countryFlagURL(singBoxUpdateTarget.snapshot.location.countryCode)" alt="" aria-hidden="true">
          <b>{{ singBoxUpdateTarget.name }}</b>
        </div>
        <div class="target-host-sub">
          <span>{{ singBoxUpdateTarget.hostname || singBoxUpdateTarget.id }} · sing-box 内核</span>
        </div>
      </div>

      <div v-if="singBoxUpdateJob?.status === 'success'" class="version-diff-card version-diff-card-success">
        <div class="version-success-banner">
          <span class="version-success-check">✓</span>
          <div class="version-success-text">
            <b>sing-box 内核已成功升级至最新版本</b>
            <span>当前运行版本：<strong>{{ latestSingBoxVersion }}</strong> · 节点与代理网络正常运行</span>
          </div>
        </div>
      </div>
      <div v-else class="version-diff-card">
        <div class="version-diff-box current">
          <span class="diff-label">当前运行版本</span>
          <span class="diff-val">{{ hostSingBoxVersion(singBoxUpdateTarget) || '—' }}</span>
        </div>
        <div class="version-diff-arrow">➔</div>
        <div class="version-diff-box latest">
          <span class="diff-label">可升级至版本</span>
          <span class="diff-val">{{ latestSingBoxVersion }}</span>
          <span class="diff-tag">官方稳定版</span>
        </div>
      </div>

      <!-- 配置兼容性预检 -->
      <div v-if="singBoxUpdateJob?.status !== 'success' && singBoxUpdateSupported(singBoxUpdateTarget)" class="singbox-preflight-card" :class="{ 'is-blocked': singBoxMigrationPlan && !singBoxMigrationPlan.compatible, 'is-success': singBoxMigrationPlan?.compatible }">
        <div class="singbox-preflight-head">
          <div class="singbox-preflight-title">
            <span class="preflight-status-badge" :class="{ spinning: singBoxMigrationLoading, success: !singBoxMigrationLoading && singBoxMigrationPlan?.compatible, blocked: !singBoxMigrationLoading && singBoxMigrationPlan && !singBoxMigrationPlan.compatible }">
              <i v-if="singBoxMigrationLoading" class="status-icon spinning"></i>
              <span v-else-if="singBoxMigrationPlan?.compatible">✓</span>
              <span v-else-if="singBoxMigrationPlan && !singBoxMigrationPlan.compatible">!</span>
              <span v-else>迁</span>
            </span>
            <div class="singbox-preflight-text">
              <div class="singbox-preflight-row">
                <b>配置兼容性预检</b>
                <span v-if="!singBoxMigrationLoading && singBoxMigrationPlan" class="preflight-tag" :class="singBoxMigrationPlan.compatible ? 'tag-success' : 'tag-blocked'">
                  {{ singBoxMigrationPlan.compatible ? '可安全迁移' : '存在阻断' }}
                </span>
              </div>
              <small v-if="singBoxMigrationLoading">正在只读扫描当前节点配置语法兼容性…</small>
              <small v-else-if="singBoxMigrationPlan?.compatible">
                {{ singBoxMigrationPlan.files.length }} 个节点配置已就绪 · {{ singBoxMigrationPlan.changes }} 项自动迁移 · 0 项阻断
              </small>
              <small v-else-if="singBoxMigrationPlan && !singBoxMigrationPlan.compatible" class="preflight-err-sub">
                检测到 {{ singBoxMigrationPlan.errors }} 项阻断，可能需要人工排查后再升级
              </small>
              <small v-else>正在准备只读扫描当前节点配置兼容性…</small>
            </div>
          </div>
          <button v-if="singBoxMigrationPlan?.files?.length && (singBoxMigrationPlan.changes > 0 || singBoxMigrationPlan.warnings > 0 || singBoxMigrationPlan.errors > 0)"
                  type="button" class="mini-btn preflight-toggle-btn" @click="singBoxMigrationDetailsOpen = !singBoxMigrationDetailsOpen">
            {{ singBoxMigrationDetailsOpen ? '收起详情 ▴' : '查看详情 ▾' }}
          </button>
        </div>

        <div v-if="singBoxMigrationDetailsOpen && singBoxMigrationPlan" class="singbox-preflight-details">
          <article v-for="file in singBoxMigrationPlan.files" :key="file.path" class="preflight-file-item">
            <div class="file-head">
              <b>{{ file.path.split(/[/\\]/).pop() || file.path }}</b>
              <small v-if="file.interfaces?.length">引用网卡 {{ file.interfaces.join(', ') }}</small>
              <span class="change-tag" v-if="file.changes?.length">{{ file.changes.length }} 项迁移</span>
            </div>
            <ul v-if="(file.changes || []).length || (file.warnings || []).length || (file.errors || []).length">
              <li v-for="item in file.changes || []" :key="`c-${item}`" class="change">＋ {{ item }}</li>
              <li v-for="item in file.warnings || []" :key="`w-${item}`" class="warning">! {{ item }}</li>
              <li v-for="item in file.errors || []" :key="`e-${item}`" class="error">× {{ item }}</li>
            </ul>
          </article>
        </div>
      </div>

      <!-- 在线一键更新进度或控制区 -->
      <div v-if="singBoxUpdateSupported(singBoxUpdateTarget)" class="singbox-online-update-section">
        <div v-if="singBoxUpdating || singBoxUpdateJob" class="singbox-update-progress-card" :class="{ 'update-success-card': singBoxUpdateJob?.status === 'success' }">
          <div class="progress-header">
            <span class="progress-status">
              <i :class="singBoxUpdateJob?.status === 'success' ? 'status-icon success' : (singBoxUpdateJob?.status === 'failed' ? 'status-icon failed' : 'status-icon spinning')"></i>
              <b>{{ singBoxUpdateJob?.status === 'success' ? 'sing-box 内核升级成功，已平滑重启' : (singBoxUpdateJob?.message || (singBoxUpdating ? '正在执行更新…' : '更新完成')) }}</b>
            </span>
            <span class="progress-pct">{{ singBoxUpdateJob?.progress ?? 0 }}%</span>
          </div>
          <div class="progress-bar-track">
            <div class="progress-bar-fill" :style="{ width: `${singBoxUpdateJob?.progress ?? 0}%` }" :class="{ success: singBoxUpdateJob?.status === 'success', failed: singBoxUpdateJob?.status === 'failed' }"></div>
          </div>
          <p v-if="singBoxUpdateJob?.status === 'success'" class="update-success-subhint">
            ✓ 内核服务已成功升级并完成健康探测，所有节点与网络规则已恢复正常代理。
          </p>
          <p v-if="singBoxUpdateError" class="singbox-update-err-msg">{{ singBoxUpdateError }}</p>
          <div v-if="singBoxUpdateJob?.status === 'failed'" class="progress-retry-action">
            <button type="button" class="mini-btn" @click="startSingBoxUpgrade(singBoxUpdateTarget)">重新尝试升级</button>
          </div>
        </div>
        <div v-else class="singbox-update-action-box">
          <div class="action-desc">
            <h4>在线一键升级</h4>
            <small>无需登录终端，点击后由中央控制台向主机调度自动化升级管道：</small>
          </div>
          <button type="button" class="primary singbox-start-btn" :disabled="singBoxUpdating || !singBoxUpdateTarget.online || singBoxMigrationLoading || Boolean(singBoxMigrationPlan && !singBoxMigrationPlan.compatible)" @click="startSingBoxUpgrade(singBoxUpdateTarget)">
            {{ singBoxMigrationLoading ? '正在检查配置兼容性…' : (singBoxMigrationPlan && !singBoxMigrationPlan.compatible) ? '存在配置阻断项，无法升级' : '🚀 立即升级内核至 ' + latestSingBoxVersion }}
          </button>
        </div>
      </div>

      <!-- 终端升级命令备选区 -->
      <div v-if="singBoxUpdateJob?.status !== 'success'" class="host-update-command-section">
        <div class="update-command-header">
          <h4>服务器终端一键升级命令</h4>
          <small>如需在终端手动执行，请登录目标机器以 <code>root</code> 执行：</small>
        </div>
        <div class="update-command-box">
          <code>{{ getSingBoxUpdateCommand() }}</code>
          <button type="button" class="mini-btn primary" @click="copySingBoxUpdateCommand">
            📋 复制命令
          </button>
        </div>
      </div>

      <div class="modal-actions host-update-modal-actions">
        <a v-if="latestSingBoxUrl" :href="latestSingBoxUrl" target="_blank" rel="noopener noreferrer" class="release-external-link">
          查看 sing-box Release ↗
        </a>
        <div class="actions-right">
          <button v-if="singBoxUpdateJob?.status === 'success'" type="button" class="primary" @click="modal = null">
            ✓ 升级完成（关闭）
          </button>
          <template v-else>
            <button type="button" class="secondary" @click="modal = null">关闭</button>
            <button v-if="!singBoxUpdating && singBoxUpdateSupported(singBoxUpdateTarget)" type="button" class="primary" :disabled="singBoxMigrationLoading || Boolean(singBoxMigrationPlan && !singBoxMigrationPlan.compatible)" @click="startSingBoxUpgrade(singBoxUpdateTarget)">
              {{ (singBoxMigrationPlan && !singBoxMigrationPlan.compatible) ? '存在配置阻断' : '立即升级内核' }}
            </button>
            <button v-else type="button" class="primary" @click="copySingBoxUpdateCommand">
              复制升级命令
            </button>
          </template>
        </div>
      </div>
    </div>
    <div v-else-if="modal === 'fleet-order'" class="modal-card fleet-order-modal" role="dialog" aria-modal="true" @keydown.esc.prevent="modal = null">
      <button type="button" class="modal-close" @click="modal = null">×</button>
      <span class="modal-seal">序</span>
      <p class="eyebrow">FLEET REORDER</p>
      <h2>主机卡片自定义排序</h2>
      <p>拖拽或点击上下箭头调整远端主机的排列顺序；中央本机与全局卡片位置保持固定。</p>

      <!-- 固定置顶中央本机提示 -->
      <div class="fleet-order-pinned-box">
        <div class="order-item-left">
          <span class="order-drag-handle disabled" title="中央本机固定首位，不可移动">🔒</span>
          <span class="order-index-badge">#1</span>
          <div class="order-host-info">
            <div class="order-host-main">
              <img v-if="centralFleetHost?.snapshot?.location?.countryCode" class="fleet-host-flag" :src="countryFlagURL(centralFleetHost.snapshot.location.countryCode)" alt="" aria-hidden="true">
              <b>中央本机</b>
              <span class="order-type-badge central">本机</span>
              <span class="order-online-dot online"></span>
            </div>
            <small class="order-host-meta">
              <span v-if="centralFleetHost?.os">{{ centralFleetHost.os }} · {{ centralFleetHost.arch || 'amd64' }}</span>
              <span v-if="centralFleetHost?.expiresAt"> · <span :class="expiryTone(centralFleetHost.expiresAt)">{{ expiryLabel(centralFleetHost.expiresAt) }}</span></span>
              <span> · 流量 {{ fleetBillingUsage(centralFleetHost?.snapshot?.overview) }}</span>
              <span v-if="centralFleetHost && fleetNetworkGroup(centralFleetHost, 'domestic')?.latencyMs"> · 国内 {{ fleetNetworkGroup(centralFleetHost, 'domestic')!.latencyMs.toFixed(1) }}ms</span>
            </small>
          </div>
        </div>
        <span class="pinned-badge">固定置顶</span>
      </div>

      <!-- 一键智能预设排序 -->
      <div class="fleet-order-presets">
        <span class="presets-label">快捷预设：</span>
        <div class="presets-buttons">
          <button type="button" class="mini-btn preset-btn" title="按国内延迟升序排列（网络最好排在前面）" @click="applyHostPresetSort('latency')">⚡ 国内延迟</button>
          <button type="button" class="mini-btn preset-btn" title="按到期时间升序排列（最近到期排在前面）" @click="applyHostPresetSort('expiry')">📅 到期时间</button>
          <button type="button" class="mini-btn preset-btn" title="按本账期已消耗流量降序排列" @click="applyHostPresetSort('traffic')">📊 账期流量</button>
          <button type="button" class="mini-btn preset-btn" title="按主机名称字母 A-Z 排列" @click="applyHostPresetSort('name')">🔤 主机名称</button>
          <button type="button" class="mini-btn preset-btn" title="恢复默认注册先后顺序" @click="applyHostPresetSort('default')">↺ 恢复默认</button>
        </div>
      </div>

      <!-- 远端主机排序列表 -->
      <div class="fleet-order-list">
        <div
          v-for="(h, idx) in fleetOrderList"
          :key="h.id"
          class="fleet-order-item"
          :class="{
            'is-dragging': modalDraggedIndex === idx,
            'drag-over': modalDragOverIndex === idx
          }"
          draggable="true"
          @dragstart="onModalDragStart($event, idx)"
          @dragover.prevent="onModalDragOver($event, idx)"
          @dragleave="modalDragOverIndex = null"
          @drop.prevent="onModalDrop($event, idx)"
          @dragend="onModalDragEnd"
        >
          <div class="order-item-left">
            <span class="order-drag-handle" title="按住拖拽调整顺序">⠿</span>
            <span class="order-index-badge">#{{ idx + 2 }}</span>
            <div class="order-host-info">
              <div class="order-host-main">
                <img v-if="h.snapshot?.location?.countryCode" class="fleet-host-flag" :src="countryFlagURL(h.snapshot.location.countryCode)" alt="" aria-hidden="true">
                <b>{{ h.name }}</b>
                <span class="order-type-badge">{{ isProbeHost(h) ? '轻量探针' : '面板' }}</span>
                <span class="order-online-dot" :class="{ online: h.online }"></span>
              </div>
              <small class="order-host-meta">
                <span v-if="h.os">{{ h.os }} · {{ h.arch }}</span>
                <span v-if="h.os"> · </span>
                <span v-if="h.expiresAt" :class="expiryTone(h.expiresAt)">{{ expiryLabel(h.expiresAt) }}</span>
                <span v-if="h.expiresAt"> · </span>
                <span>流量 {{ fleetBillingUsage(h.snapshot?.overview) }}</span>
                <span v-if="fleetNetworkGroup(h, 'domestic')?.latencyMs"> · 国内 {{ fleetNetworkGroup(h, 'domestic')!.latencyMs.toFixed(1) }}ms</span>
              </small>
            </div>
          </div>

          <div class="order-item-actions">
            <button type="button" class="mini-btn move-btn" :disabled="idx === 0" title="置顶到远端首位" @click="moveFleetHostInList(idx, 0)">⤒ <span class="move-label">置顶</span></button>
            <button type="button" class="mini-btn move-btn" :disabled="idx === 0" title="上移一位" @click="moveFleetHostInList(idx, idx - 1)">▲ <span class="move-label">上移</span></button>
            <button type="button" class="mini-btn move-btn" :disabled="idx === fleetOrderList.length - 1" title="下移一位" @click="moveFleetHostInList(idx, idx + 1)">▼ <span class="move-label">下移</span></button>
            <button type="button" class="mini-btn move-btn" :disabled="idx === fleetOrderList.length - 1" title="置底到远端末位" @click="moveFleetHostInList(idx, fleetOrderList.length - 1)">⤓ <span class="move-label">置底</span></button>
          </div>
        </div>
      </div>

      <!-- 舰队全局卡片固定提示 -->
      <div v-if="(fleetOrderList.length + 1) % 2 === 1" class="fleet-order-companion-box">
        <div class="companion-box-left">
          <span class="companion-seal-small">阵</span>
          <span><b>舰队全局扩容舱</b>（当前主机总数为奇数，固定排在最后一位扩展为双列网格）</span>
        </div>
        <span class="pinned-badge">固定末位</span>
      </div>

      <div class="modal-actions">
        <button type="button" class="secondary" @click="modal = null">取消</button>
        <button type="button" class="primary" :disabled="fleetOrderSaving" @click="saveFleetOrderModal">
          {{ fleetOrderSaving ? '正在保存…' : '保存排序' }}
        </button>
      </div>
    </div>
    <form v-else-if="modal === 'residential-remove'" class="modal-card compact danger-modal residential-remove-modal" @submit.prevent="removeResidentialExit"><span class="modal-seal red">撤</span><p class="eyebrow">RESIDENTIAL EGRESS REMOVAL</p><h2>移除落地出口？</h2><p>这会停止 A 机的落地出口隧道，删除本机 WireGuard 配置、fail-closed 策略路由和保存的 A 机密钥。</p><div class="residential-remove-impact"><article><b>A 机</b><span>隧道、策略路由与本机密钥将移除</span></article><article><b>B 机</b><span>配置不会远程删除，之后需运行 <code>--remove-residential-peer</code></span></article></div><p v-if="residentialNodesInUse.length" class="residential-remove-blocked"><b>暂时无法移除</b><span>以下节点仍在使用落地出口：{{ residentialNodesInUse.map(node => node.name).join('、') }}。请先将它们切回 A 机本地直出。</span></p><label>输入 <code>REMOVE</code> 确认<input v-model="residentialRemoveConfirm" autocomplete="off" spellcheck="false" placeholder="REMOVE" autofocus required></label><div class="modal-actions"><button type="button" class="secondary" :disabled="residentialBusy" @click="modal = null">保留落地出口</button><button class="danger-button" :disabled="residentialBusy || residentialRemoveConfirm !== 'REMOVE' || residentialNodesInUse.length > 0">{{ residentialBusy ? '正在移除…' : '确认移除' }}</button></div></form>
    <form v-else-if="modal === 'socks-remove'" class="modal-card compact danger-modal residential-remove-modal" @submit.prevent="removeSOCKSExit"><span class="modal-seal red">撤</span><p class="eyebrow">SOCKS EGRESS REMOVAL</p><h2>移除 SOCKS 出站？</h2><p>这会删除 Root Agent 加密保存的 SOCKS 服务器与认证信息，不会修改上游代理。</p><p v-if="socksNodesInUse.length" class="residential-remove-blocked"><b>暂时无法移除</b><span>以下节点仍在使用 SOCKS 出站：{{ socksNodesInUse.map(node => node.name).join('、') }}。请先将它们切回其他出口。</span></p><label>输入 <code>REMOVE</code> 确认<input v-model="socksRemoveConfirm" autocomplete="off" spellcheck="false" placeholder="REMOVE" autofocus required></label><div class="modal-actions"><button type="button" class="secondary" :disabled="socksBusy" @click="modal = null">保留 SOCKS 出站</button><button class="danger-button" :disabled="socksBusy || socksRemoveConfirm !== 'REMOVE' || socksNodesInUse.length > 0">{{ socksBusy ? '正在移除…' : '确认移除' }}</button></div></form>
    <div v-else-if="modal === 'diagnostic' && diagnosticNode" class="modal-card wide diagnostic-modal" role="dialog" aria-modal="true" @keydown.esc.prevent="modal = null">
      <button type="button" class="modal-close" aria-label="关闭" @click="modal = null">×</button>
      <div class="diagnostic-modal-head">
        <span class="modal-seal" :class="probeState(diagnosticNode) === 'success' ? 'jade' : probeState(diagnosticNode) === 'failed' ? 'red' : ''">
          {{ probeState(diagnosticNode) === 'success' ? '通' : probeState(diagnosticNode) === 'failed' ? '断' : '测' }}
        </span>
        <div>
          <p class="eyebrow">NODE PROXY LOOPBACK DIAGNOSTIC</p>
          <h2>{{ diagnosticNode.name }} 代理闭环诊断</h2>
          <div class="diagnostic-head-tags">
            <span class="protocol-badge">{{ protocolInfo(diagnosticNode.protocol).badge }}</span>
            <span class="diag-status-pill" :class="probeState(diagnosticNode)">
              <i class="diag-dot"></i>
              {{ probeState(diagnosticNode) === 'running' ? '闭环检测中' : probeState(diagnosticNode) === 'success' ? '闭环正常' : probeState(diagnosticNode) === 'failed' ? '检测异常' : '未检测' }}
            </span>
            <span v-if="diagnosticNode.probeCheckedAt" class="diag-time-pill" :title="formatFullDateTime(diagnosticNode.probeCheckedAt, language)">
              {{ formatRelativeTime(diagnosticNode.probeCheckedAt, undefined, language) }}
            </span>
            <span class="node-rate-badge" :class="{ active: nodeRate(diagnosticNode.id) > 0 }">
              <i class="rate-dot"></i>
              <span>{{ rate(nodeRate(diagnosticNode.id)) }}</span>
            </span>
          </div>
        </div>
      </div>

      <div class="diagnostic-pipeline">
        <div class="pipeline-step" :class="{ ok: probeState(diagnosticNode) === 'success', running: probeState(diagnosticNode) === 'running', failed: probeState(diagnosticNode) === 'failed' }">
          <div class="step-num">1</div>
          <div class="step-body">
            <b>{{ diagnosticNode.protocol === 'vless-ws-tunnel' ? 'Edge TLS / WebSocket' : '传输握手 & 安全层' }}</b>
            <small>{{ diagnosticNode.protocol === 'vless-ws-tunnel' ? 'Cloudflare CDN 边缘协商' : `${protocolInfo(diagnosticNode.protocol).transport} 协议握手` }}</small>
          </div>
        </div>
        <div class="pipeline-arrow" aria-hidden="true">➔</div>
        <div class="pipeline-step" :class="{ ok: probeState(diagnosticNode) === 'success', running: probeState(diagnosticNode) === 'running', failed: probeState(diagnosticNode) === 'failed' }">
          <div class="step-num">2</div>
          <div class="step-body">
            <b>入站凭据鉴权</b>
            <small>UUID / 密码 / 核心认证</small>
          </div>
        </div>
        <div class="pipeline-arrow" aria-hidden="true">➔</div>
        <div class="pipeline-step" :class="{ ok: probeState(diagnosticNode) === 'success', running: probeState(diagnosticNode) === 'running', failed: probeState(diagnosticNode) === 'failed' }">
          <div class="step-num">3</div>
          <div class="step-body">
            <b>核心路由出站</b>
            <small>{{ outboundLabel(diagnosticNode) }}</small>
          </div>
        </div>
        <div class="pipeline-arrow" aria-hidden="true">➔</div>
        <div class="pipeline-step" :class="{ ok: probeState(diagnosticNode) === 'success', running: probeState(diagnosticNode) === 'running', failed: probeState(diagnosticNode) === 'failed' }">
          <div class="step-num">4</div>
          <div class="step-body">
            <b>探测目标响应</b>
            <small>{{ diagnosticNode.probeTarget || 'www.cloudflare.com' }}</small>
          </div>
        </div>
      </div>

      <div class="diagnostic-metrics-grid">
        <div class="diag-metric-card">
          <small>往返闭环延迟</small>
          <strong :class="{ 'latency-good': (diagnosticNode.probeLatencyMs || 0) > 0 && (diagnosticNode.probeLatencyMs || 0) < 300, 'latency-mid': (diagnosticNode.probeLatencyMs || 0) >= 300 }">
            {{ diagnosticNode.probeLatencyMs ? `${diagnosticNode.probeLatencyMs} ms` : '—' }}
          </strong>
          <span>代理端点完整闭环耗时</span>
        </div>
        <div class="diag-metric-card">
          <small>探测目标端点</small>
          <code>{{ diagnosticNode.probeTarget || 'www.cloudflare.com' }}</code>
          <span>HTTP/TLS 真实可达性验证</span>
        </div>
        <div class="diag-metric-card">
          <small>落地公网出口 IP</small>
          <div class="diag-ip-row">
            <code>{{ diagnosticNode.probeExitIp || '未检测到' }}</code>
            <button v-if="diagnosticNode.probeExitIp" type="button" class="mini-btn copy-btn" title="复制出口 IP" @click="copy(diagnosticNode.probeExitIp)">复制</button>
            <button v-if="diagnosticNode.probeExitIp" type="button" class="mini-btn rep-btn" title="查询该 IP 威胁情报与信誉分" @click="openReputationModal(currentFleetHost || undefined, diagnosticNode.probeExitIp)">查信誉</button>
          </div>
          <span>经由 sing-box 路由实际出站 IP</span>
        </div>
        <div class="diag-metric-card">
          <small>主机防火墙状态</small>
          <div class="diag-fw-row">
            <span class="node-fw-badge" :class="nodeFirewallStatus(diagnosticNode).class">
              <i class="fw-dot"></i>
              <span>{{ nodeFirewallStatus(diagnosticNode).label }}</span>
            </span>
            <small class="diag-fw-port">{{ diagnosticNode.protocol === 'vless-ws-tunnel' ? '本地回环' : `${diagnosticNode.listenPort}/${protocolInfo(diagnosticNode.protocol).transport}` }}</small>
          </div>
          <span>{{ nodeFirewallStatus(diagnosticNode).title }}</span>
        </div>
        <div class="diag-metric-card">
          <small>{{ language === 'en-US' ? 'Cumulative Traffic' : '节点累计传输流量' }}</small>
          <strong>{{ bytes(diagnosticNode.trafficBytes || 0) }}</strong>
          <span>{{ nodeTrafficTooltip(diagnosticNode) }}</span>
        </div>
        <div class="diag-metric-card">
          <small>{{ language === 'en-US' ? 'Last Verification' : '最后校验时间' }}</small>
          <b class="diag-timestamp">{{ diagnosticNode.probeCheckedAt ? formatFullDateTime(diagnosticNode.probeCheckedAt, language) : (language === 'en-US' ? 'Not yet probed' : '尚未检测') }}</b>
          <span>{{ diagnosticNode.probeCheckedAt ? formatRelativeTime(diagnosticNode.probeCheckedAt, undefined, language) : (language === 'en-US' ? 'Click button below to probe' : '点击下方按钮发起检测') }}</span>
        </div>
      </div>

      <div v-if="diagnosticNode.probeError" class="diagnostic-error-box" role="alert">
        <div class="error-head">
          <span>⚠ 异常诊断报告</span>
          <button type="button" class="mini-btn copy-btn" @click="copy(diagnosticNode.probeError)">复制错误</button>
        </div>
        <code>{{ diagnosticNode.probeError }}</code>
        <div class="diagnostic-tips">
          <p><b>排障建议：</b></p>
          <ul>
            <li v-if="diagnosticNode.probeError.includes('timeout') || diagnosticNode.probeError.includes('refused') || diagnosticNode.probeError.includes('reset')">
              检测到网络超时或连接重置：请检查节点服务是否正在运行、主机防火墙（UFW/nftables）或云服务商控制台安全组是否已放行端口。
            </li>
            <li v-if="diagnosticNode.probeError.includes('tls') || diagnosticNode.probeError.includes('handshake') || diagnosticNode.probeError.includes('certificate')">
              检测到 TLS 握手异常：请检查 REALITY 伪装域名证书、SNI 是否有效；或节点证书文件是否过期失效。
            </li>
            <li v-if="diagnosticNode.protocol === 'vless-ws-tunnel'">
              Cloudflare Tunnel 节点：请检查 cloudflared 进程连接状态、隧道 Token 是否有效以及 Cloudflare 优选节点连通性。
            </li>
            <li>{{ language === 'en-US' ? 'Check "Jobs" in the left sidebar for detailed system troubleshooting logs.' : '可查阅左侧导航“任务日志”了解系统详细排错日志。' }}</li>
          </ul>
        </div>
      </div>

      <div class="modal-actions">
        <button type="button" class="secondary" @click="modal = null">关闭</button>
        <button
          type="button"
          class="primary"
          :disabled="mutationsDisabled || diagnosticNode.status !== 'active' || probeState(diagnosticNode) === 'running'"
          @click="probeNode(diagnosticNode)"
        >
          {{ probeState(diagnosticNode) === 'running' ? '正在检测中…' : '⚡ 立即重新检测' }}
        </button>
      </div>
    </div>
    <form v-else class="modal-card compact danger-modal" @submit.prevent="deleteNode"><span class="modal-seal red">删</span><p class="eyebrow">DESTRUCTIVE ACTION</p><h2>删除 {{ selectedNode?.name }}？</h2><p>{{ selectedNode?.sharedGroup && selectedNode?.ownership === 'managed' ? '系统将先创建带 SHA-256 的配置快照，只移除此设备的独立入站并重启共享进程；最后一台设备才会删除组服务。' : '系统将先创建带 SHA-256 的配置快照，再停止并删除节点服务。' }}请输入完整节点名称确认。</p><label>节点名称<input v-model="deleteConfirm" autocomplete="off" required></label><div class="modal-actions"><button type="button" class="secondary" @click="modal = null">取消</button><button class="danger-button" :disabled="busy || deleteConfirm !== selectedNode?.name">确认删除</button></div></form>
  </div>
  <transition name="toast">
    <div v-if="deploymentProgress" class="deployment-progress-indicator" role="status" aria-live="polite">
      <div class="deployment-progress-header">
        <i class="deployment-spinner"></i>
        <div class="deployment-progress-body">
          <span class="deployment-progress-title">{{ deploymentProgress.targetName }}</span>
          <span class="deployment-progress-msg">{{ deploymentProgress.message }} ({{ deploymentProgress.progress }}%)</span>
        </div>
      </div>
      <div class="deployment-progress-bar"><i :style="{ width: `${deploymentProgress.progress}%` }"></i></div>
    </div>
  </transition>
  <transition name="toast">
    <div v-if="deploymentReady" class="deployment-ready-card" role="alert">
      <div class="ready-header">
        <span class="ready-badge">✓</span>
        <div class="ready-copy">
          <b>{{ deploymentReady.title }}</b>
          <p>{{ deploymentReady.message }}</p>
        </div>
        <button type="button" class="ready-close-btn" :title="language === 'en-US' ? 'Dismiss' : '关闭'" @click="deploymentReady = null">✕</button>
      </div>
      <div class="ready-actions">
        <button v-if="deploymentReady.node" type="button" class="ready-action-btn primary" @click="quickCopyShare(deploymentReady.node)">
          {{ language === 'en-US' ? 'Copy Share Link' : '复制分享链接' }}
        </button>
        <button v-if="deploymentReady.node" type="button" class="ready-action-btn secondary" @click="revealShare(deploymentReady.node); deploymentReady = null">
          {{ language === 'en-US' ? 'QR Code' : '二维码 / 链接' }}
        </button>
        <button v-if="fleetStatus?.globalSubscription" type="button" class="ready-action-btn secondary" @click="copy(fleetStatus.globalSubscription)">
          {{ language === 'en-US' ? 'Copy Subscription' : '复制全局订阅' }}
        </button>
      </div>
    </div>
  </transition>
  <transition name="toast"><div v-if="toast" class="toast">{{ toast }}</div></transition>
</template>
