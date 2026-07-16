<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import QRCode from 'qrcode'
import { api, setCSRF, type Candidate, type EndpointStat, type Job, type NodeDeploymentDefaults, type NodeItem, type Overview, type Settings, type SingBoxMigrationPlan, type TrafficBucket, type TrafficTimeline } from './api'

type Page = 'overview' | 'nodes' | 'traffic' | 'system' | 'jobs' | 'settings'
type DeviceDraft = { key: number; name: string; listenPort: number; server: string; preferredServer: string; webSocketPath: string }

const authenticated = ref(false)
const loading = ref(true)
const username = ref('admin')
const password = ref('')
const loginError = ref('')
const mustChange = ref(false)
const newPassword = ref('')
const page = ref<Page>('overview')
const overview = ref<Overview | null>(null)
const nodes = ref<NodeItem[]>([])
const jobs = ref<Job[]>([])
const jobList = ref<HTMLElement | null>(null)
const settings = ref<Settings>({ language: 'zh-CN', timezone: 'Asia/Shanghai', interface: 'auto', trafficQuotaBytes: 0, billingResetDay: 1, collectEndpoints: true })
const endpoints = ref<EndpointStat[]>([])
const timeline = ref<TrafficTimeline | null>(null)
const migrationPlan = ref<SingBoxMigrationPlan | null>(null)
const migrationLoading = ref(false)
const timelineRange = ref<'today' | 'billing'>('today')
const activeTimelineBucket = ref<number | null>(null)
const deviceLimit = ref(3)
const busy = ref(false)
const toast = ref('')
const language = ref<'zh-CN' | 'en-US'>('zh-CN')
const modal = ref<'create' | 'device-create' | 'import' | 'share' | 'rename' | 'delete' | null>(null)
const candidates = ref<Candidate[]>([])
const selectedCandidates = ref<string[]>([])
const selectedNode = ref<NodeItem | null>(null)
const shareURI = ref('')
const shareQR = ref('')
const renameName = ref('')
const deleteConfirm = ref('')
const createForm = reactive({ protocol: 'hysteria2', name: '', mode: 'prefer_v6', listenPort: 0, server: '', domain: '', preferredServer: '', webSocketPath: '', tunnelToken: '', ipv4Bind: '', ipv6Bind: '', autoBind: true, v6OnlyDomains: 'chatgpt.com,claude.ai,anthropic.com', certificatePath: '', keyPath: '' })
const deviceMode = computed(() => modal.value === 'device-create')
const deviceSequence = ref(0)
const deviceNodes = reactive<DeviceDraft[]>([])
const deploymentDefaults = ref<NodeDeploymentDefaults>({ panelDomain: '', ipv4: [], ipv6: [] })
const bindChoice = reactive({ ipv4: '', ipv6: '' })
const defaultsLoading = ref(false)
const probeJobs = reactive<Record<string, string>>({})

const words = {
  'zh-CN': { overview: '总览', nodes: '节点', traffic: '流量', system: '系统', jobs: '任务日志', settings: '设置', deploy: '部署节点', import: '接管节点', online: '在线', offline: '离线' },
  'en-US': { overview: 'Overview', nodes: 'Nodes', traffic: 'Traffic', system: 'System', jobs: 'Jobs', settings: 'Settings', deploy: 'Deploy node', import: 'Import nodes', online: 'Online', offline: 'Offline' },
}
const t = (key: keyof typeof words['zh-CN']) => words[language.value][key]
const navItems = computed(() => [
  { id: 'overview' as Page, seal: '总', label: t('overview') },
  { id: 'nodes' as Page, seal: '节', label: t('nodes') },
  { id: 'traffic' as Page, seal: '流', label: t('traffic') },
  { id: 'system' as Page, seal: '系', label: t('system') },
  { id: 'jobs' as Page, seal: '任', label: t('jobs') },
  { id: 'settings' as Page, seal: '设', label: t('settings') },
])

const trafficPercent = computed(() => {
  const data = overview.value
  if (!data?.trafficQuota) return 0
  return Math.min(100, data.trafficUsed / data.trafficQuota * 100)
})
const quotaRing = computed(() => ({ '--progress': `${trafficPercent.value * 3.6}deg` }))
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
const protocolCatalog = {
  hysteria2: { badge: 'HY2', label: 'Hysteria2', transport: 'UDP', domainLabel: 'TLS 域名', note: 'QUIC 高速节点，适合弱网与高延迟链路。' },
  vless: { badge: 'VLESS', label: 'VLESS + REALITY', transport: 'TCP', domainLabel: 'REALITY 伪装域名', note: 'TCP 备用线路；域名必须是本机可访问的真实 TLS 站点。' },
  'vless-ws-tunnel': { badge: 'VLESS · CF', label: 'VLESS + WebSocket + Cloudflare Tunnel', transport: 'WS · CF', domainLabel: 'Cloudflare 节点域名', note: 'Cloudflare 边缘 443 入站；VPS 仅监听本机 Origin，不开放代理端口。' },
  shadowsocks: { badge: 'SS2022', label: 'Shadowsocks 2022', transport: 'TCP + UDP', domainLabel: '', note: '轻量双栈节点，使用 2022 AES-128-GCM。' },
  tuic: { badge: 'TUIC', label: 'TUIC v5', transport: 'UDP', domainLabel: 'TLS 域名', note: 'QUIC 低延迟节点，使用 BBR 拥塞控制。' },
  trojan: { badge: 'TROJAN', label: 'Trojan TLS', transport: 'TCP', domainLabel: 'TLS 域名', note: '基于标准 TLS 的 TCP 兼容节点。' },
} as const
function protocolInfo(protocol: string) { return protocolCatalog[protocol as keyof typeof protocolCatalog] || protocolCatalog.hysteria2 }
const selectedProtocolInfo = computed(() => protocolInfo(createForm.protocol))
const isTunnelProtocol = computed(() => createForm.protocol === 'vless-ws-tunnel')

function bytes(value = 0) {
  if (!Number.isFinite(value)) return '—'
  const units = ['B', 'KB', 'MB', 'GB', 'TB']
  let size = Math.max(0, value); let index = 0
  while (size >= 1000 && index < units.length - 1) { size /= 1000; index++ }
  return `${size.toFixed(index < 2 ? 0 : 2)} ${units[index]}`
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
function uptime(value = 0) { const days = Math.floor(value / 86400); const hours = Math.floor(value % 86400 / 3600); return days ? `${days}天 ${hours}时` : `${hours}时` }
function modeLabel(mode: string) { return ({ prefer_v6: 'IPv6 优先', v4only: '纯 IPv4', v6only: '纯 IPv6' } as Record<string, string>)[mode] || mode }
function jobLabel(kind: string) { return ({ 'node.create': '部署节点', 'node.create_batch': '部署设备节点', 'node.rename': '重命名节点', 'node.start': '启动节点', 'node.stop': '停止节点', 'node.restart': '重启节点', 'node.check': '校验配置', 'node.probe': '连通性检测', 'node.delete': '删除节点', 'nodes.import': '接管节点' } as Record<string, string>)[kind] || kind }
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
  if (state === 'success') return `${node.probeLatencyMs || 0} ms${node.probeExitIp ? ` · ${node.probeExitIp}` : ''}${probeTime(node.probeCheckedAt) ? ` · ${probeTime(node.probeCheckedAt)}` : ''}`
  if (state === 'failed') return node.probeError || '完整代理请求未通过'
  return node.protocol === 'vless-ws-tunnel' ? 'CF TLS · WebSocket · 认证 · 出站' : '握手 · 认证 · 出站'
}
function nodePublicPort(node: NodeItem) { return node.protocol === 'vless-ws-tunnel' ? 443 : node.listenPort }
function tunnelOrigin(node: NodeItem) { return `http://127.0.0.1:${node.listenPort}` }
function nodeDialServer(node: NodeItem) { return node.protocol === 'vless-ws-tunnel' && node.preferredServer ? node.preferredServer : node.server || node.domain }
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

async function bootstrap() {
  loading.value = true
  try {
    const me = await api.me(); setCSRF(me.csrf); authenticated.value = true; username.value = me.username; mustChange.value = me.mustChange
    if (!me.mustChange) await refreshAll()
  } catch { authenticated.value = false }
  finally { loading.value = false }
}
async function login() {
  busy.value = true; loginError.value = ''
  try { const result = await api.login(username.value, password.value); setCSRF(result.csrf); mustChange.value = result.mustChange; authenticated.value = true; password.value = ''; if (!result.mustChange) await refreshAll() }
  catch (error) { loginError.value = error instanceof Error ? error.message : '登录失败' }
  finally { busy.value = false }
}
async function changePassword() {
  busy.value = true
  try { await api.changePassword(newPassword.value); mustChange.value = false; authenticated.value = false; newPassword.value = ''; loginError.value = ''; notify('密码已更新，请重新登录') }
  catch (error) { notify(error instanceof Error ? error.message : '修改失败') }
  finally { busy.value = false }
}
async function logout() { try { await api.logout() } finally { authenticated.value = false; overview.value = null } }
async function refreshAll() {
  const [overviewData, nodeData, jobData, settingData, endpointData, timelineData] = await Promise.all([api.overview(), api.nodes(), api.jobs(), api.settings(), api.endpoints(), api.timeline()])
  overview.value = overviewData; nodes.value = nodeData; jobs.value = jobData; settings.value = settingData; endpoints.value = endpointData; timeline.value = timelineData; language.value = settingData.language === 'en-US' ? 'en-US' : 'zh-CN'
}
async function showJobLog(jobId: string) {
  page.value = 'jobs'
  await refreshAll()
  const index = jobs.value.findIndex(job => job.id === jobId)
  if (index > 0) jobs.value = [jobs.value[index], ...jobs.value.slice(0, index), ...jobs.value.slice(index + 1)]
  await nextTick()
  jobList.value?.scrollIntoView({ block: 'start', behavior: 'auto' })
}
async function createNode() {
  busy.value = true
  try {
    const creatingDeviceBatch = deviceMode.value
    const common = { ...createForm, v6OnlyDomains: createForm.v6OnlyDomains.split(',').map(item => item.trim()).filter(Boolean) }
    let jobId = ''
    if (creatingDeviceBatch) {
      const requests = deviceNodes.map(device => ({
        ...common,
        name: device.name.trim(),
        listenPort: device.listenPort,
        ...(isTunnelProtocol.value ? {
          server: device.server.trim(),
          domain: device.server.trim(),
          preferredServer: device.preferredServer.trim(),
          webSocketPath: device.webSocketPath.trim(),
        } : {}),
      }))
      jobId = (await api.createNodeBatch(requests)).jobId
    } else {
      jobId = (await api.createNode(common)).jobId
    }
    modal.value = null; notify(creatingDeviceBatch ? `${deviceNodes.length} 台设备的部署任务已进入队列` : '部署任务已进入队列'); await showJobLog(jobId)
  } catch (error) { notify(error instanceof Error ? error.message : '部署失败') }
  finally { busy.value = false }
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
watch(() => createForm.protocol, (protocol, previous) => {
  const panelDomain = deploymentDefaults.value.panelDomain
  if (protocol === 'vless-ws-tunnel') {
    if (createForm.server === panelDomain) createForm.server = ''
    createForm.domain = ''
  } else if (protocol === 'vless' && (createForm.domain === panelDomain || !createForm.domain)) createForm.domain = 'www.cloudflare.com'
  else if (protocol === 'shadowsocks') createForm.domain = ''
  else if (previous === 'vless' || previous === 'vless-ws-tunnel' || !createForm.domain) createForm.domain = panelDomain
  if (protocol !== 'vless-ws-tunnel' && !createForm.server) createForm.server = panelDomain
  if (protocol !== 'vless-ws-tunnel') createForm.preferredServer = ''
})
async function openNodeForm(kind: 'create' | 'device-create') {
  Object.assign(createForm, { protocol: 'hysteria2', name: '', mode: 'prefer_v6', listenPort: 0, server: '', domain: '', preferredServer: '', webSocketPath: '', tunnelToken: '', ipv4Bind: '', ipv6Bind: '', autoBind: true, v6OnlyDomains: 'chatgpt.com,claude.ai,anthropic.com', certificatePath: '', keyPath: '' })
  if (kind === 'device-create') resetDeviceDrafts()
  bindChoice.ipv4 = ''; bindChoice.ipv6 = ''
  modal.value = kind; defaultsLoading.value = true
  try {
    const defaults = await api.nodeDeploymentDefaults()
    deploymentDefaults.value = { panelDomain: defaults.panelDomain || '', ipv4: defaults.ipv4 || [], ipv6: defaults.ipv6 || [] }
    createForm.server = deploymentDefaults.value.panelDomain
    createForm.domain = deploymentDefaults.value.panelDomain
    if (deploymentDefaults.value.ipv4.length === 1) { bindChoice.ipv4 = deploymentDefaults.value.ipv4[0].address; applyBindChoice('ipv4') }
    if (deploymentDefaults.value.ipv6.length === 1) { bindChoice.ipv6 = deploymentDefaults.value.ipv6[0].address; applyBindChoice('ipv6') }
  } catch (error) {
    deploymentDefaults.value = { panelDomain: '', ipv4: [], ipv6: [] }
    notify(error instanceof Error ? `无法读取部署默认值：${error.message}` : '无法读取部署默认值，请手动填写')
  } finally { defaultsLoading.value = false }
}
function openCreate() { return openNodeForm('create') }
function openDeviceCreate() { return openNodeForm('device-create') }
async function nodeAction(node: NodeItem, action: string) {
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
function openRename(node: NodeItem) {
  selectedNode.value = node
  renameName.value = node.name
  modal.value = 'rename'
}
async function renameNode() {
  if (!selectedNode.value) return
  const name = renameName.value.trim()
  if (!name || name === selectedNode.value.name) return
  busy.value = true
  try {
    const result = await api.renameNode(selectedNode.value.id, name)
    modal.value = null; notify('重命名任务已创建'); await showJobLog(result.jobId)
  } catch (error) { notify(error instanceof Error ? error.message : '重命名失败') }
  finally { busy.value = false }
}
async function deleteNode() {
  if (!selectedNode.value) return
  busy.value = true
  try { const result = await api.nodeAction(selectedNode.value.id, 'delete', deleteConfirm.value); modal.value = null; notify('删除任务已创建'); await showJobLog(result.jobId) }
  catch (error) { notify(error instanceof Error ? error.message : '删除失败') }
  finally { busy.value = false }
}
async function revealShare(node: NodeItem) {
  selectedNode.value = node; shareURI.value = ''; shareQR.value = ''; modal.value = 'share'
  try { const share = await api.share(node.id); shareURI.value = share.uri; shareQR.value = await QRCode.toDataURL(share.uri, { margin: 1, width: 224, color: { dark: '#15120b', light: '#f5e9c8' } }) }
  catch (error) { notify(error instanceof Error ? error.message : '无法生成分享链接') }
}
async function openImport() {
  modal.value = 'import'; candidates.value = []; selectedCandidates.value = []
  try { candidates.value = await api.scan(); selectedCandidates.value = candidates.value.map(item => item.fingerprint) }
  catch (error) { notify(error instanceof Error ? error.message : '扫描失败') }
}
async function importSelected() {
  busy.value = true
  try { const result = await api.importNodes(selectedCandidates.value); modal.value = null; notify('接管任务已创建'); await showJobLog(result.jobId) }
  catch (error) { notify(error instanceof Error ? error.message : '接管失败') }
  finally { busy.value = false }
}
async function saveSettings() {
  try { await api.saveSettings(settings.value); language.value = settings.value.language === 'en-US' ? 'en-US' : 'zh-CN'; notify('设置已保存') }
  catch (error) { notify(error instanceof Error ? error.message : '保存失败') }
}
async function rotateSubscription() {
  try { const result = await api.rotateSubscription(); settings.value.subscriptionToken = `${result.token.slice(0, 4)}••••${result.token.slice(-4)}`; notify('订阅令牌已轮换') }
  catch (error) { notify(error instanceof Error ? error.message : '轮换失败') }
}
async function scanSingBoxMigration() {
  migrationLoading.value = true
  try { migrationPlan.value = await api.singBoxMigration(); notify('sing-box 配置兼容性扫描完成') }
  catch (error) { notify(error instanceof Error ? error.message : '兼容性扫描失败') }
  finally { migrationLoading.value = false }
}
async function copy(value: string) { await navigator.clipboard.writeText(value); notify('已复制到剪贴板') }

let timer = 0
onMounted(async () => { updateDeviceLimit(); window.addEventListener('resize', updateDeviceLimit); await bootstrap(); setTimelineRange('today'); timer = window.setInterval(() => { if (authenticated.value && !mustChange.value) refreshAll().catch(() => {}) }, 10_000) })
onBeforeUnmount(() => { window.clearInterval(timer); window.removeEventListener('resize', updateDeviceLimit) })
</script>

<template>
  <div v-if="loading" class="boot-screen"><div class="orbit-mark"><i></i><b>悟</b></div><p>正在唤醒悟空面板</p></div>

  <main v-else-if="!authenticated" class="login-stage">
    <div class="cloud cloud-a"></div><div class="cloud cloud-b"></div>
    <section class="login-brand">
      <div class="brand-kicker">WUKONG CONTROL PLANE · 01</div>
      <h1>驭云端<br><em>定乾坤</em></h1>
      <p>从一束流量，到一方节点。部署、管理与观测，在同一座控制台完成。</p>
      <div class="brand-stats"><span><b>6</b> 种协议驱动</span><span><b>10s</b> 实时采样</span><span><b>1</b> 单机自治</span></div>
    </section>
    <form class="login-panel" @submit.prevent="login">
      <div class="panel-seal">悟</div><p class="eyebrow">悟空面板</p><h2>进入控制台</h2><p class="subtle">使用安装时生成的管理员凭据</p>
      <label>管理员账号<input v-model="username" autocomplete="username" required /></label>
      <label>访问密码<input v-model="password" type="password" autocomplete="current-password" required /></label>
      <p v-if="loginError" class="form-error">{{ loginError }}</p>
      <button class="primary wide" :disabled="busy">{{ busy ? '验证中…' : '登录面板' }}<span>→</span></button>
      <small>HTTPS 加密 · 单管理员 · 操作留痕</small>
    </form>
  </main>

  <div v-else class="app-shell">
    <aside class="sidebar">
      <button class="brand-button" @click="page = 'overview'"><span class="mini-orbit">悟</span><span><strong>悟空面板</strong><small>WUKONG PANEL</small></span></button>
      <nav><button v-for="item in navItems" :key="item.id" :class="{ active: page === item.id }" @click="page = item.id"><i>{{ item.seal }}</i><span>{{ item.label }}</span><b v-if="item.id === 'jobs' && activeJobs">{{ activeJobs }}</b></button></nav>
      <div class="sidebar-foot"><div class="server-pulse"><i></i><span><b>本机 Agent</b><small>安全通道已连接</small></span></div><button class="ghost-icon" title="退出" @click="logout">↪</button></div>
    </aside>

    <section class="workspace">
      <header class="topbar">
        <div><p class="breadcrumb">天宫 / {{ navItems.find(item => item.id === page)?.label }}</p><h1>{{ navItems.find(item => item.id === page)?.label }}</h1></div>
        <div class="top-actions"><span class="clock">{{ new Date().toLocaleDateString(language, { month: 'short', day: 'numeric' }) }}</span><button class="secondary" @click="openImport">⌁ {{ t('import') }}</button><button class="device-entry" @click="openDeviceCreate"><span>器</span><b>设备专用节点</b></button><button class="primary" @click="openCreate">＋ {{ t('deploy') }}</button><span class="avatar">{{ username.slice(0, 1).toUpperCase() }}</span></div>
      </header>

      <div v-if="page === 'overview'" class="page-content overview-page">
        <section class="hero-grid">
          <article class="traffic-oracle panel-card">
            <div class="card-caption"><span>本账期流量</span><em>{{ overview?.billingStart }} — {{ overview?.billingEnd }}</em></div>
            <div class="quota-ring" :style="quotaRing"><div><small>已使用</small><strong>{{ trafficPercent.toFixed(1) }}<sup>%</sup></strong><span>{{ bytes(overview?.trafficUsed) }} / {{ overview?.trafficQuota ? bytes(overview?.trafficQuota) : '不限量' }}</span></div></div>
            <div class="oracle-meta"><span>距离重置 <b>{{ overview?.billingEnd || '—' }}</b></span><span>出口网卡 <b>{{ overview?.now.interface || '—' }}</b></span></div>
          </article>
          <div class="stat-column">
            <article class="metric-card down"><span>↓</span><div><small>实时下载</small><strong>{{ rate(overview?.now.rxBps) }}</strong></div><em>DOWNLINK</em></article>
            <article class="metric-card up"><span>↑</span><div><small>实时上传</small><strong>{{ rate(overview?.now.txBps) }}</strong></div><em>UPLINK</em></article>
            <article class="node-balance"><div><small>节点阵列</small><strong>{{ overview?.onlineNodes || 0 }}<span>/{{ overview?.nodeCount || 0 }}</span></strong></div><div class="node-dots"><i v-for="node in nodes" :key="node.id" :class="node.status"></i></div><p>{{ overview?.onlineNodes === overview?.nodeCount ? '阵列稳定，诸节点皆在位' : '存在离线节点，请检查任务日志' }}</p></article>
          </div>
        </section>

        <section class="panel-card trend-card">
          <div class="card-head flow-head"><div><span class="section-mark">流</span><div><h3>流量脉络</h3><p>最近 80 个采样点 · 每 10 秒刷新</p></div></div><div v-if="activeDevices.length" class="device-rack" aria-label="当前活跃设备"><span v-for="device in visibleDevices" :key="device.nodeId" class="device-chip" :title="`${device.nodeName} · 节点最近窗口下行 ${rate(device.rateBps)}`"><i></i><b>{{ device.nodeName }}</b><em>{{ rate(device.rateBps) }}</em></span><span v-if="hiddenDeviceCount" class="device-overflow" :title="`另有 ${hiddenDeviceCount} 个活跃设备`">+{{ hiddenDeviceCount }}</span></div><div v-else class="device-silent"><i></i>设备静默</div></div>
          <div class="flow-metrics"><span class="flow-rx"><small>下载</small><b>{{ rate(overview?.now.rxBps) }}</b></span><span class="flow-tx"><small>上传</small><b>{{ rate(overview?.now.txBps) }}</b></span><em>设备速率来自 UDP/TCP 节点采集器最近完成窗口</em></div>
          <div class="chart-wrap"><div class="chart-plot"><svg viewBox="0 0 1000 150" preserveAspectRatio="none" aria-label="实时下载与上传趋势"><defs><linearGradient id="jadeArea" x1="0" y1="0" x2="0" y2="1"><stop offset="0" stop-color="#52b690" stop-opacity=".28"/><stop offset="1" stop-color="#52b690" stop-opacity="0"/></linearGradient></defs><path :d="rxAreaPath" fill="url(#jadeArea)"/><path :d="rxChartPath" class="chart-line rx-line"/><path :d="txChartPath" class="chart-line tx-line"/></svg><div class="chart-grid"></div></div><div class="chart-axis" aria-label="流量速率刻度"><span>{{ axisRate(chartPeak) }}</span><span>{{ axisRate(chartPeak / 2) }}</span><span>0 B/s</span></div></div>
        </section>

        <section class="overview-lower">
          <article class="panel-card node-preview"><div class="card-head"><div><span class="section-mark red">阵</span><div><h3>节点兵器谱</h3><p>按服务状态实时排列</p></div></div><button class="text-button" @click="page = 'nodes'">查看全部 →</button></div><div class="compact-nodes"><div v-for="node in nodes.slice(0, 4)" :key="node.id"><i :class="node.status"></i><span><b>{{ node.name }}</b><small>{{ protocolInfo(node.protocol).badge }} · {{ nodePublicPort(node) }}/{{ protocolInfo(node.protocol).transport }}</small></span><em>{{ node.status === 'active' ? t('online') : t('offline') }}</em></div><p v-if="!nodes.length" class="empty">尚无节点，点击右上角部署第一座节点。</p></div></article>
          <article class="panel-card system-glance"><div class="card-head"><div><span class="section-mark jade">脉</span><div><h3>主机气脉</h3><p>资源水位</p></div></div><span class="uptime">运行 {{ uptime(overview?.now.uptime) }}</span></div><div class="resource-row"><span>CPU</span><div><i :style="{ width: `${overview?.now.cpu || 0}%` }"></i></div><b>{{ overview?.now.cpu.toFixed(1) || 0 }}%</b></div><div class="resource-row"><span>内存</span><div><i :style="{ width: `${overview?.now.memory || 0}%` }"></i></div><b>{{ overview?.now.memory.toFixed(1) || 0 }}%</b></div><div class="resource-row"><span>磁盘</span><div><i :style="{ width: `${overview?.now.disk || 0}%` }"></i></div><b>{{ overview?.now.disk.toFixed(1) || 0 }}%</b></div><div class="version-strip"><span>Panel {{ overview?.panelVersion }}</span><span>sing-box {{ overview?.singBoxVersion }}</span></div></article>
        </section>
      </div>

      <div v-else-if="page === 'nodes'" class="page-content">
        <div class="page-intro"><div><p>NODE ARSENAL</p><h2>管理所有代理入站</h2><small class="page-caption">“检测”执行本机完整代理闭环；公网防火墙与 NAT 可达性仍需异地验证。</small></div><div class="summary-pills"><span><i class="active"></i>{{ overview?.onlineNodes || 0 }} 在线</span><span>{{ nodes.filter(n => n.ownership === 'imported').length }} 已接管</span></div></div>
        <section class="node-grid">
          <article v-for="node in nodes" :key="node.id" class="node-card" :class="[node.status, { tunnel: node.protocol === 'vless-ws-tunnel', preferred: !!node.preferredServer }]">
            <div class="node-top"><span class="protocol-badge">{{ protocolInfo(node.protocol).badge }}</span><div class="node-state"><i></i>{{ node.status === 'active' ? '运行中' : node.status === 'inactive' ? '已停止' : '未知' }}</div></div>
            <div class="node-title-row"><h3>{{ node.name }}</h3><button type="button" title="重命名节点" :aria-label="`重命名节点 ${node.name}`" @click="openRename(node)">重命名</button></div>
            <p class="endpoint">{{ nodeDialServer(node) || '未设置出口域名' }}<b>:{{ nodePublicPort(node) }}</b><small> / {{ protocolInfo(node.protocol).transport }}</small></p>
            <div v-if="node.protocol === 'vless-ws-tunnel' && node.preferredServer" class="preferred-route"><span><small>优选接入</small><code>{{ node.preferredServer }}</code></span><i>→</i><span><small>SNI · WS HOST</small><code>{{ node.server }}</code></span></div>
            <div v-if="node.protocol === 'vless-ws-tunnel'" class="tunnel-origin"><span><small>Cloudflare Service</small><code>{{ tunnelOrigin(node) }}</code></span><button type="button" title="复制 Cloudflare Service URL" @click="copy(tunnelOrigin(node))">复制</button></div>
            <div class="node-specs"><span><small>出站策略</small><b>{{ modeLabel(node.mode) }}</b></span><span :title="`配置创建于 sing-box ${node.configVersion}`"><small>运行版本</small><b>{{ overview?.singBoxVersion || node.configVersion || '—' }}</b></span><span><small>服务管理</small><b>{{ node.serviceManager }}</b></span><span><small>归属</small><b>{{ node.ownership === 'imported' ? '接管' : '悟空' }}</b></span></div>
            <p v-if="node.sharedGroup" class="shared-note">⌁ {{ node.ownership === 'managed' ? (node.protocol === 'vless-ws-tunnel' ? '设备编队 · 独立入站，共享 sing-box 与 Tunnel 连接器' : '设备编队 · 独立入站，共享一个 sing-box 进程') : '与同配置内其他端点共享生命周期' }}</p>
            <div class="probe-strip" :class="probeState(node)" :title="probeDetail(node)" aria-live="polite"><i></i><span><b>{{ probeState(node) === 'running' ? '闭环检测中' : probeState(node) === 'success' ? '闭环正常' : probeState(node) === 'failed' ? '检测失败' : '尚未检测' }}</b><small>{{ probeDetail(node) }}</small></span></div>
            <div class="node-actions"><button @click="revealShare(node)">分享</button><button class="probe-button" :disabled="node.status !== 'active' || probeState(node) === 'running'" :title="node.status !== 'active' ? '请先启动节点' : node.protocol === 'vless-ws-tunnel' ? '验证 Cloudflare TLS、WebSocket、认证和代理出站' : '验证握手、认证和代理出站'" @click="probeNode(node)">{{ probeState(node) === 'running' ? '检测中' : '检测' }}</button><button @click="nodeAction(node, 'check')">校验</button><button v-if="node.status === 'active'" @click="nodeAction(node, 'restart')">重启</button><button v-else @click="nodeAction(node, 'start')">启动</button><button class="danger" @click="nodeAction(node, 'delete')">删除</button></div>
          </article>
          <button class="add-node-card" @click="openCreate"><span>＋</span><b>部署新节点</b><small>六协议 · 自动生成安全凭据</small></button>
        </section>
      </div>

      <div v-else-if="page === 'traffic'" class="page-content">
        <div class="page-intro"><div><p>TRAFFIC OBSERVATORY</p><h2>整机流量与账期观测</h2></div><span class="live-badge"><i></i>10 秒实时刷新</span></div>
        <section class="traffic-stat-grid"><article><small>本账期使用</small><strong>{{ bytes(overview?.trafficUsed) }}</strong><span>{{ trafficPercent.toFixed(1) }}% 配额</span></article><article><small>下载速率</small><strong>{{ rate(overview?.now.rxBps) }}</strong><span>当前出口</span></article><article><small>上传速率</small><strong>{{ rate(overview?.now.txBps) }}</strong><span>当前出口</span></article><article><small>账期重置</small><strong>{{ overview?.billingEnd || '—' }}</strong><span>{{ settings.timezone }}</span></article></section>
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
        <div class="privacy-banner"><span>隐</span><div><b>端点隐私策略</b><p>客户端 IP 默认脱敏；原始端点保留 24 小时，设备聚合保留 90 天。</p></div><label class="switch"><input v-model="settings.collectEndpoints" type="checkbox" @change="saveSettings"><i></i></label></div>
      </div>

      <div v-else-if="page === 'system'" class="page-content">
        <div class="page-intro"><div><p>HOST VITALS</p><h2>主机资源与运行态势</h2></div><span class="live-badge"><i></i>Agent 正常</span></div>
        <section class="vital-grid"><article v-for="item in vitalItems" :key="item.name"><div class="vital-dial" :style="{ '--vital': `${item.value * 3.6}deg` }"><b>{{ item.value.toFixed(1) }}<small>%</small></b></div><h3>{{ item.name }}</h3><p>{{ item.meta }}</p><strong v-if="item.usage" class="vital-usage">{{ item.usage }}</strong></article></section>
        <section class="panel-card host-table"><div class="card-head"><div><span class="section-mark jade">机</span><div><h3>系统信息</h3><p>不展示进程完整命令行</p></div></div></div><dl><div><dt>出口网卡</dt><dd>{{ overview?.now.interface || '—' }}</dd></div><div><dt>运行时间</dt><dd>{{ uptime(overview?.now.uptime) }}</dd></div><div><dt>sing-box</dt><dd>{{ overview?.singBoxVersion }}</dd></div><div><dt>悟空面板</dt><dd>{{ overview?.panelVersion }}</dd></div><div><dt>服务模式</dt><dd>Web / Root Agent 分权</dd></div><div><dt>指标保留</dt><dd>90 天</dd></div></dl></section>
        <section class="panel-card migration-panel">
          <div class="card-head"><div><span class="section-mark">迁</span><div><h3>sing-box 升级预检</h3><p>目标稳定版 1.13.14 · 只读扫描，不修改配置</p></div></div><button class="secondary" :disabled="migrationLoading" @click="scanSingBoxMigration">{{ migrationLoading ? '扫描中…' : '扫描兼容性' }}</button></div>
          <div v-if="migrationPlan" class="migration-summary" :class="migrationPlan.compatible ? 'compatible' : 'blocked'"><strong>{{ migrationPlan.compatible ? '可以安全生成迁移配置' : '存在阻断项，需要人工处理' }}</strong><span>{{ migrationPlan.files.length }} 个配置 · {{ migrationPlan.changes }} 项变更 · {{ migrationPlan.warnings }} 项提醒 · {{ migrationPlan.errors }} 项阻断</span></div>
          <div v-if="migrationPlan" class="migration-files"><article v-for="file in migrationPlan.files" :key="file.path"><div><b>{{ file.path.split('/').pop() }}</b><small v-if="file.interfaces?.length">引用网卡 {{ file.interfaces.join(', ') }}</small></div><span>{{ (file.changes || []).length }} 项变更</span><ul v-if="(file.changes || []).length || (file.warnings || []).length || (file.errors || []).length"><li v-for="item in file.changes || []" :key="`c-${item}`">＋ {{ item }}</li><li v-for="item in file.warnings || []" :key="`w-${item}`" class="warning">! {{ item }}</li><li v-for="item in file.errors || []" :key="`e-${item}`" class="error">× {{ item }}</li></ul></article></div>
          <p v-else class="migration-empty">扫描结果会列出字段迁移、共享配置、网卡依赖和无法自动处理的项目。实际升级仍由 root 权限安全安装流程执行。</p>
        </section>
        <section class="panel-card process-panel"><div class="card-head"><div><span class="section-mark">程</span><div><h3>进程</h3><p>按 CPU 与内存排序 · 不采集完整命令行</p></div></div><span class="process-count">{{ overview?.processCount || 0 }} 个</span></div><div class="process-table"><div class="process-row process-header"><span>PID</span><span>进程</span><span>CPU</span><span>内存</span></div><div class="process-scroll"><div v-for="process in overview?.processes || []" :key="process.pid" class="process-row"><code>{{ process.pid }}</code><b :title="process.name">{{ process.name }}</b><strong>{{ process.cpu.toFixed(1) }}%</strong><span class="process-memory"><em>{{ bytes(process.rssBytes) }}</em><small>{{ process.memoryPercent.toFixed(1) }}%</small></span></div><p v-if="!overview?.processes?.length" class="empty">等待 Agent 完成进程采样。</p></div></div></section>
      </div>

      <div v-else-if="page === 'jobs'" class="page-content">
        <div class="page-intro"><div><p>MISSION LOG</p><h2>任务进度与操作留痕</h2></div><span>{{ jobs.length }} 条最近任务</span></div>
        <section ref="jobList" class="job-list panel-card"><div v-for="job in jobs" :key="job.id" class="job-row"><span class="job-icon" :class="job.status">{{ job.status === 'success' ? '✓' : job.status === 'failed' ? '!' : '↻' }}</span><div class="job-copy"><b>{{ jobLabel(job.kind) }}</b><small>{{ job.target }} · {{ new Date(job.createdAt).toLocaleString(language) }}</small><p v-if="job.error">{{ job.error }}</p></div><div class="job-progress"><span>{{ job.message }}</span><div><i :class="job.status" :style="{ width: `${job.progress}%` }"></i></div></div></div><p v-if="!jobs.length" class="empty">暂无任务记录。</p></section>
      </div>

      <div v-else class="page-content settings-page">
        <div class="page-intro"><div><p>CONTROL SETTINGS</p><h2>账期、隐私与访问设置</h2></div><button class="primary" @click="saveSettings">保存更改</button></div>
        <section class="settings-grid"><article class="panel-card"><div class="setting-title"><span>时</span><div><h3>本地化与账期</h3><p>用于流量归档和面板时间</p></div></div><label>界面语言<select v-model="settings.language"><option value="zh-CN">简体中文</option><option value="en-US">English</option></select></label><label>时区<input v-model="settings.timezone"></label><label>账期重置日<input v-model.number="settings.billingResetDay" type="number" min="1" max="28"></label><label>月流量额度（GB）<input :value="settings.trafficQuotaBytes / 1_000_000_000" type="number" min="0" @input="settings.trafficQuotaBytes = Number(($event.target as HTMLInputElement).value) * 1_000_000_000"><small>0 表示不限量</small></label></article><article class="panel-card"><div class="setting-title"><span>网</span><div><h3>网络采集</h3><p>自动识别默认出口网卡</p></div></div><label>监控网卡<input v-model="settings.interface" placeholder="auto"></label><label class="toggle-row"><span><b>采集客户端端点</b><small>关闭后仍保留整机流量统计</small></span><span class="switch"><input v-model="settings.collectEndpoints" type="checkbox"><i></i></span></label></article><article class="panel-card"><div class="setting-title"><span>令</span><div><h3>订阅令牌</h3><p>与管理入口完全隔离</p></div></div><div class="token-box"><code>{{ settings.subscriptionToken || '尚未生成' }}</code><button @click="rotateSubscription">轮换</button></div><p class="help-text">令牌轮换后旧订阅地址立即失效。节点密码仅在生成订阅或短时分享时由 Root Agent 解密。</p></article><article class="panel-card danger-zone"><div class="setting-title"><span>险</span><div><h3>危险区域</h3><p>首版不会修改 SSH、防火墙或系统更新</p></div></div><p>卸载与版本回滚请通过服务器上的 <code>wukongctl</code> 执行，避免浏览器会话误操作。</p></article></section>
      </div>
    </section>
  </div>

  <div v-if="mustChange && authenticated" class="modal-backdrop locked"><form class="modal-card compact" @submit.prevent="changePassword"><span class="modal-seal">钥</span><p class="eyebrow">首次登录安全检查</p><h2>设置新的管理员密码</h2><p>密码至少 12 位。提交后所有会话将失效，需要重新登录。</p><label>新密码<input v-model="newPassword" type="password" minlength="12" autocomplete="new-password" required></label><button class="primary wide" :disabled="busy">保存并重新登录</button></form></div>

  <div v-if="modal" class="modal-backdrop" @click.self="modal = null">
    <form v-if="modal === 'create' || modal === 'device-create'" class="modal-card node-form" @submit.prevent="createNode">
      <button type="button" class="modal-close" @click="modal = null">×</button>
      <p class="eyebrow">{{ deviceMode ? 'DEPLOY DEVICE FLEET' : 'DEPLOY PROXY NODE' }}</p><h2>{{ deviceMode ? '部署设备专用节点' : '部署一座新节点' }}</h2>
      <p v-if="defaultsLoading" class="form-hint loading-hint">正在读取面板域名与本机地址…</p>
      <div class="form-grid">
        <label v-if="!deviceMode">节点名称<input v-model="createForm.name" placeholder="例如：花果山 · iPhone" required></label>
        <div v-else class="span-2 device-mode-summary"><span>器</span><div><b>设备节点编队</b><small>{{ deviceNodes.length }} 台设备 · 独立端口与凭据 · 一个 sing-box 进程</small></div></div>
        <label class="protocol-choice">节点协议<select v-model="createForm.protocol"><option value="hysteria2">Hysteria2 · UDP / QUIC</option><option value="vless">VLESS + REALITY · TCP</option><option value="vless-ws-tunnel">VLESS + WebSocket + Cloudflare Tunnel</option><option value="shadowsocks">Shadowsocks 2022 · TCP + UDP</option><option value="tuic">TUIC v5 · UDP / QUIC</option><option value="trojan">Trojan TLS · TCP</option></select><small>{{ selectedProtocolInfo.note }}</small></label>
        <label>出站策略<select v-model="createForm.mode"><option value="prefer_v6">IPv6 优先 + IPv4 兜底</option><option value="v4only">纯 IPv4</option><option value="v6only">纯 IPv6</option></select></label>
        <label v-if="!deviceMode">{{ isTunnelProtocol ? '本地 Origin 端口（TCP）' : `监听端口（${selectedProtocolInfo.transport}）` }}<input v-model.number="createForm.listenPort" type="number" min="0" max="65535" placeholder="0 = 自动"><small v-if="isTunnelProtocol">仅监听 127.0.0.1；客户端始终连接 Cloudflare 443</small></label>
        <label v-if="!isTunnelProtocol || !deviceMode">{{ isTunnelProtocol ? 'Cloudflare 节点域名' : '公网域名 / IP' }}<input v-model="createForm.server" :placeholder="isTunnelProtocol ? 'edge.example.com' : 'node.example.com'" required><small v-if="isTunnelProtocol">填写 Tunnel Published application 使用的公开主机名</small><small v-else-if="deploymentDefaults.panelDomain">已采用面板域名，可按节点需要修改</small></label>
        <label v-if="createForm.protocol !== 'shadowsocks' && !isTunnelProtocol">{{ selectedProtocolInfo.domainLabel }}<input v-model="createForm.domain" :placeholder="createForm.protocol === 'vless' ? 'www.cloudflare.com' : 'node.example.com'"><small v-if="createForm.protocol === 'vless'">默认使用已验证的 Cloudflare TLS 站点；也可改为客户端与 VPS 均可达的 TLS 1.3 站点</small><small v-else-if="deploymentDefaults.panelDomain">与面板证书域名保持一致</small></label>
        <label v-if="isTunnelProtocol && !deviceMode">WebSocket 路径<input v-model="createForm.webSocketPath" placeholder="留空自动生成随机路径" maxlength="128" autocomplete="off"><small>自定义时必须以 / 开头</small></label>
        <label v-if="isTunnelProtocol && !deviceMode" class="span-2 preferred-endpoint-field"><span>优选连接域名 / IP <em>OPTIONAL</em></span><input v-model="createForm.preferredServer" placeholder="例如：cf-best.example.com 或 104.16.0.1" autocomplete="off" spellcheck="false"><small>只替换客户端 server；TLS SNI、WebSocket Host 与 Tunnel 路由仍使用上方 Cloudflare 节点域名。留空则保持标准 Anycast 接入。</small></label>
        <label v-if="isTunnelProtocol" class="span-2 tunnel-token-field">{{ deviceMode ? '共享 Tunnel Token' : 'Tunnel Token' }}<input v-model="createForm.tunnelToken" type="password" autocomplete="new-password" spellcheck="false" placeholder="粘贴 Cloudflare Tunnel 的运行 Token" required><small>{{ deviceMode ? '整组设备共用一个 cloudflared 连接器；每台设备使用独立主机名和 Origin 端口' : '仅接受此 Tunnel 的运行 Token；不会要求或保存 Cloudflare API Key' }}</small></label>
        <div v-if="isTunnelProtocol" class="span-2 tunnel-guide"><span>隧</span><div><b>{{ deviceMode ? '一个 Tunnel，多条设备路由' : 'Cloudflare 侧需要做两步' }}</b><ol><li>在 Zero Trust 创建 remotely-managed Tunnel，并复制运行 Token。</li><li v-if="deviceMode">为下方每台设备添加一条 Published application，分别把独立主机名路由到部署后卡片显示的 <code>http://127.0.0.1:端口</code>。</li><li v-else>节点部署后，在 Published application 把 Service URL 设置为节点卡片显示的 <code>http://127.0.0.1:端口</code>。</li></ol><p>VPS 无需开放 Origin 端口；设备组共享一个 sing-box 进程和一个 cloudflared 服务。</p></div></div>
        <section v-if="deviceMode" class="span-2 device-fleet"><div class="device-fleet-head"><div><span>DEVICE FLEET</span><b>设备清单</b><small>2–20 台；端口填 0 自动分配</small></div><button type="button" :disabled="deviceNodes.length >= 20" @click="addDevice">＋ 添加设备</button></div><article v-for="(device, index) in deviceNodes" :key="device.key" class="device-draft"><header><span>{{ String(index + 1).padStart(2, '0') }}</span><b>{{ device.name || `设备 ${index + 1}` }}</b><button type="button" :disabled="deviceNodes.length <= 2" title="移除设备" @click="removeDevice(index)">×</button></header><div class="device-draft-grid"><label>设备名称<input v-model="device.name" maxlength="80" placeholder="例如：iPhone" required></label><label>{{ isTunnelProtocol ? '本地 Origin 端口' : '监听端口' }}<input v-model.number="device.listenPort" type="number" min="0" max="65535" placeholder="0 = 自动"></label><label v-if="isTunnelProtocol">Cloudflare 公开主机名<input v-model="device.server" placeholder="iphone.example.com" required><small>Published application 使用此独立主机名</small></label><label v-if="isTunnelProtocol"><span class="device-field-title">优选连接域名 / IP <em>可选</em></span><input v-model="device.preferredServer" placeholder="cf-best.example.com"></label><label v-if="isTunnelProtocol" class="span-2"><span class="device-field-title">WebSocket 路径 <em>可选</em></span><input v-model="device.webSocketPath" placeholder="留空自动生成随机路径" maxlength="128"></label></div></article></section>
        <label :class="{ 'disabled-field': createForm.mode === 'v6only' }">IPv4 出站绑定<input v-if="createForm.mode === 'v6only'" value="纯 IPv6 模式不使用 IPv4" disabled><template v-else><select v-if="deploymentDefaults.ipv4.length" v-model="bindChoice.ipv4" @change="applyBindChoice('ipv4')"><option value="">自动路由（不固定地址）</option><option v-for="item in deploymentDefaults.ipv4" :key="item.address" :value="item.address">{{ item.address }} · {{ item.interface }}</option><option value="__manual__">手动填写…</option></select><input v-if="!deploymentDefaults.ipv4.length || bindChoice.ipv4 === '__manual__'" v-model="createForm.ipv4Bind" placeholder="自动或 192.0.2.10"></template><small v-if="createForm.mode === 'v6only'">已清空，不会写入节点配置</small><small v-else-if="deploymentDefaults.ipv4.length">已识别 {{ deploymentDefaults.ipv4.length }} 个本机可绑定 IPv4；NAT 公网出口可能不同</small></label>
        <label :class="{ 'disabled-field': createForm.mode === 'v4only' }">IPv6 出站绑定<input v-if="createForm.mode === 'v4only'" value="纯 IPv4 模式不使用 IPv6" disabled><template v-else><select v-if="deploymentDefaults.ipv6.length" v-model="bindChoice.ipv6" @change="applyBindChoice('ipv6')"><option value="">自动路由（不固定地址）</option><option v-for="item in deploymentDefaults.ipv6" :key="item.address" :value="item.address">{{ item.address }} · {{ item.interface }}</option><option value="__manual__">手动填写…</option></select><input v-if="!deploymentDefaults.ipv6.length || bindChoice.ipv6 === '__manual__'" v-model="createForm.ipv6Bind" placeholder="2001:db8::10"></template><small v-if="createForm.mode === 'v4only'">已清空，不会写入节点配置</small><small v-else-if="deploymentDefaults.ipv6.length">已识别 {{ deploymentDefaults.ipv6.length }} 个本机可绑定 IPv6 地址</small></label>
        <label class="span-2">强制 IPv6 域名<input v-model="createForm.v6OnlyDomains"></label>
      </div>
      <label class="toggle-row inline"><span><b>自动跟随 IP 变化</b><small>动态地址改变时校验配置并重启受影响节点</small></span><span class="switch"><input v-model="createForm.autoBind" type="checkbox"><i></i></span></label>
      <div class="modal-actions"><button type="button" class="secondary" @click="modal = null">取消</button><button class="primary" :disabled="busy || defaultsLoading">{{ busy ? '正在创建任务…' : '确认部署' }}</button></div>
    </form>
    <section v-else-if="modal === 'import'" class="modal-card import-modal"><button class="modal-close" @click="modal = null">×</button><p class="eyebrow">DISCOVER EXISTING NODES</p><h2>扫描并接管现有节点</h2><p>接管不会重写配置或升级 sing-box；未知字段将原样保留。</p><div class="candidate-list"><label v-for="item in candidates" :key="item.fingerprint"><input v-model="selectedCandidates" type="checkbox" :value="item.fingerprint"><span><b>{{ item.name }} · {{ protocolInfo(item.protocol).badge }}</b><small>{{ item.configPath }} · {{ item.serviceName }}</small></span><em>{{ item.listenPort }}/{{ protocolInfo(item.protocol).transport }}</em></label><p v-if="!candidates.length" class="empty">未发现可接管的代理节点</p></div><div class="modal-actions"><button class="secondary" @click="modal = null">取消</button><button class="primary" :disabled="busy || !selectedCandidates.length" @click="importSelected">接管 {{ selectedCandidates.length }} 个端点</button></div></section>
    <section v-else-if="modal === 'share'" class="modal-card share-modal"><button class="modal-close" @click="modal = null">×</button><p class="eyebrow">EPHEMERAL SHARE</p><h2>{{ selectedNode?.name }}</h2><p>敏感链接仅在当前会话短时显示。</p><img v-if="shareQR" :src="shareQR" alt="节点二维码"><div class="share-code"><code>{{ shareURI || '正在向 Root Agent 请求密钥…' }}</code><button :disabled="!shareURI" @click="copy(shareURI)">复制</button></div></section>
    <form v-else-if="modal === 'rename'" class="modal-card compact rename-modal" @submit.prevent="renameNode"><button type="button" class="modal-close" @click="modal = null">×</button><span class="modal-seal">名</span><p class="eyebrow">RENAME NODE</p><h2>重命名 {{ selectedNode?.name }}</h2><p>只修改面板显示名称、分享链接标题与扫描识别名称；不会改变端口、密码、服务或节点配置。</p><label>新节点名称<input v-model="renameName" maxlength="80" autocomplete="off" autofocus required></label><div class="modal-actions"><button type="button" class="secondary" @click="modal = null">取消</button><button class="primary" :disabled="busy || !renameName.trim() || renameName.trim() === selectedNode?.name">{{ busy ? '正在创建任务…' : '确认重命名' }}</button></div></form>
    <form v-else class="modal-card compact danger-modal" @submit.prevent="deleteNode"><span class="modal-seal red">删</span><p class="eyebrow">DESTRUCTIVE ACTION</p><h2>删除 {{ selectedNode?.name }}？</h2><p>{{ selectedNode?.sharedGroup && selectedNode?.ownership === 'managed' ? '系统将先创建带 SHA-256 的配置快照，只移除此设备的独立入站并重启共享进程；最后一台设备才会删除组服务。' : '系统将先创建带 SHA-256 的配置快照，再停止并删除节点服务。' }}请输入完整节点名称确认。</p><label>节点名称<input v-model="deleteConfirm" autocomplete="off" required></label><div class="modal-actions"><button type="button" class="secondary" @click="modal = null">取消</button><button class="danger-button" :disabled="busy || deleteConfirm !== selectedNode?.name">确认删除</button></div></form>
  </div>
  <transition name="toast"><div v-if="toast" class="toast">{{ toast }}</div></transition>
</template>
