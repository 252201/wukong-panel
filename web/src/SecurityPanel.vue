<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref, watch } from 'vue'
import { hostSecurityAPI, lookupIPLocation, type IPSourceLocation, type FirewallState, type Fail2banState, type SecurityRequest, type SecurityPreview, type SSHProtectionConfig, type Job } from './api'
import { countryFlagURL } from './countryFlags'
import BanDurationInput from './BanDurationInput.vue'
import { translateText } from './i18n'
import { securityStatusCache } from './securityStatus'
import { afterFirewallRead } from './securityRefresh'
import { parseSecurityPorts, securityRuleServices, securityRuleMatchesProtocol, securityStateFresh, securityBatchEligible, securityRuleChange, formatProtocol, formatHumanSeconds, sortFirewallRules } from './securityRules'
const props = defineProps<{hostId: string; hostName: string; online: boolean; compatible: boolean; capabilities: string[]; language: string}>()
const client = hostSecurityAPI(props.hostId)
const t = (zh: string, en: string) => props.language === 'en-US' ? en : zh
const securityCopy = (text: string) => securityRuleChange(text,props.language) || translateText(text,props.language === 'en-US' ? 'en-US' : 'zh-CN')
const firewall = ref<FirewallState | null>(securityStatusCache.read(props.hostId,'firewall'))
const fail2ban = ref<Fail2banState | null>(securityStatusCache.read(props.hostId,'fail2ban'))
const fwVerified = ref(false)
const fbVerified = ref(false)
const fwLoading = ref(false)
const fbLoading = ref(false)
const fwError = ref('')
const fbError = ref('')
const error = ref('')
const resetConfirmation = ref('')
const busy = ref(false)
const refreshing = ref(false)
const zone = ref(firewall.value?.zone || '')
const batchMode = ref<'adopt'|'delete'>('adopt')
const selectedRules = ref<string[]>([])
const ruleFilter = ref('')
const showManualPorts = ref(false)
const batchSupported = computed(() => support('firewall.batch') && !!firewall.value?.supportsBatch)
const batchWritable = computed(() => fwWritable.value && batchSupported.value && !pending.value)
const adoptEligibleCount = computed(() => (firewall.value?.rules || []).filter(item => securityBatchEligible(item, 'adopt')).length)
const deleteEligibleCount = computed(() => (firewall.value?.rules || []).filter(item => securityBatchEligible(item, 'delete')).length)
watch([adoptEligibleCount, deleteEligibleCount], ([adoptCount, deleteCount]) => {
 if (selectedRules.value.length > 0) return
 if (batchMode.value === 'adopt' && adoptCount === 0 && deleteCount > 0) batchMode.value = 'delete'
 else if (batchMode.value === 'delete' && deleteCount === 0 && adoptCount > 0) batchMode.value = 'adopt'
}, {immediate: true})
// Display protected rules first, then sort remaining rules by port ascending.
const sortedRules = computed(() => sortFirewallRules(firewall.value?.rules || []))
const displayedRules = computed(() => {
 const q = ruleFilter.value.trim().toLowerCase()
 if (!q) return sortedRules.value
 return sortedRules.value.filter(item => {
  const ports = `${item.portFrom}${item.portTo !== item.portFrom ? '-' + item.portTo : ''}/${formatProtocol(item.protocol)}`.toLowerCase()
  const services = securityRuleServices(item, firewall.value?.requiredPorts || [], props.language).join(' ').toLowerCase()
  const owner = item.protected ? t('受保护','protected') : item.managed ? t('悟空管理','wukong managed') : t('外部规则','external')
  return ports.includes(q) || services.includes(q) || (item.source || '').toLowerCase().includes(q) || (item.description || '').toLowerCase().includes(q) || owner.toLowerCase().includes(q)
 })
})
const batchEligible = computed(() => displayedRules.value.filter(item => securityBatchEligible(item, batchMode.value)))
const allSelected = computed(() => batchEligible.value.length > 0 && batchEligible.value.slice(0,100).every(item => selectedRules.value.includes(item.id)))
watch([batchMode, zone], () => { selectedRules.value = [] })
function selectAll() { selectedRules.value = allSelected.value ? [] : batchEligible.value.slice(0,100).map(item => item.id) }
function stageBatch() {
 if (!batchWritable.value || !selectedRules.value.length || selectedRules.value.length > 100) return
 void stage('firewall', {operation:`batch-${batchMode.value}`,ruleIds:[...selectedRules.value]})
}
const now = ref(Date.now())
const pending = ref<{kind: 'firewall'|'fail2ban'; request: SecurityRequest; preview: SecurityPreview} | null>(null)
const job = ref<Job | null>(null)
const rule = reactive({action: 'allow' as 'allow'|'deny', protocol: 'tcp' as 'tcp'|'udp'|'tcp/udp'|'tcp+udp', portFrom: '' as number | '', portTo: '' as number | '', source: ''})
const manualSSH = ref('')
const manualPanel = ref('')
const hasDetectedProtectedPorts = computed(() => {
 const req = firewall.value?.requiredPorts || []
 return req.some(p => p.protected && p.reason === 'SSH') && req.some(p => p.protected && p.reason !== 'SSH')
})
const manualPortsVisible = computed(() => showManualPorts.value || !!manualSSH.value.trim() || !!manualPanel.value.trim() || (fwVerified.value && !hasDetectedProtectedPorts.value))
function stageAddRule() {
 const from = Number(rule.portFrom)
 const to = rule.portTo === '' || rule.portTo === null || rule.portTo === undefined || Number(rule.portTo) === 0 ? from : Number(rule.portTo)
 if (!Number.isInteger(from) || from < 1 || from > 65535) return
 if (!Number.isInteger(to) || to < from || to > 65535) return
 void stage('firewall', {operation:'add', rule:{action:rule.action, protocol:rule.protocol, portFrom:from, portTo:to, source:rule.source.trim() || 'any'}})
}
const config = reactive<SSHProtectionConfig>({maxRetry:5,findTime:600,banTime:3600,mode:'normal',ignoreIPs:[]})
const permanentBanSupported = computed(() => support('fail2ban.permanent') && !!fail2ban.value?.supportsPermanentBan)
const whitelist = ref('')
let refreshVersion = 0
let refreshZone = ''
let refreshTask: Promise<void> | null = null
let hydrated = false
let alive = true
let refreshTimer: ReturnType<typeof setInterval>
let clockTimer: ReturnType<typeof setInterval>
let locationTimer: ReturnType<typeof setInterval>
const locations = reactive<Record<string, IPSourceLocation>>({})
const locationRetry = new Map<string, number>()
const locationInFlight = new Set<string>()
const sourceIPs = computed(() => [...new Set((fail2ban.value?.jails || []).flatMap(jail => [...(jail.failures || []).map(source => source.ip), ...jail.banned]))].slice(0,100))
function sourceCountry(ip: string) {
 if (!sourceIPs.value.includes(ip)) return t('国家未知','Unknown country')
 const location = locations[ip]
 if (location?.countryCode) {
  try {return new Intl.DisplayNames([props.language], {type:'region'}).of(location.countryCode) || location.countryCode} catch {return location.countryCode}
 }
 return location?.status === 'private' ? t('内网 / 保留地址','Private / reserved address') : location?.status === 'unavailable' ? t('国家未知','Unknown country') : t('查询国家中…','Looking up country…')
}
function loadLocations() {
 if (!alive || !props.online) return
 const wanted = sourceIPs.value
 for (const ip of Object.keys(locations)) if (!wanted.includes(ip)) {delete locations[ip];locationRetry.delete(ip)}
 for (const ip of wanted) {
  if (locationInFlight.size >= 4) break
  if (locationInFlight.has(ip) || (locationRetry.get(ip) || 0) > Date.now()) continue
  locationInFlight.add(ip)
  void lookupIPLocation(ip).then(result => {
   if (!alive || !sourceIPs.value.includes(ip)) return
   locations[ip] = result
   locationRetry.set(ip, Date.now() + (result.status === 'pending' ? 2000 : result.status === 'unavailable' ? 300_000 : 86_400_000))
  }).catch(() => {
   if (alive && sourceIPs.value.includes(ip)) {locations[ip] = {ip,status:'unavailable'};locationRetry.set(ip,Date.now()+60_000)}
  }).finally(() => locationInFlight.delete(ip))
 }
}
const support = (kind: string) => props.hostId === 'local' || props.capabilities.includes(`security.${kind}`)
const fwCurrent = computed(() => fwVerified.value && !!firewall.value && securityStateFresh(firewall.value.checkedAt,now.value))
const fbCurrent = computed(() => fbVerified.value && !!fail2ban.value && securityStateFresh(fail2ban.value.checkedAt,now.value))
const enabled = computed(() => props.online && props.compatible && fwCurrent.value && !busy.value && !job.value && !firewall.value?.pending)
const fwWritable = computed(() => enabled.value && support('firewall') && fwVerified.value && firewall.value?.writable && securityStateFresh(firewall.value.checkedAt, now.value))
const fbWritable = computed(() => enabled.value && support('fail2ban') && fbVerified.value && fail2ban.value?.writable && securityStateFresh(fail2ban.value.checkedAt, now.value))
const manualBanSupported = computed(() => support('fail2ban.ban') && !!fail2ban.value?.supportsManualBan)
const manualBanWritable = computed(() => fbWritable.value && manualBanSupported.value && fail2ban.value?.active)
const unbanWritable = computed(() => enabled.value && support('fail2ban') && fbCurrent.value && fail2ban.value?.active)
const resetWritable = computed(() => enabled.value && support('fail2ban.reset') && fbVerified.value && fail2ban.value?.canReset && securityStateFresh(fail2ban.value.checkedAt, now.value))
const seconds = computed(() => Math.max(0, Math.ceil((Date.parse(firewall.value?.pending?.deadline || '') - now.value) / 1000)))
function configRequest(): SSHProtectionConfig { return {...config, ignoreIPs: whitelist.value.split(/[\s,]+/).filter(Boolean)} }
function portAllowed(port: {port:number;protocol:string}): boolean {return !!firewall.value?.rules.some(rule => rule.adoptable && rule.action==='allow' && rule.source==='any' && securityRuleMatchesProtocol(rule,port.protocol) && ((rule.protocol!=='tcp/udp' && rule.protocol!=='tcp+udp') || (rule.addressFamilies?.includes('ipv4') && rule.addressFamilies?.includes('ipv6'))) && rule.portFrom<=port.port && rule.portTo>=port.port)}

function invalidateStatus() {
 securityStatusCache.clear(props.hostId)
 refreshVersion++
 refreshTask = null
 refreshing.value = false
 fwVerified.value = false
 fbVerified.value = false
}
function changeZone() {
 fwVerified.value = false
 firewall.value = securityStatusCache.read(props.hostId,'firewall',zone.value)
 void refresh()
}
function refresh(skip: ('firewall'|'fail2ban')[] = []): Promise<void> {
 if (!alive) return Promise.resolve()
 if (refreshTask && refreshZone === zone.value) return refreshTask
 const version = ++refreshVersion
 const requestedZone = zone.value
 refreshZone = requestedZone
 const current = () => alive && version === refreshVersion
 refreshing.value = true
 fwLoading.value = support('firewall') && !skip.includes('firewall')
 fbLoading.value = support('fail2ban') && !skip.includes('fail2ban')
 fwError.value = ''; fbError.value = ''
 const fwTask = fwLoading.value ? securityStatusCache.refresh(props.hostId,'firewall',requestedZone,() => client.firewall(requestedZone)).then(fw => {
  if (!current()) return
  if (fw.revision !== firewall.value?.revision) selectedRules.value = []
  firewall.value = fw
  fwVerified.value = true
  if (fw.zone) {zone.value = fw.zone;refreshZone = fw.zone}
 }).catch(e => {if (current()) {fwVerified.value = false;fwError.value = e instanceof Error ? e.message : String(e)}}).finally(() => {if (current()) fwLoading.value = false}) : Promise.resolve()
 const fbTask = fbLoading.value ? afterFirewallRead(fwTask, () => securityStatusCache.refresh(props.hostId,'fail2ban','',() => client.fail2ban()), current).then(fb => {
  if (!fb) return
  if (!current()) return
  fail2ban.value = fb
  fbVerified.value = true
  loadLocations()
  if (!hydrated) {
   const existing = fb.jails.length === 1 && !fb.managedJail && fb.active ? fb.jails[0].config : fb.config
   const cleaned = Array.from(new Set((existing.ignoreIPs || []).map(ip => ip === '127.0.0.0/8' ? '127.0.0.1/8' : ip === '::1/128' ? '::1' : ip)))
   Object.assign(config,existing);whitelist.value = cleaned.join('\n');hydrated = true
  }
 }).catch(e => {if (current()) {fbVerified.value = false;fbError.value = e instanceof Error ? e.message : String(e)}}).finally(() => {if (current()) fbLoading.value = false}) : Promise.resolve()
 // Each resource publishes immediately. Start SSH after the firewall read (or
 // a bounded wait) to avoid CPU contention; either resource can still fail alone.
 refreshTask = Promise.all([fwTask,fbTask]).then(async () => {
  if (current() && job.value) {
   const updated = await client.job(job.value.id)
   if (!current()) return
   job.value = updated
   if (updated.status === 'success' || updated.status === 'failed') {
    error.value = updated.error || '';job.value = null;hydrated = false
    invalidateStatus()
    await refresh()
   }
  }
 }).catch(e => {if (current()) error.value = e instanceof Error ? e.message : String(e)}).finally(() => {
  if (current()) {refreshing.value = false;refreshTask = null}
 })
 return refreshTask
}
function requestReady(kind: 'firewall'|'fail2ban') {return enabled.value && (kind === 'firewall' || fbCurrent.value)}
async function stage(kind: 'firewall'|'fail2ban', request: SecurityRequest) {
 if (!requestReady(kind)) return
 busy.value = true;error.value = ''
 try {
  const body: SecurityRequest = {...request,zone:zone.value}
  if (kind === 'firewall') {body.sshPorts = parseSecurityPorts(manualSSH.value);body.panelPorts = parseSecurityPorts(manualPanel.value)}
  const preview = await client.preview(kind, body)
  if (alive) {resetConfirmation.value = '';pending.value = {kind, request: {...body,revision:preview.revision},preview}}
 } catch (e) {if (alive) error.value = e instanceof Error ? e.message : String(e)}
 finally {busy.value = false}
}
async function apply() {
 const staged = pending.value
 if (!staged || !requestReady(staged.kind) || staged.request.operation === 'reinstall' && (!resetWritable.value || resetConfirmation.value !== 'RESET FAIL2BAN')) return
 const previousFirewall = fwVerified.value ? firewall.value : null
 busy.value = true;error.value = ''
 try {
  invalidateStatus()
  const result = await client.apply(staged.kind, {...staged.request, ...(staged.request.operation === 'reinstall' ? {confirmation:resetConfirmation.value} : {})})
  if (!alive) return
  pending.value = null
  selectedRules.value = []
  if (staged.kind === 'firewall' && staged.request.operation === 'add') {
   rule.portFrom = ''
   rule.portTo = ''
   rule.source = ''
  }
  if (result.firewall) {
   firewall.value = result.firewall;fwVerified.value = true
   securityStatusCache.publish(props.hostId,'firewall',result.firewall.zone || zone.value,result.firewall)
  }
  if (result.fail2ban) {
   fail2ban.value = result.fail2ban;fbVerified.value = true
   securityStatusCache.publish(props.hostId,'fail2ban','',result.fail2ban)
   loadLocations()
  }
  if (result.jobId) job.value = {id:result.jobId,status:'running',progress:0,message:t('正在安装','Installing'),kind:'security.install',target:props.hostName,error:'',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()}
  // A writable SSH result has already passed post-write verification. Older
  // Agents return a self-pending sample, so retain the full refresh for them.
  if (staged.kind === 'fail2ban' && result.fail2ban?.writable && !result.jobId) {
   // Keep the already verified firewall sample while its background read is
   // running. Its original timestamp still expires, and previews check live.
   if (previousFirewall) {
    firewall.value = previousFirewall;fwVerified.value = true
    securityStatusCache.publish(props.hostId,'firewall',previousFirewall.zone || zone.value,previousFirewall)
   }
   void refresh(['fail2ban'])
  }
  else await refresh()
 } catch (e) {if (alive) {error.value = e instanceof Error ? e.message : String(e);pending.value = null;await refresh()}}
 finally {busy.value = false}
}
async function confirm() {
 const transaction = firewall.value?.pending
 if (!transaction || !fwCurrent.value || !props.online || busy.value || seconds.value <= 0) return
 busy.value = true
 try {invalidateStatus();await client.confirm(transaction.id);if (alive) await refresh()}
 catch(e) {if (alive) {error.value = e instanceof Error ? e.message : String(e);await refresh()}}
 finally {busy.value = false}
}
const externalSSH = computed(() => fail2ban.value?.jails.length === 1 && !fail2ban.value.managedJail ? fail2ban.value.jails[0] : null)
const showSSHGuidance = computed(() => !fail2ban.value || !fail2ban.value.active || !!fail2ban.value.canActivate || !!(externalSSH.value && fail2ban.value.active) || (fbVerified.value && fail2ban.value.installed && !fbWritable.value))
const banFilter = ref('')
const bansExpanded = ref(false)
function displayedBannedIPs(ips: string[]): string[] {
 const q = banFilter.value.trim().toLowerCase()
 const filtered = q ? ips.filter(ip => ip.toLowerCase().includes(q) || sourceCountry(ip).toLowerCase().includes(q)) : ips
 if (q || bansExpanded.value || filtered.length <= 10) return filtered
 return filtered.slice(0, 10)
}
function stageSSH() {
 const existing = externalSSH.value
 void stage('fail2ban', {operation: existing ? 'adopt' : fail2ban.value?.managedJail ? 'configure' : 'enable', jail: existing?.name, config: configRequest()})
}
onMounted(() => {void refresh();loadLocations();refreshTimer = setInterval(() => {if (!busy.value) void refresh()}, 10_000);clockTimer = setInterval(() => {now.value = Date.now()},1000);locationTimer = setInterval(loadLocations,2000)})
onBeforeUnmount(() => {alive = false;clearInterval(refreshTimer);clearInterval(clockTimer);clearInterval(locationTimer);pending.value = null})
</script>

<template>
 <div class="page-content security-page">
  <div class="page-intro"><div><p>HOST SECURITY</p><h2>{{t('主机安全','Host security')}}</h2><small>{{hostName}}</small></div><button class="secondary" :disabled="refreshing || busy" @click="refresh()">{{t('刷新状态','Refresh')}}</button></div>
  <p v-if="!online || !compatible" class="security-warning">{{t('此主机离线或协议不兼容；只能查看最后状态，已禁用操作。','This host is offline or incompatible. Displayed snapshots are historical; actions are disabled.')}}</p>
  <p v-if="error" role="alert" class="security-warning">{{error}}</p>
  <section v-if="job" class="panel-card security-notice"><b>{{t('安全组件安装','Security component installation')}}</b><p>{{job.message}} · {{job.progress}}%</p><small>{{t('进度和错误同时记录在任务日志。','Progress and errors are also recorded in Jobs.')}}</small></section>
  <section v-if="firewall?.pending" class="panel-card security-notice danger"><h3>{{t('请确认连接仍正常','Confirm connectivity')}}</h3><p>{{t('变更将在倒计时结束后自动恢复。请确认能够重新连接 SSH 和面板后保留配置。','The change will roll back when the timer expires. Keep it only after verifying new SSH and panel connections.')}}</p><b>{{seconds}} s</b><button class="primary" :disabled="busy || !online || !fwCurrent || seconds <= 0" @click="confirm">{{t('连接正常，保留变更','Connections work — keep change')}}</button><p v-if="firewall.pending.error">{{firewall.pending.error}}</p></section>
  <section class="panel-card security-card fw-security-card">
   <div class="card-head">
    <div>
     <span class="section-mark jade">防</span>
     <div>
      <h3>{{t('防火墙管理','Firewall')}}</h3>
      <p>{{firewall?.backend ? firewall.backend.toUpperCase() : '—'}} · {{firewall?.policy === 'deny' ? t('默认拒绝入站 (DENY)','Default deny inbound (DENY)') : firewall?.policy === 'allow' ? t('默认放行入站 (ALLOW)','Default allow inbound (ALLOW)') : (firewall?.policy || '—')}}</p>
     </div>
    </div>
    <span class="ssh-status-indicator" :class="{active: fwVerified && firewall?.active && online && securityStateFresh(firewall.checkedAt,now) && firewall.policy === 'deny'}">{{!fwVerified ? t('状态待复核','Status awaiting verification') : firewall?.active && online && securityStateFresh(firewall.checkedAt,now) && firewall.policy === 'deny' ? t('入站防护已开启','Inbound protection enabled') : t('入站防护未开启','Inbound protection disabled')}}</span>
   </div>
   <p v-if="!support('firewall')" class="security-warning">{{t('远端 Agent 不支持防火墙管理，请更新完整面板。','The remote Agent does not support firewall management. Update the full panel.')}}</p>
   <p v-if="fwLoading && !fwCurrent" class="security-loading" role="status">{{firewall ? t('正在复核防火墙；下方是上次采样结果。','Checking firewall; the previous sample is shown below.') : t('正在读取防火墙状态…','Loading firewall status…')}}</p>
   <p v-if="fwError" role="alert" class="security-warning">{{t('防火墙状态读取失败：','Failed to load firewall status: ')}}{{fwError}} {{firewall ? t('下方仅显示上次采样，已禁用操作。','The previous sample is shown; actions are disabled.') : ''}}</p>
   <p v-if="firewall?.reason" class="security-warning">{{firewall.reason}}</p>
   <div class="ssh-meta-toolbar">
    <div class="ssh-meta-left">
     <span v-if="firewall" class="ssh-ownership-badge" :class="{managed: firewall.active && firewall.policy === 'deny'}">{{t(`共 ${firewall.rules.length} 条规则`, `${firewall.rules.length} rules`)}} · {{t(`${firewall.rules.filter(r => r.protected).length} 受保护`, `${firewall.rules.filter(r => r.protected).length} protected`)}} · {{t(`${firewall.rules.filter(r => r.managed && !r.protected).length} 悟空管理`, `${firewall.rules.filter(r => r.managed && !r.protected).length} managed`)}}<template v-if="firewall.rules.some(r => !r.managed)"> · {{t(`${firewall.rules.filter(r => !r.managed).length} 外部`, `${firewall.rules.filter(r => !r.managed).length} external`)}}</template></span>
     <small v-if="firewall" :class="{stale: !securityStateFresh(firewall.checkedAt, now)}">{{t('采样时间','Sampled')}} {{new Date(firewall.checkedAt).toLocaleString(language)}} {{!securityStateFresh(firewall.checkedAt,now) ? t('（已过期）','(stale)') : ''}}</small>
    </div>
    <div class="security-actions ssh-header-actions">
     <label v-if="firewall?.zones.length" class="fw-zone-select">
      <span>{{t('区域','Zone')}}</span>
      <select v-model="zone" :disabled="busy || !!firewall.pending" @change="changeZone"><option v-for="item in firewall.zones" :key="item">{{item}}</option></select>
     </label>
     <button v-if="firewall && !firewall.installed" class="primary" :disabled="!fwWritable" @click="stage('firewall',{operation:'install'})">{{t('安装防火墙组件','Install firewall')}}</button>
     <button v-else-if="firewall?.active && firewall?.policy === 'deny'" class="secondary" :disabled="!fwWritable" @click="stage('firewall',{operation:'enable'})">{{t('重新同步防护策略','Resync protection policy')}}</button>
     <button v-else class="primary" :disabled="!fwWritable" @click="stage('firewall',{operation:'enable'})">{{t('开启入站防护','Enable inbound protection')}}</button>
     <button class="secondary" :disabled="!fwWritable || !firewall?.active" @click="stage('firewall',{operation:'disable'})">{{t('关闭防火墙','Disable firewall')}}</button>
    </div>
   </div>
   <div class="fw-suggestions-panel">
    <div class="ssh-section-head">
     <div class="ssh-head-title">
      <b>{{t('管理保护与节点端口建议','Protected management ports & node suggestions')}}</b>
      <span class="ssh-count-pill">{{firewall?.requiredPorts?.length || 0}}</span>
     </div>
     <button type="button" class="secondary ssh-expand-btn" @click="showManualPorts = !showManualPorts">{{manualPortsVisible && showManualPorts ? t('收起手动端口设置','Hide manual port override') : t('手动指定保护端口','Override protected ports')}}</button>
    </div>
    <div v-if="manualPortsVisible" class="security-form security-ports fw-manual-ports">
     <label>{{t('SSH 端口（无法识别时填写）','SSH ports (if not detected)')}}<input v-model="manualSSH" placeholder="46961" :disabled="!enabled"><small>{{t('逗号分隔，不默认使用 22','Comma separated; never defaults to 22')}}</small></label>
     <label>{{t('面板入口端口（无法识别时填写）','Public panel ports (if not detected)')}}<input v-model="manualPanel" placeholder="9443" :disabled="!enabled"><small>{{t('填写本机实际入口，NAT 公网映射另行设置','Use the local public listener; configure external NAT separately')}}</small></label>
    </div>
    <div v-if="firewall?.requiredPorts?.length" class="fw-port-chips">
     <div v-for="port in firewall.requiredPorts" :key="`${port.port}/${port.protocol}`" class="fw-port-chip" :class="port.protected ? 'is-protected' : portAllowed(port) ? 'is-allowed' : 'is-pending'">
      <span class="fw-port-main">
       <code>{{port.port}}/{{formatProtocol(port.protocol)}}</code>
       <span class="ssh-dot">·</span>
       <span class="fw-port-reason">{{port.reason}}</span>
      </span>
      <button v-if="!port.protected && !portAllowed(port)" type="button" class="fw-allow-btn" :disabled="!fwWritable" @click="stage('firewall',{operation:'add',rule:{action:'allow',protocol:port.protocol as 'tcp'|'udp',portFrom:port.port,source:'any'}})">{{t('放行','Allow')}}</button>
      <span v-else class="fw-port-status" :class="port.protected ? 'protected' : 'allowed'">{{port.protected ? t('受保护','Protected') : t('已允许','Allowed')}}</span>
     </div>
    </div>
   </div>
   <div class="fw-add-panel">
    <div class="ssh-section-head">
     <div class="ssh-head-title">
      <b>{{t('添加入站规则','Add inbound rule')}}</b>
     </div>
     <small>{{t('支持单端口或连续端口段，选择 TCP+UDP 可同时放行双协议','Supports single port or range; choose TCP+UDP to allow both protocols')}}</small>
    </div>
    <form class="security-form fw-add-form" @submit.prevent="stageAddRule">
     <label>{{t('操作','Action')}}<select v-model="rule.action"><option value="allow">{{t('允许 (ALLOW)','Allow (ALLOW)')}}</option><option value="deny">{{t('拒绝 (DENY)','Deny (DENY)')}}</option></select></label>
     <label>{{t('协议','Protocol')}}<select v-model="rule.protocol"><option value="tcp">TCP</option><option value="udp">UDP</option><option value="tcp/udp">TCP+UDP</option></select></label>
     <label>{{t('起始端口','First port')}}<input v-model.number="rule.portFrom" type="number" min="1" max="65535" placeholder="1–65535" required></label>
     <label>{{t('结束端口（可选）','Last port (optional)')}}<input v-model.number="rule.portTo" type="number" :min="rule.portFrom || 1" max="65535" :placeholder="rule.portFrom ? String(rule.portFrom) : t('留空为单端口','Same as start')"></label>
     <label class="fw-source-field">{{t('来源 IP / CIDR（留空为任意）','Source IP / CIDR (empty means any)')}}<input v-model="rule.source" placeholder="192.0.2.1/32 · 2001:db8::/64"></label>
     <button class="primary fw-add-submit" :disabled="!fwWritable">{{t('预览添加规则','Preview rule')}}</button>
    </form>
   </div>
   <div class="fw-rules-panel">
    <div class="fw-table-toolbar">
     <div class="fw-toolbar-left">
      <div class="ssh-head-title">
       <b>{{t('当前防火墙规则','Firewall rules')}}</b>
       <span class="ssh-count-pill">{{displayedRules.length}}<template v-if="ruleFilter.trim()"> / {{firewall?.rules?.length || 0}}</template></span>
      </div>
      <input v-if="(firewall?.rules?.length || 0) > 6" v-model="ruleFilter" type="search" class="ssh-ban-search" :placeholder="t('搜索端口、服务或来源 IP…','Filter port, service or source IP…')" :aria-label="t('搜索防火墙规则','Filter firewall rules')">
     </div>
     <div class="fw-toolbar-batch">
      <span class="fw-batch-count" aria-live="polite">{{t('已选','Selected')}} <b>{{selectedRules.length}}</b> / 100</span>
      <select v-model="batchMode" class="fw-batch-select" :disabled="!batchWritable" :aria-label="t('批量操作','Batch action')">
       <option value="delete">{{t(`删除悟空规则 (${deleteEligibleCount})`,`Delete managed rules (${deleteEligibleCount})`)}}</option>
       <option value="adopt">{{t(`接管外部规则 (${adoptEligibleCount})`,`Adopt external rules (${adoptEligibleCount})`)}}</option>
      </select>
      <button v-if="selectedRules.length > 0" type="button" class="secondary fw-batch-btn" :disabled="!batchWritable" @click="selectedRules = []">{{t('清空选择','Clear')}}</button>
      <button type="button" class="fw-batch-btn" :class="batchMode === 'delete' ? 'danger-button' : 'primary'" :disabled="!batchWritable || !selectedRules.length || selectedRules.length > 100" @click="stageBatch">{{batchMode === 'delete' ? t('预览批量删除','Preview batch deletion') : t('预览批量接管','Preview batch adoption')}}</button>
     </div>
    </div>
    <p v-if="!batchSupported" class="security-footnote">{{t('Agent 不支持防火墙批量操作，请更新完整面板。','Update the full panel to support firewall batch actions.')}}</p>
    <div tabindex="0" role="region" :aria-label="t('防火墙规则列表','Firewall rules table')" class="security-table-wrap"><table class="security-table fw-table">
     <thead><tr><th class="security-select"><input type="checkbox" :checked="allSelected" :indeterminate="selectedRules.length > 0 && !allSelected" :disabled="!batchWritable || !batchEligible.length" :aria-label="t('全选可操作规则（最多 100 条）','Select eligible rules (up to 100)')" @change="selectAll"></th><th>{{t('规则','Rule')}}</th><th>{{t('对应服务 / 用途','Service / purpose')}}</th><th>{{t('来源 IP','Source IP')}}</th><th>{{t('归属','Ownership')}}</th><th class="fw-col-action">{{t('操作','Actions')}}</th></tr></thead>
     <tbody>
      <tr v-for="item in displayedRules" :key="item.id" :class="{'is-selected': selectedRules.includes(item.id)}">
       <td class="security-select"><input v-model="selectedRules" type="checkbox" :value="item.id" :disabled="!batchWritable || !securityBatchEligible(item,batchMode) || selectedRules.length >= 100 && !selectedRules.includes(item.id)" :aria-label="`${t('选择规则','Select rule')} ${item.portFrom}/${formatProtocol(item.protocol)}`"></td>
       <td>
        <div class="fw-rule-cell">
         <span class="fw-action-badge" :class="item.action === 'allow' ? 'is-allow' : 'is-deny'">{{item.action === 'allow' ? t('允许','Allow') : t('拒绝','Deny')}}</span>
         <code class="fw-rule-port">{{item.description || `${item.portFrom}${item.portTo !== item.portFrom ? '–'+item.portTo : ''}/${formatProtocol(item.protocol)}`}}</code>
         <span v-if="item.addressFamilies?.length" class="fw-family-tag">{{item.addressFamilies.map(family => family === 'ipv4' ? 'IPv4' : 'IPv6').join(' · ')}}</span>
        </div>
       </td>
       <td class="security-rule-services">
        <div v-if="securityRuleServices(item, firewall?.requiredPorts || [], language).length" class="fw-service-tags">
         <span v-for="service in securityRuleServices(item, firewall?.requiredPorts || [], language)" :key="service" class="fw-service-tag">{{service}}</span>
        </div>
        <small v-else class="fw-unidentified">{{t('未识别服务','Unidentified service')}}</small>
       </td>
       <td>
        <span v-if="item.source === 'any'" class="fw-source-any">{{t('任意 IP','Any IP')}}</span>
        <code v-else class="fw-source-cidr">{{item.source || '—'}}</code>
       </td>
       <td>
        <span class="fw-owner-badge" :class="item.protected ? 'is-protected' : item.managed ? 'is-managed' : 'is-external'">{{item.protected ? t('受保护','Protected') : item.managed ? t('悟空管理','Wukong managed') : t('外部规则','External rule')}}</span>
       </td>
       <td class="fw-col-action">
        <button v-if="item.adoptable && !item.managed" class="fw-row-btn" :disabled="!fwWritable" @click="stage('firewall',{operation:'adopt',ruleId:item.id})">{{t('接管','Adopt')}}</button>
        <button v-else-if="item.managed && !item.protected" class="fw-row-btn is-danger" :disabled="!fwWritable" @click="stage('firewall',{operation:'delete',ruleId:item.id})">{{t('删除','Delete')}}</button>
        <small v-else-if="item.protected" class="fw-op-note">{{t('系统保护','Protected')}}</small>
        <small v-else class="fw-op-note">{{t('只读','Read only')}}</small>
       </td>
      </tr>
      <tr v-if="!displayedRules.length">
       <td colspan="6" class="fw-empty-row">{{ruleFilter.trim() ? t('没有匹配的防火墙规则。','No matching firewall rules.') : t('当前暂无防火墙规则。','No firewall rules found.')}}</td>
      </tr>
     </tbody>
    </table></div>
    <div class="fw-footnotes">
     <small class="security-footnote">{{t('受保护规则不可删除；批量操作将整批预览并应用，执行失败自动恢复全部变更。','Protected rules cannot be deleted. Batch actions are reviewed and applied together; failures roll back all changes.')}}</small>
     <small class="security-footnote">{{t('用途按当前主机的端口建议匹配，不代表服务正在运行。后续节点不会自动修改防火墙；云安全组和 NAT 映射需单独配置。','Purposes match suggested ports and do not indicate running services. Cloud security groups and NAT require separate configuration.')}}</small>
    </div>
   </div>
  </section>
  <section class="panel-card security-card ssh-security-card">
   <div class="card-head">
    <div>
     <span class="section-mark">护</span>
     <div>
      <h3>{{t('SSH 登录防护（Fail2ban）','SSH login protection (Fail2ban)')}}</h3>
      <p>{{fail2ban?.logBackend || '—'}} {{fail2ban?.logPath}} · SSH {{fail2ban?.sshPorts.join(', ') || '—'}}</p>
     </div>
    </div>
    <span class="ssh-status-indicator" :class="{active: fbVerified && fail2ban?.active && !fail2ban.reason && online && fail2ban.logBackend && securityStateFresh(fail2ban.checkedAt,now)}">{{!fbVerified ? t('状态待复核','Status awaiting verification') : fail2ban?.active && !fail2ban.reason && online && fail2ban.logBackend && securityStateFresh(fail2ban.checkedAt,now) ? t('SSH 登录防护已开启','SSH login protection enabled') : t('防护尚未就绪','Protection not ready')}}</span>
   </div>
   <p v-if="!support('fail2ban')" class="security-warning">{{t('远端 Agent 不支持 SSH 防护管理，请更新完整面板。','The remote Agent does not support SSH protection. Update the full panel.')}}</p>
   <p v-if="fbLoading && !fbCurrent" class="security-loading" role="status">{{fail2ban ? t('正在复核 SSH 防护；下方是上次采样结果。','Checking SSH protection; the previous sample is shown below.') : t('正在读取 SSH 防护状态…','Loading SSH protection status…')}}</p>
   <p v-if="fbError" role="alert" class="security-warning">{{t('SSH 防护状态读取失败：','Failed to load SSH protection status: ')}}{{fbError}} {{fail2ban ? t('下方仅显示上次采样，已禁用操作。','The previous sample is shown; actions are disabled.') : ''}}</p>
   <div v-if="showSSHGuidance" class="security-guidance">
    <b v-if="fail2ban?.canActivate">{{t('已安装，SSH 登录防护尚未启用','Installed; SSH login protection is not enabled')}}</b>
    <b v-else-if="externalSSH && fail2ban?.active">{{t('发现已有 SSH 登录防护','Existing SSH login protection detected')}}</b>
    <b v-else-if="fail2ban?.installed && !fail2ban.active">{{t('SSH 登录防护尚未运行','SSH login protection is not running')}}</b>
    <p>{{t('此功能会检测 SSH 登录失败，达到你设定的次数后，阻止该 IP 继续连接 SSH。','This feature detects failed SSH logins and blocks an IP from SSH after your chosen failure limit.')}}</p>
    <p v-if="fail2ban?.canActivate">{{t('已有一份防护配置。检查下方参数后，点击“预览并启用现有防护”；面板会检查配置、启动防护并负责后续管理。','An existing protection configuration was found. Review the settings below and choose “Preview and enable existing protection”. The panel will validate, start and manage it.')}}</p>
    <p v-else-if="externalSSH && fail2ban?.active">{{t('可将现有防护交由面板管理，继续使用原配置名称，避免重复封禁。预览中会列出参数变更。','Let the panel manage the existing protection using its original name to avoid duplicate bans. Parameter changes appear in the preview.')}}</p>
    <p v-else-if="fbVerified && fail2ban?.installed && !fbWritable">{{t('目前无法安全启用。请根据下方原因处理；不熟悉服务器操作时，可把原因发给服务器管理员协助检查。','Protection cannot be safely enabled yet. Resolve the reason below, or ask your server administrator for help.')}}</p>
   </div>
   <p v-if="fail2ban?.reason && !fail2ban.canActivate" class="security-warning">{{fail2ban.reason}}</p>
   <div class="ssh-meta-toolbar">
    <div class="ssh-meta-left">
     <span v-if="fail2ban?.jails?.length" class="ssh-ownership-badge" :class="{managed: fail2ban.jails[0]?.managed}">{{fail2ban.jails[0]?.managed ? t('由面板管理','Managed by panel') : t('已有配置，尚未交由面板管理','Existing configuration; not managed by panel')}}</span>
     <small v-if="fail2ban" :class="{stale: !securityStateFresh(fail2ban.checkedAt,now)}">{{t('采样时间','Sampled')}} {{new Date(fail2ban.checkedAt).toLocaleString(language)}} {{!securityStateFresh(fail2ban.checkedAt,now) ? t('（已过期）','(stale)') : ''}}</small>
     <small v-if="!showSSHGuidance" class="ssh-brief-desc">· {{t('检测 SSH 登录失败并在达到阈值后自动封禁来源 IP','Detects failed SSH logins and blocks IPs exceeding your threshold')}}</small>
    </div>
    <div v-if="fail2ban && (!fail2ban.installed || fail2ban.managedJail)" class="security-actions ssh-header-actions">
     <button v-if="!fail2ban.installed" class="primary" :disabled="!fbWritable" @click="stage('fail2ban',{operation:'install'})">{{t('安装 Fail2ban','Install Fail2ban')}}</button>
     <button v-if="fail2ban.managedJail" class="secondary" :disabled="!fbWritable || !fail2ban.managedJail" @click="stage('fail2ban',{operation:'reload'})">{{t('重载防护','Reload protection')}}</button>
     <button v-if="fail2ban.managedJail" class="secondary" :disabled="!enabled || !fbCurrent || !fail2ban.managedJail" @click="stage('fail2ban',{operation:'disable'})">{{t('停用 SSH 防护','Disable SSH protection')}}</button>
     <button v-if="fail2ban.managedJail" class="secondary" :disabled="!enabled || !fbCurrent || !fail2ban.managedJail" @click="stage('fail2ban',{operation:'detach'})">{{t('解除接管','Release ownership')}}</button>
    </div>
   </div>
   <article v-for="jail in fail2ban?.jails" :key="jail.name" class="security-jail">
    <header v-if="(fail2ban?.jails?.length || 0) > 1"><b>{{t('SSH 登录防护','SSH login protection')}} · {{jail.name}}</b><span>{{jail.managed ? t('由面板管理','Managed by panel') : t('已有配置，尚未交由面板管理','Existing configuration; not managed by panel')}}</span></header>
    <p v-if="jail.configuredOnly || !fail2ban?.active" class="ssh-inactive-banner">{{t('尚未运行，无法读取失败次数和封禁记录。','Not running; failure counts and ban records are unavailable.')}}</p>
    <template v-else>
     <div class="ssh-metrics-grid">
      <div class="ssh-metric-card" :class="{'is-alert': jail.banned.length > 0}">
       <span class="ssh-metric-label">{{t('当前封禁','Current bans')}}</span>
       <strong class="ssh-metric-value">{{jail.banned.length}}</strong>
       <small class="ssh-metric-sub">{{t('正在拦截的 IP','Active blocked IPs')}}</small>
      </div>
      <div class="ssh-metric-card">
       <span class="ssh-metric-label">{{t('累计封禁','Total bans')}}</span>
       <strong class="ssh-metric-value">{{jail.totalBanned}}</strong>
       <small class="ssh-metric-sub">{{t('历史累计拦截','Historical blocks')}}</small>
      </div>
      <div class="ssh-metric-card" :class="{'is-warn': jail.failed > 0}">
       <span class="ssh-metric-label">{{t('当前失败','Current failures')}}</span>
       <strong class="ssh-metric-value">{{jail.failed}}</strong>
       <small class="ssh-metric-sub">{{t('统计窗口内失败','Failures in window')}}</small>
      </div>
      <div class="ssh-metric-card">
       <span class="ssh-metric-label">{{t('累计失败','Total failures')}}</span>
       <strong class="ssh-metric-value">{{jail.totalFailed}}</strong>
       <small class="ssh-metric-sub">{{t('历史累计失败尝试','Total failed attempts')}}</small>
      </div>
     </div>
     <div class="security-failure-sources">
      <div class="ssh-section-head">
       <div class="ssh-head-title">
        <b>{{t('最近失败来源（24 小时）','Recent failure sources (24 hours)')}}</b>
        <span class="ssh-count-pill">{{jail.failures?.length || 0}}</span>
       </div>
       <small v-if="jail.managed">{{t('手动封禁仅影响 SSH，时长沿用已保存的防护设置；已封禁的 IP 可在这里解除。','Manual bans affect SSH only and use the saved protection duration. Banned IPs can be unbanned here.')}}</small>
      </div>
      <small v-if="jail.managed && !manualBanSupported" class="security-warning">{{t('此 Agent 暂不支持手动封禁，请更新完整面板。','Update the full panel Agent to manually ban failure sources.')}}</small>
      <p v-if="!fail2ban.failureSourcesAvailable">{{fail2ban.failureSourcesReason ? t('失败来源暂不可用：','Failure sources unavailable: ') + securityCopy(fail2ban.failureSourcesReason) : t('此 Agent 暂不支持失败来源列表，请更新完整面板。','This Agent does not support failure sources yet. Update the full panel.')}}</p>
      <template v-else>
       <div v-if="jail.failures?.length" class="ssh-failure-list">
        <div v-for="source in jail.failures" :key="source.ip" class="security-failure-row">
         <span class="security-ip-country">
          <code>{{source.ip}}</code>
          <span class="ssh-dot">·</span>
          <img v-if="locations[source.ip]?.countryCode" :src="countryFlagURL(locations[source.ip]!.countryCode!)" alt="" aria-hidden="true">
          <span>{{sourceCountry(source.ip)}}</span>
          <span v-if="jail.banned.includes(source.ip)" class="ssh-status-badge is-banned">{{t('已封禁','Banned')}}</span>
         </span>
         <div class="security-failure-actions">
          <span class="ssh-attempt-badge">{{source.count}} {{t('次','attempts')}}</span>
          <span class="security-failure-detail">{{new Date(source.lastSeen).toLocaleString(language)}}</span>
          <button v-if="jail.managed && jail.banned.includes(source.ip)" class="secondary ssh-action-btn" :disabled="!unbanWritable" @click="stage('fail2ban',{operation:'unban',jail:jail.name,ip:source.ip})">{{t('解除封禁','Unban')}}</button>
          <button v-else-if="jail.managed" class="secondary ssh-action-btn" :disabled="!manualBanWritable" @click="stage('fail2ban',{operation:'ban',jail:jail.name,ip:source.ip})">{{t('手动封禁','Ban IP')}}</button>
         </div>
        </div>
       </div>
       <p v-else class="ssh-empty-hint">{{t('最近保留的日志中没有失败来源。','No failure sources in the recent retained logs.')}}</p>
       <div class="ssh-failure-footnotes">
        <small>{{t('按 Fail2ban 保留的检测日志统计，不含已忽略的连接；与上方累计计数可能不同。国家为 IP 归属信息。','Based on retained Fail2ban detection logs; ignored connections are excluded. Counts may differ from totals above. Country indicates IP allocation.')}}</small>
        <small v-if="fail2ban.failureSourcesLimited">{{t('日志读取或来源数量达到上限，仅展示最近记录（最多 50 个 IP）。','Log or source limit reached; only recent records are shown (up to 50 IPs).')}}</small>
       </div>
      </template>
     </div>
     <div class="security-bans-section">
      <div class="ssh-section-head">
       <div class="ssh-head-title">
        <b>{{t('当前封禁 IP','Currently banned IPs')}}</b>
        <span class="ssh-count-pill" :class="{'is-alert': jail.banned.length > 0}">{{jail.banned.length}}</span>
       </div>
       <div v-if="jail.banned.length > 0" class="ssh-bans-tools">
        <input v-if="jail.banned.length > 6" v-model="banFilter" type="search" class="ssh-ban-search" :placeholder="t('搜索 IP 或国家…','Filter IP or country…')" :aria-label="t('搜索封禁 IP 或国家','Filter banned IP or country')">
        <button v-if="!banFilter.trim() && jail.banned.length > 10" type="button" class="secondary ssh-expand-btn" @click="bansExpanded = !bansExpanded">{{bansExpanded ? t('收起列表','Collapse') : t(`展开全部 (${jail.banned.length})`,`Show all (${jail.banned.length})`)}}</button>
       </div>
      </div>
      <div v-if="displayedBannedIPs(jail.banned).length" class="security-bans">
       <div v-for="ip in displayedBannedIPs(jail.banned)" :key="ip" class="security-ban-chip">
        <span class="security-ip-country">
         <code>{{ip}}</code>
         <span class="ssh-dot">·</span>
         <img v-if="locations[ip]?.countryCode" :src="countryFlagURL(locations[ip]!.countryCode!)" alt="" aria-hidden="true">
         <span class="ssh-country-name" :title="sourceCountry(ip)">{{sourceCountry(ip)}}</span>
        </span>
        <button v-if="jail.managed" type="button" class="ssh-chip-unban" :disabled="!unbanWritable" @click="stage('fail2ban',{operation:'unban',jail:jail.name,ip})">{{t('解除封禁','Unban')}}</button>
       </div>
      </div>
      <p v-else-if="jail.banned.length" class="ssh-empty-hint">{{t('未找到匹配的封禁 IP。','No matching banned IPs found.')}}</p>
      <p v-else class="ssh-empty-hint">{{t('当前没有处于封禁状态的 IP。','No IPs are currently banned.')}}</p>
     </div>
    </template>
   </article>
   <div class="ssh-config-panel">
    <div class="ssh-section-head">
     <div class="ssh-head-title">
      <b>{{t('防护规则与白名单配置','Protection policy & whitelist')}}</b>
     </div>
     <small>{{t('调整阈值、检测窗口、封禁时长与可信白名单，保存后自动重载生效。','Configure threshold, detection window, ban duration and trusted whitelist.')}}</small>
    </div>
    <form class="security-form ssh-config-form" @submit.prevent="stageSSH">
     <label>
      <span class="ssh-field-label">
       <span>{{t('失败次数','Max retries')}}</span>
       <small class="ssh-field-hint">{{t('触发阈值','Threshold')}}</small>
      </span>
      <input v-model.number="config.maxRetry" type="number" min="1" max="100" required>
     </label>
     <label>
      <span class="ssh-field-label">
       <span>{{t('统计窗口（秒）','Find time (seconds)')}}</span>
       <small v-if="formatHumanSeconds(config.findTime, language)" class="ssh-window-human">≈ {{formatHumanSeconds(config.findTime, language)}}</small>
      </span>
      <input v-model.number="config.findTime" type="number" min="60" max="604800" required>
      <span class="ssh-preset-row">
       <button v-for="preset in [600, 3600, 86400, 604800]" :key="preset" type="button" class="ssh-preset-chip" :class="{active: config.findTime === preset}" @click="config.findTime = preset">{{formatHumanSeconds(preset, language)}}</button>
      </span>
     </label>
     <BanDurationInput v-model="config.banTime" :language="language" :permanent-supported="permanentBanSupported" />
     <label>
      <span class="ssh-field-label">
       <span>{{t('检测模式','Filter mode')}}</span>
      </span>
      <select v-model="config.mode">
       <option value="normal">{{t('标准模式 (NORMAL · 推荐)','Standard (NORMAL · recommended)')}}</option>
       <option value="ddos">{{t('防扫描模式 (DDOS)','Anti-scan (DDOS)')}}</option>
       <option value="extra">{{t('扩展检测模式 (EXTRA)','Extended (EXTRA)')}}</option>
       <option value="aggressive">{{t('严格检测模式 (AGGRESSIVE)','Aggressive (AGGRESSIVE)')}}</option>
      </select>
     </label>
     <label class="wide">
      <span>{{t('白名单 IP / CIDR','Whitelist IP / CIDR')}}</span>
      <textarea v-model="whitelist" rows="3" placeholder="192.0.2.1/32&#10;2001:db8::/64"></textarea>
      <small>{{t('填写不希望被封禁的可信 IP，每行一个。默认放行 127.0.0.1/8 与 ::1（本机回环），防止本地反代、探针与系统服务被误封锁死；不会自动加入当前上网 IP。','Enter trusted IPs that should never be banned, one per line. Defaults include 127.0.0.1/8 and ::1 (loopback) to prevent local proxies/probes from being locked out; your current IP is not added automatically.')}}</small>
     </label>
     <button class="primary" :disabled="!fbWritable || !fail2ban?.installed">{{fail2ban?.canActivate ? t('预览并启用现有防护','Preview and enable existing protection') : externalSSH ? t('预览并交由面板管理','Preview panel management') : fail2ban?.managedJail ? t('预览并保存防护设置','Preview and save protection settings') : t('预览并启用 SSH 防护','Preview and enable SSH protection')}}</button>
    </form>
   </div>
   <div v-if="fail2ban?.installed || fail2ban?.jails?.length" class="ssh-footer-drawers">
    <details v-for="jail in fail2ban?.jails" :key="`tech-${jail.name}`" class="security-technical">
     <summary>{{t('技术详情','Technical details')}}</summary>
     <p>{{t('配置名称（Fail2ban jail）','Configuration name (Fail2ban jail)')}}：<code>{{jail.name}}</code></p>
     <p>{{t('jail 是一组日志检测和封禁设置，页面称为“登录防护”。','A jail groups log detection and ban settings; this page calls it login protection.')}}</p>
     <p>{{t('白名单默认包含 127.0.0.1/8 与 ::1（IPv4/IPv6 本机回环），确保本地代理、探针与系统进程间通信永不被阻断。','The whitelist always includes 127.0.0.1/8 and ::1 (IPv4/IPv6 loopback) so local proxies, probes and daemon communications are never blocked.')}}</p>
     <p>{{t('国家信息由 ipwho.is 查询，只发送公开 IP；内网或保留地址不查询。','Country lookup uses ipwho.is and sends only public IPs; private and reserved addresses are not queried.')}}</p>
    </details>
    <details v-if="fail2ban?.installed" class="security-reset">
     <summary>{{t('修复与重新安装','Repair and reinstall')}}</summary>
     <p>{{t('多个配置冲突或安装损坏时，可备份后完全清理并重新安装。会删除所有 Fail2ban 防护配置、白名单和历史封禁，包括非 SSH 防护。重装后保持停用，请重新启用。','For conflicting configurations or a damaged installation, back up and reset Fail2ban. This removes all protection configurations, whitelists and ban history, including non-SSH protection. Protection stays disabled until you enable it again.')}}</p>
     <p v-if="fail2ban.resetReason" class="security-warning">{{securityCopy(fail2ban.resetReason)}}</p>
     <p v-if="!support('fail2ban.reset')" class="security-warning">{{t('远端 Agent 不支持清理重装，请更新完整面板。','Update the full remote panel to support resetting Fail2ban.')}}</p>
     <button class="danger-button" :disabled="!resetWritable" @click="stage('fail2ban',{operation:'reinstall'})">{{t('预览清理并重新安装','Preview reset and reinstall')}}</button>
    </details>
   </div>
  </section>
  <Teleport to="body"><div v-if="pending" class="modal-backdrop"><div class="modal-card security-preview" role="dialog" aria-modal="true" :aria-label="t('安全变更预览','Security change preview')"><p class="eyebrow">SECURITY CHANGE REVIEW</p><h2>{{t('确认应用到','Apply to')}} {{hostName}}</h2><ul><li v-for="change in pending.preview.changes" :key="change">{{securityCopy(change)}}</li></ul><div v-if="pending.request.operation === 'enable' && pending.kind === 'firewall'" class="security-port-list"><span v-for="port in pending.preview.requiredPorts" :key="`${port.port}/${port.protocol}`">{{port.port}}/{{formatProtocol(port.protocol)}} · {{port.reason}}</span></div><p v-for="warning in pending.preview.warnings" :key="warning">{{securityCopy(warning)}}</p><p v-if="pending.preview.needsConfirmation" class="security-warning">{{t('应用后需在 90 秒内确认连接，超时自动恢复。','After applying, confirm connectivity within 90 seconds or the change rolls back.')}}</p><label v-if="pending.request.operation === 'reinstall'" class="security-reset-confirm">{{t('输入 RESET FAIL2BAN 确认清理此主机的全部 Fail2ban 防护','Type RESET FAIL2BAN to reset all Fail2ban protection on this host')}}<input v-model="resetConfirmation" autocomplete="off" spellcheck="false" placeholder="RESET FAIL2BAN"></label><div class="modal-actions"><button class="secondary" :disabled="busy" @click="pending = null">{{t('取消','Cancel')}}</button><button :class="pending.request.operation === 'reinstall' ? 'danger-button' : 'primary'" :disabled="busy || !requestReady(pending.kind) || pending.request.operation === 'reinstall' && (!resetWritable || resetConfirmation !== 'RESET FAIL2BAN')" @click="apply">{{busy ? t('正在应用…','Applying…') : pending.request.operation === 'reinstall' ? t('确认清理并重新安装','Reset and reinstall') : t('确认应用','Apply change')}}</button></div></div></div></Teleport>
 </div>
</template>

<style scoped>
.ssh-status-indicator.active{color:var(--jade);font-weight:600}
.ssh-meta-toolbar{display:flex;align-items:center;justify-content:space-between;gap:14px;flex-wrap:wrap;padding:10px 0 14px;border-bottom:1px solid var(--line)}
.ssh-meta-left{display:flex;align-items:center;gap:10px;flex-wrap:wrap;font-size:11px;color:var(--muted)}
.ssh-ownership-badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:3px;font-size:11px;border:1px solid var(--line);background:var(--surface-code);color:var(--muted)}
.ssh-ownership-badge.managed{border-color:rgba(82,182,144,.38);background:rgba(82,182,144,.1);color:var(--jade)}
.ssh-brief-desc{color:var(--muted)}
.ssh-header-actions{margin:0!important}
.ssh-inactive-banner{padding:12px 14px;background:var(--surface-code);border:1px solid var(--line);font-size:12px;color:var(--muted);margin:12px 0}
.ssh-metrics-grid{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:12px;margin:14px 0}
.ssh-metric-card{display:flex;flex-direction:column;gap:4px;padding:12px 14px;background:var(--surface-code);border:1px solid var(--line);border-radius:4px;min-width:0}
.ssh-metric-card.is-alert{border-color:rgba(212,173,87,.42);background:rgba(212,173,87,.06)}
.ssh-metric-card.is-warn{border-color:rgba(227,107,89,.35)}
.ssh-metric-label{font-size:11px;color:var(--muted);line-height:1.4}
.ssh-metric-value{font-size:22px;font-weight:700;font-family:var(--mono,monospace);color:var(--paper);line-height:1.2}
.ssh-metric-card.is-alert .ssh-metric-value{color:var(--gold)}
.ssh-metric-sub{font-size:10px;color:var(--muted);line-height:1.4}
.ssh-section-head{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;margin-bottom:10px}
.ssh-section-head>small{font-size:11px;color:var(--muted);line-height:1.5}
.ssh-head-title{display:flex;align-items:center;gap:8px}
.ssh-head-title b{font-size:13px;color:var(--paper)}
.ssh-count-pill{display:inline-flex;align-items:center;justify-content:center;min-width:22px;height:18px;padding:0 6px;border-radius:999px;font-size:11px;font-family:var(--mono,monospace);background:rgba(var(--wash-rgb),.08);color:var(--paper);border:1px solid var(--line)}
.ssh-count-pill.is-alert{background:rgba(212,173,87,.16);border-color:rgba(212,173,87,.45);color:var(--gold);font-weight:600}
.security-failure-sources{margin:14px 0;padding:16px;border:1px solid var(--line);border-radius:4px;background:rgba(var(--wash-rgb),.015)}
.ssh-failure-list{border-top:1px solid var(--line);margin-top:6px}
.security-failure-row{display:flex;align-items:center;justify-content:space-between;gap:12px;padding:10px 0;border-bottom:1px solid var(--line);font-size:12px}
.security-ip-country{display:flex;align-items:center;gap:7px;min-width:0;flex-wrap:wrap}
.security-ip-country code{overflow-wrap:anywhere;font-weight:600}
.security-ip-country img{width:18px;height:13px;object-fit:cover;flex:none;border-radius:1px}
.ssh-dot{color:var(--muted)}
.ssh-status-badge{display:inline-flex;align-items:center;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;line-height:1.5}
.ssh-status-badge.is-banned{background:rgba(227,107,89,.15);border:1px solid rgba(227,107,89,.4);color:var(--danger-text)}
.security-failure-actions{display:flex;align-items:center;justify-content:flex-end;gap:10px;flex-wrap:wrap}
.security-failure-actions button{white-space:nowrap}
.ssh-attempt-badge{display:inline-flex;align-items:center;padding:2px 7px;border-radius:3px;font-size:11px;font-family:var(--mono,monospace);background:var(--surface-code);border:1px solid var(--line);color:var(--paper);white-space:nowrap}
.security-failure-detail{color:var(--muted);font-size:11px;white-space:nowrap}
.ssh-failure-footnotes{margin-top:10px;display:grid;gap:4px}
.ssh-failure-footnotes small{color:var(--muted);font-size:11px;line-height:1.6}
.security-bans-section{margin:14px 0;padding:16px;border:1px solid var(--line);border-radius:4px;background:rgba(var(--wash-rgb),.015)}
.ssh-bans-tools{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.ssh-ban-search{height:30px;padding:0 10px;font-size:12px;min-width:180px;border:1px solid var(--line);background:var(--surface-input);color:var(--paper);border-radius:3px}
.ssh-expand-btn{min-height:30px;padding:4px 10px;font-size:11px}
.security-bans{display:grid;grid-template-columns:repeat(auto-fill,minmax(240px,1fr));gap:10px;margin-top:10px}
.security-ban-chip{display:flex;align-items:center;justify-content:space-between;gap:8px;padding:8px 10px;background:var(--surface-code);border:1px solid var(--line);border-radius:4px;font-size:12px;min-width:0;transition:border-color .15s}
.security-ban-chip:hover{border-color:rgba(212,173,87,.38)}
.security-ban-chip .security-ip-country{flex:1;min-width:0;flex-wrap:nowrap;overflow:hidden}
.security-ban-chip .security-ip-country code{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;font-size:12px}
.ssh-country-name{white-space:nowrap;overflow:hidden;text-overflow:ellipsis;color:var(--muted);font-size:11px}
.ssh-chip-unban{flex:none;background:transparent;border:1px solid var(--line);color:var(--gold);padding:3px 9px;border-radius:3px;font-size:11px;cursor:pointer;white-space:nowrap;transition:background .15s,border-color .15s}
.ssh-chip-unban:hover:not(:disabled){background:rgba(212,173,87,.14);border-color:var(--gold)}
.ssh-chip-unban:disabled{opacity:.45;cursor:default}
.ssh-empty-hint{margin:10px 0 0;font-size:12px;color:var(--muted)}
.ssh-config-panel{margin-top:18px;padding-top:18px;border-top:1px solid var(--line)}
.ssh-config-form{margin-top:12px!important}
.ssh-field-label{display:flex;align-items:center;justify-content:space-between;gap:6px;flex-wrap:wrap}
.ssh-field-hint{font-size:10px!important;color:var(--muted)}
.ssh-window-human{font-size:11px!important;color:var(--gold)!important;font-weight:600}
.ssh-preset-row{display:flex;flex-wrap:wrap;gap:6px;margin-top:2px}
.ssh-preset-chip{background:var(--surface-code);border:1px solid var(--line);color:var(--muted);padding:2px 7px;border-radius:3px;font-size:10px;cursor:pointer;min-height:auto!important;grid-column:auto!important}
.ssh-preset-chip:hover,.ssh-preset-chip.active{border-color:var(--gold);color:var(--gold);background:rgba(212,173,87,.1)}
.ssh-footer-drawers{display:grid;grid-template-columns:repeat(auto-fit,minmax(260px,1fr));gap:12px;margin-top:18px;padding-top:14px;border-top:1px solid var(--line);align-items:start}
.ssh-footer-drawers .security-technical,.ssh-footer-drawers .security-reset{margin:0;padding:10px 12px;border:1px solid var(--line);border-radius:4px;background:var(--surface-code)}
.ssh-footer-drawers summary{cursor:pointer;color:var(--muted);font-size:12px;font-weight:500}
.ssh-footer-drawers p{font-size:11px;line-height:1.65;color:var(--muted);margin:8px 0 0}
.ssh-footer-drawers button{margin-top:10px}
.fw-zone-select{display:inline-flex!important;align-items:center;gap:6px;font-size:11px;color:var(--muted)}
.fw-zone-select select{height:30px;padding:0 8px;font-size:12px}
.fw-suggestions-panel{margin:14px 0;padding:16px;border:1px solid var(--line);border-radius:4px;background:rgba(var(--wash-rgb),.015)}
.fw-manual-ports{margin:10px 0 14px!important;padding:12px 14px;background:var(--surface-code);border:1px solid var(--line);border-radius:4px}
.fw-port-chips{display:flex;flex-wrap:wrap;gap:8px;margin-top:6px}
.fw-port-chip{display:inline-flex;align-items:center;gap:8px;padding:6px 10px;border:1px solid var(--line);border-radius:4px;background:var(--surface-code);font-size:12px;transition:border-color .15s}
.fw-port-chip.is-protected{border-color:rgba(212,173,87,.35);background:rgba(212,173,87,.05)}
.fw-port-chip.is-allowed{border-color:rgba(82,182,144,.28)}
.fw-port-chip.is-pending{border-color:rgba(212,173,87,.55);background:rgba(212,173,87,.08)}
.fw-port-main{display:inline-flex;align-items:center;gap:6px}
.fw-port-main code{font-weight:600;color:var(--paper)}
.fw-port-reason{color:var(--muted);font-size:11px}
.fw-port-status{display:inline-flex;align-items:center;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600}
.fw-port-status.protected{background:rgba(212,173,87,.14);color:var(--gold);border:1px solid rgba(212,173,87,.35)}
.fw-port-status.allowed{background:rgba(82,182,144,.12);color:var(--jade);border:1px solid rgba(82,182,144,.32)}
.fw-allow-btn{background:transparent;border:1px solid var(--gold);color:var(--gold);padding:2px 8px;border-radius:3px;font-size:11px;font-weight:600;cursor:pointer;transition:background .15s}
.fw-allow-btn:hover:not(:disabled){background:rgba(212,173,87,.15)}
.fw-allow-btn:disabled{opacity:.45;cursor:default}
.fw-add-panel{margin:14px 0;padding:16px;border:1px solid var(--line);border-radius:4px;background:rgba(var(--wash-rgb),.015)}
.fw-add-form{grid-template-columns:130px 120px 120px 140px minmax(180px,1fr) auto;align-items:end;margin:10px 0 0!important;gap:10px}
.fw-source-field{grid-column:auto}
.fw-add-submit{grid-column:auto!important;min-height:38px!important;white-space:nowrap}
.fw-rules-panel{margin-top:16px}
.fw-table-toolbar{display:flex;align-items:center;justify-content:space-between;gap:12px;flex-wrap:wrap;padding-bottom:12px}
.fw-toolbar-left{display:flex;align-items:center;gap:12px;flex-wrap:wrap}
.fw-toolbar-batch{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.fw-batch-count{font-size:12px;color:var(--muted);white-space:nowrap}
.fw-batch-count b{color:var(--paper);font-family:var(--mono,monospace)}
.fw-batch-select{height:32px;padding:0 10px;font-size:12px;min-width:170px}
.fw-batch-btn{min-height:32px;padding:4px 12px;font-size:12px;white-space:nowrap}
.fw-table{border-collapse:separate;border-spacing:0}
.fw-table thead{position:sticky;inset-block-start:0;z-index:1;background:var(--surface-card,var(--bg))}
.fw-table tbody tr:hover{background:rgba(var(--wash-rgb),.025)}
.fw-table tbody tr.is-selected{background:rgba(212,173,87,.06)}
.fw-rule-cell{display:flex;align-items:center;gap:8px;flex-wrap:wrap}
.fw-action-badge{display:inline-flex;align-items:center;padding:1px 6px;border-radius:3px;font-size:10px;font-weight:600;line-height:1.5}
.fw-action-badge.is-allow{background:rgba(82,182,144,.12);border:1px solid rgba(82,182,144,.35);color:var(--jade)}
.fw-action-badge.is-deny{background:rgba(227,107,89,.14);border:1px solid rgba(227,107,89,.38);color:var(--danger-text)}
.fw-rule-port{font-size:12px;font-weight:600;color:var(--paper)}
.fw-family-tag{display:inline-flex;align-items:center;padding:1px 5px;border-radius:3px;font-size:10px;background:var(--surface-code);border:1px solid var(--line);color:var(--muted)}
.fw-service-tags{display:flex;flex-wrap:wrap;gap:6px}
.fw-service-tag{display:inline-flex!important;align-items:center;padding:2px 8px;border-radius:3px;font-size:11px;background:var(--surface-code);border:1px solid var(--line);color:var(--paper);min-width:auto!important;max-width:none!important;line-height:1.4!important}
.fw-unidentified{color:var(--muted);opacity:.65;font-size:11px}
.fw-source-any{color:var(--muted);font-size:12px}
.fw-source-cidr{font-size:12px;color:var(--paper)}
.fw-owner-badge{display:inline-flex;align-items:center;padding:2px 8px;border-radius:999px;font-size:11px;border:1px solid var(--line);background:var(--surface-code);color:var(--muted);white-space:nowrap}
.fw-owner-badge.is-protected{border-color:rgba(212,173,87,.4);background:rgba(212,173,87,.1);color:var(--gold)}
.fw-owner-badge.is-managed{border-color:rgba(82,182,144,.36);background:rgba(82,182,144,.1);color:var(--jade)}
.fw-col-action{text-align:right!important;white-space:nowrap}
.fw-row-btn{background:transparent;border:1px solid var(--line);color:var(--gold);padding:3px 10px;border-radius:3px;font-size:11px;cursor:pointer;margin:0!important;transition:background .15s,border-color .15s}
.fw-row-btn:hover:not(:disabled){background:rgba(212,173,87,.14);border-color:var(--gold)}
.fw-row-btn.is-danger:hover:not(:disabled){background:rgba(227,107,89,.14);border-color:var(--danger-text);color:var(--danger-text)}
.fw-row-btn:disabled{opacity:.45;cursor:default}
.fw-op-note{color:var(--muted);opacity:.65;font-size:11px}
.fw-empty-row{text-align:center!important;padding:24px 12px!important;color:var(--muted)}
.fw-footnotes{margin-top:12px;display:grid;gap:4px}
@media(max-width:1050px){
 .fw-add-form{grid-template-columns:repeat(4,minmax(0,1fr))}
 .fw-source-field{grid-column:1/4}
 .fw-add-submit{grid-column:4/5;justify-self:stretch}
}
.security-loading{font-size:12px;color:var(--muted);line-height:1.65}
.security-batch-heading{display:flex;align-items:center;gap:10px;flex-wrap:wrap}.security-batch-heading small{font-size:12px;color:var(--muted);white-space:nowrap}.security-select{width:32px}.security-select input{width:16px;height:16px;accent-color:var(--gold);cursor:pointer}.security-select input:disabled{cursor:default}
.security-reset{border-top:1px solid var(--line);padding:16px 0;margin:16px 0}.security-reset summary{cursor:pointer;color:var(--muted);font-size:12px}.security-reset p{font-size:12px;line-height:1.7}.security-reset-confirm{display:grid;gap:10px;font-size:12px;margin:18px 0}.security-card{padding:22px;margin-bottom:20px}.security-card>.card-head{margin-bottom:15px}.security-warning{color:var(--danger-text);font-size:12px;line-height:1.65;overflow-wrap:anywhere}.security-actions{display:flex;flex-wrap:wrap;align-items:end;gap:10px;margin:18px 0}.security-form{display:grid;align-items:start;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:20px 0}.security-form label,.security-actions label{display:grid;gap:7px;min-width:0;font-size:12px}.security-form small,.security-footnote,.security-card>small{font-size:11px;color:var(--muted);line-height:1.6}.security-form .wide{grid-column:1/-1}.security-form>button{align-self:end;min-height:40px;grid-column:1/-1;justify-self:start}.security-ports{grid-template-columns:repeat(2,minmax(0,1fr))}.security-port-list{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}.security-port-list>b{width:100%;font-size:12px}.security-port-list>span{padding:6px 9px;border:1px solid var(--line);font-size:11px;overflow-wrap:anywhere}.security-port-list button,.security-table button,.security-jail header button{background:transparent;border:1px solid var(--line);color:var(--gold);padding:4px 8px;margin-left:6px;cursor:pointer}.security-table-wrap{overflow-x:auto}.security-table{width:100%;border-collapse:collapse;font-size:12px}.security-table th,.security-table td{text-align:left;padding:12px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.security-rule-services span{display:block;min-width:140px;max-width:320px;line-height:1.65}.security-rule-services small{color:var(--muted)}.security-table th{color:var(--muted);font-weight:500}.security-notice{padding:20px;margin-bottom:20px}.security-notice p{font-size:12px;line-height:1.7}.security-notice b{margin-right:16px}.security-guidance{padding:14px 16px;margin:14px 0;background:var(--surface-code);border-left:3px solid var(--gold)}.security-guidance b{font-size:13px}.security-guidance p{font-size:12px;line-height:1.7;margin:6px 0;color:var(--muted)}.security-technical{font-size:11px;color:var(--muted)}.security-technical summary{cursor:pointer}.security-technical code{overflow-wrap:anywhere}.security-jail{padding:6px 0 4px}.security-jail header{display:flex;align-items:center;gap:12px;flex-wrap:wrap;margin-bottom:8px}.security-jail header span,.security-jail p{font-size:11px;color:var(--muted)}.security-preview ul{padding-left:18px;font-size:13px;line-height:1.8}.security-preview p{font-size:12px;line-height:1.7}.stale{color:var(--danger-text)!important}
@media(max-width:700px){
 .ssh-metrics-grid{grid-template-columns:repeat(2,minmax(0,1fr))}
 .security-failure-row{align-items:flex-start;flex-direction:column;gap:8px}
 .security-failure-detail{white-space:normal}
 .security-form,.fw-add-form{grid-template-columns:repeat(2,minmax(0,1fr))}
 .fw-source-field,.fw-add-submit{grid-column:1/-1!important}
 .security-ports{grid-template-columns:1fr}
 .security-card{padding:16px}
 .security-table{min-width:680px}
 .security-notice button{display:block;margin-top:12px}
}
@media(max-width:400px){
 .ssh-metrics-grid{grid-template-columns:1fr}
 .security-form{grid-template-columns:1fr}
 .security-preview{padding:20px}
}
</style>
