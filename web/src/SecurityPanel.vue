<script setup lang="ts">
import { computed, onBeforeUnmount, onMounted, reactive, ref } from 'vue'
import { hostSecurityAPI, type FirewallState, type Fail2banState, type SecurityRequest, type SecurityPreview, type SSHProtectionConfig, type Job } from './api'
import { translateText } from './i18n'
import { parseSecurityPorts, securityRuleServices, securityStateFresh } from './securityRules'
const props = defineProps<{hostId: string; hostName: string; online: boolean; compatible: boolean; capabilities: string[]; language: string}>()
const client = hostSecurityAPI(props.hostId)
const t = (zh: string, en: string) => props.language === 'en-US' ? en : zh
const securityCopy = (text: string) => translateText(text,props.language === 'en-US' ? 'en-US' : 'zh-CN')
const firewall = ref<FirewallState | null>(null)
const fail2ban = ref<Fail2banState | null>(null)
const error = ref('')
const resetConfirmation = ref('')
const busy = ref(false)
const refreshing = ref(false)
const zone = ref('')
const now = ref(Date.now())
const pending = ref<{kind: 'firewall'|'fail2ban'; request: SecurityRequest; preview: SecurityPreview} | null>(null)
const job = ref<Job | null>(null)
const rule = reactive({action: 'allow' as 'allow'|'deny', protocol: 'tcp' as 'tcp'|'udp', portFrom: 0, portTo: 0, source: ''})
const manualSSH = ref('')
const manualPanel = ref('')
const config = reactive<SSHProtectionConfig>({maxRetry:5,findTime:600,banTime:3600,mode:'normal',ignoreIPs:[]})
const whitelist = ref('')
let hydrated = false
let alive = true
let refreshTimer: ReturnType<typeof setInterval>
let clockTimer: ReturnType<typeof setInterval>
const support = (kind: string) => props.hostId === 'local' || props.capabilities.includes(`security.${kind}`)
const enabled = computed(() => props.online && props.compatible && !busy.value && !job.value && !firewall.value?.pending)
const fwWritable = computed(() => enabled.value && support('firewall') && firewall.value?.writable && securityStateFresh(firewall.value.checkedAt, now.value))
const fbWritable = computed(() => enabled.value && support('fail2ban') && fail2ban.value?.writable && securityStateFresh(fail2ban.value.checkedAt, now.value))
const resetWritable = computed(() => enabled.value && support('fail2ban.reset') && fail2ban.value?.canReset && securityStateFresh(fail2ban.value.checkedAt, now.value))
const seconds = computed(() => Math.max(0, Math.ceil((Date.parse(firewall.value?.pending?.deadline || '') - now.value) / 1000)))
function configRequest(): SSHProtectionConfig { return {...config, ignoreIPs: whitelist.value.split(/[\s,]+/).filter(Boolean)} }
function portAllowed(port: {port:number;protocol:string}): boolean {return !!firewall.value?.rules.some(rule => rule.adoptable && rule.action==='allow' && rule.source==='any' && rule.protocol===port.protocol && rule.portFrom<=port.port && rule.portTo>=port.port)}

async function refresh() {
 if (refreshing.value || !alive) return
 refreshing.value = true
 try {
  const [fw, fb] = await Promise.allSettled([support('firewall') ? client.firewall(zone.value) : Promise.resolve(null),support('fail2ban') ? client.fail2ban() : Promise.resolve(null)])
  if (!alive) return
  if (fw.status === 'fulfilled') { firewall.value = fw.value; if (fw.value?.zone) zone.value = fw.value.zone }
  else error.value = String(fw.reason?.message || fw.reason)
  if (fb.status === 'fulfilled') { fail2ban.value = fb.value; if (fb.value && !hydrated) {const existing = fb.value.jails.length === 1 && !fb.value.managedJail && fb.value.active ? fb.value.jails[0].config : fb.value.config;Object.assign(config, existing); whitelist.value = existing.ignoreIPs.join('\n');hydrated = true} }
  else error.value = String(fb.reason?.message || fb.reason)
  if (job.value) {const updated = await client.job(job.value.id);if (!alive) return;job.value = updated;if (updated.status === 'success' || updated.status === 'failed') {error.value = updated.error || '';job.value = null;hydrated = false}}
 } finally {refreshing.value = false}
}
async function stage(kind: 'firewall'|'fail2ban', request: SecurityRequest) {
 if (!enabled.value) return
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
 if (!staged || !enabled.value || staged.request.operation === 'reinstall' && (!resetWritable.value || resetConfirmation.value !== 'RESET FAIL2BAN')) return
 busy.value = true;error.value = ''
 try {
  const result = await client.apply(staged.kind, {...staged.request, ...(staged.request.operation === 'reinstall' ? {confirmation:resetConfirmation.value} : {})})
  if (!alive) return
  pending.value = null
  if (result.firewall) firewall.value = result.firewall
  if (result.fail2ban) fail2ban.value = result.fail2ban
  if (result.jobId) job.value = {id:result.jobId,status:'running',progress:0,message:t('正在安装','Installing'),kind:'security.install',target:props.hostName,error:'',createdAt:new Date().toISOString(),updatedAt:new Date().toISOString()}
  await refresh()
 } catch (e) {if (alive) {error.value = e instanceof Error ? e.message : String(e);pending.value = null;await refresh()}}
 finally {busy.value = false}
}
async function confirm() {
 const transaction = firewall.value?.pending
 if (!transaction || !props.online || busy.value || seconds.value <= 0) return
 busy.value = true
 try {await client.confirm(transaction.id);if (alive) await refresh()}
 catch(e) {if (alive) error.value = e instanceof Error ? e.message : String(e)}
 finally {busy.value = false}
}
const externalSSH = computed(() => fail2ban.value?.jails.length === 1 && !fail2ban.value.managedJail ? fail2ban.value.jails[0] : null)
function stageSSH() {
 const existing = externalSSH.value
 void stage('fail2ban', {operation: existing ? 'adopt' : fail2ban.value?.managedJail ? 'configure' : 'enable', jail: existing?.name, config: configRequest()})
}
onMounted(() => {void refresh();refreshTimer = setInterval(() => {void refresh()}, 10_000);clockTimer = setInterval(() => {now.value = Date.now()},1000)})
onBeforeUnmount(() => {alive = false;clearInterval(refreshTimer);clearInterval(clockTimer);pending.value = null})
</script>

<template>
 <div class="page-content security-page">
  <div class="page-intro"><div><p>HOST SECURITY</p><h2>{{t('主机安全','Host security')}}</h2><small>{{hostName}}</small></div><button class="secondary" :disabled="refreshing || busy" @click="refresh">{{t('刷新状态','Refresh')}}</button></div>
  <p v-if="!online || !compatible" class="security-warning">{{t('此主机离线或协议不兼容；只能查看最后状态，已禁用操作。','This host is offline or incompatible. Displayed snapshots are historical; actions are disabled.')}}</p>
  <p v-if="error" role="alert" class="security-warning">{{error}}</p>
  <section v-if="job" class="panel-card security-notice"><b>{{t('安全组件安装','Security component installation')}}</b><p>{{job.message}} · {{job.progress}}%</p><small>{{t('进度和错误同时记录在任务日志。','Progress and errors are also recorded in Jobs.')}}</small></section>
  <section v-if="firewall?.pending" class="panel-card security-notice danger"><h3>{{t('请确认连接仍正常','Confirm connectivity')}}</h3><p>{{t('变更将在倒计时结束后自动恢复。请确认能够重新连接 SSH 和面板后保留配置。','The change will roll back when the timer expires. Keep it only after verifying new SSH and panel connections.')}}</p><b>{{seconds}} s</b><button class="primary" :disabled="busy || !online || seconds <= 0" @click="confirm">{{t('连接正常，保留变更','Connections work — keep change')}}</button><p v-if="firewall.pending.error">{{firewall.pending.error}}</p></section>
  <section class="panel-card security-card">
   <div class="card-head"><div><span class="section-mark jade">防</span><div><h3>{{t('防火墙管理','Firewall')}}</h3><p>{{firewall?.backend || '—'}} · {{firewall?.policy || '—'}}</p></div></div><span>{{firewall?.active && online && securityStateFresh(firewall.checkedAt,now) && firewall.policy === 'deny' ? t('入站防护已开启','Inbound protection enabled') : t('入站防护未开启','Inbound protection disabled')}}</span></div>
   <p v-if="!support('firewall')" class="security-warning">{{t('远端 Agent 不支持防火墙管理，请更新完整面板。','The remote Agent does not support firewall management. Update the full panel.')}}</p>
   <p v-if="firewall?.reason" class="security-warning">{{firewall.reason}}</p>
   <small v-if="firewall" :class="{stale: !securityStateFresh(firewall.checkedAt, now)}">{{t('采样时间','Sampled')}} {{new Date(firewall.checkedAt).toLocaleString(language)}} {{!securityStateFresh(firewall.checkedAt,now) ? t('（已过期）','(stale)') : ''}}</small>
   <div class="security-actions">
    <button v-if="firewall && !firewall.installed" class="primary" :disabled="!fwWritable" @click="stage('firewall',{operation:'install'})">{{t('安装防火墙组件','Install firewall')}}</button>
    <button v-else class="primary" :disabled="!fwWritable" @click="stage('firewall',{operation:'enable'})">{{t('开启入站防护','Enable inbound protection')}}</button>
    <button class="secondary" :disabled="!fwWritable || !firewall?.active" @click="stage('firewall',{operation:'disable'})">{{t('关闭防火墙','Disable firewall')}}</button>
    <label v-if="firewall?.zones.length">{{t('区域','Zone')}}<select v-model="zone" :disabled="busy || !!firewall.pending" @change="refresh"><option v-for="item in firewall.zones" :key="item">{{item}}</option></select></label>
   </div>
   <div class="security-form security-ports"><label>{{t('SSH 端口（无法识别时填写）','SSH ports (if not detected)')}}<input v-model="manualSSH" placeholder="46961" :disabled="!enabled"><small>{{t('逗号分隔，不默认使用 22','Comma separated; never defaults to 22')}}</small></label><label>{{t('面板入口端口（无法识别时填写）','Public panel ports (if not detected)')}}<input v-model="manualPanel" placeholder="9443" :disabled="!enabled"><small>{{t('填写本机实际入口，NAT 公网映射另行设置','Use the local public listener; configure external NAT separately')}}</small></label></div>
   <div class="security-port-list"><b>{{t('管理保护与节点端口建议','Protected management ports and node suggestions')}}</b><span v-for="port in firewall?.requiredPorts" :key="`${port.port}/${port.protocol}`">{{port.port}}/{{port.protocol}} · {{port.reason}} <button v-if="!port.protected && !portAllowed(port)" :disabled="!fwWritable" @click="stage('firewall',{operation:'add',rule:{action:'allow',protocol:port.protocol as 'tcp'|'udp',portFrom:port.port,source:'any'}})">{{t('放行','Allow')}}</button><small v-else>{{port.protected ? t('受保护','Protected') : t('已允许','Allowed')}}</small></span></div>
   <form class="security-form" @submit.prevent="stage('firewall',{operation:'add',rule:{...rule,portTo:rule.portTo || rule.portFrom,source:rule.source || 'any'}})">
    <label>{{t('操作','Action')}}<select v-model="rule.action"><option value="allow">{{t('允许','Allow')}}</option><option value="deny">{{t('拒绝','Deny')}}</option></select></label>
    <label>{{t('协议','Protocol')}}<select v-model="rule.protocol"><option>tcp</option><option>udp</option></select></label>
    <label>{{t('起始端口','First port')}}<input v-model.number="rule.portFrom" type="number" min="1" max="65535" required></label>
    <label>{{t('结束端口（可选）','Last port (optional)')}}<input v-model.number="rule.portTo" type="number" min="0" max="65535"></label>
    <label class="wide">{{t('来源 IP / CIDR（留空为任意）','Source IP / CIDR (empty means any)')}}<input v-model="rule.source" placeholder="192.0.2.1/32 · 2001:db8::/64"></label>
    <button class="primary" :disabled="!fwWritable">{{t('预览添加规则','Preview rule')}}</button>
   </form>
   <div class="security-table-wrap"><table class="security-table">
    <thead><tr><th>{{t('规则','Rule')}}</th><th>{{t('对应服务 / 用途','Service / purpose')}}</th><th>{{t('来源 IP','Source IP')}}</th><th>{{t('归属','Ownership')}}</th><th>{{t('操作','Actions')}}</th></tr></thead>
    <tbody><tr v-for="item in firewall?.rules" :key="item.id">
     <td>{{item.description || `${t(item.action === 'allow' ? '允许' : '拒绝',item.action)} ${item.portFrom}${item.portTo !== item.portFrom ? '–'+item.portTo : ''}/${item.protocol}`}}</td>
     <td class="security-rule-services"><span v-for="service in securityRuleServices(item, firewall?.requiredPorts || [], language)" :key="service">{{service}}</span><small v-if="!securityRuleServices(item, firewall?.requiredPorts || [], language).length">{{t('未识别服务','Unidentified service')}}</small></td>
     <td>{{item.source === 'any' ? t('任意 IP','Any IP') : item.source || '—'}}</td>
     <td>{{item.protected ? t('受保护','Protected') : item.managed ? t('悟空管理','Wukong managed') : t('已有外部规则','Existing external rule')}}</td>
     <td><button v-if="item.adoptable && !item.managed" :disabled="!fwWritable" @click="stage('firewall',{operation:'adopt',ruleId:item.id})">{{t('接管','Adopt')}}</button><button v-if="item.managed" :disabled="!fwWritable || item.protected" @click="stage('firewall',{operation:'delete',ruleId:item.id})">{{t('删除','Delete')}}</button><small v-if="!item.adoptable">{{t('只读','Read only')}}</small></td>
    </tr></tbody>
   </table></div>
   <p class="security-footnote">{{t('用途按当前主机的端口建议匹配，不代表服务正在运行。任意 IP 表示不限制访问来源。','Purposes match this host’s suggested ports and do not indicate running services. Any IP means unrestricted source addresses.')}}</p>
   <p class="security-footnote">{{t('后续节点不会自动修改防火墙；云安全组和 NAT 映射需单独配置。','Future nodes do not automatically change firewall rules. Cloud security groups and NAT need separate configuration.')}}</p>
  </section>
  <section class="panel-card security-card">
   <div class="card-head"><div><span class="section-mark">护</span><div><h3>{{t('SSH 登录防护（Fail2ban）','SSH login protection (Fail2ban)')}}</h3><p>{{fail2ban?.logBackend || '—'}} {{fail2ban?.logPath}} · SSH {{fail2ban?.sshPorts.join(', ') || '—'}}</p></div></div><span>{{fail2ban?.active && !fail2ban.reason && online && fail2ban.logBackend && securityStateFresh(fail2ban.checkedAt,now) ? t('SSH 登录防护已开启','SSH login protection enabled') : t('防护尚未就绪','Protection not ready')}}</span></div>
   <p v-if="!support('fail2ban')" class="security-warning">{{t('远端 Agent 不支持 SSH 防护管理，请更新完整面板。','The remote Agent does not support SSH protection. Update the full panel.')}}</p>
   <div class="security-guidance">
    <b v-if="fail2ban?.canActivate">{{t('已安装，SSH 登录防护尚未启用','Installed; SSH login protection is not enabled')}}</b>
    <b v-else-if="externalSSH && fail2ban?.active">{{t('发现已有 SSH 登录防护','Existing SSH login protection detected')}}</b>
    <b v-else-if="fail2ban?.installed && !fail2ban.active">{{t('SSH 登录防护尚未运行','SSH login protection is not running')}}</b>
    <p>{{t('此功能会检测 SSH 登录失败，达到你设定的次数后，临时阻止该 IP 继续连接 SSH。','This feature detects failed SSH logins and temporarily blocks an IP from SSH after your chosen failure limit.')}}</p>
    <p v-if="fail2ban?.canActivate">{{t('已有一份防护配置。检查下方参数后，点击“预览并启用现有防护”；面板会检查配置、启动防护并负责后续管理。','An existing protection configuration was found. Review the settings below and choose “Preview and enable existing protection”. The panel will validate, start and manage it.')}}</p>
    <p v-else-if="externalSSH && fail2ban?.active">{{t('可将现有防护交由面板管理，继续使用原配置名称，避免重复封禁。预览中会列出参数变更。','Let the panel manage the existing protection using its original name to avoid duplicate bans. Parameter changes appear in the preview.')}}</p>
    <p v-else-if="fail2ban?.installed && !fbWritable">{{t('目前无法安全启用。请根据下方原因处理；不熟悉服务器操作时，可把原因发给服务器管理员协助检查。','Protection cannot be safely enabled yet. Resolve the reason below, or ask your server administrator for help.')}}</p>
   </div>
   <p v-if="fail2ban?.reason && !fail2ban.canActivate" class="security-warning">{{fail2ban.reason}}</p>
   <small v-if="fail2ban">{{t('采样时间','Sampled')}} {{new Date(fail2ban.checkedAt).toLocaleString(language)}} {{!securityStateFresh(fail2ban.checkedAt,now) ? t('（已过期）','(stale)') : ''}}</small>
   <div class="security-actions"><button v-if="fail2ban && !fail2ban.installed" class="primary" :disabled="!fbWritable" @click="stage('fail2ban',{operation:'install'})">{{t('安装 Fail2ban','Install Fail2ban')}}</button><button v-if="fail2ban?.managedJail" class="secondary" :disabled="!fbWritable || !fail2ban?.managedJail" @click="stage('fail2ban',{operation:'reload'})">{{t('重载防护','Reload protection')}}</button><button v-if="fail2ban?.managedJail" class="secondary" :disabled="!enabled || !fail2ban?.managedJail" @click="stage('fail2ban',{operation:'disable'})">{{t('停用 SSH 防护','Disable SSH protection')}}</button><button v-if="fail2ban?.managedJail" class="secondary" :disabled="!enabled || !fail2ban?.managedJail" @click="stage('fail2ban',{operation:'detach'})">{{t('解除接管','Release ownership')}}</button></div>
   <details v-if="fail2ban?.installed" class="security-reset"><summary>{{t('修复与重新安装','Repair and reinstall')}}</summary><p>{{t('多个配置冲突或安装损坏时，可备份后完全清理并重新安装。会删除所有 Fail2ban 防护配置、白名单和历史封禁，包括非 SSH 防护。重装后保持停用，请重新启用。','For conflicting configurations or a damaged installation, back up and reset Fail2ban. This removes all protection configurations, whitelists and ban history, including non-SSH protection. Protection stays disabled until you enable it again.')}}</p><p v-if="fail2ban.resetReason" class="security-warning">{{securityCopy(fail2ban.resetReason)}}</p><p v-if="!support('fail2ban.reset')" class="security-warning">{{t('远端 Agent 不支持清理重装，请更新完整面板。','Update the full remote panel to support resetting Fail2ban.')}}</p><button class="danger-button" :disabled="!resetWritable" @click="stage('fail2ban',{operation:'reinstall'})">{{t('预览清理并重新安装','Preview reset and reinstall')}}</button></details>
   <form class="security-form" @submit.prevent="stageSSH"><label>{{t('失败次数','Max retries')}}<input v-model.number="config.maxRetry" type="number" min="1" max="100" required></label><label>{{t('统计窗口（秒）','Find time (seconds)')}}<input v-model.number="config.findTime" type="number" min="60" max="604800" required></label><label>{{t('封禁时长（秒）','Ban time (seconds)')}}<input v-model.number="config.banTime" type="number" min="60" max="2592000" required></label><label>{{t('检测模式','Filter mode')}}<select v-model="config.mode"><option value="normal">{{t('标准（推荐）','Standard (recommended)')}}</option><option>ddos</option><option>extra</option><option>aggressive</option></select></label><label class="wide">{{t('白名单 IP / CIDR','Whitelist IP / CIDR')}}<textarea v-model="whitelist" rows="3" placeholder="192.0.2.1/32&#10;2001:db8::/64"></textarea><small>{{t('填写不希望被封禁的可信 IP，每行一个。本机地址始终放行；不会自动加入你当前的上网 IP。','Enter trusted IPs that should never be banned, one per line. Local addresses remain trusted; your current Internet IP is not added automatically.')}}</small></label><button class="primary" :disabled="!fbWritable || !fail2ban?.installed">{{fail2ban?.canActivate ? t('预览并启用现有防护','Preview and enable existing protection') : externalSSH ? t('预览并交由面板管理','Preview panel management') : fail2ban?.managedJail ? t('预览并保存防护设置','Preview and save protection settings') : t('预览并启用 SSH 防护','Preview and enable SSH protection')}}</button></form>
   <article v-for="jail in fail2ban?.jails" :key="jail.name" class="security-jail">
    <header><b>{{t('SSH 登录防护','SSH login protection')}}</b><span>{{jail.managed ? t('由面板管理','Managed by panel') : t('已有配置，尚未交由面板管理','Existing configuration; not managed by panel')}}</span></header>
    <p v-if="jail.configuredOnly || !fail2ban?.active">{{t('尚未运行，无法读取失败次数和封禁记录。','Not running; failure counts and ban records are unavailable.')}}</p>
    <p v-else>{{t('当前失败','Current failures')}} {{jail.failed}} · {{t('累计失败','Total failures')}} {{jail.totalFailed}} · {{t('当前封禁','Current bans')}} {{jail.banned.length}} · {{t('累计封禁','Total bans')}} {{jail.totalBanned}}</p>
    <div class="security-bans"><span v-for="ip in jail.banned" :key="ip"><code>{{ip}}</code><button v-if="jail.managed" :disabled="!enabled" @click="stage('fail2ban',{operation:'unban',ip})">{{t('解封','Unban')}}</button></span></div>
    <details class="security-technical"><summary>{{t('技术详情','Technical details')}}</summary><p>{{t('配置名称（Fail2ban jail）','Configuration name (Fail2ban jail)')}}：<code>{{jail.name}}</code></p><p>{{t('jail 是一组日志检测和封禁设置，页面称为“登录防护”。','A jail groups log detection and ban settings; this page calls it login protection.')}}</p></details>
   </article>
  </section>
  <Teleport to="body"><div v-if="pending" class="modal-backdrop"><div class="modal-card security-preview" role="dialog" aria-modal="true" :aria-label="t('安全变更预览','Security change preview')"><p class="eyebrow">SECURITY CHANGE REVIEW</p><h2>{{t('确认应用到','Apply to')}} {{hostName}}</h2><ul><li v-for="change in pending.preview.changes" :key="change">{{securityCopy(change)}}</li></ul><div v-if="pending.request.operation === 'enable' && pending.kind === 'firewall'" class="security-port-list"><span v-for="port in pending.preview.requiredPorts" :key="`${port.port}/${port.protocol}`">{{port.port}}/{{port.protocol}} · {{port.reason}}</span></div><p v-for="warning in pending.preview.warnings" :key="warning">{{securityCopy(warning)}}</p><p v-if="pending.preview.needsConfirmation" class="security-warning">{{t('应用后需在 90 秒内确认连接，超时自动恢复。','After applying, confirm connectivity within 90 seconds or the change rolls back.')}}</p><label v-if="pending.request.operation === 'reinstall'" class="security-reset-confirm">{{t('输入 RESET FAIL2BAN 确认清理此主机的全部 Fail2ban 防护','Type RESET FAIL2BAN to reset all Fail2ban protection on this host')}}<input v-model="resetConfirmation" autocomplete="off" spellcheck="false" placeholder="RESET FAIL2BAN"></label><div class="modal-actions"><button class="secondary" :disabled="busy" @click="pending = null">{{t('取消','Cancel')}}</button><button :class="pending.request.operation === 'reinstall' ? 'danger-button' : 'primary'" :disabled="busy || !enabled || pending.request.operation === 'reinstall' && (!resetWritable || resetConfirmation !== 'RESET FAIL2BAN')" @click="apply">{{busy ? t('正在应用…','Applying…') : pending.request.operation === 'reinstall' ? t('确认清理并重新安装','Reset and reinstall') : t('确认应用','Apply change')}}</button></div></div></div></Teleport>
 </div>
</template>

<style scoped>
.security-reset{border-top:1px solid var(--line);padding:16px 0;margin:16px 0}.security-reset summary{cursor:pointer;color:var(--muted);font-size:12px}.security-reset p{font-size:12px;line-height:1.7}.security-reset-confirm{display:grid;gap:10px;font-size:12px;margin:18px 0}.security-card{padding:22px;margin-bottom:20px}.security-card>.card-head{margin-bottom:15px}.security-warning{color:var(--danger-text);font-size:12px;line-height:1.65;overflow-wrap:anywhere}.security-actions{display:flex;flex-wrap:wrap;align-items:end;gap:10px;margin:18px 0}.security-form{display:grid;grid-template-columns:repeat(4,minmax(0,1fr));gap:14px;margin:20px 0}.security-form label,.security-actions label{display:grid;gap:7px;min-width:0;font-size:12px}.security-form small,.security-footnote,.security-card>small{font-size:11px;color:var(--muted);line-height:1.6}.security-form .wide{grid-column:1/-1}.security-form button{align-self:end;min-height:40px;grid-column:1/-1;justify-self:start}.security-ports{grid-template-columns:repeat(2,minmax(0,1fr))}.security-port-list{display:flex;flex-wrap:wrap;gap:8px;margin:16px 0}.security-port-list>b{width:100%;font-size:12px}.security-port-list>span{padding:6px 9px;border:1px solid var(--line);font-size:11px;overflow-wrap:anywhere}.security-port-list button,.security-table button,.security-bans button,.security-jail header button{background:transparent;border:1px solid var(--line);color:var(--gold);padding:4px 8px;margin-left:6px;cursor:pointer}.security-table-wrap{overflow-x:auto}.security-table{width:100%;border-collapse:collapse;font-size:12px}.security-table th,.security-table td{text-align:left;padding:12px 8px;border-bottom:1px solid var(--line);overflow-wrap:anywhere}.security-rule-services span{display:block;min-width:140px;max-width:320px;line-height:1.65}.security-rule-services small{color:var(--muted)}.security-table th{color:var(--muted);font-weight:500}.security-notice{padding:20px;margin-bottom:20px}.security-notice p{font-size:12px;line-height:1.7}.security-notice b{margin-right:16px}.security-guidance{padding:14px 16px;margin:14px 0;background:var(--surface-code);border-left:3px solid var(--gold)}.security-guidance b{font-size:13px}.security-guidance p{font-size:12px;line-height:1.7;margin:6px 0;color:var(--muted)}.security-technical{font-size:11px;color:var(--muted)}.security-technical summary{cursor:pointer}.security-technical code{overflow-wrap:anywhere}.security-jail{border-top:1px solid var(--line);padding:16px 0}.security-jail header{display:flex;align-items:center;gap:12px;flex-wrap:wrap}.security-jail header span,.security-jail p{font-size:11px;color:var(--muted)}.security-bans{display:flex;flex-wrap:wrap;gap:10px}.security-bans span{display:flex;align-items:center}.security-preview ul{padding-left:18px;font-size:13px;line-height:1.8}.security-preview p{font-size:12px;line-height:1.7}.stale{color:var(--danger-text)!important}@media(max-width:700px){.security-form{grid-template-columns:repeat(2,minmax(0,1fr))}.security-ports{grid-template-columns:1fr}.security-reset{border-top:1px solid var(--line);padding:16px 0;margin:16px 0}.security-reset summary{cursor:pointer;color:var(--muted);font-size:12px}.security-reset p{font-size:12px;line-height:1.7}.security-reset-confirm{display:grid;gap:10px;font-size:12px;margin:18px 0}.security-card{padding:16px}.security-table{min-width:680px}.security-notice button{display:block;margin-top:12px}}@media(max-width:400px){.security-form{grid-template-columns:1fr}.security-preview{padding:20px}}
</style>
