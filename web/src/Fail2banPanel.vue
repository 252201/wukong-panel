<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api, type Fail2banConfig, type Fail2banStatus } from './api'

const props = defineProps<{ hostKey: string; writable: boolean }>()
const status = ref<Fail2banStatus | null>(null)
const draft = ref<Fail2banConfig>({ enabled: false, maxRetry: 5, findTime: 600, banTime: 3600, mode: 'normal', ignoreIPs: [] })
const trusted = ref('')
const loading = ref(false), busy = ref(false), dirty = ref(false)
const error = ref(''), notice = ref(''), unbanning = ref(''), confirmDisable = ref(false)
let alive = true
const canWrite = computed(() => props.writable && status.value?.writable && !busy.value && !loading.value)
const valid = computed(() => Number.isInteger(draft.value.maxRetry) && draft.value.maxRetry >= 1 && draft.value.maxRetry <= 100 && Number.isInteger(draft.value.findTime) && draft.value.findTime >= 60 && draft.value.findTime <= 604800 && Number.isInteger(draft.value.banTime) && draft.value.banTime >= 60 && draft.value.banTime <= 2592000 && (!draft.value.enabled || trusted.value.trim().length > 0))
const failure = (e: unknown) => e instanceof Error ? e.message : 'Fail2ban 操作失败'
function accept(result: Fail2banStatus, reset = false) {
  status.value = result
  if (reset || !dirty.value) { draft.value = { ...result.config, ignoreIPs: [...result.config.ignoreIPs] }; trusted.value = result.config.ignoreIPs.join('\n'); dirty.value = false }
}
async function load() {
  if (loading.value || busy.value) return
  loading.value = true; error.value = ''
  try { const result = await api.fail2ban(props.hostKey); if (alive) accept(result) }
  catch (e) { if (alive) { error.value = failure(e); status.value = null } }
  finally { if (alive) loading.value = false }
}
async function save(confirmed = false) {
  if (!canWrite.value || !valid.value) return
  if (status.value?.active && !draft.value.enabled && !confirmed) { confirmDisable.value = true; return }
  const host = props.hostKey
  const payload = { ...draft.value, ignoreIPs: trusted.value.split(/[\s,]+/).filter(Boolean) }
  busy.value = true; error.value = ''; notice.value = ''; confirmDisable.value = false
  try { const result = await api.configureFail2ban(host, payload); if (alive) { accept(result, true); notice.value = 'SSH 防护设置已保存' } }
  catch (e) { if (alive) error.value = failure(e) }
  finally { if (alive) busy.value = false }
}
async function unban() {
  if (!canWrite.value || !status.value?.active || !unbanning.value) return
  const ip = unbanning.value, host = props.hostKey
  busy.value = true; error.value = ''; notice.value = ''
  try { const result = await api.unbanFail2ban(host, ip); if (alive) { accept(result); unbanning.value = ''; notice.value = 'IP 已从悟空 SSH 防护中解封' } }
  catch (e) { if (alive) error.value = failure(e) }
  finally { if (alive) busy.value = false }
}
async function copy(text: string) {
  try { await navigator.clipboard.writeText(text); if (alive) notice.value = '命令已复制' }
  catch { if (alive) error.value = '复制失败，请手动复制命令' }
}
watch(() => props.hostKey, () => { status.value = null; dirty.value = false; unbanning.value = ''; confirmDisable.value = false; void load() }, { immediate: true })
watch(() => props.writable, () => { unbanning.value = ''; confirmDisable.value = false })
onBeforeUnmount(() => { alive = false })
</script>

<template>
  <section class="panel-card f2b-panel">
    <div class="card-head">
      <div><span class="section-mark">御</span><div><h3>Fail2ban SSH 防护</h3><p>识别重复登录失败 · 自动封禁来源 IP</p></div></div>
      <button class="secondary" :disabled="loading || busy" @click="load">{{ loading ? '读取中…' : '刷新防护状态' }}</button>
    </div>
    <p v-if="error" class="f2b-error" role="alert">{{ error }}</p>
    <p v-if="notice" class="f2b-notice" role="status">{{ notice }}</p>
    <template v-if="status">
      <div class="f2b-status"><strong>Fail2ban <small>{{ status.version }}</small></strong><span :class="{ active: status.active }">{{ !status.installed ? '未安装' : !status.running ? '服务未运行' : status.active ? 'SSH 防护已启用' : 'SSH 防护未启用' }}</span><span v-if="status.demo">演示模式</span><small>{{ new Date(status.checkedAt).toLocaleString() }}</small></div>
      <p v-if="status.reason" class="f2b-reason">{{ status.reason }}</p>
      <p v-if="!writable" class="f2b-reason">主机当前不可操作，防护状态仅供查看。</p>
      <div v-if="!status.installed || !status.running" class="f2b-setup">
        <template v-if="(!status.installed && status.installCommand) || (status.installed && status.startCommand)">
          <p>{{ status.installed ? '在当前主机以 root 启动服务后刷新。' : '在当前主机以 root 安装并启动 Fail2ban 后刷新。' }}</p>
          <pre>{{ status.installed ? status.startCommand : status.installCommand }}</pre><button class="secondary" @click="copy(status.installed ? status.startCommand : status.installCommand)">复制命令</button>
        </template>
        <p v-else>请使用当前系统的软件包管理器安装并启动 Fail2ban。</p>
        <p class="f2b-help">启动服务会加载此主机已有的启用规则，请先核对服务器上的 Fail2ban 配置。</p>
      </div>
      <template v-else>
        <div class="f2b-metrics"><div><small>当前封禁</small><b>{{ status.bannedIPs.length }}</b></div><div><small>累计失败</small><b>{{ status.totalFailed }}</b></div><div><small>累计封禁</small><b>{{ status.totalBanned }}</b></div><div><small>SSH 端口 / 日志</small><b>{{ status.sshPorts.join(', ') || '—' }}</b><small>{{ status.backend || '—' }}</small></div></div>
        <p class="f2b-help">计数来自 wukong-sshd 当前运行实例，规则重启后可能重置。</p>
        <form class="f2b-form" @submit.prevent="save()" @input="dirty = true; confirmDisable = false" @change="dirty = true; confirmDisable = false">
          <label class="f2b-toggle"><input v-model="draft.enabled" type="checkbox" :disabled="!canWrite">启用悟空 SSH 防护</label>
          <div class="f2b-fields">
            <label>触发次数<input v-model.number="draft.maxRetry" type="number" min="1" max="100" required :disabled="!canWrite"></label>
            <label>观察窗口（秒）<input v-model.number="draft.findTime" type="number" min="60" max="604800" required :disabled="!canWrite"></label>
            <label>封禁时长（秒）<input v-model.number="draft.banTime" type="number" min="60" max="2592000" required :disabled="!canWrite"></label>
            <label>SSH 检测模式<select v-model="draft.mode" :disabled="!canWrite"><option value="normal">标准 · 登录失败</option><option value="aggressive">严格 · 包含握手探测</option></select></label>
          </div>
          <label class="f2b-trusted">可信 IP / CIDR<textarea v-model="trusted" rows="3" placeholder="填写你的管理出口 IP，每行一条；支持 IPv4 / IPv6 和 CIDR" :disabled="!canWrite"></textarea></label>
          <p class="f2b-help">启用前填写自己的管理出口 IP。自动忽略本机和回环地址；出口 IP 变化时需更新白名单。严格模式可能封禁反复中断握手的合法客户端；单次扫描通常不会达到触发次数。</p>
          <button class="primary" type="submit" :disabled="!canWrite || !valid">{{ busy ? '处理中…' : '保存 SSH 防护设置' }}</button>
        </form>
        <div v-if="confirmDisable" class="f2b-confirm" role="alert"><p>关闭悟空 SSH 防护会解除此规则当前的封禁，确认关闭？</p><button class="danger-button" :disabled="!canWrite" @click="save(true)">确认关闭 SSH 防护</button><button class="secondary" :disabled="busy" @click="confirmDisable = false">取消</button></div>
        <div class="f2b-bans"><h4>悟空 SSH 封禁列表</h4><div v-for="ip in status.bannedIPs" :key="ip" class="f2b-ban"><code>{{ ip }}</code><button class="secondary" :disabled="!canWrite" @click="unbanning = ip">解封</button></div><p v-if="!status.bannedIPs.length" class="f2b-help">当前没有被此规则封禁的 IP。</p></div>
        <div v-if="unbanning" class="f2b-confirm" role="alert"><p>确认解除此 IP 的 SSH 封禁？<code>{{ unbanning }}</code></p><button class="danger-button" :disabled="!canWrite" @click="unban">确认解封</button><button class="secondary" :disabled="busy" @click="unbanning = ''">取消</button></div>
        <p v-if="status.otherJails.length" class="f2b-help">其他运行规则（只读）：<code>{{ status.otherJails.join(', ') }}</code></p>
        <p class="f2b-help">面板仅管理 wukong-sshd。SSH 公钥认证和关闭密码登录仍需单独配置；Fail2ban 不会阻止所有扫描，也不能替代上游 DDoS 防护。</p>
      </template>
    </template>
  </section>
</template>

<style scoped>
.f2b-panel { padding: 28px; scroll-margin-top: 110px; }
.f2b-panel .card-head > div { min-width: 0; }
.f2b-panel .card-head button { flex-shrink: 0; white-space: nowrap; }
.f2b-panel button, .f2b-panel input, .f2b-panel select, .f2b-panel textarea { scroll-margin-top: 110px; scroll-margin-bottom: 90px; }
.f2b-status { display:flex; flex-wrap:wrap; align-items:center; gap:12px; margin:22px 0 14px; }
.f2b-status strong { font-family: 'IBM Plex Mono', monospace; }
.f2b-status span { border:1px solid var(--line); padding:5px 10px; font-size:12px; color:var(--muted); }
.f2b-status .active { color:var(--jade); border-color:var(--jade); }
.f2b-status small { color:var(--muted); font-weight:400; }
.f2b-status > small { margin-left:auto; }
.f2b-error, .f2b-notice, .f2b-reason { padding:12px 16px; border:1px solid var(--line); line-height:1.7; overflow-wrap:anywhere; }
.f2b-error { color:var(--cinnabar); }.f2b-notice { color:var(--jade); }.f2b-reason { color:var(--gold); }
.f2b-metrics { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); border:1px solid var(--line); margin:20px 0 8px; }
.f2b-metrics > div { display:grid; align-content:start; gap:8px; padding:16px; border-right:1px solid var(--line); }
.f2b-metrics > div:last-child { border:0; }.f2b-metrics b { font-family: 'IBM Plex Mono', monospace; font-size:22px; overflow-wrap:anywhere; }
.f2b-metrics small, .f2b-help { color:var(--muted); font-size:12px; line-height:1.8; }
.f2b-form { display:grid; gap:16px; margin:24px 0; }.f2b-form label { display:grid; gap:8px; font-size:13px; color:var(--text-label); }
.f2b-fields { display:grid; grid-template-columns:repeat(4,minmax(0,1fr)); gap:16px; }.f2b-fields input, .f2b-fields select { width:100%; min-width:0; }
.f2b-form .f2b-toggle { display:flex; align-items:center; gap:10px; width:fit-content; cursor:pointer; }
.f2b-toggle input { width:18px; height:18px; accent-color:var(--gold); margin:0; }
.f2b-trusted textarea { background:var(--surface-input); color:var(--paper); border:1px solid var(--line); padding:12px; resize:vertical; font:inherit; width:100%; }
.f2b-form > button { justify-self:start; }.f2b-form .f2b-help { margin:0; }
.f2b-bans { border-top:1px solid var(--line); padding-top:12px; }.f2b-bans h4 { font-size:14px; }
.f2b-ban { display:flex; gap:16px; align-items:center; justify-content:space-between; padding:12px 0; border-bottom:1px solid var(--line); }
.f2b-ban code, .f2b-confirm code { overflow-wrap:anywhere; }.f2b-ban button { flex-shrink:0; }
.f2b-confirm { border:1px solid var(--cinnabar); padding:16px; margin:20px 0; }.f2b-confirm p { margin-top:0; }.f2b-confirm code { margin-left:10px; }.f2b-confirm button + button { margin-left:12px; }
.f2b-setup pre { background:var(--surface-code); border:1px solid var(--line); padding:16px; overflow:auto; font-size:12px; }
.f2b-panel button:not(:disabled):hover { filter:brightness(1.15); border-color:var(--gold); }.f2b-panel button:focus-visible { outline:2px solid var(--gold); outline-offset:3px; }
@media(max-width:700px) { .f2b-panel { padding:18px; }.f2b-status > small { margin-left:0; width:100%; }.f2b-metrics, .f2b-fields { grid-template-columns:repeat(2,minmax(0,1fr)); }.f2b-metrics > div { border-bottom:1px solid var(--line); }.f2b-metrics > div:nth-child(even) { border-right:0; }.f2b-metrics > div:nth-child(3) { border-bottom:0; }.f2b-fields { grid-template-columns:1fr; }.f2b-panel .card-head { align-items:start; gap:12px; flex-wrap:wrap; } }
</style>
