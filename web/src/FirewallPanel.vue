<script setup lang="ts">
import { computed, onBeforeUnmount, ref, watch } from 'vue'
import { api, type FirewallRule, type FirewallStatus, type NodeItem } from './api'
import { nodeFirewallPorts } from './firewallPorts'

const props = defineProps<{ hostKey: string; nodes: NodeItem[]; writable: boolean }>()
const status = ref<FirewallStatus | null>(null)
const loading = ref(false)
const busy = ref(false)
const error = ref('')
const notice = ref('')
const zone = ref('')
const port = ref<number | ''>('')
const protocol = ref<'tcp' | 'udp'>('tcp')
const nodeID = ref('')
const removing = ref<FirewallRule | null>(null)
let alive = true
let revision = 0
const canWrite = computed(() => props.writable && status.value?.writable && !loading.value && !busy.value)
const quickNodes = computed(() => props.nodes.filter(node => nodeFirewallPorts(node).length))
const selectedNode = computed(() => quickNodes.value.find(node => node.id === nodeID.value))
const selectedPorts = computed(() => selectedNode.value ? nodeFirewallPorts(selectedNode.value) : [])
const pendingPorts = computed(() => selectedPorts.value.filter(p => !status.value?.rules.some(r => r.port === p.port && r.protocol === p.protocol)))
const portValid = computed(() => typeof port.value === 'number' && Number.isInteger(port.value) && port.value > 0 && port.value <= 65535)
const failure = (e: unknown) => e instanceof Error ? e.message : '防火墙操作失败'

async function load() {
  if (busy.value || loading.value) return
  const version = ++revision
  loading.value = true
  error.value = ''
  try {
    const result = await api.firewall(props.hostKey, zone.value)
    if (!alive || version !== revision) return
    status.value = result
    zone.value = result.zone || ''
  } catch (e) { if (alive && version === revision) { error.value = failure(e); status.value = null } }
  finally { if (alive && version === revision) loading.value = false }
}
async function add(quick = false) {
  if (!canWrite.value || (!quick && !portValid.value)) return
  const ports = quick ? [...pendingPorts.value] : [{ port: Number(port.value), protocol: protocol.value }]
  if (!ports.length) return
  const host = props.hostKey
  const targetZone = zone.value
  busy.value = true
  error.value = ''; notice.value = ''; removing.value = null
  let completed = 0
  try {
    for (const p of ports) {
      if (!alive) break
      const result = await api.addFirewallPort(host, { ...p, zone: targetZone })
      completed++
      if (alive) status.value = result
    }
    if (alive) notice.value = '端口放行规则已保存'
  } catch (e) {
    if (alive) {
      error.value = failure(e)
      if (completed) notice.value = '部分端口已放行，请查看规则后重试'
    }
  } finally { if (alive) busy.value = false }
}
async function remove() {
  const rule = removing.value
  if (!canWrite.value || !rule?.id || rule.protected || !status.value?.protectedPorts.length) return
  busy.value = true
  error.value = ''; notice.value = ''
  try {
    const result = await api.removeFirewallPort(props.hostKey, rule.id)
    if (alive) { status.value = result; removing.value = null; notice.value = '端口放行规则已删除' }
  } catch (e) { if (alive) error.value = failure(e) }
  finally { if (alive) busy.value = false }
}
watch(() => props.hostKey, () => { status.value = null; zone.value = ''; nodeID.value = ''; removing.value = null; void load() }, { immediate: true })
watch(() => props.writable, () => { removing.value = null })
onBeforeUnmount(() => { alive = false; revision++ })
</script>

<template>
  <section class="panel-card firewall-panel">
    <div class="card-head">
      <div><span class="section-mark">防</span><div><h3>防火墙端口管理</h3><p>查看主机规则 · 按需放行 TCP / UDP 端口</p></div></div>
      <button class="secondary" :disabled="loading || busy" @click="load">{{ loading ? '读取中…' : '刷新规则' }}</button>
    </div>
    <p v-if="error" class="fw-error" role="alert">{{ error }}</p>
    <p v-if="notice" class="fw-notice" role="status">{{ notice }}</p>
    <template v-if="status">
      <div class="fw-status">
        <strong>{{ status.backend === 'none' ? '未检测到防火墙' : status.backend.toUpperCase() }}</strong>
        <span :class="{ active: status.active }">{{ status.active ? '已启用' : '未启用 / 状态未知' }}</span>
        <span v-if="status.demo">演示模式</span>
        <small>采集时间 <time>{{ new Date(status.checkedAt).toLocaleString() }}</time></small>
      </div>
      <p v-if="status.reason" class="fw-reason">{{ status.reason }}</p>
      <p v-if="!writable" class="fw-reason">主机当前不可操作，规则仅供查看。</p>
      <div v-if="status.zones.length" class="fw-zone"><label>firewalld 区域<select v-model="zone" :disabled="busy || loading || !writable" @change="load"><option v-for="z in status.zones" :key="z" :value="z">{{ z }}</option></select></label><small>选择实际绑定网卡的区域；可在完整规则中核对。</small></div>
      <form class="fw-form" @submit.prevent="add()">
        <label>放行端口<input v-model.number="port" type="number" min="1" max="65535" required placeholder="1–65535" :disabled="!canWrite"></label>
        <label>传输协议<select v-model="protocol" :disabled="!canWrite"><option value="tcp">TCP</option><option value="udp">UDP</option></select></label>
        <button class="primary" :disabled="!canWrite || !portValid" type="submit">{{ busy ? '处理中…' : '添加放行规则' }}</button>
      </form>
      <div v-if="quickNodes.length" class="fw-quick">
        <label>按节点放行<select v-model="nodeID" :disabled="!canWrite"><option value="">选择节点</option><option v-for="node in quickNodes" :key="node.id" :value="node.id">{{ node.name }} · {{ node.listenPort }} · {{ node.protocol }}</option></select></label>
        <button class="secondary" :disabled="!canWrite || !pendingPorts.length" @click="add(true)">放行节点端口</button>
        <small v-if="selectedPorts.length">{{ selectedPorts.map(p => `${p.port}/${p.protocol.toUpperCase()}`).join(' + ') }}<span v-if="!pendingPorts.length"> · 已有放行规则</span></small>
      </div>
      <p class="fw-help">Cloudflare Tunnel 节点仅监听本机，不需要放行公网端口。节点部署不会自动添加规则。</p>
      <div v-if="status.protectedPorts.length" class="fw-protected"><b>受保护端口</b><span v-for="p in status.protectedPorts" :key="`${p.port}-${p.protocol}`">{{ p.port }}/{{ p.protocol.toUpperCase() }} · {{ p.reason }}</span></div>
      <div class="fw-table-wrap"><table class="fw-table"><thead><tr><th>端口 / 协议</th><th>规则归属</th><th>生效状态</th><th>操作</th></tr></thead><tbody>
        <tr v-for="(rule, i) in status.rules" :key="rule.id || `${rule.port}-${rule.protocol}-${i}`">
          <td><code>{{ rule.port }}/{{ rule.protocol.toUpperCase() }}</code></td><td>{{ rule.managed ? '面板创建' : '系统规则' }}<small v-if="rule.protected"> · 受保护</small></td>
          <td>{{ rule.runtime ? '已加载' : '未加载' }}<small v-if="rule.permanent"> · 已持久化</small></td>
          <td><button v-if="rule.managed" class="danger-button" :disabled="!canWrite || rule.protected || !status.protectedPorts.length" @click="removing = rule">删除</button><span v-else class="fw-readonly">只读</span></td>
        </tr>
      </tbody></table><p v-if="!status.rules.length" class="fw-help">暂无可展示的单端口放行规则。</p></div>
      <div v-if="removing" class="fw-confirm" role="alert">
        <p>确认删除此端口的放行规则？<code>{{ removing.port }}/{{ removing.protocol.toUpperCase() }}</code></p>
        <button class="danger-button" :disabled="!canWrite" @click="remove">确认删除规则</button><button class="secondary" :disabled="busy" @click="removing = null">取消</button>
      </div>
      <details v-if="status.raw" class="fw-raw"><summary>查看完整规则（只读）</summary><pre>{{ status.raw }}</pre></details>
      <p class="fw-help">仅删除面板创建的规则；SSH 和检测到的管理入口受保护。复杂规则请在完整规则中查看；云厂商安全组需单独配置。</p>
    </template>
  </section>
</template>

<style scoped>
.firewall-panel { padding: 28px; scroll-margin-top: 110px; }
.firewall-panel .card-head > div { min-width: 0; }
.firewall-panel .card-head button { flex-shrink: 0; white-space: nowrap; }
.firewall-panel button, .firewall-panel input, .firewall-panel select { scroll-margin-top: 110px; scroll-margin-bottom: 90px; }
.fw-status { display: flex; align-items: center; flex-wrap: wrap; gap: 12px; margin: 22px 0 14px; }
.fw-status strong { color: var(--paper); font-family: 'IBM Plex Mono', monospace; }
.fw-status span, .fw-protected span { padding: 5px 10px; border: 1px solid var(--line); color: var(--muted); font-size: 12px; }
.fw-status .active { color: var(--jade); border-color: var(--jade); }
.fw-status small { color: var(--muted); margin-left: auto; }
.fw-form, .fw-quick, .fw-zone { display: flex; gap: 14px; align-items: end; flex-wrap: wrap; margin: 20px 0; }
.fw-form label, .fw-quick label, .fw-zone label { display: grid; gap: 8px; color: var(--text-label); font-size: 13px; }
.fw-form input { width: 180px; }
.fw-form select { width: 140px; }
.fw-quick select { max-width: 440px; }
.fw-quick small, .fw-zone small { color: var(--muted); padding-bottom: 12px; }
.fw-reason, .fw-error, .fw-notice { padding: 12px 16px; line-height: 1.6; border: 1px solid var(--line); overflow-wrap: anywhere; }
.fw-reason { color: var(--gold); }
.fw-error { color: var(--cinnabar); }
.fw-notice { color: var(--jade); }
.fw-help, .fw-readonly, td small { color: var(--muted); font-size: 12px; line-height: 1.8; }
.fw-protected { display: flex; align-items: center; flex-wrap: wrap; gap: 10px; margin: 20px 0; }
.fw-protected b { font-size: 13px; }
.fw-table-wrap { overflow-x: auto; margin: 20px 0; }
.fw-table { width: 100%; border-collapse: collapse; text-align: left; white-space: nowrap; }
.fw-table th { color: var(--muted); font-size: 12px; font-weight: 400; }
.fw-table td, .fw-table th { padding: 12px 16px; border-bottom: 1px solid var(--line); }
.fw-table td { font-size: 13px; }
.fw-table code { color: var(--paper); }
.fw-confirm { border: 1px solid var(--cinnabar); padding: 16px; margin: 20px 0; }
.fw-confirm p { margin-top: 0; }
.fw-confirm code { margin-left: 12px; }
.fw-confirm button + button { margin-left: 12px; }
.fw-raw { margin: 20px 0; }
.fw-raw summary { color: var(--gold); cursor: pointer; width: fit-content; }
.fw-raw pre { background: var(--surface-code); border: 1px solid var(--line); padding: 16px; max-height: 320px; overflow: auto; font-size: 12px; line-height: 1.7; }
.firewall-panel button:not(:disabled):hover { filter: brightness(1.15); border-color: var(--gold); }
.firewall-panel button:focus-visible, .firewall-panel summary:focus-visible { outline: 2px solid var(--gold); outline-offset: 3px; }
@media (max-width: 700px) {
  .firewall-panel { padding: 18px; }
  .fw-status small { margin-left: 0; width: 100%; }
  .fw-form label, .fw-quick label, .fw-quick select { width: 100%; max-width: none; }
  .fw-form input, .fw-form select { width: 100%; }
  .fw-table td, .fw-table th { padding: 12px 8px; }
}
</style>
