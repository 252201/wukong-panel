<script setup lang="ts">
import { computed, watch, onBeforeUnmount, ref } from 'vue'
import { cloudflaredAPI, type CloudflaredState, type Job } from './api'
const props = defineProps<{ hostId: string; online: boolean; compatible: boolean; capabilities: string[]; language: string }>()
const client = cloudflaredAPI(props.hostId)
const t = (zh: string, en: string) => props.language === 'en-US' ? en : zh
const supported = computed(() => props.hostId === 'local' || props.capabilities.includes('cloudflared.update'))
const available = computed(() => supported.value && props.online && props.compatible && !props.capabilities.includes('probe'))
const state = ref<CloudflaredState | null>(null)
const error = ref('')
const busy = ref(false)
const confirmation = ref<'update' | 'auto' | null>(null)
const job = ref<Job | null>(null)
let alive = true
let timer: ReturnType<typeof setTimeout> | undefined
const writable = computed(() => available.value && !!state.value?.writable && !busy.value && !jobRunning.value)
const jobRunning = computed(() => job.value?.status === 'queued' || job.value?.status === 'running')
const message = (e: unknown) => e instanceof Error ? e.message : t('操作失败', 'Operation failed')
async function load() {
  if (!available.value) return
  try { const result = await client.status(); if (alive) { state.value = result; error.value = '' } }
  catch (e) { if (alive) error.value = message(e) }
}
async function check() {
  if (!available.value || busy.value || jobRunning.value) return
  busy.value = true; error.value = ''; confirmation.value = null
  try { const result = await client.check(); if (alive) state.value = result }
  catch (e) {
    if (alive) error.value = message(e)
    try { const result = await client.status(); if (alive) state.value = result } catch { /* Keep the failed check visible. */ }
  }
  finally { if (alive) busy.value = false }
}
async function setAuto(enabled: boolean) {
  if (!available.value || busy.value || jobRunning.value) return
  busy.value = true; error.value = ''
  try { const result = await client.settings(enabled); if (alive) { state.value = result; confirmation.value = null } }
  catch (e) { if (alive) error.value = message(e) }
  finally { if (alive) busy.value = false }
}
async function pollJob(id: string) {
  try {
    const result = await client.job(id)
    if (!alive) return
    job.value = result
    if (result.status === 'success' || result.status === 'failed') {
      if (result.status === 'failed') error.value = result.error || result.message
      try { const latest = await client.status(); if (alive) state.value = latest } catch (e) { if (alive && !error.value) error.value = message(e) }
      return
    }
  } catch (e) { if (!alive) return; error.value = message(e) }
  if (alive) timer = setTimeout(() => pollJob(id), 2000)
}
async function upgrade() {
  if (!writable.value || !state.value?.updateAvailable) return
  busy.value = true; error.value = ''
  try {
    const result = await client.update(state.value.currentVersion, state.value.latestVersion)
    if (!alive) return
    confirmation.value = null
    job.value = { id: result.jobId, kind: 'cloudflared.update', target: props.hostId, status: 'queued', progress: 0, message: t('等待更新', 'Waiting for update'), createdAt: '', updatedAt: '' }
    void pollJob(result.jobId)
  } catch (e) { if (alive) error.value = message(e) }
  finally { if (alive) busy.value = false }
}
watch(available, ready => { if (ready) void load(); else confirmation.value = null }, { immediate: true })
onBeforeUnmount(() => { alive = false; if (timer) clearTimeout(timer) })
</script>

<template>
  <section class="panel-card cloudflared-panel">
    <div class="card-head"><div><span class="section-mark jade">隧</span><div><h3>Cloudflare Tunnel</h3><p>{{ t('cloudflared 连接器更新', 'cloudflared connector updates') }}</p></div></div><span v-if="state?.updateAvailable" class="update-badge">{{ t('有新版本', 'Update available') }}</span></div>
    <p v-if="!available" class="help-text">{{ !supported ? t('此主机的 Agent 尚不支持连接器更新，请先升级完整面板。', 'This Agent does not support connector updates. Upgrade the full panel first.') : t('此主机当前不可操作。', 'This host is currently unavailable.') }}</p>
    <template v-else>
      <div class="connector-versions"><div><small>{{ t('当前版本', 'Installed version') }}</small><strong>{{ state?.currentVersion || (state && !state.installed ? t('未安装', 'Not installed') : '—') }}</strong></div><div><small>{{ t('最新稳定版', 'Latest stable version') }}</small><strong>{{ state?.latestVersion || '—' }}</strong></div><button :disabled="busy || jobRunning" @click="check">{{ busy ? t('处理中…', 'Working…') : t('检查更新', 'Check for updates') }}</button><button v-if="state?.updateAvailable" class="primary" :disabled="!writable" @click="confirmation = 'update'">{{ t('升级到', 'Update to') }} {{ state.latestVersion }}</button></div>
      <label class="toggle-row"><span><b>{{ t('自动更新 cloudflared', 'Update cloudflared automatically') }}</b><small>{{ t('每天检查稳定版；更新时短暂重启运行中的悟空隧道。', 'Checks stable releases daily; updates briefly restart running Wukong tunnels.') }}</small></span><span class="switch"><input type="checkbox" :checked="!!state?.autoUpdate" :disabled="!state || busy || jobRunning || (!state.autoUpdate && !writable)" @click.prevent="state?.autoUpdate ? setAuto(false) : confirmation = 'auto'"><i></i></span></label>
      <div v-if="confirmation" class="connector-confirm"><p>{{ confirmation === 'auto' ? t('启用后，悟空将自动安装官方稳定版，并重启正在运行的隧道。更新失败时恢复原版本。', 'Wukong will install official stable releases and restart running tunnels automatically. Failed updates restore the previous version.') : t('升级会短暂重启正在运行的悟空隧道；失败时恢复原版本。', 'Updating briefly restarts running Wukong tunnels; failures restore the previous version.') }}</p><div><button class="primary" :disabled="!writable" @click="confirmation === 'auto' ? setAuto(true) : upgrade()">{{ t('确认', 'Confirm') }}</button><button :disabled="busy" @click="confirmation = null">{{ t('取消', 'Cancel') }}</button></div></div>
      <p v-if="state?.reason" class="help-text">{{ state.reason }}</p>
      <p v-if="state?.checkedAt && !state.checkedAt.startsWith('0001')" class="help-text">{{ t('最后检查', 'Last checked') }} {{ new Date(state.checkedAt).toLocaleString(language) }}</p>
      <p v-if="job" role="status">{{ job.message }} · {{ job.progress }}%</p>
      <p v-if="error || state?.lastError" class="connector-error" role="alert">{{ error || state?.lastError }}</p>
    </template>
  </section>
</template>

<style scoped>
.cloudflared-panel{margin-top:17px;padding:24px}.connector-versions{display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin:20px 0}.connector-versions>div{display:flex;flex-direction:column;gap:6px;min-width:130px}.connector-versions small{color:var(--muted)}.connector-versions strong{font-size:18px;font-family:"IBM Plex Mono",monospace}.update-badge{color:var(--gold);font-size:12px}.connector-confirm{margin-top:16px;padding:16px;border:1px solid var(--line);border-radius:10px}.connector-confirm>div{display:flex;gap:10px;margin-top:12px}.connector-error{color:var(--danger-text);overflow-wrap:anywhere}.toggle-row small{display:block;margin-top:5px;line-height:1.6}.help-text{overflow-wrap:anywhere}@media(max-width:600px){.cloudflared-panel{padding:18px}.connector-versions{gap:12px}.connector-versions>div{min-width:110px}.toggle-row{gap:14px}}
</style>
