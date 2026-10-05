<script setup lang="ts">
import { computed, watch, onBeforeUnmount, ref } from 'vue'
import { startComponentUpdateJob, refreshComponentUpdateJob, pendingComponentUpdateJob } from './componentUpdateJobs'
import { componentUpdateAPI, type ComponentUpdateState, type Job } from './api'
const props = defineProps<{ component: 'cloudflared' | 'sing-box'; hostId: string; online: boolean; compatible: boolean; capabilities: string[]; language: string }>()
const isTunnel = computed(() => props.component === 'cloudflared')
const title = computed(() => isTunnel.value ? 'Cloudflare Tunnel' : 'sing-box')
const binaryName = computed(() => isTunnel.value ? 'cloudflared' : 'sing-box')
const client = componentUpdateAPI(props.hostId, props.component)
const t = (zh: string, en: string) => props.language === 'en-US' ? en : zh
const supported = computed(() => props.hostId === 'local' || props.capabilities.includes(`${props.component}.update`))
const available = computed(() => supported.value && props.online && props.compatible && !props.capabilities.includes('probe'))
const state = ref<ComponentUpdateState | null>(null)
const error = ref('')
const busy = ref(false)
const confirmation = ref<'update' | 'auto' | null>(null)
const job = ref<Job | null>(null)
let alive = true
let timer: ReturnType<typeof setTimeout> | undefined
const writable = computed(() => available.value && !!state.value?.writable && !busy.value && !jobRunning.value)
const jobRunning = computed(() => job.value?.status === 'queued' || job.value?.status === 'running')
const updateMessages: Record<string, readonly [string, string]> = {
  'managed service is not running the configured binary': [
    '无法确认至少一个悟空登记的 sing-box 服务正在运行面板配置的二进制文件，因此为避免替换错误程序或影响其他服务，已禁止升级。若主机使用 Alpine/OpenRC，旧版 Agent 可能把 musl 加载器误认为 sing-box；请先升级到包含 OpenRC 检测修复的悟空版本，再重新检查。其他系统请核对服务启动命令是否指向面板配置的 sing-box 路径。',
    'At least one Wukong-managed sing-box service could not be verified as running the configured binary, so the update was blocked to avoid replacing the wrong executable or affecting another service. On Alpine/OpenRC, an older Agent may mistake the musl loader for sing-box; upgrade to a Wukong version with the OpenRC detection fix, then check again. On other systems, verify that the service command points to the sing-box path configured by the panel.',
  ],
  'unmanaged configuration prevents runtime updates': [
    'sing-box 配置目录中存在未登记到悟空面板的配置文件。升级器无法确认它是否兼容新版本，因此已阻止升级。请先在悟空中接管对应节点，或确认文件无用后自行移除，再重新检查。',
    'The sing-box configuration directory contains a file not registered with Wukong. The updater cannot verify that it is compatible with the new version, so the update was blocked. Import the corresponding node into Wukong, or remove the file yourself if it is unused, then check again.',
  ],
  'unmanaged nodes prevent runtime updates': [
    '存在未由悟空管理的 sing-box 节点。升级器无法迁移并验证这些节点的配置，因此已阻止升级。请先接管这些节点，或在确认不再使用后移除，再重新检查。',
    'One or more sing-box nodes are not managed by Wukong. The updater cannot migrate and verify their configurations, so the update was blocked. Import those nodes into Wukong, or remove them if they are no longer used, then check again.',
  ],
  'node configuration is outside the managed directory': [
    '至少一个节点的配置文件不在悟空管理的配置目录内。升级器只会迁移和备份管理目录中的配置，为避免遗漏或改动外部文件，已阻止升级。请将节点配置迁入面板管理目录并重新登记，或改用其他方式维护该节点。',
    'At least one node configuration is outside Wukong’s managed configuration directory. The updater only migrates and backs up files in that directory, so it blocked the update to avoid missing or changing external files. Move and register the configuration under the managed directory, or maintain that node separately.',
  ],
  'configuration directory must be absolute': [
    '悟空的 sing-box 配置目录不是绝对路径，无法安全定位和备份节点配置，因此已阻止升级。请修正 Agent 的配置目录设置后重试。',
    'Wukong’s sing-box configuration directory is not an absolute path, so node configurations cannot be located and backed up safely. The update was blocked. Correct the Agent configuration and try again.',
  ],
  'configuration must be a regular file without group/world write access': [
    '节点配置不是普通文件，或允许同组/其他用户写入。为避免升级时使用可被替换或篡改的配置，已阻止升级。请检查文件类型和权限，确保只有所有者可以写入后重试。',
    'A node configuration is not a regular file or is writable by its group or other users. The update was blocked to prevent using a replaceable or modified configuration. Check the file type and permissions, and allow writes only by the owner before retrying.',
  ],
  'managed configuration is missing': [
    '悟空登记的节点配置文件缺失。升级器无法为该节点备份和迁移配置，因此已阻止升级。请恢复配置文件或修正节点登记后重新检查。',
    'A configuration registered to a Wukong node is missing. The updater cannot back up and migrate that node, so the update was blocked. Restore the file or correct the node registration, then check again.',
  ],
  'unsupported managed runtime service': [
    '至少一个节点使用了悟空更新器不支持的服务名称或服务管理方式，因此无法安全停止、升级并恢复节点，更新已被阻止。请检查节点的 systemd/OpenRC 服务登记。',
    'At least one node uses a service name or service manager that the Wukong updater does not support. It cannot safely stop, update, and restore the node, so the update was blocked. Check the node’s systemd/OpenRC service registration.',
  ],
  'conflicting runtime service managers': [
    '同一个 sing-box 服务被登记为多个不同的服务管理器。为避免操作错误的服务，更新已被阻止。请修正节点服务登记，使每个服务只对应一个管理器后重试。',
    'The same sing-box service is registered under more than one service manager. The update was blocked to avoid operating on the wrong service. Correct the node registration so each service has one manager, then retry.',
  ],
  'runtime binary is also used by an unmanaged process': [
    '检测到悟空托管服务以外的进程也在使用这份 sing-box 二进制文件。替换它可能影响该进程，因此更新已被阻止。请先确认并停止或迁移该外部进程，再重新检查。',
    'A process outside the Wukong-managed services is also using this sing-box binary. Replacing it could affect that process, so the update was blocked. Identify and stop or migrate the external process, then check again.',
  ],
  'runtime service is using a different executable; restart it before updating': [
    '运行中的节点服务仍在使用另一份 sing-box 程序，而不是面板当前配置的二进制文件。为避免升级错误文件，更新已被阻止。请先用面板配置的程序重启该服务，再重新检查。',
    'A running node service is using a different sing-box executable from the one configured by the panel. The update was blocked to avoid updating the wrong file. Restart the service with the panel-configured executable, then check again.',
  ],
  'runtime is not installed': [
    '没有找到面板配置路径上的 sing-box 程序，因此无法检查或升级。请先安装 sing-box，或修正 Agent 中的二进制路径。',
    'No sing-box executable was found at the path configured by the panel, so it cannot be checked or updated. Install sing-box or correct the binary path in the Agent configuration.',
  ],
  'connector must be a regular executable without group/world write access': [
    '面板配置的 sing-box 文件不是普通可执行文件，或允许同组/其他用户写入。为避免替换不安全的程序，更新已被阻止。请检查文件类型和权限后重试。',
    'The configured sing-box file is not a regular executable or is writable by its group or other users. The update was blocked to avoid replacing an unsafe executable. Check the file type and permissions, then retry.',
  ],
  'cannot determine runtime version': [
    '无法读取当前 sing-box 程序的版本，不能确认升级目标和版本顺序，因此已阻止更新。请检查二进制文件是否可执行且可正常运行。',
    'The current sing-box version could not be read, so the updater cannot verify the target or version order. The update was blocked. Check that the binary is executable and runs correctly.',
  ],
  'unsupported architecture': [
    '当前服务器的 CPU 架构不受自动更新支持；目前仅支持 Linux amd64 和 arm64。',
    'Automatic updates do not support this server architecture. Linux amd64 and arm64 are currently supported.',
  ],
  'update recovery is pending': [
    '检测到上一次更新尚未完成恢复。为避免在恢复期间再次替换程序，更新已被阻止。请先完成或排查上一次更新的恢复任务，再重新检查。',
    'Recovery from a previous update is still pending. The update was blocked to avoid replacing the executable during recovery. Complete or investigate the recovery first, then check again.',
  ],
  'latest release requires a newer panel compatibility profile': [
    '最新版本要求更新的面板兼容配置，当前悟空版本无法安全迁移或验证它。请先升级悟空面板/Agent，再重新检查。',
    'The latest release requires a newer panel compatibility profile that this Wukong version cannot safely migrate or verify. Upgrade the Wukong panel/Agent, then check again.',
  ],
}
const updateMessage = (raw?: string) => {
  if (!raw) return raw
  const exact = updateMessages[raw]
  if (exact) return t(exact[0].replaceAll('sing-box', binaryName.value), exact[1].replaceAll('sing-box', binaryName.value))
  const migration = raw.match(/^configuration (.+) requires manual migration$/)
  if (migration) return t(`配置文件 ${migration[1]} 包含无法自动迁移的内容。为避免破坏节点，升级已被阻止；请先按新版本要求手动调整配置，再重新检查。`, `Configuration ${migration[1]} contains data that cannot be migrated automatically. The update was blocked to protect the node; adjust the configuration for the new version, then check again.`)
  const iface = raw.match(/^configuration references unavailable interface (.+)$/)
  if (iface) return t(`节点配置引用了本机不存在或不可用的网络接口 ${iface[1]}，升级前校验无法通过，因此已阻止升级。请检查接口名称或配置后重试。`, `The node configuration references network interface ${iface[1]}, which is unavailable on this host. Pre-update validation failed, so the update was blocked. Check the interface name or configuration, then retry.`)
  const proxy = raw.match(/^node (.+) failed the local proxy round trip$/)
  if (proxy) return t(`节点 ${proxy[1]} 更新后的本机代理连通性检测失败。系统已中止更新并自动恢复原版本；请检查节点配置和本机监听后重试。`, `The local proxy connectivity check failed after updating node ${proxy[1]}. The update was stopped and the previous version was restored. Check the node configuration and local listener before retrying.`)
  const service = raw.match(/^runtime service (.+) is not active after restart$/)
  if (service) return t(`服务 ${service[1]} 在更新后未能正常启动。系统已中止更新并自动恢复原版本；请查看该服务日志后重试。`, `Service ${service[1]} did not start after the update. The update was stopped and the previous version was restored. Check the service logs before retrying.`)
  const http = raw.match(/^runtime download HTTP (\d+)$/)
  if (http) return t(`连接官方更新源失败（HTTP ${http[1]}），无法读取或下载新版本。请检查服务器网络及 GitHub 连通性后重新检查。`, `The official update source returned HTTP ${http[1]}, so the release could not be read or downloaded. Check server network access to GitHub, then retry.`)
  return raw
}
const reasonText = computed(() => updateMessage(state.value?.reason))
const errorText = computed(() => updateMessage(error.value || state.value?.lastError))
const message = (e: unknown) => e instanceof Error ? e.message : t('操作失败', 'Operation failed')
async function load() {
  if (!available.value) return
  const pending = pendingComponentUpdateJob(props.hostId, props.component)
  if (pending && !jobRunning.value) { job.value = pending; void pollJob(pending.id) }
  if (job.value?.status !== 'failed') error.value = ''
  try { const result = await client.status(); if (alive) state.value = result }
  catch (e) { if (alive && !error.value) error.value = message(e) }
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
    refreshComponentUpdateJob(props.hostId, props.component, result)
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
    const queued: Job = { id: result.jobId, kind: `${props.component}.update`, target: props.hostId, status: 'queued', progress: 0, message: t('等待更新', 'Waiting for update'), createdAt: '', updatedAt: '' }
    startComponentUpdateJob(props.hostId, props.component, queued)
    if (!alive) return
    confirmation.value = null
    job.value = queued
    void pollJob(result.jobId)
  } catch (e) { if (alive) error.value = message(e) }
  finally { if (alive) busy.value = false }
}
watch(available, ready => { if (ready) void load(); else confirmation.value = null }, { immediate: true })
onBeforeUnmount(() => { alive = false; if (timer) clearTimeout(timer) })
</script>

<template>
  <section class="panel-card component-update-panel" :data-component="component">
    <div class="card-head"><div><span class="section-mark jade">{{ isTunnel ? t('隧', 'T') : t('核', 'S') }}</span><div><h3>{{ title }}</h3><p>{{ isTunnel ? t('cloudflared 连接器更新', 'cloudflared connector updates') : t('代理内核更新', 'Proxy runtime updates') }}</p></div></div><span v-if="state?.updateAvailable" class="update-badge">{{ t('有新版本', 'Update available') }}</span></div>
    <p v-if="!available" class="help-text">{{ !supported ? t('此主机的 Agent 尚不支持组件更新，请先升级完整面板。', 'This Agent does not support component updates. Upgrade the full panel first.') : t('此主机当前不可操作。', 'This host is currently unavailable.') }}</p>
    <template v-else>
      <div class="connector-versions"><div><small>{{ t('当前版本', 'Installed version') }}</small><strong>{{ state?.currentVersion || (state && !state.installed ? t('未安装', 'Not installed') : '—') }}</strong></div><div><small>{{ t('最新稳定版', 'Latest stable version') }}</small><strong>{{ state?.latestVersion || '—' }}</strong></div><button :disabled="busy || jobRunning" @click="check">{{ busy ? t('处理中…', 'Working…') : t('检查更新', 'Check for updates') }}</button><button v-if="state?.updateAvailable" class="primary" :disabled="!writable" @click="confirmation = 'update'">{{ t('升级到', 'Update to') }} {{ state.latestVersion }}</button></div>
      <label v-if="isTunnel" class="toggle-row"><span><b>{{ t('自动更新 cloudflared', 'Update cloudflared automatically') }}</b><small>{{ t('每天检查稳定版；更新时短暂重启运行中的悟空隧道。', 'Checks stable releases daily; updates briefly restart running Wukong tunnels.') }}</small></span><span class="switch"><input type="checkbox" :checked="!!state?.autoUpdate" :disabled="!state || busy || jobRunning || (!state.autoUpdate && !writable)" @click.prevent="state?.autoUpdate ? setAuto(false) : confirmation = 'auto'"><i></i></span></label>
      <div v-if="confirmation" class="connector-confirm"><p>{{ confirmation === 'auto' ? t('启用后，悟空将自动安装官方稳定版，并重启正在运行的隧道。更新失败时恢复原版本。', 'Wukong will install official stable releases and restart running tunnels automatically. Failed updates restore the previous version.') : (isTunnel ? t('升级会短暂重启正在运行的悟空隧道；失败时恢复原版本。', 'Updating briefly restarts running Wukong tunnels; failures restore the previous version.') : t('更新会校验并迁移托管配置、备份并重启运行中的节点；失败时恢复原版本和配置。', 'Updating validates and migrates managed configurations, backs up files and restarts running nodes; failures restore the previous runtime and configurations.')) }}</p><div><button class="primary" :disabled="!writable" @click="confirmation === 'auto' ? setAuto(true) : upgrade()">{{ t('确认', 'Confirm') }}</button><button :disabled="busy" @click="confirmation = null">{{ t('取消', 'Cancel') }}</button></div></div>
      <p v-if="!isTunnel" class="help-text runtime-update-note">{{ t('更新前校验并迁移托管配置；更新后执行本机代理探测，失败自动恢复。', 'Validates and migrates managed configurations, then probes the local proxy; failures restore the previous files.') }}</p>
      <p v-if="state?.reason" class="help-text">{{ reasonText }}</p>
      <p v-if="state?.checkedAt && !state.checkedAt.startsWith('0001')" class="help-text">{{ t('最后检查', 'Last checked') }} {{ new Date(state.checkedAt).toLocaleString(language) }}</p>
      <p v-if="job" role="status">{{ job.message }} · {{ job.progress }}%</p>
      <p v-if="errorText" class="connector-error" role="alert">{{ errorText }}</p>
    </template>
  </section>
</template>

<style scoped>
.component-update-panel{min-width:0;margin:0;padding:24px}.connector-versions{display:flex;align-items:center;gap:18px;flex-wrap:wrap;margin:20px 0}.connector-versions>div{display:flex;flex-direction:column;gap:6px;min-width:110px}.connector-versions small{color:var(--muted)}.connector-versions strong{font-size:18px;font-family:"IBM Plex Mono",monospace}.update-badge{color:var(--gold);font-size:12px}.connector-confirm{margin-top:16px;padding:16px;border:1px solid var(--line);border-radius:10px}.connector-confirm>div{display:flex;gap:10px;margin-top:12px}.connector-error{color:var(--danger-text);overflow-wrap:anywhere}.toggle-row small{display:block;margin-top:5px;line-height:1.6}.help-text{overflow-wrap:anywhere}@media(max-width:600px){.component-update-panel{padding:18px}.connector-versions{gap:12px}.connector-versions>div{min-width:110px}.toggle-row{gap:14px}}
</style>
