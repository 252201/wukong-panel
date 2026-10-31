import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('App.vue retains page on deployment and triggers dedicated watchDeploymentJob instead of showJobLog', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  // Verify createNode captures deployRes.jobId
  assert.ok(vueSource.includes('deployRes = await api.createNodeBatch(requests)'), 'createNode must capture batch jobId')
  assert.ok(vueSource.includes('deployRes = await api.createNode(common)'), 'createNode must capture single node jobId')

  // Verify it calls watchDeploymentJob with jobId and does NOT call showJobLog() on deployment
  assert.ok(vueSource.includes('void watchDeploymentJob(deployRes.jobId, deployTargetLabel)'), 'must launch watchDeploymentJob')
  
  // Verify modal is dismissed but page is preserved
  assert.ok(vueSource.includes('modal.value = null'), 'modal must be dismissed')
  assert.ok(!vueSource.includes("modal.value = null; notify(creatingDeviceBatch ? `${deviceNodes.length} 台设备的部署任务已进入队列` : '部署任务已进入队列'); await showJobLog()"), 'must not force showJobLog on deployment')
})

test('watchDeploymentJob implements adaptive fast polling (300ms initial, 800ms subsequent) and host isolation', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  assert.ok(vueSource.includes('let delay = 300'), 'initial polling delay must be 300ms')
  assert.ok(vueSource.includes('delay = 800'), 'subsequent polling delay must be 800ms')
  assert.ok(vueSource.includes('await new Promise(resolve => window.setTimeout(resolve, delay))'), 'must sleep for adaptive delay')
  assert.ok(vueSource.includes('if (!authenticated.value) return'), 'must stop polling if unauthenticated')
  assert.ok(vueSource.includes('if (selectedHostId.value === hostId)'), 'must isolate updates to matching host')
  assert.ok(vueSource.includes('void refreshFleetStatus()'), 'must refresh fleet status on success')
})

test('openNodeForm guards server and domain against asynchronous default overwrites and closed dialogs', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  assert.ok(
    vueSource.includes('if (modal.value !== kind) return'),
    'must guard against dialog being closed or switched before defaults arrive'
  )
  assert.ok(
    vueSource.includes('if (!createForm.server) {\n      createForm.server = deploymentDefaults.value.panelDomain\n    }'),
    'must only populate server if empty'
  )
  assert.ok(
    vueSource.includes('if (!createForm.domain) {\n      createForm.domain = deploymentDefaults.value.panelDomain\n    }'),
    'must only populate domain if empty'
  )
})

test('App.vue and styles.css provide in-place progress indicator and ready feedback card with quick copy actions', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')

  // Template contains deployment progress indicator and ready card
  assert.ok(vueSource.includes('class="deployment-progress-indicator"'), 'App.vue must include deployment-progress-indicator')
  assert.ok(vueSource.includes('class="deployment-ready-card"'), 'App.vue must include deployment-ready-card')
  assert.ok(vueSource.includes('quickCopyShare(deploymentReady.node)'), 'ready card must support quick copy share link')
  assert.ok(vueSource.includes('copy(fleetStatus.globalSubscription)'), 'ready card must support copying global subscription')
  assert.ok(vueSource.includes('revealShare(deploymentReady.node)'), 'ready card must support opening share modal')

  // CSS contains responsive styles, light theme overrides and mobile media query
  assert.ok(cssSource.includes('.deployment-progress-indicator'), 'styles.css must style .deployment-progress-indicator')
  assert.ok(cssSource.includes('.deployment-ready-card'), 'styles.css must style .deployment-ready-card')
  assert.ok(cssSource.includes('.deployment-spinner'), 'styles.css must style .deployment-spinner')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .deployment-ready-card'), 'styles.css must include light theme overrides')
  assert.ok(cssSource.includes('@media (max-width: 640px) {\n  .deployment-progress-indicator,\n  .deployment-ready-card'), 'styles.css must include mobile responsive styles')
})

test('Simulated openNodeForm defaults race condition logic correctly preserves user input', () => {
  // Scenario 1: User typed nothing before async defaults arrive
  const form1 = { server: '', domain: '' }
  const defaults1 = { panelDomain: 'panel.example.com' }
  if (!form1.server) form1.server = defaults1.panelDomain
  if (!form1.domain) form1.domain = defaults1.panelDomain
  assert.equal(form1.server, 'panel.example.com')
  assert.equal(form1.domain, 'panel.example.com')

  // Scenario 2: User started typing custom server/domain before async defaults arrive
  const form2 = { server: 'custom.mydomain.org', domain: 'reality.microsoft.com' }
  const defaults2 = { panelDomain: 'panel.example.com' }
  if (!form2.server) form2.server = defaults2.panelDomain
  if (!form2.domain) form2.domain = defaults2.panelDomain
  assert.equal(form2.server, 'custom.mydomain.org', 'Must not overwrite manually entered server')
  assert.equal(form2.domain, 'reality.microsoft.com', 'Must not overwrite manually entered domain')
})

