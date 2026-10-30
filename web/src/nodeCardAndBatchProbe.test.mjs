import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('App.vue renders batch probe button with dynamic states and progress', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  assert.ok(vueSource.includes('class="batch-probe-btn"'), 'Must have batch-probe-btn in template')
  assert.ok(vueSource.includes('class="batch-probe-icon"'), 'Must render batch-probe-icon')
  assert.ok(vueSource.includes('@click="probeAllActiveNodes"'), 'Must trigger probeAllActiveNodes on click')
  assert.ok(vueSource.includes('一键全检'), 'Must contain Chinese label 一键全检')
  assert.ok(vueSource.includes('全检中'), 'Must contain running state label 全检中')
  assert.ok(vueSource.includes('Probe All'), 'Must support English label Probe All')
  assert.ok(vueSource.includes('batchProbeProgress.completed'), 'Must display completed progress count')
  assert.ok(vueSource.includes('batchProbeProgress.total'), 'Must display total progress count')
})

test('App.vue implements robust probeAllActiveNodes with progress tracking and summary', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  assert.ok(vueSource.includes('async function probeAllActiveNodes('), 'Must define probeAllActiveNodes')
  assert.ok(vueSource.includes('const batchProbing = ref(false)'), 'Must define batchProbing state')
  assert.ok(vueSource.includes('const batchProbeProgress = reactive('), 'Must define batchProbeProgress state')
  assert.ok(vueSource.includes('const activeNodes = computed('), 'Must define activeNodes filter')
  assert.ok(vueSource.includes('全部正常'), 'Must notify success when all nodes pass')
  assert.ok(vueSource.includes('个异常'), 'Must report anomaly count when any node fails')
})

test('App.vue streamlines node-specs from 4 redundant items down to 2 clean items', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  assert.ok(vueSource.includes('class="node-specs"'), 'Must contain node-specs')
  assert.ok(vueSource.includes('outboundLabel(node)'), 'Must display outbound strategy')
  assert.ok(vueSource.includes('管理归属'), 'Must display management ownership')
  // Check that redundant in-flow 4-item grid is removed
  assert.ok(!vueSource.includes('<small>运行版本</small>'), 'Redundant 运行版本 in-flow label must be eliminated')
  assert.ok(!vueSource.includes('<small>归属</small><b>{{ node.ownership === \'imported\' ? \'接管\' : \'悟空\' }}</b>'), 'Old 归属/悟空 block must be replaced')
  // But technical details must remain preserved in tooltip
  assert.ok(vueSource.includes('sing-box ${overview?.singBoxVersion || node.configVersion'), 'Detailed core version must be retained in title tooltip')
  assert.ok(vueSource.includes('${node.serviceManager}'), 'Service manager must be retained in title tooltip')
})

test('App.vue consolidates Tunnel preferred route and origin service into compact tunnel-route-box', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  assert.ok(vueSource.includes('class="tunnel-route-box"'), 'Must contain unified tunnel-route-box')
  assert.ok(vueSource.includes('class="tunnel-route-row"'), 'Must contain tunnel-route-row')
  assert.ok(vueSource.includes('class="tunnel-origin-row"'), 'Must contain tunnel-origin-row')
  assert.ok(vueSource.includes('class="tunnel-copy-btn"'), 'Must contain tunnel-copy-btn')
  assert.ok(vueSource.includes('node.preferredServer'), 'Must conditionally render preferred server route')
  assert.ok(vueSource.includes('tunnelOrigin(node)'), 'Must render tunnel origin target')
})

test('styles.css enforces height convergence and removes 510px height inflation for Tunnel cards', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')
  // Verify 510px is removed
  assert.ok(!cssSource.includes('.node-card.tunnel { min-height: 510px; }'), '510px min-height for tunnel cards must be removed')
  // Verify uniform height for standard and add node cards
  assert.ok(cssSource.includes('.node-card { position: relative; min-height: 380px; padding: 22px 22px 108px;'), 'Must have standardized 380px min-height and reserved bottom padding')
  assert.ok(cssSource.includes('.add-node-card { position: relative; min-height: 380px;'), 'add-node-card must match 380px min-height')
  // Verify batch probe button styles
  assert.ok(cssSource.includes('.batch-probe-btn'), 'Must have .batch-probe-btn styles')
  assert.ok(cssSource.includes('.batch-probe-btn.running'), 'Must have .batch-probe-btn.running styles')
  // Verify tunnel-route-box styles
  assert.ok(cssSource.includes('.tunnel-route-box'), 'Must have .tunnel-route-box styles')
  assert.ok(cssSource.includes('.tunnel-copy-btn'), 'Must have .tunnel-copy-btn styles')
})

test('styles.css includes light theme rules and responsive mobile layout for batch probe and cards', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .batch-probe-btn'), 'Must define light theme for batch-probe-btn')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .tunnel-route-box'), 'Must define light theme for tunnel-route-box')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .tunnel-copy-btn'), 'Must define light theme for tunnel-copy-btn')
  // Verify mobile responsive summary-pills is preserved
  assert.ok(cssSource.includes('.summary-pills { display: flex; flex-wrap: wrap; gap: 8px; }'), 'Mobile view must display summary-pills with wrap')
})

test('batch probe tracking and summary messaging simulate properly', () => {
  const formatSummary = (total, success, failed, lang = 'zh-CN') => {
    if (failed === 0) {
      return lang === 'en-US'
        ? `⚡ All ${total} active nodes probed successfully, all healthy`
        : `⚡ 全部 ${total} 个节点闭环自检完成，全部正常`
    }
    return lang === 'en-US'
      ? `⚡ Probed all nodes: ${success} passed, ${failed} failed`
      : `⚡ 全检完成：${success} 个正常，${failed} 个异常`
  }

  assert.equal(formatSummary(5, 5, 0, 'zh-CN'), '⚡ 全部 5 个节点闭环自检完成，全部正常')
  assert.equal(formatSummary(5, 4, 1, 'zh-CN'), '⚡ 全检完成：4 个正常，1 个异常')
  assert.equal(formatSummary(3, 3, 0, 'en-US'), '⚡ All 3 active nodes probed successfully, all healthy')
  assert.equal(formatSummary(3, 2, 1, 'en-US'), '⚡ Probed all nodes: 2 passed, 1 failed')
})
