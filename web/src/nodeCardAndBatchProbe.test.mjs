import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('App.vue summary-pills is clean without batch probe button and diagnostic modal removes job log button', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  // Verify batch probe button is removed
  assert.ok(!vueSource.includes('class="batch-probe-btn"'), 'batch-probe-btn must be removed from App.vue')
  assert.ok(!vueSource.includes('probeAllActiveNodes'), 'probeAllActiveNodes must be removed from App.vue')
  assert.ok(!vueSource.includes('const batchProbing ='), 'batchProbing state must be removed from App.vue')
  // Verify clean summary pills
  assert.ok(vueSource.includes('class="summary-pills"'), 'Must have summary-pills container')
  assert.ok(vueSource.includes('overview?.onlineNodes'), 'Must display online nodes count')
  assert.ok(vueSource.includes('已接管'), 'Must display imported nodes count')
  // Verify diagnostic modal removes 查看任务日志 button
  assert.ok(!vueSource.includes('查看任务日志</button>'), '查看任务日志 button must be removed from diagnostic modal footer')
})

test('App.vue streamlines node-specs into clean outbounds, cumulative traffic, and ownership', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')
  assert.ok(vueSource.includes('class="node-specs"'), 'Must contain node-specs')
  assert.ok(vueSource.includes('outboundLabel(node)'), 'Must display outbound strategy')
  assert.ok(vueSource.includes('累计流量'), 'Must display cumulative traffic')
  assert.ok(vueSource.includes('nodeTrafficTooltip'), 'Must provide cumulative traffic tooltip')
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

test('styles.css enforces height convergence and removes batch probe styling', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')
  // Verify 510px is removed
  assert.ok(!cssSource.includes('.node-card.tunnel { min-height: 510px; }'), '510px min-height for tunnel cards must be removed')
  // Verify uniform height for standard and add node cards
  assert.ok(cssSource.includes('.node-card { position: relative; min-height: 380px; padding: 22px 22px 108px;'), 'Must have standardized 380px min-height and reserved bottom padding')
  assert.ok(cssSource.includes('.add-node-card { position: relative; min-height: 380px;'), 'add-node-card must match 380px min-height')
  // Verify batch probe button styles are removed
  assert.ok(!cssSource.includes('.batch-probe-btn'), 'batch-probe-btn styles must be removed')
  // Verify tunnel-route-box styles
  assert.ok(cssSource.includes('.tunnel-route-box'), 'Must have .tunnel-route-box styles')
  assert.ok(cssSource.includes('.tunnel-copy-btn'), 'Must have .tunnel-copy-btn styles')
})

test('styles.css includes light theme rules and responsive mobile layout', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')
  assert.ok(!cssSource.includes(':root[data-effective-theme="light"] .batch-probe-btn'), 'Light theme for batch-probe-btn must be removed')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .tunnel-route-box'), 'Must define light theme for tunnel-route-box')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .tunnel-copy-btn'), 'Must define light theme for tunnel-copy-btn')
  // Verify mobile responsive summary-pills is preserved
  assert.ok(cssSource.includes('.summary-pills { display: flex; flex-wrap: wrap; gap: 8px; }'), 'Mobile view must display summary-pills with wrap')
})
