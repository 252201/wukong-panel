import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('api.ts includes ExternalSubscription interface and API methods', () => {
  const apiSource = readFileSync(new URL('./api.ts', import.meta.url), 'utf8')
  assert.ok(apiSource.includes('export interface ExternalSubscription'), 'api.ts must export ExternalSubscription interface')
  assert.ok(apiSource.includes('proxyUrl?: string'), 'ExternalSubscription must support proxyUrl')
  assert.ok(apiSource.includes('rawContent?: string'), 'ExternalSubscription must support rawContent')
  assert.ok(apiSource.includes('normalizeExternalSubscription'), 'api.ts must define normalizeExternalSubscription helper')
  assert.ok(apiSource.includes('externalSubscriptions:'), 'api.ts must define externalSubscriptions method')
  assert.ok(apiSource.includes('createExternalSubscription:'), 'api.ts must define createExternalSubscription method')
  assert.ok(apiSource.includes('updateExternalSubscription:'), 'api.ts must define updateExternalSubscription method')
  assert.ok(apiSource.includes('deleteExternalSubscription:'), 'api.ts must define deleteExternalSubscription method')
  assert.ok(apiSource.includes('syncExternalSubscription:'), 'api.ts must define syncExternalSubscription method')
})

test('App.vue renders multi-format switcher chips and QR code import action', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  // Reactive state & methods
  assert.ok(vueSource.includes('selectedSubFormat'), 'App.vue must declare selectedSubFormat')
  assert.ok(vueSource.includes('subscriptionQRDataUrl'), 'App.vue must declare subscriptionQRDataUrl')
  assert.ok(vueSource.includes('fleetSubscriptionUrl'), 'App.vue must declare fleetSubscriptionUrl')
  assert.ok(vueSource.includes('openSubscriptionQR'), 'App.vue must declare openSubscriptionQR')

  // Multi-format switcher UI
  assert.ok(vueSource.includes('class="sub-format-chips"'), 'App.vue must render sub-format-chips')
  assert.ok(vueSource.includes("selectedSubFormat === 'auto'"), 'App.vue must support auto format')
  assert.ok(vueSource.includes("selectedSubFormat === 'clash'"), 'App.vue must support clash format')
  assert.ok(vueSource.includes("selectedSubFormat === 'base64'"), 'App.vue must support base64 format')
  assert.ok(vueSource.includes("selectedSubFormat === 'singbox'"), 'App.vue must support singbox format')

  // QR Modal
  assert.ok(vueSource.includes("modal === 'subscription-qr'"), 'App.vue must render subscription-qr modal')
  assert.ok(vueSource.includes('扫码导入'), 'App.vue must include 扫码导入 action button')
})

test('App.vue renders external subscriptions card, sync actions, and node selection grid', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  // Reactive state & methods
  assert.ok(vueSource.includes('externalSubs'), 'App.vue must declare externalSubs')
  assert.ok(vueSource.includes('loadExternalSubscriptions'), 'App.vue must declare loadExternalSubscriptions')
  assert.ok(vueSource.includes('syncExternalSubscription'), 'App.vue must declare syncExternalSubscription')
  assert.ok(vueSource.includes('toggleExternalSubEnabled'), 'App.vue must declare toggleExternalSubEnabled')
  assert.ok(vueSource.includes('toggleExternalNodeSelected'), 'App.vue must declare toggleExternalNodeSelected')
  assert.ok(vueSource.includes('toggleAllExternalNodes'), 'App.vue must declare toggleAllExternalNodes')
  assert.ok(vueSource.includes('externalSubNodes'), 'App.vue must declare externalSubNodes defensive helper')
  assert.ok(vueSource.includes('externalSubSelectedIds'), 'App.vue must declare externalSubSelectedIds defensive helper')
  assert.ok(vueSource.includes('formatExternalExpiry'), 'App.vue must declare formatExternalExpiry defensive helper')

  // Guard against null nodes crashes in template
  assert.ok(!vueSource.includes('sub.nodes.map'), 'App.vue must not directly call sub.nodes.map without null guard')
  assert.ok(!vueSource.includes('sub.nodes.length'), 'App.vue must not directly call sub.nodes.length without null guard')

  // Support direct paste & proxy URL & formatExternalSyncTime
  assert.ok(vueSource.includes('formatExternalSyncTime'), 'App.vue must define formatExternalSyncTime helper')
  assert.ok(vueSource.includes('externalSubImportMode'), 'App.vue must define externalSubImportMode')
  assert.ok(vueSource.includes('class="sub-mode-tabs"'), 'App.vue must render sub-mode-tabs in modal')
  assert.ok(vueSource.includes('class="external-raw-textarea"'), 'App.vue must render raw textarea in modal')
  assert.ok(vueSource.includes('filteredExternalNodes'), 'App.vue must define filteredExternalNodes helper')
  assert.ok(vueSource.includes('externalNodeFilter'), 'App.vue must define externalNodeFilter state')

  // Template section
  assert.ok(vueSource.includes('class="panel-card external-subscriptions-section"'), 'App.vue must render external-subscriptions-section')
  assert.ok(vueSource.includes('外部订阅与机场混流'), 'App.vue must render section title')
  assert.ok(vueSource.includes('class="external-sub-card"'), 'App.vue must render external-sub-card')
  assert.ok(vueSource.includes('class="external-quota-bar"'), 'App.vue must render external-quota-bar')
  assert.ok(vueSource.includes('class="external-node-chip"'), 'App.vue must render external-node-chip')

  // External Sub Modal
  assert.ok(vueSource.includes("modal === 'external-sub'"), 'App.vue must render external-sub modal')
  assert.ok(vueSource.includes('submitExternalSubModal'), 'App.vue must define submitExternalSubModal')
  assert.ok(vueSource.includes('autoSync: false'), 'externalSubDraft must default autoSync to false')

  // External Sub Delete Confirmation Modal (no browser native confirm popups)
  assert.ok(vueSource.includes('externalSubDeleteTarget'), 'App.vue must declare externalSubDeleteTarget')
  assert.ok(vueSource.includes('openDeleteExternalSubModal'), 'App.vue must declare openDeleteExternalSubModal')
  assert.ok(vueSource.includes('confirmDeleteExternalSub'), 'App.vue must declare confirmDeleteExternalSub')
  assert.ok(vueSource.includes("modal === 'external-sub-delete'"), 'App.vue must render external-sub-delete modal')
  assert.ok(!vueSource.includes("confirm(`确认删除外部订阅"), 'App.vue must not use browser native confirm for deletion')
})

test('styles.css contains styling for multi-format switcher, external subs, and QR code modal', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')

  assert.ok(cssSource.includes('.sub-format-chips'), 'styles.css must style .sub-format-chips')
  assert.ok(cssSource.includes('.sub-format-chip'), 'styles.css must style .sub-format-chip')
  assert.ok(cssSource.includes('.external-subscriptions-section'), 'styles.css must style .external-subscriptions-section')
  assert.ok(cssSource.includes('.external-sub-card'), 'styles.css must style .external-sub-card')
  assert.ok(cssSource.includes('.external-sub-badge'), 'styles.css must style .external-sub-badge')
  assert.ok(cssSource.includes('.sub-mode-tabs'), 'styles.css must style .sub-mode-tabs')
  assert.ok(cssSource.includes('.external-raw-textarea'), 'styles.css must style .external-raw-textarea')
  assert.ok(cssSource.includes('.external-quota-bar'), 'styles.css must style .external-quota-bar')
  assert.ok(cssSource.includes('.external-node-chip'), 'styles.css must style .external-node-chip')
  assert.ok(cssSource.includes('.external-sub-delete-modal'), 'styles.css must style .external-sub-delete-modal')
  assert.ok(cssSource.includes('.external-sub-delete-target'), 'styles.css must style .external-sub-delete-target')
  assert.ok(cssSource.includes('.external-nodes-filter-input'), 'styles.css must style .external-nodes-filter-input')
  assert.ok(cssSource.includes('.subscription-qr-modal'), 'styles.css must style .subscription-qr-modal')

  // Checkbox dimension and overflow-x protections to avoid squashing node names
  assert.ok(cssSource.includes('.external-nodes-grid'), 'styles.css must style .external-nodes-grid')
  assert.ok(cssSource.includes('overflow-x: hidden'), 'styles.css .external-nodes-grid must hide horizontal overflow')
  assert.ok(cssSource.includes('.external-node-chip input[type="checkbox"]'), 'styles.css must style external node checkbox')
  assert.ok(cssSource.includes('flex: 0 0 14px !important'), 'checkbox must fix flex sizing to prevent expanding to 100% width')
})

test('externalSubSelectedIds filters out obsolete node IDs not present in subscription nodes', () => {
  // Simulate externalSubSelectedIds logic
  function externalSubNodes(sub) {
    if (!sub || !Array.isArray(sub.nodes)) return []
    return sub.nodes
  }

  function externalSubSelectedIds(sub) {
    const nodes = externalSubNodes(sub)
    if (!nodes.length) return []
    if (Array.isArray(sub?.selectedNodeIds)) {
      const validIds = new Set(nodes.map(n => n.id))
      return sub.selectedNodeIds.filter(id => validIds.has(id))
    }
    return nodes.map(n => n.id)
  }

  const sub = {
    id: 'sub-test',
    nodes: [
      { id: 'node-1', name: 'HK 01' },
      { id: 'node-2', name: 'SG 01' },
    ],
    selectedNodeIds: ['node-1', 'obsolete-announcement-1', 'obsolete-announcement-2'],
  }

  const selected = externalSubSelectedIds(sub)
  assert.deepEqual(selected, ['node-1'], 'should prune obsolete IDs so count matches valid nodes')
  assert.equal(selected.length, 1)

  // When selectedNodeIds is undefined, default to all valid nodes
  assert.deepEqual(externalSubSelectedIds({ nodes: sub.nodes }), ['node-1', 'node-2'])

  // When selectedNodeIds is empty array (user explicitly unselected all), return empty array
  assert.deepEqual(externalSubSelectedIds({ nodes: sub.nodes, selectedNodeIds: [] }), [])
})

test('bytesBinary accurately formats binary traffic (1024 base) matching airport packages', () => {
  function bytesBinary(value = 0) {
    if (!Number.isFinite(value) || value <= 0) return '0 B'
    const units = ['B', 'KB', 'MB', 'GB', 'TB', 'PB']
    let size = value
    let index = 0
    while (size >= 1024 && index < units.length - 1) {
      size /= 1024
      index++
    }
    const formatted = size.toFixed(index < 2 ? 0 : 2)
    const clean = formatted.replace(/\.00$/, '')
    return `${clean} ${units[index]}`
  }

  // 11.72 GB parsed from airport announcement node
  const usedBytes = Math.round(11.72 * 1024 * 1024 * 1024)
  assert.equal(bytesBinary(usedBytes), '11.72 GB', 'used bytes must format as exactly 11.72 GB')

  // 200 GB parsed from airport announcement node
  const totalBytes = 200 * 1024 * 1024 * 1024
  assert.equal(bytesBinary(totalBytes), '200 GB', 'total bytes must format as 200 GB (not 214.75 GB)')
})

test('formatExternalExpiry avoids UTC timezone day shift for date-only strings', () => {
  function formatExternalExpiry(expiresAt, language = 'zh-CN') {
    if (!expiresAt || expiresAt === '0' || expiresAt === 'null' || expiresAt === 'undefined') return ''
    const trimmed = expiresAt.trim()
    const dateMatch = trimmed.match(/^(\d{4})[-/](\d{1,2})[-/](\d{1,2})(?:[T ]00:00:00(?:\.000)?Z?)?$/)
    if (dateMatch) {
      const localDate = new Date(Number(dateMatch[1]), Number(dateMatch[2]) - 1, Number(dateMatch[3]))
      return Number.isNaN(localDate.getTime()) ? trimmed : localDate.toLocaleDateString(language)
    }
    const num = Number(trimmed)
    const date = !Number.isNaN(num) && num > 0 ? new Date(num > 1e11 ? num : num * 1000) : new Date(trimmed)
    return Number.isNaN(date.getTime()) ? trimmed : date.toLocaleDateString(language)
  }

  // 2027-02-18 should not shift to 2027/2/17 regardless of local UTC offset
  const formattedZh = formatExternalExpiry('2027-02-18', 'zh-CN')
  assert.equal(formattedZh, '2027/2/18')

  const formattedSlash = formatExternalExpiry('2027/02/18', 'zh-CN')
  assert.equal(formattedSlash, '2027/2/18')

  const formattedUtcIso = formatExternalExpiry('2027-02-18T00:00:00Z', 'zh-CN')
  assert.equal(formattedUtcIso, '2027/2/18')
})
