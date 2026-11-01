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

  // Template section
  assert.ok(vueSource.includes('class="panel-card external-subscriptions-section"'), 'App.vue must render external-subscriptions-section')
  assert.ok(vueSource.includes('外部订阅与机场混流'), 'App.vue must render section title')
  assert.ok(vueSource.includes('class="external-sub-card"'), 'App.vue must render external-sub-card')
  assert.ok(vueSource.includes('class="external-quota-bar"'), 'App.vue must render external-quota-bar')
  assert.ok(vueSource.includes('class="external-node-chip"'), 'App.vue must render external-node-chip')

  // External Sub Modal
  assert.ok(vueSource.includes("modal === 'external-sub'"), 'App.vue must render external-sub modal')
  assert.ok(vueSource.includes('submitExternalSubModal'), 'App.vue must define submitExternalSubModal')
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
  assert.ok(cssSource.includes('.subscription-qr-modal'), 'styles.css must style .subscription-qr-modal')
})
