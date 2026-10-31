import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('api.ts includes subscriptionTemplate in Settings interface', () => {
  const apiSource = readFileSync(new URL('./api.ts', import.meta.url), 'utf8')
  assert.ok(
    apiSource.includes('subscriptionTemplate?: string') || apiSource.includes("subscriptionTemplate?: 'minimal' | 'standard' | 'smart' | string"),
    'Settings interface must include subscriptionTemplate property'
  )
})

test('i18n.ts includes bilingual keys for subscription rule templates', () => {
  const i18nSource = readFileSync(new URL('./i18n.ts', import.meta.url), 'utf8')

  const expectedKeys = [
    "'规则模板预设': 'Rule template preset'",
    "'规则模板': 'Rule template'",
    "'标准开箱即用 (推荐)': 'Standard (Recommended)'",
    "'智能流媒体与 AI': 'Smart (Streaming & AI)'",
    "'极简纯净': 'Minimal clean'",
    "'复制选定模板订阅': 'Copy template subscription'"
  ]

  for (const entry of expectedKeys) {
    assert.ok(i18nSource.includes(entry), `i18n must define "${entry}"`)
  }
})

test('App.vue renders subscription template options and fleet URL generator with template', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  // Reactive state
  assert.ok(vueSource.includes('subscriptionTemplate:'), 'settings ref must contain subscriptionTemplate')
  assert.ok(vueSource.includes('selectedFleetTemplate'), 'must declare selectedFleetTemplate ref')
  assert.ok(vueSource.includes('fleetSubscriptionUrlWithTemplate'), 'must define fleetSubscriptionUrlWithTemplate helper')

  // URL query parameter generation logic
  assert.ok(vueSource.includes('template='), 'fleet URL helper must support template query param')

  // Template selector in single-host settings
  assert.ok(vueSource.includes('class="subscription-template-row"'), 'Settings must render subscription-template-row')
  assert.ok(vueSource.includes('v-model="settings.subscriptionTemplate"'), 'Template select must be bound to settings.subscriptionTemplate')
  assert.ok(vueSource.includes('value="standard"'), 'Must have standard option')
  assert.ok(vueSource.includes('value="smart"'), 'Must have smart option')
  assert.ok(vueSource.includes('value="minimal"'), 'Must have minimal option')

  // Fleet template dropdown in fleet subscription card
  assert.ok(vueSource.includes('class="fleet-template-picker"'), 'Fleet card must render fleet-template-picker')
  assert.ok(vueSource.includes('v-model="selectedFleetTemplate"'), 'Fleet template picker must be bound to selectedFleetTemplate')
})

test('styles.css contains styling for subscription template components', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')

  assert.ok(cssSource.includes('.fleet-template-picker'), 'Must style .fleet-template-picker')
  assert.ok(cssSource.includes('.scope-template-select'), 'Must style .scope-template-select')
  assert.ok(cssSource.includes('.subscription-template-row'), 'Must style .subscription-template-row')
})
