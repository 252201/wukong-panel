import test from 'node:test'
import assert from 'node:assert/strict'
import fs from 'node:fs'
import path from 'node:path'
import { fileURLToPath } from 'node:url'

const __dirname = path.dirname(fileURLToPath(import.meta.url))
const apiSource = fs.readFileSync(path.join(__dirname, 'api.ts'), 'utf8')
const vueSource = fs.readFileSync(path.join(__dirname, 'App.vue'), 'utf8')
const stylesSource = fs.readFileSync(path.join(__dirname, 'styles.css'), 'utf8')

test('api.ts includes ChainedProxy interface and API methods', () => {
  assert.ok(apiSource.includes('export interface ChainedProxy'), 'api.ts must export ChainedProxy interface')
  assert.ok(apiSource.includes('entryNodeName: string'), 'ChainedProxy must have entryNodeName')
  assert.ok(apiSource.includes('exitNodeName: string'), 'ChainedProxy must have exitNodeName')
  assert.ok(apiSource.includes('chainedProxies:'), 'api must have chainedProxies method')
  assert.ok(apiSource.includes('saveChainedProxy:'), 'api must have saveChainedProxy method')
  assert.ok(apiSource.includes('deleteChainedProxy:'), 'api must have deleteChainedProxy method')
  assert.ok(apiSource.includes('toggleChainedProxy:'), 'api must have toggleChainedProxy method')
})

test('App.vue implements Chained Proxies section, candidate computation and modals', () => {
  assert.ok(vueSource.includes('chainedProxies = ref<ChainedProxy[]>'), 'App.vue must declare chainedProxies ref')
  assert.ok(vueSource.includes('availableChainedCandidates'), 'App.vue must declare availableChainedCandidates computed')
  assert.ok(vueSource.includes('groupedChainedCandidates'), 'App.vue must declare groupedChainedCandidates computed')
  assert.ok(vueSource.includes('loadChainedProxies'), 'App.vue must declare loadChainedProxies')
  assert.ok(vueSource.includes('openCreateChainedProxyModal'), 'App.vue must declare openCreateChainedProxyModal')
  assert.ok(vueSource.includes('openEditChainedProxyModal'), 'App.vue must declare openEditChainedProxyModal')
  assert.ok(vueSource.includes('toggleChainedProxy'), 'App.vue must declare toggleChainedProxy')
  assert.ok(vueSource.includes('confirmDeleteChainedProxy'), 'App.vue must declare confirmDeleteChainedProxy')
  assert.ok(vueSource.includes('chained-proxies-section'), 'App.vue must render chained-proxies-section')
  assert.ok(vueSource.includes('modal === \'chained-proxy\''), 'App.vue must render chained-proxy modal')
  assert.ok(vueSource.includes('modal === \'delete-chained-proxy\''), 'App.vue must render delete-chained-proxy modal')
})

test('styles.css contains styling for Chained Proxies section and light theme', () => {
  assert.ok(stylesSource.includes('.chained-proxies-section'), 'styles.css must style .chained-proxies-section')
  assert.ok(stylesSource.includes('.chained-proxy-card'), 'styles.css must style .chained-proxy-card')
  assert.ok(stylesSource.includes('.route-node-pill'), 'styles.css must style .route-node-pill')
  assert.ok(stylesSource.includes('.route-node-pill.entry'), 'styles.css must style entry route pill')
  assert.ok(stylesSource.includes('.route-node-pill.exit'), 'styles.css must style exit route pill')
  assert.ok(stylesSource.includes('.section-mark.purple'), 'styles.css must style .section-mark.purple')
  assert.ok(stylesSource.includes('.modal-seal.purple'), 'styles.css must style .modal-seal.purple')
  assert.ok(stylesSource.includes(':root[data-effective-theme="light"] .chained-proxy-card'), 'styles.css must style chained-proxy-card in light theme')
})
