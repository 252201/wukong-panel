import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('App.vue streamlines topbar action buttons and consolidates deployment into deploy dropdown', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  // Topbar action bar structure
  assert.ok(vueSource.includes('class="top-actions"'), 'Must have top-actions container')
  assert.ok(vueSource.includes('class="secondary ip-rep-topbar-btn"'), 'Must keep IP reputation secondary button')
  assert.ok(vueSource.includes('class="secondary import-topbar-btn"'), 'Must keep import node secondary button')
  assert.ok(vueSource.includes('↳ {{ t(\'import\') }}'), 'Must render import button with ↳ icon and localized label')

  // Old loose device-entry must NOT be a top-level child of top-actions
  assert.ok(!vueSource.includes('<button v-if="page !== \'fleet\'" class="device-entry"'), 'Loose device-entry button must be removed from top-actions')

  // Deploy dropdown container and main button
  assert.ok(vueSource.includes('class="deploy-dropdown-wrap"'), 'Must have deploy-dropdown-wrap container')
  assert.ok(vueSource.includes('class="primary deploy-btn-main"'), 'Must have primary deploy-btn-main button')
  assert.ok(vueSource.includes('class="deploy-caret"'), 'Must have deploy-caret indicator')
  assert.ok(vueSource.includes('@click.stop="toggleDeployMenu"'), 'Must toggle dropdown on button click')

  // Dropdown menu items
  assert.ok(vueSource.includes('class="deploy-dropdown-menu"'), 'Must render deploy-dropdown-menu when open')
  assert.ok(vueSource.includes('@click="selectDeployOption(\'standard\')"'), 'Option 1 must select standard node deployment')
  assert.ok(vueSource.includes('@click="selectDeployOption(\'device\')"'), 'Option 2 must select device fleet deployment')
  assert.ok(vueSource.includes('标准代理节点'), 'Option 1 must have Chinese label 标准代理节点')
  assert.ok(vueSource.includes('设备专用编队'), 'Option 2 must have Chinese label 设备专用编队')
  assert.ok(vueSource.includes('class="menu-item-icon device"'), 'Device option must render seal icon 器')

  // Reactive state and lifecycle handling
  assert.ok(vueSource.includes('const deployMenuOpen = ref(false)'), 'Must declare deployMenuOpen ref')
  assert.ok(vueSource.includes('function toggleDeployMenu()'), 'Must implement toggleDeployMenu')
  assert.ok(vueSource.includes('function selectDeployOption('), 'Must implement selectDeployOption')
  assert.ok(vueSource.includes('function onDocumentClick('), 'Must implement outside click listener')
  assert.ok(vueSource.includes('function onDocumentKeydown('), 'Must implement Escape key listener')
  assert.ok(vueSource.includes("window.addEventListener('click', onDocumentClick)"), 'Must register click listener on mount')
  assert.ok(vueSource.includes("window.removeEventListener('click', onDocumentClick)"), 'Must cleanup click listener on unmount')
})

test('styles.css contains styling for deploy dropdown menu, caret, and items', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')

  // Wrap and main button
  assert.ok(cssSource.includes('.deploy-dropdown-wrap'), 'Must style .deploy-dropdown-wrap')
  assert.ok(cssSource.includes('.deploy-btn-main'), 'Must style .deploy-btn-main')
  assert.ok(cssSource.includes('.deploy-caret'), 'Must style .deploy-caret')
  assert.ok(cssSource.includes('.deploy-caret.open'), 'Must style open state for caret with rotation')

  // Menu and items
  assert.ok(cssSource.includes('.deploy-dropdown-menu'), 'Must style .deploy-dropdown-menu')
  assert.ok(cssSource.includes('.deploy-menu-item'), 'Must style .deploy-menu-item')
  assert.ok(cssSource.includes('.menu-item-icon.standard'), 'Must style standard icon')
  assert.ok(cssSource.includes('.menu-item-icon.device'), 'Must style device seal icon')
  assert.ok(cssSource.includes('.menu-item-tag.gold'), 'Must style gold protocol tag')
  assert.ok(cssSource.includes('.menu-item-tag.jade'), 'Must style jade fleet tag')

  // Transition and light theme
  assert.ok(cssSource.includes('.dropdown-enter-active'), 'Must define dropdown transition')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .deploy-dropdown-menu'), 'Must define light theme menu style')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .deploy-menu-item:hover'), 'Must define light theme hover style')
})
