import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'

test('App.vue implements wide multi-column layout, seven protocols matrix, and mode tabs', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  // Modal header with seal and deploy mode switcher tabs
  assert.ok(vueSource.includes('class="node-form-top"'), 'Must have node-form-top header')
  assert.ok(vueSource.includes('class="node-form-title-area"'), 'Must have title area container')
  assert.ok(vueSource.includes("class=\"modal-seal\" :class=\"{ jade: deviceMode, gold: !deviceMode && !isEditing, amber: isEditing }\""), 'Must render seal badge for deploy modes')
  assert.ok(vueSource.includes('class="deploy-mode-tabs"'), 'Must include deploy-mode-tabs segmented control')
  assert.ok(vueSource.includes("switchDeployKind('create')"), 'Must switch to standard node create')
  assert.ok(vueSource.includes("switchDeployKind('device-create')"), 'Must switch to device fleet create')

  // Protocol matrix deck
  assert.ok(vueSource.includes('class="protocol-selection-area"'), 'Must have protocol-selection-area')
  assert.ok(vueSource.includes('class="protocol-matrix"'), 'Must render protocol-matrix grid')
  assert.ok(vueSource.includes('class="protocol-matrix-card"'), 'Must render protocol-matrix-card items')
  assert.ok(vueSource.includes('class="protocol-note-strip"'), 'Must render protocol-note-strip info pill')
  assert.ok(vueSource.includes('const protocolList = ['), 'Must declare protocolList data with 7 protocols')

  // Dual column structured form layout
  assert.ok(vueSource.includes('class="node-form-dual-grid"'), 'Must have node-form-dual-grid container')
  assert.ok(vueSource.includes('class="form-section-card inbound-section"'), 'Must render inbound section card')
  assert.ok(vueSource.includes('class="form-section-card egress-section"'), 'Must render egress section card')
  assert.ok(vueSource.includes('class="advanced-network-box"'), 'Must render advanced-network-box subcard')

  // Port random generator and conflict pre-flight
  assert.ok(vueSource.includes('class="mini-dice-btn"'), 'Must provide mini-dice-btn for quick random port')
  assert.ok(vueSource.includes('@click="pickRandomAvailablePort"'), 'Must bind click to pickRandomAvailablePort')
  assert.ok(vueSource.includes('class="port-conflict-hint"'), 'Must render port-conflict-hint when port is occupied')
  assert.ok(vueSource.includes('const conflictingNodeName = computed('), 'Must compute conflictingNodeName')

  // Device fleet tools and responsive grid
  assert.ok(vueSource.includes('class="fleet-deploy-grid"'), 'Must render fleet-deploy-grid in deviceMode')
  assert.ok(vueSource.includes('fleet-devices-card'), 'Must render fleet-devices-card')
  assert.ok(vueSource.includes('class="device-fleet-grid"'), 'Must render multi-column device-fleet-grid')
  assert.ok(vueSource.includes('class="tunnel-guide tunnel-fleet-banner"'), 'Must render tunnel-fleet-banner guide inside fleet-devices-card')
  assert.ok(vueSource.includes('@click="batchRenameDevices()"'), 'Must support batchRenameDevices')
  assert.ok(vueSource.includes('@click="autoAssignSequentialPorts()"'), 'Must support autoAssignSequentialPorts')
  assert.ok(vueSource.includes('const hasDevicePortDuplicate = computed('), 'Must compute hasDevicePortDuplicate')

  // Footer status bar
  assert.ok(vueSource.includes('class="node-form-foot"'), 'Must have node-form-foot footer')
  assert.ok(vueSource.includes('class="node-form-status-bar"'), 'Must have status chips bar in footer')
})

test('styles.css contains wide 1200px modal layout and responsive styles', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')

  // 1200px wide modal
  assert.ok(cssSource.includes('.modal-card.node-form'), 'Must style .modal-card.node-form')
  assert.ok(cssSource.includes('width: min(1200px, calc(100vw - 48px));'), 'Must widen modal to 1200px (approx 2/3 wider than 720px)')
  assert.ok(cssSource.includes('max-width: 1200px;'), 'Must set max-width to 1200px')

  // Header and switcher tabs
  assert.ok(cssSource.includes('.node-form-top'), 'Must style .node-form-top')
  assert.ok(cssSource.includes('.modal-card.node-form .modal-close'), 'Must style .modal-card.node-form .modal-close as header item without overlap')
  assert.ok(cssSource.includes('.deploy-mode-tabs'), 'Must style .deploy-mode-tabs')
  assert.ok(cssSource.includes('.deploy-mode-tab.active'), 'Must style active mode tab')

  // Protocol matrix
  assert.ok(cssSource.includes('.protocol-matrix'), 'Must style .protocol-matrix grid')
  assert.ok(cssSource.includes('grid-template-columns: repeat(7, minmax(0, 1fr));'), 'Must use 7-column grid on desktop')
  assert.ok(cssSource.includes('.protocol-matrix-card.active'), 'Must style active protocol card with glow')
  assert.ok(cssSource.includes('.protocol-note-strip'), 'Must style protocol-note-strip')

  // Dual grid and cards
  assert.ok(cssSource.includes('.node-form-dual-grid'), 'Must style dual grid')
  assert.ok(cssSource.includes('.form-section-card'), 'Must style section card')
  assert.ok(cssSource.includes('.mini-dice-btn'), 'Must style dice button')
  assert.ok(cssSource.includes('.port-conflict-hint'), 'Must style port conflict warning')

  // Device fleet grid and tools
  assert.ok(cssSource.includes('.device-fleet-grid'), 'Must style device fleet grid')
  assert.ok(cssSource.includes('.tunnel-fleet-banner'), 'Must style .tunnel-fleet-banner')
  assert.ok(cssSource.includes('.field-grid-4 > .span-2'), 'Must style .field-grid-4 > .span-2')
  assert.ok(cssSource.includes('.mini-tool-btn'), 'Must style batch mini tools')
  assert.ok(cssSource.includes('.node-form-foot'), 'Must style footer bar')

  // Light theme overrides
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .modal-card.node-form'), 'Must style light theme modal')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .protocol-matrix-card.active'), 'Must style light theme active protocol card')

  // Responsiveness
  assert.ok(cssSource.includes('@media (max-width: 980px)'), 'Must include 980px tablet breakpoint')
  assert.ok(cssSource.includes('@media (max-width: 650px)'), 'Must include 650px mobile breakpoint')
})
