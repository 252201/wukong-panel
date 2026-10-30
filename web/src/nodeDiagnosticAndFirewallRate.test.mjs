import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

function transpileModule(path) {
  const source = readFileSync(new URL(path, import.meta.url), 'utf8')
  const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
  return import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
}

const { formatRelativeTime, formatFullDateTime } = await transpileModule('./timeFormat.ts')
const { securityRuleMatchesProtocol } = await transpileModule('./securityRules.ts')

test('formatRelativeTime formats durations correctly in Chinese and English', () => {
  const now = 1700000000000

  // Empty or invalid input
  assert.equal(formatRelativeTime(undefined, now, 'zh-CN'), '')
  assert.equal(formatRelativeTime('', now, 'zh-CN'), '')
  assert.equal(formatRelativeTime('invalid-date', now, 'zh-CN'), '')

  // < 45 seconds -> 刚刚 / just now
  const justNow = new Date(now - 15 * 1000).toISOString()
  assert.equal(formatRelativeTime(justNow, now, 'zh-CN'), '刚刚')
  assert.equal(formatRelativeTime(justNow, now, 'en-US'), 'just now')

  // 12 minutes -> 12分钟前 / 12m ago
  const twelveMinAgo = new Date(now - 12 * 60 * 1000).toISOString()
  assert.equal(formatRelativeTime(twelveMinAgo, now, 'zh-CN'), '12分钟前')
  assert.equal(formatRelativeTime(twelveMinAgo, now, 'en-US'), '12m ago')

  // 3 hours -> 3小时前 / 3h ago
  const threeHoursAgo = new Date(now - 3 * 3600 * 1000).toISOString()
  assert.equal(formatRelativeTime(threeHoursAgo, now, 'zh-CN'), '3小时前')
  assert.equal(formatRelativeTime(threeHoursAgo, now, 'en-US'), '3h ago')

  // 1 day -> 昨天 ... / yesterday ...
  const yesterday = new Date(now - 25 * 3600 * 1000).toISOString()
  assert.ok(formatRelativeTime(yesterday, now, 'zh-CN').startsWith('昨天'))
  assert.ok(formatRelativeTime(yesterday, now, 'en-US').startsWith('yesterday'))

  // 4 days -> 4天前 / 4d ago
  const fourDaysAgo = new Date(now - 4 * 86400 * 1000).toISOString()
  assert.equal(formatRelativeTime(fourDaysAgo, now, 'zh-CN'), '4天前')
  assert.equal(formatRelativeTime(fourDaysAgo, now, 'en-US'), '4d ago')
})

test('formatFullDateTime formats full readable timestamp or returns empty string', () => {
  assert.equal(formatFullDateTime(''), '')
  assert.equal(formatFullDateTime(undefined), '')
  const ts = '2026-10-30T10:20:30Z'
  const formattedZh = formatFullDateTime(ts, 'zh-CN')
  assert.ok(formattedZh.length > 10, 'Full date time must be non-empty')
})

test('Firewall status resolver handles tunnel exemption, allowed, and pending states', () => {
  // Test helper simulating nodeFirewallStatus logic in App.vue
  function resolveStatus(node, fw, lang = 'zh-CN') {
    const isEn = lang === 'en-US'
    if (node.protocol === 'vless-ws-tunnel') {
      return { status: 'tunnel', label: isEn ? 'Tunnel Loopback' : '免开公网端口', class: 'tunnel' }
    }
    if (!fw || !fw.active) {
      return { status: 'disabled', label: isEn ? 'Firewall Off' : '防火墙未启用', class: 'idle' }
    }
    const transport = (node.transport || 'tcp').toLowerCase()
    const port = node.listenPort
    const isAllowed = fw.rules && fw.rules.some(rule =>
      rule.action === 'allow' &&
      securityRuleMatchesProtocol(rule, transport) &&
      rule.portFrom <= port &&
      rule.portTo >= port
    )
    if (isAllowed) {
      return { status: 'allowed', label: isEn ? 'Port Allowed' : '端口已放行', class: 'allowed' }
    }
    return { status: 'blocked', label: isEn ? 'Port Not Allowed' : '端口待放行', class: 'warning' }
  }

  // 1. Cloudflare Tunnel node -> 免开公网端口
  const tunnelNode = { protocol: 'vless-ws-tunnel', listenPort: 34509 }
  assert.equal(resolveStatus(tunnelNode, { active: true, rules: [] }).label, '免开公网端口')

  // 2. Firewall disabled -> 防火墙未启用
  const regularNode = { protocol: 'hysteria2', listenPort: 52246, transport: 'udp' }
  assert.equal(resolveStatus(regularNode, { active: false, rules: [] }).label, '防火墙未启用')

  // 3. Firewall active, port allowed -> 端口已放行
  const allowedFw = {
    active: true,
    rules: [
      { action: 'allow', protocol: 'udp', portFrom: 52000, portTo: 53000 }
    ]
  }
  assert.equal(resolveStatus(regularNode, allowedFw).label, '端口已放行')

  // 4. Firewall active, port NOT allowed -> 端口待放行
  const blockedFw = {
    active: true,
    rules: [
      { action: 'allow', protocol: 'tcp', portFrom: 80, portTo: 80 }
    ]
  }
  assert.equal(resolveStatus(regularNode, blockedFw).label, '端口待放行')
})

test('App.vue contains rate badge, firewall indicator, relative probe strip and diagnostic modal', () => {
  const vueSource = readFileSync(new URL('./App.vue', import.meta.url), 'utf8')

  // Node card top left rate badge
  assert.ok(vueSource.includes('class="node-top-left"'), 'Must have node-top-left wrapper')
  assert.ok(vueSource.includes('class="node-rate-badge"'), 'Must have node-rate-badge')
  assert.ok(vueSource.includes('class="rate-dot"'), 'Must have rate-dot inside badge')

  // Endpoint row and firewall status badge
  assert.ok(vueSource.includes('class="endpoint-row"'), 'Must have endpoint-row wrapper')
  assert.ok(vueSource.includes('class="node-fw-badge"'), 'Must have node-fw-badge')
  assert.ok(vueSource.includes('class="fw-dot"'), 'Must have fw-dot inside firewall badge')

  // Probe strip relative time and click-to-diagnose
  assert.ok(vueSource.includes('class="probe-strip clickable"'), 'Must have clickable probe-strip')
  assert.ok(vueSource.includes('class="probe-diag-hint"'), 'Must have probe-diag-hint label')
  assert.ok(vueSource.includes('@click="openDiagnostic(node)"'), 'Must open diagnostic modal on click')

  // Diagnostic modal
  assert.ok(vueSource.includes("modal === 'diagnostic' && diagnosticNode"), 'Must have diagnostic modal condition')
  assert.ok(vueSource.includes('class="diagnostic-pipeline"'), 'Must have 4-step diagnostic pipeline')
  assert.ok(vueSource.includes('Edge TLS / WebSocket') || vueSource.includes('传输握手 & 安全层'), 'Pipeline step 1 must verify edge/transport')
  assert.ok(vueSource.includes('入站凭据鉴权'), 'Pipeline step 2 must verify authentication')
  assert.ok(vueSource.includes('核心路由出站'), 'Pipeline step 3 must verify routing')
  assert.ok(vueSource.includes('探测目标响应'), 'Pipeline step 4 must verify target response')

  // Diagnostic telemetry metrics
  assert.ok(vueSource.includes('class="diagnostic-metrics-grid"'), 'Must have telemetry metrics grid')
  assert.ok(vueSource.includes('往返闭环延迟'), 'Must display loopback latency metric')
  assert.ok(vueSource.includes('探测目标端点'), 'Must display target endpoint metric')
  assert.ok(vueSource.includes('落地公网出口 IP'), 'Must display egress public IP')
  assert.ok(vueSource.includes('openReputationModal(currentFleetHost || undefined, diagnosticNode.probeExitIp)'), 'Must support 1-click IP reputation query')
  assert.ok(vueSource.includes('主机防火墙状态'), 'Must display firewall allow status')
  assert.ok(vueSource.includes('实时窗口下行速率'), 'Must display live traffic rate')
  assert.ok(vueSource.includes('节点累计传输流量'), 'Must display cumulative traffic metric in diagnostic modal')
  assert.ok(vueSource.includes('最后校验时间'), 'Must display last checked time with relative format')

  // Diagnostic error reporting & troubleshooting tips
  assert.ok(vueSource.includes('class="diagnostic-error-box"'), 'Must render error diagnosis box when probe failed')
  assert.ok(vueSource.includes('class="diagnostic-tips"'), 'Must render actionable troubleshooting tips')
  assert.ok(vueSource.includes('⚡ 立即重新检测'), 'Must provide direct re-probe button in diagnostic modal')
})

test('styles.css contains complete styles for rate badge, firewall badge, and diagnostic modal', () => {
  const cssSource = readFileSync(new URL('./styles.css', import.meta.url), 'utf8')

  // Rate badge styles
  assert.ok(cssSource.includes('.node-top-left'), 'Must style .node-top-left')
  assert.ok(cssSource.includes('.node-rate-badge'), 'Must style .node-rate-badge')
  assert.ok(cssSource.includes('.node-rate-badge.active'), 'Must style active rate badge')
  assert.ok(cssSource.includes('@keyframes rate-pulse'), 'Must define rate-pulse animation')

  // Firewall badge styles
  assert.ok(cssSource.includes('.endpoint-row'), 'Must style .endpoint-row')
  assert.ok(cssSource.includes('.node-fw-badge'), 'Must style .node-fw-badge')
  assert.ok(cssSource.includes('.node-fw-badge.tunnel'), 'Must style tunnel loopback state')
  assert.ok(cssSource.includes('.node-fw-badge.allowed'), 'Must style allowed port state')
  assert.ok(cssSource.includes('.node-fw-badge.warning'), 'Must style pending/blocked port state')

  // Probe strip clickable & diag hint styles
  assert.ok(cssSource.includes('.probe-strip.clickable'), 'Must style .probe-strip.clickable')
  assert.ok(cssSource.includes('.probe-diag-hint'), 'Must style .probe-diag-hint')

  // Diagnostic modal styles
  assert.ok(cssSource.includes('.diagnostic-modal'), 'Must style .diagnostic-modal')
  assert.ok(cssSource.includes('.diagnostic-pipeline'), 'Must style .diagnostic-pipeline')
  assert.ok(cssSource.includes('.pipeline-step'), 'Must style .pipeline-step')
  assert.ok(cssSource.includes('.diagnostic-metrics-grid'), 'Must style .diagnostic-metrics-grid')
  assert.ok(cssSource.includes('.diag-metric-card'), 'Must style .diag-metric-card')
  assert.ok(cssSource.includes('.diagnostic-error-box'), 'Must style .diagnostic-error-box')
  assert.ok(cssSource.includes(':root[data-effective-theme="light"] .diagnostic-error-box code'), 'Must have light theme code override')
})
