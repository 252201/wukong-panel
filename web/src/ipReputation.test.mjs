import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('./api.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source, {
  compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 },
}).outputText
const { getIPReputation } = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)

test('getIPReputation rejects empty or whitespace IP', async () => {
  await assert.rejects(() => getIPReputation(''), /IP is required/)
  await assert.rejects(() => getIPReputation('   '), /IP is required/)
})

test('getIPReputation returns Net.Coffee result when fetch succeeds', async () => {
  const originalFetch = globalThis.fetch
  globalThis.fetch = async (url) => {
    if (String(url).includes('23.246.167.100')) {
      return {
        ok: true,
        json: async () => ({
          ip: '23.246.167.100',
          trust_score: 76,
          is_datacenter: true,
          isResidential: false,
        }),
      }
    }
    return { ok: false, status: 404 }
  }

  try {
    const res = await getIPReputation('23.246.167.100')
    assert.equal(res.ip, '23.246.167.100')
    assert.equal(res.trust_score, 76)
    assert.equal(res.is_datacenter, true)
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('getIPReputation falls back to backend proxy when Net.Coffee fetch fails', async () => {
  const originalFetch = globalThis.fetch
  const calls = []
  globalThis.fetch = async (url) => {
    calls.push(String(url))
    if (String(url).startsWith('https://ip.net.coffee/')) {
      throw new Error('network timeout')
    }
    // Backend proxy call
    if (String(url).includes('system/ip-reputation')) {
      return {
        ok: true,
        json: async () => ({
          ip: '2602:faa8:502:5a::a',
          trust_score: 78,
          is_datacenter: true,
        }),
      }
    }
    return { ok: false, status: 500 }
  }

  try {
    const res = await getIPReputation('2602:faa8:502:5a::a')
    assert.equal(res.ip, '2602:faa8:502:5a::a')
    assert.equal(res.trust_score, 78)
    assert.equal(calls.length, 2)
    assert(calls[0].includes('ip.net.coffee'))
    assert(calls[1].includes('system/ip-reputation'))
  } finally {
    globalThis.fetch = originalFetch
  }
})

test('getHostCandidateIPs discovers multiple interface IPv6 addresses and node probeExitIp', () => {
  // Test simulated helper matching App.vue logic
  const isIPv4 = (ip) => /^(?:[0-9]{1,3}\.){3}[0-9]{1,3}$/.test(ip.trim().replace(/^\[|\]$/g, ''))
  const isIPv6 = (ip) => {
    const clean = ip.trim().replace(/^\[|\]$/g, '')
    return clean.includes(':') && /^[0-9a-fA-F:]+$/.test(clean)
  }
  const isPublicIP = (ip) => {
    const clean = ip.trim().replace(/^\[|\]$/g, '')
    if (isIPv4(clean)) {
      const parts = clean.split('.').map(Number)
      if (parts[0] === 10 || parts[0] === 127 || parts[0] === 0) return false
      if (parts[0] === 172 && parts[1] >= 16 && parts[1] <= 31) return false
      if (parts[0] === 192 && parts[1] === 168) return false
      if (parts[0] === 100 && parts[1] >= 64 && parts[1] <= 127) return false
      if (parts[0] >= 224) return false
      return true
    }
    if (isIPv6(clean)) {
      const lower = clean.toLowerCase()
      if (lower === '::1' || lower.startsWith('fe80:') || lower.startsWith('fc00:') || lower.startsWith('fd00:')) return false
      return true
    }
    return false
  }

  const getHostCandidateIPs = (host) => {
    if (!host) return []
    const list = []
    const seen = new Set()
    const addIP = (raw, label, kind) => {
      if (!raw) return
      const clean = raw.trim().replace(/^\[|\]$/g, '')
      if (!clean || !isPublicIP(clean) || seen.has(clean)) return
      seen.add(clean)
      list.push({ ip: clean, label, kind, family: isIPv6(clean) ? 'v6' : 'v4' })
    }
    if (host.snapshot?.location?.publicIP) {
      const raw = host.snapshot.location.publicIP
      addIP(raw, isIPv6(raw) ? '出口公网 IPv6' : '出口公网 IPv4', 'public')
    }
    if (host.snapshot?.location?.ipv4) addIP(host.snapshot.location.ipv4, '出口公网 IPv4', 'public')
    if (host.snapshot?.location?.ipv6) addIP(host.snapshot.location.ipv6, '出口公网 IPv6', 'public')
    if (host.snapshot?.deploymentDefaults?.ipv4) {
      for (const item of host.snapshot.deploymentDefaults.ipv4) addIP(item.address, `本机 IPv4 (${item.interface})`, 'public')
    }
    if (host.snapshot?.deploymentDefaults?.ipv6) {
      for (const item of host.snapshot.deploymentDefaults.ipv6) addIP(item.address, `本机 IPv6 (${item.interface})`, 'public')
    }
    if (host.snapshot?.nodes) {
      for (const n of host.snapshot.nodes) {
        if (n.server) addIP(n.server, `节点: ${n.name}`, 'node')
        if (n.ipv4Bind) addIP(n.ipv4Bind, `绑定: ${n.name}`, 'node')
        if (n.ipv6Bind) addIP(n.ipv6Bind, `绑定: ${n.name}`, 'node')
        if (n.probeExitIp) addIP(n.probeExitIp, `节点出口: ${n.name}`, 'node')
      }
    }
    const v4List = list.filter(item => item.family === 'v4')
    const v6List = list.filter(item => item.family === 'v6')
    return [...v4List, ...v6List]
  }

  // Simulated host: ac (has 3 v6 on interface eth0)
  const acHost = {
    snapshot: {
      location: { publicIP: '2602:faa8:502:5a::a', ipv4: '23.246.167.100', ipv6: '2602:faa8:502:5a::a' },
      deploymentDefaults: {
        ipv4: [{ address: '23.246.167.100', interface: 'eth0' }],
        ipv6: [
          { address: '2600:1700:443:580f:a::3188', interface: 'eth0' },
          { address: '2600:1700:2bc1:409d:a::3188', interface: 'eth0' },
          { address: '2602:faa8:502:5a::a', interface: 'eth0' }
        ]
      },
      nodes: [
        { name: 'US-Node', ipv6Bind: '2600:1700:443:580f:a::3188' }
      ]
    }
  }

  const acCandidates = getHostCandidateIPs(acHost)
  assert.equal(acCandidates[0].ip, '23.246.167.100', 'IPv4 must be sorted first')
  assert.equal(acCandidates[0].family, 'v4', 'first candidate must be IPv4')
  const acV6s = acCandidates.filter(c => c.family === 'v6')
  assert.equal(acV6s.length, 3, 'all 3 IPv6 addresses on ac must be discovered')
  assert(acV6s.some(c => c.ip === '2600:1700:443:580f:a::3188'))
  assert(acV6s.some(c => c.ip === '2600:1700:2bc1:409d:a::3188'))
  assert(acV6s.some(c => c.ip === '2602:faa8:502:5a::a'))

  // Simulated host: 青蛙 (NAT IPv4 with probeExitIp)
  const frogHost = {
    snapshot: {
      location: { publicIP: '2a01:4f9:6b:47e9::1967', ipv6: '2a01:4f9:6b:47e9::1967' },
      deploymentDefaults: {
        ipv4: [{ address: '192.168.19.67', interface: 'eth0' }],
        ipv6: [{ address: '2a01:4f9:6b:47e9::1967', interface: 'eth0' }]
      },
      nodes: [
        { name: 'FL-CF-纯V4', ipv4Bind: '192.168.19.67', probeExitIp: '65.108.71.229' }
      ]
    }
  }

  const frogCandidates = getHostCandidateIPs(frogHost)
  const frogV4 = frogCandidates.find(c => c.family === 'v4')
  assert(frogV4, 'public IPv4 probeExitIp must be discovered')
  assert.equal(frogV4.ip, '65.108.71.229')
})

test('reputationBadgeText formats dual stack as v4:76分 / v6:78分', () => {
  const formatBadge = (v4, v6, state4, state6) => {
    if (!v4 && !v6) return 'IP检测'
    const score4 = state4?.report?.trust_score
    const score6 = state6?.report?.trust_score

    if (score4 !== undefined && score6 !== undefined) {
      return `v4:${score4}分 / v6:${score6}分`
    }
    if (score4 !== undefined) {
      if (v6 && state6?.loading && !state6?.report) {
        return `v4:${score4}分 / v6:...`
      }
      return `v4:${score4}分`
    }
    if (score6 !== undefined) {
      if (v4 && state4?.loading && !state4?.report) {
        return `v4:... / v6:${score6}分`
      }
      return `v6:${score6}分`
    }
    if ((state4?.loading && !state4?.report) || (state6?.loading && !state6?.report)) return '...'
    if (state4?.error || state6?.error) return '--分'
    return 'IP分'
  }

  assert.equal(
    formatBadge('23.246.167.100', '2602:faa8:502:5a::a', { report: { trust_score: 76 } }, { report: { trust_score: 78 } }),
    'v4:76分 / v6:78分'
  )
  assert.equal(
    formatBadge('23.246.167.100', '', { report: { trust_score: 76 } }, null),
    'v4:76分'
  )
  assert.equal(
    formatBadge('', '2602:faa8:502:5a::a', null, { report: { trust_score: 78 } }),
    'v6:78分'
  )
  assert.equal(
    formatBadge('23.246.167.100', '2602:faa8:502:5a::a', { report: { trust_score: 76 } }, { loading: true }),
    'v4:76分 / v6:...'
  )
  assert.equal(
    formatBadge('23.246.167.100', '2602:faa8:502:5a::a', { loading: true }, { loading: true }),
    '...'
  )
})
