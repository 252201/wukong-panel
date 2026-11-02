import test from 'node:test'
import assert from 'node:assert/strict'
import {
  matchCountryFlag,
  formatNodeNameWithFlag,
  FLAG_EMOJI_REGEX,
  normalizeProtocolClass,
  formatExternalProtocolBadge,
  detectNodeRegion,
  extractSubscriptionRegions,
  sanitizeNodeName,
} from './nodeFlags.ts'

test('FLAG_EMOJI_REGEX correctly detects emoji flags', () => {
  assert.equal(FLAG_EMOJI_REGEX.test('🇭🇰 Hong Kong'), true)
  assert.equal(FLAG_EMOJI_REGEX.test('🇹🇼 Taiwan'), true)
  assert.equal(FLAG_EMOJI_REGEX.test('Hong Kong | 01'), false)
  assert.equal(FLAG_EMOJI_REGEX.test('Traffic: 11.72 GB'), false)
})

test('matchCountryFlag matches common regions without flags', () => {
  assert.equal(matchCountryFlag('Hong Kong | 01'), '🇭🇰')
  assert.equal(matchCountryFlag('HK-01-Trojan'), '🇭🇰')
  assert.equal(matchCountryFlag('Taiwan | 02'), '🇹🇼')
  assert.equal(matchCountryFlag('台北 01'), '🇹🇼')
  assert.equal(matchCountryFlag('Japan | 03'), '🇯🇵')
  assert.equal(matchCountryFlag('Tokyo-01'), '🇯🇵')
  assert.equal(matchCountryFlag('Singapore | 04'), '🇸🇬')
  assert.equal(matchCountryFlag('狮城-高速'), '🇸🇬')
  assert.equal(matchCountryFlag('United States | 05'), '🇺🇸')
  assert.equal(matchCountryFlag('Los Angeles-01'), '🇺🇸')
  assert.equal(matchCountryFlag('Korea | 06'), '🇰🇷')
  assert.equal(matchCountryFlag('首尔-01'), '🇰🇷')
  assert.equal(matchCountryFlag('Germany | 07'), '🇩🇪')
  assert.equal(matchCountryFlag('Frankfurt-01'), '🇩🇪')
  assert.equal(matchCountryFlag('United Kingdom | 08'), '🇬🇧')
  assert.equal(matchCountryFlag('London-01'), '🇬🇧')
})

test('matchCountryFlag does not duplicate existing emoji flags', () => {
  assert.equal(matchCountryFlag('🇭🇰 Hong Kong | 01'), '')
  assert.equal(matchCountryFlag('🇹🇼 台湾 02'), '')
  assert.equal(matchCountryFlag('🇯🇵 日本 03'), '')
  assert.equal(matchCountryFlag('🇺🇸 美国 04'), '')
})

test('sanitizeNodeName removes ads, URLs, rate indicators, and promotional junk', () => {
  assert.equal(
    sanitizeNodeName('⚡️香港专线 01 | 剩余流量：999G | 官网：https://airport.com'),
    '⚡️香港专线 01'
  )
  assert.equal(
    sanitizeNodeName('[1.5x] 台湾 02 - 请勿测速 - 防失联：t.me/channel'),
    '台湾 02'
  )
  assert.equal(
    sanitizeNodeName('日本 03 | 最新网址：www.abc-def.xyz | [2.0倍率]'),
    '日本 03'
  )
  assert.equal(
    sanitizeNodeName('🇸🇬 新加坡 04 - 4K 优质解锁'),
    '🇸🇬 新加坡 04 - 4K 优质解锁'
  )
})

test('formatNodeNameWithFlag sanitizes noise and prepends flag correctly', () => {
  assert.equal(
    formatNodeNameWithFlag('Hong Kong | 01 | 官网：abc.com'),
    '🇭🇰 Hong Kong | 01'
  )
  assert.equal(
    formatNodeNameWithFlag('Taiwan | 02 | 剩余流量999G'),
    '🇹🇼 Taiwan | 02'
  )
  assert.equal(
    formatNodeNameWithFlag('🇭🇰 Hong Kong | 01'),
    '🇭🇰 Hong Kong | 01'
  )
  assert.equal(
    formatNodeNameWithFlag('Custom Node Without Country'),
    'Custom Node Without Country'
  )
})

test('detectNodeRegion correctly resolves region codes, names, and flags', () => {
  const hk1 = detectNodeRegion('Hong Kong | 01')
  assert.equal(hk1.code, 'HK')
  assert.equal(hk1.name, '香港')
  assert.equal(hk1.flag, '🇭🇰')

  const hk2 = detectNodeRegion('🇭🇰 香港专线 02')
  assert.equal(hk2.code, 'HK')

  const tw = detectNodeRegion('台北 01 - BGP')
  assert.equal(tw.code, 'TW')
  assert.equal(tw.name, '台湾')

  const jp = detectNodeRegion('Tokyo 05')
  assert.equal(jp.code, 'JP')

  const us = detectNodeRegion('🇺🇸 Silicon Valley')
  assert.equal(us.code, 'US')

  const other = detectNodeRegion('Unknown-Tunnel-01')
  assert.equal(other.code, 'OTHER')
  assert.equal(other.name, '其他')
})

test('extractSubscriptionRegions aggregates regions and node IDs accurately', () => {
  const nodes = [
    { id: 'n1', name: 'Hong Kong 01' },
    { id: 'n2', name: '🇭🇰 Hong Kong 02' },
    { id: 'n3', name: 'Tokyo 01' },
    { id: 'n4', name: 'Taiwan 01' },
    { id: 'n5', name: 'Los Angeles 01' },
    { id: 'n6', name: 'Custom Gateway' },
  ]

  const regions = extractSubscriptionRegions(nodes)
  // Expected order: HK, TW, JP, US, OTHER
  assert.equal(regions.length, 5)
  assert.equal(regions[0].code, 'HK')
  assert.equal(regions[0].totalCount, 2)
  assert.deepEqual(regions[0].nodeIds, ['n1', 'n2'])

  assert.equal(regions[1].code, 'TW')
  assert.equal(regions[1].totalCount, 1)

  assert.equal(regions[2].code, 'JP')
  assert.equal(regions[2].totalCount, 1)

  assert.equal(regions[3].code, 'US')
  assert.equal(regions[3].totalCount, 1)

  assert.equal(regions[4].code, 'OTHER')
  assert.equal(regions[4].totalCount, 1)
  assert.deepEqual(regions[4].nodeIds, ['n6'])
})

test('normalizeProtocolClass maps all protocols to deployment badge classes', () => {
  assert.equal(normalizeProtocolClass('trojan'), 'trojan')
  assert.equal(normalizeProtocolClass('TROJAN'), 'trojan')
  assert.equal(normalizeProtocolClass('hysteria2'), 'hysteria2')
  assert.equal(normalizeProtocolClass('hy2'), 'hysteria2')
  assert.equal(normalizeProtocolClass('vless'), 'vless')
  assert.equal(normalizeProtocolClass('vless-ws-tunnel'), 'vless-ws-tunnel')
  assert.equal(normalizeProtocolClass('shadowsocks'), 'shadowsocks')
  assert.equal(normalizeProtocolClass('ss'), 'shadowsocks')
  assert.equal(normalizeProtocolClass('ss2022'), 'shadowsocks')
  assert.equal(normalizeProtocolClass('tuic'), 'tuic')
  assert.equal(normalizeProtocolClass('anytls'), 'anytls')
  assert.equal(normalizeProtocolClass('vmess'), 'vmess')
  assert.equal(normalizeProtocolClass(''), '')
})

test('formatExternalProtocolBadge formats concise uppercase badges', () => {
  assert.equal(formatExternalProtocolBadge('trojan'), 'TROJAN')
  assert.equal(formatExternalProtocolBadge('vless'), 'VLESS')
  assert.equal(formatExternalProtocolBadge('hysteria2'), 'HY2')
  assert.equal(formatExternalProtocolBadge('hy2'), 'HY2')
  assert.equal(formatExternalProtocolBadge('shadowsocks'), 'SS')
  assert.equal(formatExternalProtocolBadge('ss'), 'SS')
  assert.equal(formatExternalProtocolBadge('ss2022'), 'SS2022')
  assert.equal(formatExternalProtocolBadge('tuic'), 'TUIC')
  assert.equal(formatExternalProtocolBadge('anytls'), 'ANYTLS')
  assert.equal(formatExternalProtocolBadge('vmess'), 'VMESS')
  assert.equal(formatExternalProtocolBadge('vless-ws-tunnel'), 'VLESS · CF')
})
