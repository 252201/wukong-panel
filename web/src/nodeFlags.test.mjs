import test from 'node:test'
import assert from 'node:assert/strict'
import { matchCountryFlag, formatNodeNameWithFlag, FLAG_EMOJI_REGEX, normalizeProtocolClass, formatExternalProtocolBadge } from './nodeFlags.ts'

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

test('formatNodeNameWithFlag prepends flag correctly', () => {
  assert.equal(formatNodeNameWithFlag('Hong Kong | 01'), '🇭🇰 Hong Kong | 01')
  assert.equal(formatNodeNameWithFlag('Taiwan | 02'), '🇹🇼 Taiwan | 02')
  assert.equal(formatNodeNameWithFlag('Singapore | 03'), '🇸🇬 Singapore | 03')
  assert.equal(formatNodeNameWithFlag('Japan | 04'), '🇯🇵 Japan | 04')
  assert.equal(formatNodeNameWithFlag('🇭🇰 Hong Kong | 01'), '🇭🇰 Hong Kong | 01')
  assert.equal(formatNodeNameWithFlag('Custom Node Without Country'), 'Custom Node Without Country')
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

