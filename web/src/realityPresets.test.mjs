import test from 'node:test'
import assert from 'node:assert/strict'
import { realityPresets, flattenRealityPresets, findRealityPreset } from './realityPresets.ts'

test('realityPresets contains all required categories and domains from requirements', () => {
  const categories = realityPresets.map(c => c.category)
  assert.ok(categories.includes('Apple 系'))
  assert.ok(categories.includes('Microsoft 系'))
  assert.ok(categories.includes('AWS / 亚马逊'))
  assert.ok(!categories.includes('Cloudflare'))

  const flattened = flattenRealityPresets(realityPresets)
  assert.equal(flattened.length, 7)

  const expectedDomains = [
    'swdist.apple.com',
    'itunes.apple.com',
    'mensura.cdn-apple.com',
    'learn.microsoft.com',
    's0.awsstatic.com',
    'd1.awsstatic.com',
    'aws.amazon.com',
  ]

  for (const domain of expectedDomains) {
    const item = flattened.find(p => p.domain === domain)
    assert.ok(item, `Domain ${domain} should be present in presets`)
    assert.ok(item.title && item.title.trim().length > 0, `Title for ${domain} should not be empty`)
    assert.ok(item.desc && item.desc.trim().length > 0, `Desc for ${domain} should not be empty`)
    assert.ok(item.category && item.category.trim().length > 0, `Category for ${domain} should not be empty`)
  }
})

test('findRealityPreset normalizes domain casing and whitespace', () => {
  const matchedUpper = findRealityPreset('  SWDIST.APPLE.COM  ')
  assert.ok(matchedUpper)
  assert.equal(matchedUpper.domain, 'swdist.apple.com')
  assert.equal(matchedUpper.category, 'Apple 系')
  assert.equal(matchedUpper.title, '苹果软件分发')

  const matchedAws = findRealityPreset('AWS.amazon.com')
  assert.ok(matchedAws)
  assert.equal(matchedAws.domain, 'aws.amazon.com')
  assert.equal(matchedAws.category, 'AWS / 亚马逊')

  assert.equal(findRealityPreset(''), undefined)
  assert.equal(findRealityPreset('www.cloudflare.com'), undefined)
  assert.equal(findRealityPreset('unknown-custom-domain.com'), undefined)
})
