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
