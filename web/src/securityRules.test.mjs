import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('./securityRules.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source, {compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const {parseSecurityPorts,securityStateFresh} = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
test('explicit ports reject invalid values and preserve non-default SSH', () => {
 assert.deepEqual(parseSecurityPorts('46961, 9443,46961'),[9443,46961])
 assert.deepEqual(parseSecurityPorts(''),[])
 for (const invalid of ['0','65536','22;rm','1.5','NaN']) assert.throws(() => parseSecurityPorts(invalid))
})
test('offline historical samples and invalid clocks never count as current protection',()=>{
 const now = Date.parse('2026-10-03T00:00:00Z')
 assert.equal(securityStateFresh('2026-10-03T00:00:00Z',now),true)
 assert.equal(securityStateFresh('2026-10-02T23:58:00Z',now),false)
 assert.equal(securityStateFresh('2026-10-03T00:01:00Z',now),false)
 assert.equal(securityStateFresh('',now),false)
})
