import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('./securityRules.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source, {compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const {parseSecurityPorts,securityStateFresh,securityRuleServices} = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
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

test('rule purposes match the host protocol and range, preserving node names and source restrictions', () => {
 const ports = [
  {port:46961,protocol:'tcp',reason:'SSH'},
  {port:9443,protocol:'tcp',reason:'面板入口'},
  {port:49707,protocol:'udp',reason:'节点 US-纯V6-旧金山'},
  {port:49708,protocol:'udp',reason:'节点 Second'},
 ]
 const rule = {adoptable:true,protocol:'udp',portFrom:49707,portTo:49708,source:'2001:db8::/64',action:'deny'}
 assert.deepEqual(securityRuleServices(rule,ports,'zh-CN'),['节点 US-纯V6-旧金山','节点 Second'])
 assert.deepEqual(securityRuleServices({...rule,protocol:'tcp'},ports,'zh-CN'),[])
 assert.deepEqual(securityRuleServices({...rule,adoptable:false},ports,'zh-CN'),[])
 assert.deepEqual(securityRuleServices(rule,[],'zh-CN'),[])
 assert.deepEqual(securityRuleServices({...rule,protocol:'tcp',portFrom:9443,portTo:9443},ports,'en-US'),['Panel entrance'])
 assert.deepEqual(securityRuleServices({...rule,portTo:49707},ports,'en-US'),['Node US-纯V6-旧金山'])
})
