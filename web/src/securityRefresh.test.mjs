import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'

const source = readFileSync(new URL('./securityRefresh.ts',import.meta.url),'utf8')
const js = ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const {afterFirewallRead} = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
const deferred = () => {let resolve,reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}}

test('firewall has priority and SSH starts immediately on completion',async()=>{
 const firewall=deferred(),ssh=deferred();let calls=0
 const task=afterFirewallRead(firewall.promise,()=>{calls++;return ssh.promise},()=>true)
 await Promise.resolve();assert.equal(calls,0)
 firewall.resolve('firewall sample')
 await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1)
 ssh.resolve('SSH sample');assert.equal(await task,'SSH sample')
})

test('a firewall failure does not suppress the SSH sample or its own error',async()=>{
 const firewall=deferred()
 const task=afterFirewallRead(firewall.promise,async()=>'SSH sample',()=>true)
 firewall.reject(new Error('firewall unavailable'))
 assert.equal(await task,'SSH sample')
 await assert.rejects(firewall.promise,/firewall unavailable/)
})

test('a stuck firewall cannot starve SSH, which still reports independent failures',async()=>{
 const firewall=deferred();let calls=0
 await assert.rejects(afterFirewallRead(firewall.promise,async()=>{calls++;throw new Error('SSH unavailable')},()=>true,10),/SSH unavailable/)
 assert.equal(calls,1)
 // Late firewall completion must not dispatch a second SSH read.
 firewall.resolve('late');await new Promise(resolve=>setImmediate(resolve));assert.equal(calls,1)
})

test('leaving the page, changing zone or invalidating a mutation skips a queued SSH read',async()=>{
 const firewall=deferred();let current=true,calls=0
 const task=afterFirewallRead(firewall.promise,async()=>{calls++;return 'obsolete'},()=>current)
 current=false;firewall.resolve('obsolete')
 assert.equal(await task,undefined);assert.equal(calls,0)
})
