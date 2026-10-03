import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('./securityStatus.ts',import.meta.url),'utf8')
const js = ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const {createSecurityStatusCache} = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
const deferred = () => {let resolve, reject;const promise=new Promise((a,b)=>{resolve=a;reject=b});return {promise,resolve,reject}}
const sample = revision => ({revision,checkedAt:'2026-10-03T00:00:00Z',rules:[{id:revision}],zone:'public'})

test('fast firewall publishes before delayed Fail2ban and independent failure',async()=>{
 const cache=createSecurityStatusCache();const slow=deferred();let shown=null,fbError=''
 const firewall=cache.refresh('ac','firewall','',async()=>sample('fw')).then(value=>{shown=value})
 const fail2ban=cache.refresh('ac','fail2ban','',()=>slow.promise).catch(error=>{fbError=error.message})
 await firewall
 assert.equal(shown.revision,'fw')
 assert.equal(cache.read('ac','fail2ban'),null)
 slow.reject(new Error('SSH log unavailable'));await fail2ban
 assert.equal(fbError,'SSH log unavailable')
 assert.equal(cache.read('ac','firewall').revision,'fw')
})

test('returning to a host restores only its sample without changing its timestamp and still revalidates',async()=>{
 const cache=createSecurityStatusCache()
 await cache.refresh('ac','firewall','public',async()=>sample('ac'))
 await cache.refresh('qw','firewall','public',async()=>sample('qw'))
 assert.equal(cache.read('ac','firewall').revision,'ac')
 assert.equal(cache.read('qw','firewall').revision,'qw')
 assert.equal(cache.read('unknown','firewall'),null)
 assert.equal(cache.read('ac','firewall','private'),null)
 const previous=cache.read('ac','firewall');previous.rules[0].id='edited'
 assert.equal(cache.read('ac','firewall').rules[0].id,'ac')
 const next=deferred();const pending=cache.refresh('ac','firewall','public',()=>next.promise)
 assert.equal(cache.read('ac','firewall').checkedAt,'2026-10-03T00:00:00Z')
 next.resolve(sample('new'));await pending
 assert.equal(cache.read('ac','firewall').revision,'new')
})

test('rapid re-entry shares only an in-flight read; settled reads are never used as a network cache',async()=>{
 const cache=createSecurityStatusCache();const slow=deferred();let calls=0
 const request=()=>{calls++;return slow.promise}
 const one=cache.refresh('ac','firewall','public',request)
 const two=cache.refresh('ac','firewall','public',request)
 await Promise.resolve();assert.equal(calls,1)
 slow.resolve(sample('old'));const [a,b]=await Promise.all([one,two])
 a.rules[0].id='mutated';assert.equal(b.rules[0].id,'old')
 await cache.refresh('ac','firewall','public',async()=>{calls++;return sample('current')})
 assert.equal(calls,2)
})

test('a failed recheck retains the old display sample and permits a later retry',async()=>{
 const cache=createSecurityStatusCache();await cache.refresh('ac','fail2ban','',async()=>sample('old'))
 await assert.rejects(cache.refresh('ac','fail2ban','',async()=>{throw new Error('offline')}),/offline/)
 assert.equal(cache.read('ac','fail2ban').revision,'old')
 await cache.refresh('ac','fail2ban','',async()=>sample('retry'))
 assert.equal(cache.read('ac','fail2ban').revision,'retry')
})

test('mutations and logout invalidate old in-flight responses; host and zone requests stay isolated',async()=>{
 const cache=createSecurityStatusCache();const old=deferred()
 const stale=cache.refresh('ac','firewall','public',()=>old.promise)
 cache.clear('ac')
 await cache.refresh('ac','firewall','public',async()=>sample('after-apply'))
 old.resolve(sample('before-apply'));await stale
 assert.equal(cache.read('ac','firewall').revision,'after-apply')
 await cache.refresh('ac','firewall','private',async()=>sample('private'))
 assert.equal(cache.read('ac','firewall','public').revision,'after-apply')
 assert.equal(cache.read('ac','firewall','private').revision,'private')
 const late=deferred();const loggedOut=cache.refresh('qw','fail2ban','',()=>late.promise)
 cache.clear();late.resolve(sample('late'));await loggedOut
 assert.equal(cache.read('qw','fail2ban'),null)
 assert.equal(cache.read('ac','firewall'),null)
})

test('memory use is bounded across fleet hosts',async()=>{
 const cache=createSecurityStatusCache(2)
 for(const host of ['ac','qw','third'])await cache.refresh(host,'firewall','',async()=>sample(host))
 assert.equal(cache.read('ac','firewall'),null)
 assert.equal(cache.read('qw','firewall').revision,'qw')
})
