import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source=readFileSync(new URL('./api.ts',import.meta.url),'utf8')
const js=ts.transpileModule(source,{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const api=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
test('connector requests and job polling stay bound to their original host',async()=>{
 const requests=[]
 const previous=globalThis.fetch
 globalThis.fetch=async(url,options)=>{requests.push({url,options});return new Response('{}',{status:200,headers:{'Content-Type':'application/json'}})}
 try{
  api.setCSRF('test-csrf')
  const ac=api.cloudflaredAPI('ac')
  api.setFleetHost('qw')
  await ac.status();await ac.check();await ac.settings(true);await ac.update('2026.8.2','2026.9.3');await ac.job('job-1')
  assert.ok(requests.every(r=>r.url.startsWith('api/v1/fleet/hosts/ac/')))
  assert.equal(requests[4].url,'api/v1/fleet/hosts/ac/jobs/job-1')
  for(const r of requests.slice(1,4)){assert.equal(r.options.headers.get('X-CSRF-Token'),'test-csrf');assert.equal(r.options.method,'POST')}
  assert.deepEqual(JSON.parse(requests[3].options.body),{currentVersion:'2026.8.2',targetVersion:'2026.9.3'})
  requests.length=0
  await api.cloudflaredAPI('local').status()
  assert.equal(requests[0].url,'api/v1/system/cloudflared')
 }finally{globalThis.fetch=previous;api.setFleetHost('local');api.setCSRF('')}
})

test('sing-box updates and jobs stay bound to their original host',async()=>{
 const requests=[]
 const previous=globalThis.fetch
 globalThis.fetch=async(url,options)=>{requests.push({url,options});return new Response('{}',{status:200,headers:{'Content-Type':'application/json'}})}
 try{
  api.setCSRF('test-csrf')
  const ac=api.componentUpdateAPI('ac','sing-box')
  api.setFleetHost('qw')
  await ac.status();await ac.check();await ac.update('1.14.1','1.14.2');await ac.job('job-1')
  assert.ok(requests.every(r=>r.url.startsWith('api/v1/fleet/hosts/ac/')))
  assert.equal(requests[3].url,'api/v1/fleet/hosts/ac/jobs/job-1')
  for(const r of requests.slice(1,3)){assert.equal(r.options.headers.get('X-CSRF-Token'),'test-csrf');assert.equal(r.options.method,'POST')}
  assert.deepEqual(JSON.parse(requests[2].options.body),{currentVersion:'1.14.1',targetVersion:'1.14.2'})
  requests.length=0
  await api.componentUpdateAPI('local','sing-box').status()
  assert.equal(requests[0].url,'api/v1/system/sing-box')
 }finally{globalThis.fetch=previous;api.setFleetHost('local');api.setCSRF('')}
})
