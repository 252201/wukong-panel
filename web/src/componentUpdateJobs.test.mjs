import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('./componentUpdateJobs.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.ESNext, target: ts.ScriptTarget.ES2022 } }).outputText
const {startComponentUpdateJob:start, refreshComponentUpdateJob:refresh, pendingComponentUpdateJob:pending} = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
const job = (id,status='running') => ({id,status,kind:'update',target:'ac',progress:10,message:'',createdAt:'',updatedAt:''})
test('updates resume independently for each host and component',()=>{
 start('ac','sing-box',job('sing'))
 start('ac','cloudflared',job('tunnel'))
 start('qw','sing-box',job('other'))
 assert.equal(pending('ac','sing-box').id,'sing')
 assert.equal(pending('ac','cloudflared').id,'tunnel')
 assert.equal(pending('qw','sing-box').id,'other')
 refresh('ac','sing-box',job('sing','success'))
 assert.equal(pending('ac','sing-box'),undefined)
 assert.equal(pending('ac','cloudflared').id,'tunnel')
})
test('a late completion cannot erase a newer update job',()=>{
 start('ac','sing-box',job('first'))
 start('ac','sing-box',job('second'))
 refresh('ac','sing-box',job('first','failed'))
 assert.equal(pending('ac','sing-box').id,'second')
})
test('abandoned update tracking expires and memory is bounded',()=>{
 const previous=Date.now;let now=1000;Date.now=()=>now
 try {
  start('old','sing-box',job('old'));now+=16*60*1000
  assert.equal(pending('old','sing-box'),undefined)
  for(let i=0;i<140;i++)start('host-'+i,'sing-box',job(String(i)))
  assert.equal(pending('host-0','sing-box'),undefined)
  assert.equal(pending('host-139','sing-box').id,'139')
 } finally {Date.now=previous}
})
