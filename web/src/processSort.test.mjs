import test from 'node:test'
import assert from 'node:assert/strict'
import {readFileSync} from 'node:fs'
import ts from 'typescript'
const js = ts.transpileModule(readFileSync(new URL('./processSort.ts',import.meta.url),'utf8'),{compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const {sortProcesses}=await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)
test('CPU and RSS sorting toggle direction, retain labels and never mutate snapshots',()=>{
 const input=[{pid:4,cpu:3,rssBytes:10},{pid:2,cpu:0,rssBytes:100,service:'fail2ban',nodes:['node']},{pid:3,cpu:3,rssBytes:20},{pid:1,cpu:3,rssBytes:20}]
 const before=structuredClone(input)
 assert.deepEqual(sortProcesses(input,'cpu').map(p=>p.pid),[1,3,4,2])
 assert.deepEqual(sortProcesses(input,'memory').map(p=>p.pid),[2,1,3,4])
 assert.deepEqual(sortProcesses(input,'memory',true).map(p=>p.pid),[4,1,3,2])
 assert.deepEqual(sortProcesses(input,'cpu',true).map(p=>p.pid),[2,4,1,3])
 assert.deepEqual(sortProcesses(input,'memory')[0].nodes,['node'])
 assert.deepEqual(input,before)
 assert.deepEqual(sortProcesses([],'cpu'),[])
})
