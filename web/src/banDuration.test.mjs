import test from 'node:test'
import assert from 'node:assert/strict'
import { readFileSync } from 'node:fs'
import ts from 'typescript'
const source = readFileSync(new URL('./banDuration.ts', import.meta.url), 'utf8')
const js = ts.transpileModule(source, {compilerOptions:{module:ts.ModuleKind.ESNext,target:ts.ScriptTarget.ES2022}}).outputText
const {banDurationPresets,formatBanDuration,parseBanDuration} = await import(`data:text/javascript;base64,${Buffer.from(js).toString('base64')}`)

test('presets and custom durations round trip in Chinese and English without changing seconds', () => {
 for (const language of ['zh-CN','en-US']) {
  for (const seconds of [...banDurationPresets,60,61,5400,86401]) assert.equal(parseBanDuration(formatBanDuration(seconds,language),true),seconds)
 }
 for (const [input,seconds] of [['90 分钟',5400],['1.5 hours',5400],['3600',3600],['30天',2592000],['60 seconds',60],['2d',172800]]) assert.equal(parseBanDuration(input,true),seconds)
 assert.equal(formatBanDuration(2592000,'zh-CN'),'30 天')
})
test('permanent requires Agent capability and never exposes a negative number in the control', () => {
 for (const text of ['永久','永久（不自动解除）','Permanent','Permanent (no automatic expiry)']) {
  assert.equal(parseBanDuration(text,true),-1)
  assert.equal(parseBanDuration(text,false),null)
 }
 assert.equal(parseBanDuration('3600',false),3600)
})
test('invalid drafts, fractional seconds, out of range and numeric special values cannot be submitted', () => {
 for (const text of ['', '0','59','-1','-2','31 days','2592001','1e3','Infinity','NaN','0.333 minutes','60 seconds; reboot','1 小时 30 分钟']) assert.equal(parseBanDuration(text,true),null)
})
