<script setup lang="ts">
import { computed, nextTick, onBeforeUnmount, onMounted, ref, useId, watch } from 'vue'
import { banDurationPresets, formatBanDuration, parseBanDuration } from './banDuration'

const props = defineProps<{modelValue: number; language: string; permanentSupported: boolean}>()
const emit = defineEmits<{ 'update:modelValue': [value: number] }>()
const id = useId()
const root = ref<HTMLElement>()
const input = ref<HTMLInputElement>()
const text = ref(formatBanDuration(props.modelValue, props.language))
const open = ref(false)
const active = ref(-1)
const t = (zh: string, en: string) => props.language === 'en-US' ? en : zh
const options = computed(() => banDurationPresets.filter(value => value !== -1 || props.permanentSupported || props.modelValue === -1))
const available = (value: number) => value !== -1 || props.permanentSupported
// An old Agent may report an existing permanent setting; display it, but require a timed replacement.
const parsed = computed(() => parseBanDuration(text.value, props.permanentSupported))
function validate() {
 input.value?.setCustomValidity(parsed.value === null ? t('请选择时长或输入 60 秒至 30 天的自定义时长。', 'Choose a duration or enter a custom duration from 60 seconds to 30 days.') : '')
}
function edit(event: Event) {
 text.value = (event.target as HTMLInputElement).value
 open.value = false
 active.value = -1
 if (parsed.value !== null) emit('update:modelValue', parsed.value)
 validate()
}
function show() {
 open.value = true
 active.value = options.value.findIndex(value => value === props.modelValue && available(value))
}
async function choose(index: number) {
 const value = options.value[index]
 if (value !== undefined && !available(value)) return
 open.value = false
 active.value = -1
 if (value === undefined) text.value = ''
 else {text.value = formatBanDuration(value, props.language);emit('update:modelValue', value)}
 await nextTick()
 validate()
 input.value?.focus()
 input.value?.select()
}
function keydown(event: KeyboardEvent) {
 if (event.key === 'Escape') {event.preventDefault();open.value = false;return}
 if (event.key === 'ArrowDown' || event.key === 'ArrowUp') {
  event.preventDefault()
  if (!open.value) {show();return}
  const direction = event.key === 'ArrowDown' ? 1 : -1
  do {active.value = (active.value + direction + options.value.length + 1) % (options.value.length + 1)}
  while (active.value < options.value.length && !available(options.value[active.value]!))
 } else if (event.key === 'Enter' && open.value) {
  event.preventDefault()
  if (active.value >= 0) void choose(active.value)
  else open.value = false
 }
}
function blur(event: FocusEvent) {
 if (root.value?.contains(event.relatedTarget as Node)) return
 open.value = false
 if (parsed.value !== null) text.value = formatBanDuration(parsed.value, props.language)
}
function outside(event: PointerEvent) {
 if (!root.value?.contains(event.target as Node)) open.value = false
}
watch(() => props.modelValue, value => {
 // Don't reformat a valid draft while the user is still typing.
 if (parseBanDuration(text.value, true) !== value) text.value = formatBanDuration(value, props.language)
})
watch(() => props.language, () => {
 const value = parseBanDuration(text.value, true)
 if (value !== null) text.value = formatBanDuration(value, props.language)
})
watch([text, () => props.permanentSupported], validate, {flush:'post'})
onMounted(() => {validate();document.addEventListener('pointerdown', outside)})
onBeforeUnmount(() => document.removeEventListener('pointerdown', outside))
</script>

<template>
 <div ref="root" class="ban-duration">
  <label :for="id">{{t('封禁时长','Ban duration')}}</label>
  <div class="duration-control">
   <input :id="id" ref="input" :value="text" type="text" role="combobox" required autocomplete="off" spellcheck="false"
    aria-autocomplete="none" aria-haspopup="listbox" :aria-expanded="open" :aria-controls="`${id}-options`"
    :aria-activedescendant="open && active >= 0 ? `${id}-option-${active}` : undefined"
    :placeholder="t('选择或输入时长','Choose or enter a duration')" @input="edit" @keydown="keydown" @blur="blur">
   <button type="button" class="duration-toggle" tabindex="-1" :aria-label="t('选择封禁时长','Choose ban duration')" :aria-expanded="open"
    @pointerdown.prevent @click="input?.focus(); open ? open = false : show()"><span aria-hidden="true">⌄</span></button>
   <div v-if="open" :id="`${id}-options`" class="duration-options" role="listbox" :aria-label="t('封禁时长','Ban duration')">
    <div v-for="(value, index) in options" :id="`${id}-option-${index}`" :key="value" role="option" :aria-selected="modelValue === value" :aria-disabled="!available(value)"
     :class="{active:active === index, selected:modelValue === value, disabled:!available(value)}" @pointerdown.prevent @click="choose(index)">{{formatBanDuration(value,language)}}</div>
    <div :id="`${id}-option-${options.length}`" role="option" :aria-selected="false" :class="{active:active === options.length}" @pointerdown.prevent @click="choose(options.length)">{{t('自定义时长…','Custom duration…')}}</div>
   </div>
  </div>
  <small v-if="!permanentSupported">{{t('此 Agent 暂不支持永久封禁，请更新完整面板。','Update the full panel Agent to support permanent bans.')}}</small>
 </div>
</template>

<style scoped>
.ban-duration{display:flex;flex-direction:column;gap:7px;min-width:0;font-size:12px;align-self:start}
.duration-control{position:relative}
.duration-control input{width:100%;padding-right:38px}
.duration-control .duration-toggle{position:absolute;right:1px;top:1px;bottom:1px;min-height:0;width:36px;margin:0;padding:0;border:0;background:transparent;color:var(--muted);cursor:pointer;display:flex;align-items:center;justify-content:center}
.duration-options{position:absolute;top:calc(100% + 4px);left:0;right:0;z-index:20;max-height:310px;overflow-y:auto;border:1px solid var(--line);background:var(--surface-input);box-shadow:0 8px 24px rgba(0,0,0,.18);padding:4px}
.duration-options [role=option]{padding:10px 12px;cursor:pointer;line-height:1.5}
.duration-options [role=option]:hover,.duration-options .active{background:var(--surface-code);color:var(--gold)}
.duration-options .selected{color:var(--gold)}
.duration-options .disabled{opacity:.45;cursor:default}
.ban-duration small{font-size:11px;color:var(--muted);line-height:1.6}
</style>
