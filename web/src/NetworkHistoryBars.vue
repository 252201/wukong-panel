<script setup lang="ts">
import { computed, ref, useId } from 'vue'
import type { NetworkSample } from './api'
import type { Locale } from './i18n'
import { targetLossState } from './networkHistory'

const props = defineProps<{
  samples: (NetworkSample | null)[]
  metric: 'latency' | 'loss'
  groupLabel: string
  language: Locale
  historyLabel: string
}>()

const tooltipId = useId()
const activeIndex = ref<number | null>(null)
const tooltipStyle = ref<Record<string, string>>({})
const activeSample = computed(() => activeIndex.value === null ? null : props.samples[activeIndex.value])
const english = computed(() => props.language === 'en-US')

function tone(sample: NetworkSample | null) {
  if (!sample) return 'network-history-empty'
  if (sample.status === 'error' || !sample.packetsSent) return 'unavailable'
  if (props.metric === 'latency') {
    if (!sample.packetsReceived || sample.latencyMs >= 200) return 'bad'
    if (sample.status === 'partial') return 'partial'
    return sample.latencyMs >= 100 ? 'warn' : 'good'
  }
  if (sample.packetLossPct >= 5) return 'bad'
  if (sample.status === 'partial') return 'partial'
  return sample.packetLossPct > 0 ? 'warn' : 'good'
}

function summary(sample: NetworkSample | null) {
  if (!sample) return english.value ? 'No sample in this minute' : '该分钟没有采样'
  const time = new Date(sample.checkedAt).toLocaleString(props.language, { hour: '2-digit', minute: '2-digit' })
  const value = sample.status === 'error' || !sample.packetsSent
    ? (english.value ? 'ICMP unavailable' : 'ICMP 不可用')
    : props.metric === 'latency'
      ? (sample.packetsReceived ? `${sample.latencyMs.toFixed(1)} ms` : (english.value ? 'No reply' : '无响应'))
      : `${sample.packetLossPct.toFixed(1)}%`
  const partial = sample.status === 'partial' ? (english.value ? ' · partial failure' : ' · 部分目标异常') : ''
  return `${props.groupLabel} · ${time} · ${value} · ${sample.packetsReceived}/${sample.packetsSent}${partial}`
}

function targetResult(sample: NetworkSample, target: string) {
  return sample.targetResults?.find(item => item.target === target)
}

function show(event: Event, index: number) {
  const rect = (event.currentTarget as HTMLElement).getBoundingClientRect()
  const width = Math.min(340, window.innerWidth - 16)
  const center = Math.max(8 + width / 2, Math.min(window.innerWidth - 8 - width / 2, rect.left + rect.width / 2))
  const below = rect.top < 130
  tooltipStyle.value = {
    left: `${center}px`,
    top: `${below ? rect.bottom + 8 : rect.top - 8}px`,
    transform: `translate(-50%, ${below ? '0' : '-100%'})`,
  }
  activeIndex.value = index
}

function hide() {
  activeIndex.value = null
}
</script>

<template>
  <div class="network-history-bars" role="group" :aria-label="historyLabel">
    <i v-for="(sample, index) in samples" :key="index" role="img" :class="tone(sample)"
      :tabindex="sample ? 0 : undefined" :aria-label="sample ? `${summary(sample)} · ${sample.targets?.join(' / ') || ''}` : undefined"
      :aria-hidden="!sample" :aria-describedby="activeIndex === index ? tooltipId : undefined"
      @mouseenter="show($event, index)" @mouseleave="hide" @focus="show($event, index)" @blur="hide"></i>
  </div>
  <Teleport to="body">
    <div v-if="activeIndex !== null" :id="tooltipId" class="network-history-tooltip" :style="tooltipStyle" role="tooltip">
      <span>{{ summary(activeSample) }}</span>
      <div v-if="activeSample?.targets?.length" class="network-history-tooltip-targets">
        <template v-for="(target, index) in activeSample.targets" :key="target">
          <span v-if="index" class="network-history-tooltip-separator">/</span>
          <span :class="{ loss: targetLossState(activeSample, target) === 'loss' }">{{ target }}<small v-if="targetResult(activeSample, target)"> {{ targetResult(activeSample, target)?.packetsReceived }}/{{ targetResult(activeSample, target)?.packetsSent }}</small></span>
        </template>
      </div>
      <small v-if="activeSample && activeSample.packetLossPct > 0 && !activeSample.targetResults?.length" class="network-history-tooltip-legacy">{{ english ? 'Per-target loss unavailable for this older sample' : '旧样本无单 IP 丢包明细' }}</small>
    </div>
  </Teleport>
</template>
