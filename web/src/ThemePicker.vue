<script setup lang="ts">
import { useId } from 'vue'
import type { ThemePreference } from './theme'

defineProps<{ modelValue: ThemePreference; compact?: boolean; ariaLabel?: string }>()
const emit = defineEmits<{ 'update:modelValue': [value: ThemePreference] }>()
const groupName = `theme-${useId()}`
const options: { value: ThemePreference; label: string; description: string }[] = [
  { value: 'dark', label: '暗色', description: '墨夜金阙' },
  { value: 'light', label: '亮色', description: '暖白宣纸' },
  { value: 'system', label: '系统', description: '跟随设备' },
]
</script>

<template>
  <div class="theme-picker" :class="{ compact }" role="radiogroup" :aria-label="ariaLabel || '界面主题'">
    <label v-for="option in options" :key="option.value">
      <input
        :name="groupName"
        type="radio"
        :value="option.value"
        :checked="modelValue === option.value"
        :aria-checked="modelValue === option.value"
        @change="emit('update:modelValue', option.value)"
      >
      <span class="theme-choice">
        <i class="theme-swatch" :class="`theme-swatch-${option.value}`" aria-hidden="true"><b></b><em></em></i>
        <span><b>{{ option.label }}</b><small v-if="!compact">{{ option.description }}</small></span>
      </span>
    </label>
  </div>
</template>
