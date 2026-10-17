<script setup lang="ts">
import { computed } from 'vue'

const props = defineProps<{
  /** Number of addresses currently in use, formatted as a decimal string. */
  used: string
  /** Quota limit (`count`, `/prefix_len`, or empty for unlimited). */
  limit: string
  /** Address width in bits (`32` for IPv4, `128` for IPv6). */
  bits: 32 | 128
}>()

const max = computed(() => {
  if (!props.limit) return undefined
  return props.limit.startsWith('/') ? 2n ** BigInt(props.bits - Number(props.limit.slice(1))) : BigInt(props.limit)
})
const percent = computed(() => (max.value ? Number((BigInt(props.used) * 100n) / max.value) : 0))
/** Formats large address counts (such as IPv6 `/64` blocks) as powers of two. */
const usedLabel = computed(() => {
  const n = BigInt(props.used)
  return n < 1_000_000n ? n.toString() : `≈2^${n.toString(2).length - 1}`
})
</script>

<template>
  <div class="min-w-32">
    <div class="text-sm">
      {{ usedLabel }} <span class="text-muted">of {{ limit || 'unlimited' }}</span>
    </div>
    <UProgress v-if="max" :model-value="Math.min(percent, 100)" size="xs" class="mt-1" />
  </div>
</template>
