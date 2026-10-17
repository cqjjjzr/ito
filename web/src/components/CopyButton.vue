<script setup lang="ts">
import { ref } from 'vue'

const props = defineProps<{ value: string }>()
const copied = ref(false)

async function copy() {
  await navigator.clipboard.writeText(props.value)
  copied.value = true
  setTimeout(() => (copied.value = false), 1500)
}
</script>

<template>
  <UButton :icon="copied ? 'i-lucide-check' : 'i-lucide-copy'" aria-label="Copy" color="neutral" variant="link" size="sm" @click="copy" />
</template>
