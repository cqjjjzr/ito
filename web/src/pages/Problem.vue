<script setup lang="ts">
import { computed } from 'vue'
import type { Problem } from '../api'
import CopyButton from '../components/CopyButton.vue'

const props = defineProps<{ problem: Partial<Problem> }>()
/** Request UUID extracted from the RFC 9457 `instance` URI (`urn:uuid:<id>`). */
const requestId = computed(() => props.problem.instance?.replace(/^urn:uuid:/, ''))
</script>

<template>
  <div class="flex min-h-dvh flex-col items-center justify-center px-4">
    <UColorModeButton class="absolute end-4 top-4" />
    <img src="/logo.svg" alt="" class="size-16 opacity-60 grayscale">
    <p v-if="problem.status" class="mt-6 font-mono text-sm text-muted">
      {{ problem.status }}<template v-if="problem.code"> · {{ problem.code }}</template>
    </p>
    <h1 class="mt-2 max-w-xl text-center text-2xl font-semibold">{{ problem.title ?? 'Something went wrong.' }}</h1>
    <p v-if="problem.detail" class="mt-3 max-w-xl text-center text-muted">{{ problem.detail }}</p>
    <p v-if="requestId" class="mt-6 flex items-center gap-1 text-sm text-muted">
      Request ID <code>{{ requestId }}</code>
      <CopyButton :value="requestId" />
    </p>
    <UButton to="/" external size="lg" class="mt-10" label="Back to Ito" icon="i-lucide-arrow-left" />
  </div>
</template>
