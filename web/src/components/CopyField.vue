<script setup lang="ts">
import { ref } from 'vue'
import CopyButton from './CopyButton.vue'

const props = defineProps<{ value: string; secret?: boolean }>()
const shown = ref(!props.secret)
</script>

<template>
  <UInput :model-value="value" :type="shown ? 'text' : 'password'" readonly class="w-full" :ui="{ base: 'font-mono' }">
    <template #trailing>
      <UButton
        v-if="secret"
        :icon="shown ? 'i-lucide-eye-off' : 'i-lucide-eye'"
        :aria-label="shown ? 'Hide' : 'Show'"
        color="neutral"
        variant="link"
        size="sm"
        @click="shown = !shown"
      />
      <CopyButton :value="value" />
    </template>
  </UInput>
</template>
