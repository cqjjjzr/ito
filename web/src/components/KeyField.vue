<script setup lang="ts">
import { computed, ref } from 'vue'
import { useRun } from '../run'
import { generateKey, isValidKey } from '../wireguard'
import CopyButton from './CopyButton.vue'

const props = defineProps<{ kind: 'private' | 'preshared'; autofocus?: boolean; disabled?: boolean; allowEmpty?: boolean }>()
const key = defineModel<string>({ required: true })
const label = computed(() => props.kind === 'private' ? 'Private key' : 'Preshared key')
const shown = ref(false)
const run = useRun()
</script>

<template>
  <UFormField
    :label="label"
    :error="key && !isValidKey(key) ? 'Enter a nonzero 32-byte key in canonical base64, or generate one.' : undefined"
    :help="kind === 'private' ? 'Paste an existing private key or generate one. The private key never leaves this browser.' : 'Paste an existing key or generate one. Saved only when submitted.'"
  >
    <UInput v-model="key" :type="shown ? 'text' : 'password'" autocomplete="off" :required="!allowEmpty" :autofocus="autofocus" :disabled="disabled" class="w-full" :ui="{ base: 'font-mono' }">
      <template #trailing>
        <UButton :icon="shown ? 'i-lucide-eye-off' : 'i-lucide-eye'" :aria-label="`${shown ? 'Hide' : 'Show'} ${label.toLowerCase()}`" color="neutral" variant="link" size="sm" @click="shown = !shown" />
        <CopyButton v-if="isValidKey(key)" :value="key.trim()" />
      </template>
    </UInput>
    <UButton class="mt-2" label="Generate" :aria-label="`Generate ${label.toLowerCase()}`" color="neutral" variant="outline" :disabled="disabled" @click="run(async () => { key = generateKey() })" />
  </UFormField>
</template>
