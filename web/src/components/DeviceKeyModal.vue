<script setup lang="ts">
import { ref } from 'vue'
import type { Device } from '../api'
import { useRun } from '../run'
import { importKeyPair, isValidKey, type KeyPair } from '../wireguard'
import KeyField from './KeyField.vue'

const props = defineProps<{ device: Device }>()
const emit = defineEmits<{ close: [KeyPair?] }>()
const run = useRun()

const replaces = !!props.device.public_key
const privateKey = ref('')

async function choose() {
  if (!isValidKey(privateKey.value)) return
  const keys = await run(() => importKeyPair(privateKey.value))
  if (keys) emit('close', keys)
}
</script>

<template>
  <UModal
    :title="replaces ? `Replace the key of ${device.name}?` : `Set up the key of ${device.name}`"
    :description="replaces ? 'The device\'s current configuration will stop working and active connections will disconnect.' : undefined"
  >
    <template #body>
      <form class="space-y-4" @submit.prevent="choose">
        <KeyField v-model="privateKey" kind="private" autofocus />
        <div class="flex justify-end gap-2">
          <UButton label="Cancel" color="neutral" variant="ghost" @click="emit('close')" />
          <UButton type="submit" :disabled="!isValidKey(privateKey)" :label="replaces ? 'Replace' : 'Set up'" :color="replaces ? 'error' : 'primary'" />
        </div>
      </form>
    </template>
  </UModal>
</template>
