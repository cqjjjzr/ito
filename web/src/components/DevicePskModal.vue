<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { callApi, type Device, type DeviceConfig } from '../api'
import { useRun } from '../run'
import { isValidKey } from '../wireguard'
import KeyField from './KeyField.vue'

const props = defineProps<{ device: Device }>()
const run = useRun()

const config = ref<Pick<DeviceConfig, 'revision' | 'preshared_key'>>()
const psk = ref('')
const busy = ref(false)
const confirmingRemoval = ref(false)

async function load() {
  const loaded = await run(() => callApi<DeviceConfig>('GET', `/devices/${props.device.id}/config`))
  if (loaded) {
    config.value = loaded
    psk.value = loaded.preshared_key
  }
}

async function set(remove = false) {
  if (busy.value || !config.value) return
  const value = remove ? '' : psk.value.trim()
  if (!value && config.value.preshared_key) {
    confirmingRemoval.value = true
    return
  }
  await save(value)
}

async function save(value: string) {
  if (busy.value || !config.value) return
  if (value && !isValidKey(value)) return
  const saved = config.value
  busy.value = true
  try {
    await run(async () => {
      const updated = await callApi<Device>('PUT', `/devices/${props.device.id}/psk`, {
        body: { preshared_key: value }, revision: saved.revision,
      })
      config.value = { revision: updated.revision, preshared_key: value }
      psk.value = value
      confirmingRemoval.value = false
    }, 'Preshared key saved')
  } finally {
    busy.value = false
  }
}

onMounted(load)
</script>

<template>
  <UModal :title="confirmingRemoval ? `Remove the preshared key of ${device.name}?` : `Preshared key of ${device.name}`">
    <template #body>
      <div v-if="confirmingRemoval" class="space-y-4">
        <p class="text-sm text-muted">Remove PresharedKey from your WireGuard configuration to keep the tunnel connected.</p>
        <div class="flex justify-end gap-2">
          <UButton label="Cancel" color="neutral" variant="ghost" :disabled="busy" @click="confirmingRemoval = false" />
          <UButton label="Remove" color="error" :loading="busy" @click="save('')" />
        </div>
      </div>
      <form v-else class="space-y-4" @submit.prevent="set()">
        <p class="text-sm text-muted">
          A preshared key adds extra security to the tunnel against post-quantum attack. Set it to your own config after saving.
        </p>
        <KeyField v-model="psk" kind="preshared" allow-empty :disabled="busy || !config" />
        <p class="text-sm text-muted">Leave empty to remove the preshared key.</p>
        <p v-if="config?.preshared_key === ''" class="text-sm">This device has no preshared key.</p>
        <div class="flex justify-end gap-2">
          <UButton v-if="config?.preshared_key" label="Remove" color="error" variant="ghost" :disabled="busy" @click="set(true)" />
          <UButton type="submit" label="Save" :loading="busy" :disabled="!config || (!!psk.trim() && !isValidKey(psk)) || psk.trim() === config.preshared_key" />
        </div>
      </form>
    </template>
  </UModal>
</template>
