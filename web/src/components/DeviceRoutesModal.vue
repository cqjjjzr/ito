<script setup lang="ts">
import { ref } from 'vue'
import { callApi, type Device } from '../api'
import { useRun } from '../run'
import PrefixListInput from './PrefixListInput.vue'

const props = defineProps<{ device: Device }>()
/** Closes with `true` once saved, so the opener reloads. */
const emit = defineEmits<{ close: [saved?: true] }>()
const run = useRun()

const routes = ref([...props.device.extra_allowed_ips])
const busy = ref(false)

async function save() {
  busy.value = true
  const { id, revision } = props.device
  const body = { allowed_ips: routes.value.map((r) => r.trim()).filter(Boolean) }
  const device = await run(() => callApi<Device>('PUT', `/devices/${id}/allowed-ips`, { body, revision }))
  busy.value = false
  if (device) emit('close', true)
}
</script>

<template>
  <UModal :title="`Server routes of ${device.name}`">
    <template #body>
      <form class="space-y-4" @submit.prevent="save">
        <p class="text-sm text-muted">
          Server routes are extra prefixes the server forwards through this device, such as a network behind it.
          They apply only to the server; the device's own WireGuard configuration remains unchanged.
        </p>
        <UFormField label="Routes">
          <PrefixListInput v-model="routes" placeholder="192.168.1.0/24" />
        </UFormField>
        <div class="flex justify-end">
          <UButton type="submit" label="Save" :loading="busy" />
        </div>
      </form>
    </template>
  </UModal>
</template>
