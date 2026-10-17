<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { ApiError, callApi, type Device, type DeviceConfig, type DeviceStatus } from '../api'
import { listAdditionalGrants } from '../wireguard'
import CopyField from './CopyField.vue'

const props = defineProps<{ device: Device }>()

const status = ref<DeviceStatus>()
// Why the live status could not be read, such as an interface the controller cannot reach.
const statusError = ref<string>()
const additionalGrants = computed(() => listAdditionalGrants(props.device))
const config = ref<DeviceConfig>()
const formatTime = (t?: string | null) => (t ? new Date(t).toLocaleString() : '—')
function formatBytes(bytes: number): string {
  const units = ['B', 'KiB', 'MiB', 'GiB', 'TiB', 'PiB', 'EiB']
  let unit = 0
  while (bytes >= 1024 && unit < units.length - 1) {
    bytes /= 1024
    unit++
  }
  return `${bytes.toLocaleString(undefined, { maximumFractionDigits: 1 })} ${units[unit]}`
}

onMounted(async () => {
  const path = `/devices/${props.device.id}`
  const [s, c] = await Promise.allSettled([callApi<DeviceStatus>('GET', `${path}/status`), callApi<DeviceConfig>('GET', `${path}/config`)])
  if (s.status === 'fulfilled') status.value = s.value
  else statusError.value = s.reason instanceof ApiError ? s.reason.problem.title : String(s.reason)
  if (c.status === 'fulfilled') config.value = c.value
})
</script>

<template>
  <dl class="grid gap-x-8 gap-y-3 px-2 py-1 text-sm sm:grid-cols-2 lg:grid-cols-3">
    <div>
      <dt class="text-muted">Last handshake</dt>
      <dd v-if="status">{{ status.handshake ? formatTime(status.handshake) : 'Never' }}</dd>
      <dd v-else>—</dd>
    </div>
    <div>
      <dt class="text-muted">Transfer</dt>
      <dd v-if="status">{{ formatBytes(status.receive_bytes) }} received, {{ formatBytes(status.transmit_bytes) }} sent</dd>
      <dd v-else>—</dd>
    </div>
    <div>
      <dt class="text-muted">Endpoint</dt>
      <dd class="font-mono">{{ status?.endpoint || '—' }}</dd>
    </div>
    <div>
      <dt class="text-muted">DNS label</dt>
      <dd class="font-mono">{{ device.dns_name || '—' }}</dd>
    </div>
    <div>
      <dt class="text-muted">Key expires</dt>
      <dd>{{ formatTime(device.key_expires_at) }}</dd>
    </div>
    <div>
      <dt class="text-muted">Agent credential</dt>
      <dd>{{ config?.agent_credential_issued_at ? `Issued ${formatTime(config.agent_credential_issued_at)}` : 'None' }}</dd>
    </div>
    <div>
      <dt class="text-muted">Additional grants</dt>
      <dd class="font-mono">{{ additionalGrants.join(', ') || '—' }}</dd>
    </div>
    <div>
      <dt class="text-muted">Server routes</dt>
      <dd class="font-mono">{{ device.extra_allowed_ips.join(', ') || '—' }}</dd>
    </div>
    <div>
      <dt class="text-muted">Created</dt>
      <dd>{{ formatTime(device.created_at) }}</dd>
    </div>
    <div v-if="device.public_key" class="sm:col-span-2">
      <dt class="mb-1 text-muted">Public key</dt>
      <dd><CopyField :value="device.public_key" /></dd>
    </div>
    <div v-if="device.note" class="sm:col-span-2 lg:col-span-3">
      <dt class="text-muted">Note</dt>
      <dd class="whitespace-pre-wrap">{{ device.note }}</dd>
    </div>
    <div v-if="statusError" class="sm:col-span-2 lg:col-span-3">
      <dt class="text-muted">Live status</dt>
      <dd class="text-error">{{ statusError }}</dd>
    </div>
    <div v-if="device.apply_error" class="sm:col-span-2 lg:col-span-3">
      <dt class="text-muted">Last apply error</dt>
      <dd class="text-error">{{ device.apply_error }}</dd>
    </div>
  </dl>
</template>
