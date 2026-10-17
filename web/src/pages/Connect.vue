<script setup lang="ts">
import { computed, onMounted, ref } from 'vue'
import { useRoute } from 'vue-router'
import { callApi, type Device, type Interface } from '../api'
import { formatCheckCode, isApprovable } from '../claims'
import { buildDnsLabel } from '../dns'
import DnsLabelInput from '../components/DnsLabelInput.vue'
import { useRun } from '../run'
import { session } from '../session'

// Query parameters set by `ito-agent login`: `id` (request SHA-256), `t` (Unix timestamp), and
// either `device` (target device ID) or `name` (default host name for creating a new device).
const query = useRoute().query
const requestId = String(query.id ?? '')
const requestedAt = Number(query.t)
const boundId = typeof query.device === 'string' ? query.device : undefined
const code = formatCheckCode(requestId)
const approvable = isApprovable(requestId, requestedAt)

const run = useRun()
const devices = ref<Device[]>([])
const interfaces = ref<Interface[]>([])
const loaded = ref(false)
const choice = ref(boundId ?? 'new')
const name = ref(String(query.name ?? ''))
const dnsName = ref(buildDnsLabel(name.value))
const interfaceId = ref('')
const busy = ref(false)
const approved = ref(false)

const bound = computed(() => devices.value.find((d) => d.id === boundId))
const items = computed(() => [
  ...devices.value.map((d) => ({ label: d.name, description: `${d.interface_id} · ${d.client_addresses.join(', ')}`, value: d.id })),
  { label: 'Create a new device', value: 'new' },
])

onMounted(async () => {
  if (!approvable) return
  await run(async () => {
    if (boundId) {
      devices.value = [await callApi<Device>('GET', `/devices/${boundId}`)]
    } else {
      const all = await callApi<Device[]>('GET', '/devices')
      // Filter to the signed-in user's own active devices even when signed in as an administrator.
      devices.value = all.filter((d) => d.account_id === session.value!.account_id && !d.deleting && !d.blocked)
      interfaces.value = await callApi<Interface[]>('GET', '/interfaces')
      interfaceId.value = interfaces.value[0]?.name ?? ''
    }
  })
  if (!boundId && devices.value.length) choice.value = devices.value[0]!.id
  loaded.value = true
})

async function approve() {
  busy.value = true
  await run(async () => {
    let target = choice.value
    if (target === 'new') {
      const body = { name: name.value, dns_name: dnsName.value, interface_id: interfaceId.value, account_id: session.value!.account_id }
      target = (await callApi<Device>('POST', '/devices', { body })).id
      choice.value = target
    }
    await callApi('POST', `/devices/${target}/claims`, { body: { id: requestId, t: requestedAt } })
    approved.value = true
  })
  busy.value = false
}
</script>

<template>
  <div class="max-w-xl space-y-6">
    <h1 class="text-2xl font-semibold">Connect a computer</h1>
    <UAlert
      v-if="!approvable"
      color="warning"
      variant="subtle"
      title="This link is incomplete or expired"
      description="Start again on the computer. Login links expire after 15 minutes."
    />
    <UAlert
      v-else-if="approved"
      color="success"
      variant="subtle"
      icon="i-lucide-check"
      title="Approved"
      description="The computer connects within a few seconds. You can close this page."
    />
    <form v-else-if="loaded" class="space-y-5" @submit.prevent="approve">
      <p>
        The computer showing <span class="font-mono font-semibold">{{ code }}</span> requested to connect.
        Approve only a computer you are setting up yourself.
      </p>
      <p v-if="bound">
        It connects as <span class="font-semibold">{{ bound.name }}</span> on {{ bound.interface_id }}.
      </p>
      <template v-else-if="!boundId">
        <URadioGroup v-if="devices.length" v-model="choice" :items="items" />
        <div v-if="choice === 'new'" class="space-y-4">
          <UFormField label="Name">
            <UInput v-model="name" required maxlength="255" class="w-full" />
          </UFormField>
          <UFormField label="DNS label" help="Device name in the interface DNS zone. Leave empty to skip DNS publishing.">
            <DnsLabelInput v-model="dnsName" :name="name" follow />
          </UFormField>
          <UFormField v-if="interfaces.length > 1" label="Interface">
            <USelect v-model="interfaceId" :items="interfaces.map((i) => i.name)" class="w-full" />
          </UFormField>
        </div>
      </template>
      <UButton type="submit" label="Approve" :loading="busy" :disabled="!!boundId && !bound" />
    </form>
  </div>
</template>
