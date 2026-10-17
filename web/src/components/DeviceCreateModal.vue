<script setup lang="ts">
import { computed, ref } from 'vue'
import { callApi, type AccountView, type Device, type Interface } from '../api'
import { useRun } from '../run'
import { importKeyPair, isValidKey, type KeyPair } from '../wireguard'
import DnsLabelInput from './DnsLabelInput.vue'
import KeyField from './KeyField.vue'

const props = defineProps<{
  interfaces: Interface[]
  /** Accounts available when an administrator creates a device on behalf of a user. */
  accounts?: AccountView[]
  defaultAccountId: string
}>()
const emit = defineEmits<{ close: [{ device: Device; keys: KeyPair }] }>()
const run = useRun()

const name = ref('')
const dnsName = ref('')
const privateKey = ref('')
const withPsk = ref(true)
const presharedKey = ref('')
const created = ref<Device>()
const validKeys = computed(() => isValidKey(privateKey.value) && (!withPsk.value || isValidKey(presharedKey.value)))
const interfaceId = ref(props.interfaces[0]!.name)
const accountId = ref(props.defaultAccountId)
const busy = ref(false)

const describePools = (id: string) => props.interfaces.find((i) => i.name === id)?.pools.map((p) => p.prefix).join(', ')

async function create() {
  if (busy.value || !validKeys.value) return
  busy.value = true
  await run(async () => {
    const keys = await importKeyPair(privateKey.value)
    const psk = withPsk.value ? presharedKey.value.trim() : undefined
    // Keep the created device for retry if saving its PSK fails.
    if (created.value) {
      created.value = await callApi<Device>('GET', `/devices/${created.value.id}`)
    } else {
      const body = { name: name.value, dns_name: dnsName.value, interface_id: interfaceId.value, account_id: accountId.value }
      created.value = await callApi<Device>('POST', '/devices', { body })
    }
    if (psk) {
      created.value = await callApi<Device>('PUT', `/devices/${created.value.id}/psk`, {
        body: { preshared_key: psk }, revision: created.value.revision,
      })
    }
    emit('close', { device: created.value, keys })
  })
  busy.value = false
}
</script>

<template>
  <UModal title="New device">
    <template #body>
      <form class="space-y-4" @submit.prevent="create">
        <fieldset :disabled="busy || !!created" class="space-y-4">
          <UFormField label="Name">
            <UInput v-model="name" required maxlength="255" autofocus class="w-full" />
          </UFormField>
          <UFormField label="DNS label" help="Device name in the interface DNS zone. Leave empty to skip DNS publishing.">
            <DnsLabelInput v-model="dnsName" :name="name" follow />
          </UFormField>
          <UFormField v-if="accounts" label="Owner">
            <USelectMenu v-model="accountId" :items="accounts" label-key="display_name" value-key="id" class="w-full" />
          </UFormField>
          <UFormField label="Interface" :help="`Addresses come from ${describePools(interfaceId) || 'no pool'}.`">
            <USelect v-model="interfaceId" :items="interfaces.map((i) => i.name)" class="w-full" />
          </UFormField>
        </fieldset>
        <KeyField v-model="privateKey" kind="private" :disabled="busy" />
        <UCheckbox v-model="withPsk" label="Use a preshared key" :disabled="busy" description="Adds extra security to the tunnel against post-quantum attack." />
        <KeyField v-if="withPsk" v-model="presharedKey" kind="preshared" :disabled="busy" />
        <p class="text-sm text-muted">
          The device receives an available address from each IP address pool.
        </p>
        <div class="flex justify-end">
          <UButton type="submit" :label="created ? 'Finish setup' : 'Create'" :loading="busy" :disabled="!validKeys" />
        </div>
      </form>
    </template>
  </UModal>
</template>
