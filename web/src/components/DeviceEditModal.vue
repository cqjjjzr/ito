<script setup lang="ts">
import { ref } from 'vue'
import { callApi, type Device } from '../api'
import { useRun } from '../run'
import DnsLabelInput from './DnsLabelInput.vue'

const props = defineProps<{ device: Device }>()
/** Closes with `true` once saved, so the opener reloads. */
const emit = defineEmits<{ close: [saved?: true] }>()
const run = useRun()

const name = ref(props.device.name)
const dnsName = ref(props.device.dns_name ?? '')
const note = ref(props.device.note)
const busy = ref(false)

async function save() {
  busy.value = true
  const body = { name: name.value, dns_name: dnsName.value, note: note.value }
  const { id, revision } = props.device
  const device = await run(() => callApi<Device>('PATCH', `/devices/${id}`, { body, revision }))
  busy.value = false
  if (device) emit('close', true)
}
</script>

<template>
  <UModal :title="`Edit ${device.name}`">
    <template #body>
      <form class="space-y-4" @submit.prevent="save">
        <UFormField label="Name">
          <UInput v-model="name" required maxlength="255" class="w-full" />
        </UFormField>
        <UFormField label="DNS label" help="Device name in the interface DNS zone. Leave empty to skip DNS publishing.">
          <DnsLabelInput v-model="dnsName" :name="name" />
        </UFormField>
        <UFormField label="Note">
          <UTextarea v-model="note" autoresize class="w-full" />
        </UFormField>
        <div class="flex justify-end">
          <UButton type="submit" label="Save" :loading="busy" />
        </div>
      </form>
    </template>
  </UModal>
</template>
