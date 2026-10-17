<script setup lang="ts">
import { computed, ref } from 'vue'
import { callApi, type Device, type Interface } from '../api'
import { useRun } from '../run'
import { countAddressBits, listAdditionalGrants } from '../wireguard'
import PoolList from './PoolList.vue'
import PrefixListInput from './PrefixListInput.vue'

const props = defineProps<{ device: Device; interface?: Interface }>()
/** Closes with `true` once saved, so the opener reloads. */
const emit = defineEmits<{ close: [saved?: true] }>()
const run = useRun()

const pools = props.interface?.pools ?? []
const own = ref([...props.device.client_addresses])
const additional = ref(listAdditionalGrants(props.device))
const allocate = ref<{ pool: string; prefix_length: number; address: boolean }[]>([])
const kinds = [
  { label: 'Own address', value: true },
  { label: 'Additional grant', value: false },
]
const trimPrefixes = (prefixes: string[]) => prefixes.map((p) => p.trim()).filter(Boolean)
const hasOwn = computed(() => trimPrefixes(own.value).length > 0 || allocate.value.some((a) => a.address))
const busy = ref(false)

function findMinLength(prefix: string) {
  const pool = pools.find((p) => p.prefix === prefix)
  return pool?.min_prefix_length ?? countAddressBits(prefix)
}

function addAllocation() {
  const pool = pools[0]!.prefix
  allocate.value.push({ pool, prefix_length: findMinLength(pool), address: false })
}

async function save() {
  busy.value = true
  const body = {
    addresses: trimPrefixes(own.value),
    allocate_addresses: allocate.value.filter((a) => a.address).map((a) => a.pool),
    grants: trimPrefixes(additional.value),
    allocate_grants: allocate.value.filter((a) => !a.address).map(({ pool, prefix_length }) => ({ pool, prefix_length })),
  }
  const { id, revision } = props.device
  const device = await run(() => callApi<Device>('PUT', `/devices/${id}/addresses`, { body, revision }))
  busy.value = false
  if (device) emit('close', true)
}
</script>

<template>
  <UModal :title="`Addresses of ${device.name}`" :ui="{ content: 'sm:max-w-2xl' }">
    <template #body>
      <form class="space-y-5" @submit.prevent="save">
        <p class="text-sm text-muted">
          Own addresses are single addresses assigned to the device interface. Additional grants are further prefixes routed to this device, such as a network behind it.
          Each must belong to a pool listed below; an own address may also lie inside an additional grant. After changing own addresses, update the Address line in the device's WireGuard configuration.
        </p>
        <UFormField label="Own addresses" :error="hasOwn ? undefined : 'Keep at least one address, entered above or allocated below.'">
          <PrefixListInput v-model="own" placeholder="10.0.0.2" />
        </UFormField>
        <UFormField label="Additional grants">
          <PrefixListInput v-model="additional" placeholder="10.0.0.16/28" />
        </UFormField>
        <UFormField label="Free blocks to add when saving" :help="pools.length ? undefined : 'This interface has no pools.'">
          <div class="space-y-2">
            <div v-for="(a, i) in allocate" :key="i" class="flex items-center gap-2">
              <USelect
                v-model="a.pool"
                :items="pools.map((p) => p.prefix)"
                aria-label="Pool"
                class="flex-1 font-mono"
                @update:model-value="a.prefix_length = findMinLength($event)"
              />
              <template v-if="!a.address">
                <span class="text-muted">/</span>
                <UInputNumber v-model="a.prefix_length" :min="findMinLength(a.pool)" :max="countAddressBits(a.pool)" aria-label="Size" class="w-28" />
              </template>
              <USelect v-model="a.address" :items="kinds" aria-label="Type" class="w-40" />
              <UButton icon="i-lucide-x" color="neutral" variant="ghost" aria-label="Remove" @click="allocate.splice(i, 1)" />
            </div>
            <UButton label="Add block" icon="i-lucide-plus" color="neutral" variant="outline" size="sm" :disabled="!pools.length" @click="addAllocation" />
          </div>
        </UFormField>
        <div class="rounded-md bg-elevated p-3 text-sm">
          <div class="mb-1 font-medium">Pools on {{ device.interface_id }}</div>
          <PoolList :pools="pools" />
        </div>
        <div class="flex justify-end">
          <UButton type="submit" label="Save" :loading="busy" :disabled="!hasOwn" />
        </div>
      </form>
    </template>
  </UModal>
</template>
