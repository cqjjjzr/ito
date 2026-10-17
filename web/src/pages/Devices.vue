<script setup lang="ts">
import type { DropdownMenuItem, TableColumn } from '@nuxt/ui'
import { useOverlay } from '@nuxt/ui/composables'
import { computed, onMounted, ref } from 'vue'
import { callApi, type AccountView, type Device, type DeviceConfig, type Interface } from '../api'
import ConfirmModal from '../components/ConfirmModal.vue'
import ConnectComputerModal from '../components/ConnectComputerModal.vue'
import DeviceAddressesModal from '../components/DeviceAddressesModal.vue'
import DeviceConfigModal from '../components/DeviceConfigModal.vue'
import DeviceCreateModal from '../components/DeviceCreateModal.vue'
import DeviceDetails from '../components/DeviceDetails.vue'
import DeviceEditModal from '../components/DeviceEditModal.vue'
import DeviceKeyModal from '../components/DeviceKeyModal.vue'
import DevicePskModal from '../components/DevicePskModal.vue'
import DeviceRoutesModal from '../components/DeviceRoutesModal.vue'
import { isDeviceChanging, usePolling } from '../polling'
import { useRun } from '../run'
import { session } from '../session'
import type { KeyPair } from '../wireguard'

const run = useRun()
const overlay = useOverlay()
const modals = {
  confirm: overlay.create(ConfirmModal),
  connect: overlay.create(ConnectComputerModal),
  addresses: overlay.create(DeviceAddressesModal),
  config: overlay.create(DeviceConfigModal),
  create: overlay.create(DeviceCreateModal),
  edit: overlay.create(DeviceEditModal),
  key: overlay.create(DeviceKeyModal),
  psk: overlay.create(DevicePskModal),
  routes: overlay.create(DeviceRoutesModal),
}

const admin = session.value!.admin
const devices = ref<Device[]>([])
const interfaces = ref<Interface[]>([])
const accounts = ref<AccountView[]>()
const ownerNames = computed(() => new Map(accounts.value?.map((a) => [a.id, a.display_name])))

const load = usePolling(
  () =>
    run(async () => {
      const list = await callApi<Device[]>('GET', '/devices')
      devices.value = list.sort((a, b) => a.name.localeCompare(b.name))
    }),
  () => devices.value.some(isDeviceChanging),
)
onMounted(async () => {
  await run(async () => {
    interfaces.value = await callApi<Interface[]>('GET', '/interfaces')
    if (admin) accounts.value = await callApi<AccountView[]>('GET', '/accounts')
  })
  await load()
})

const reasons: Record<NonNullable<Device['disabled_reason']>, string> = {
  interface_not_configured: 'Interface removed',
  interface_disabled: 'Interface disabled',
  deleting: 'Deleting',
  blocked: 'Blocked',
  account_inactive: 'Account inactive',
  paused: 'Paused',
  outside_pools: 'Outside pools',
  address_conflict: 'Address conflict',
  no_key: 'No key',
  key_expired: 'Key expired',
  unknown: 'Unavailable',
}

function describeState(d: Device) {
  if (d.apply_error) return { label: 'Apply failed', color: 'error' as const }
  if (d.applied_revision !== d.revision) return { label: 'Applying', color: 'info' as const }
  if (d.disabled_reason) {
    const quiet = d.disabled_reason === 'paused' || d.disabled_reason === 'deleting'
    return { label: reasons[d.disabled_reason] ?? 'Unavailable', color: quiet ? ('neutral' as const) : ('warning' as const) }
  }
  return { label: 'Ready', color: 'success' as const }
}

/** Returns true if the current user cannot edit or delete `d`. */
const isLocked = (d: Device) => d.deleting || (d.blocked && !admin)

const columns: TableColumn<Device>[] = [
  { id: 'expand' },
  { accessorKey: 'name', header: 'Name' },
  { accessorKey: 'client_addresses', header: 'Addresses' },
  ...(admin ? [{ id: 'owner', header: 'Owner' }] : []),
  { accessorKey: 'interface_id', header: 'Interface' },
  { id: 'actions' },
]

/** Opens the device creation modal, then sets up the new device's key. */
async function create() {
  const props = { interfaces: interfaces.value, accounts: accounts.value, defaultAccountId: session.value!.account_id }
  const created = await modals.create.open(props)
  if (created) await setUpKey(created.device, created.keys)
  else await load()
}

/** Binds `keys.publicKey` to `d` and opens the client configuration modal with `keys.privateKey`. */
async function setUpKey(d: Device, keys: KeyPair) {
  const config = await run(async () => {
    await callApi('POST', `/devices/${d.id}/key`, { body: { public_key: keys.publicKey }, revision: d.revision })
    return callApi<DeviceConfig>('GET', `/devices/${d.id}/config`)
  })
  await load()
  if (!config) return
  await modals.config.open({ name: d.name, config, privateKey: keys.privateKey })
}

async function confirm(title: string, description: string, label: string) {
  return (await modals.confirm.open({ title, description, confirm: label })) === true
}

async function runThenReload(request: () => Promise<unknown>, success: string) {
  await run(request, success)
  await load()
}

async function replaceKey(d: Device) {
  const keys = await modals.key.open({ device: d })
  if (keys) await setUpKey(d, keys)
}

async function openThenReload<P>(modal: { open: (props: P) => PromiseLike<unknown> }, props: P) {
  await modal.open(props)
  await load()
}

function buildMenu(d: Device): DropdownMenuItem[][] {
  const path = `/devices/${d.id}`
  const revision = d.revision
  return [
    [
      {
        label: 'Renew key',
        icon: 'i-lucide-timer-reset',
        disabled: !d.public_key || isLocked(d),
        onSelect: () => runThenReload(() => callApi('POST', `${path}/key`, { body: {}, revision }), 'Key renewed'),
      },
      {
        label: d.paused ? 'Resume' : 'Pause',
        icon: d.paused ? 'i-lucide-play' : 'i-lucide-pause',
        disabled: d.deleting,
        onSelect: () => runThenReload(() => callApi('PATCH', path, { body: { paused: !d.paused }, revision }), d.paused ? 'Resumed' : 'Paused'),
      },
      { label: 'Preshared key', icon: 'i-lucide-shield', disabled: isLocked(d), onSelect: () => openThenReload(modals.psk, { device: d }) },
      { label: 'Connect a computer', icon: 'i-lucide-monitor-smartphone', disabled: d.deleting || d.blocked, onSelect: () => openThenReload(modals.connect, { device: d }) },
    ],
    ...(admin
      ? [
          [
            { label: 'Server routes', icon: 'i-lucide-route', disabled: d.deleting, onSelect: () => openThenReload(modals.routes, { device: d }) },
            {
              label: d.blocked ? 'Unblock' : 'Block',
              icon: 'i-lucide-ban',
              disabled: d.deleting,
              onSelect: () => runThenReload(() => callApi('POST', `${path}/${d.blocked ? 'unblock' : 'block'}`), d.blocked ? 'Unblocked' : 'Blocked'),
            },
          ],
        ]
      : []),
    [
      {
        label: 'Revoke',
        icon: 'i-lucide-circle-slash',
        disabled: d.deleting,
        onSelect: async () => {
          const description = 'Removes the device WireGuard key and agent login while keeping its IP addresses. It needs a new key to reconnect.'
          if (await confirm(`Revoke ${d.name}?`, description, 'Revoke')) await runThenReload(() => callApi('POST', `${path}/revoke`), 'Revoked')
        },
      },
      {
        label: 'Delete',
        icon: 'i-lucide-trash-2',
        color: 'error',
        disabled: isLocked(d),
        onSelect: async () => {
          const description = 'Permanently removes this device and frees its allocated addresses.'
          if (await confirm(`Delete ${d.name}?`, description, 'Delete')) await runThenReload(() => callApi('DELETE', path), 'Deleted')
        },
      },
    ],
  ]
}
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <h1 class="text-2xl font-semibold">Devices</h1>
      <UButton label="New device" icon="i-lucide-plus" :disabled="!interfaces.length" @click="create" />
    </div>
    <UTable :data="devices" :columns="columns" :get-row-id="(d: Device) => d.id" :ui="{ td: 'align-top' }">
      <template #expand-cell="{ row }">
        <UButton
          icon="i-lucide-chevron-right"
          color="neutral"
          variant="ghost"
          :aria-label="row.getIsExpanded() ? 'Hide details' : 'Show details'"
          :aria-expanded="row.getIsExpanded()"
          :ui="{ leadingIcon: ['transition-transform', row.getIsExpanded() ? 'rotate-90' : ''] }"
          @click="row.toggleExpanded()"
        />
      </template>
      <template #name-cell="{ row: { original: d } }">
        <div class="flex items-center gap-2">
          <span class="font-medium text-highlighted">{{ d.name }}</span>
          <UBadge v-bind="describeState(d)" variant="subtle" size="sm" />
        </div>
      </template>
      <template #client_addresses-cell="{ row: { original: d } }">
        <div class="font-mono text-xs">
          <div v-for="a in d.client_addresses" :key="a">{{ a }}</div>
        </div>
      </template>
      <template #owner-cell="{ row: { original: d } }">
        {{ ownerNames.get(d.account_id) ?? d.account_id }}
      </template>
      <template #actions-cell="{ row: { original: d } }">
        <div class="flex justify-end gap-1">
          <UTooltip text="Edit">
            <UButton icon="i-lucide-pencil" color="neutral" variant="ghost" aria-label="Edit" :disabled="d.deleting" @click="openThenReload(modals.edit, { device: d })" />
          </UTooltip>
          <UTooltip text="Addresses">
            <UButton
              icon="i-lucide-network"
              color="neutral"
              variant="ghost"
              aria-label="Addresses"
              :disabled="isLocked(d)"
              @click="openThenReload(modals.addresses, { device: d, interface: interfaces.find((i) => i.name === d.interface_id) })"
            />
          </UTooltip>
          <UTooltip :text="d.public_key ? 'New key' : 'Set up key'">
            <UButton icon="i-lucide-key-round" color="neutral" variant="ghost" :aria-label="d.public_key ? 'New key' : 'Set up key'" :disabled="isLocked(d)" @click="replaceKey(d)" />
          </UTooltip>
          <UDropdownMenu :items="buildMenu(d)" :content="{ align: 'end' }">
            <UButton icon="i-lucide-ellipsis-vertical" color="neutral" variant="ghost" aria-label="More actions" />
          </UDropdownMenu>
        </div>
      </template>
      <template #expanded="{ row }">
        <DeviceDetails :key="row.original.revision" :device="row.original" />
      </template>
      <template #empty>
        <p class="py-6 text-muted">No devices yet.</p>
      </template>
    </UTable>
  </div>
</template>
