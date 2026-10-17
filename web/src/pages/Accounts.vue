<script setup lang="ts">
import type { DropdownMenuItem, TableColumn } from '@nuxt/ui'
import { useOverlay } from '@nuxt/ui/composables'
import { onMounted, ref } from 'vue'
import { callApi, type AccountView } from '../api'
import AccountPolicyModal from '../components/AccountPolicyModal.vue'
import AccountStatus from '../components/AccountStatus.vue'
import ConfirmModal from '../components/ConfirmModal.vue'
import QuotaUsage from '../components/QuotaUsage.vue'
import { useRun } from '../run'
import { session } from '../session'

const run = useRun()
const overlay = useOverlay()
const policyModal = overlay.create(AccountPolicyModal)
const confirmModal = overlay.create(ConfirmModal)
const accounts = ref<AccountView[]>([])

async function load() {
  await run(async () => {
    const list = await callApi<AccountView[]>('GET', '/accounts')
    accounts.value = list.sort((a, b) => a.display_name.localeCompare(b.display_name))
  })
}
onMounted(load)

async function editPolicy(account: AccountView) {
  if (await policyModal.open({ account })) await load()
}

async function setBlocked(a: AccountView, blocked: boolean) {
  const description = 'Signs out the account and disables WireGuard keys and agent logins for all of its devices.'
  if (blocked && !(await confirmModal.open({ title: `Block ${a.display_name}?`, description, confirm: 'Block' }))) return
  const body = { blocked, quota: { ipv4: a.quota_ipv4, ipv6: a.quota_ipv6 } }
  await run(() => callApi('PUT', `/accounts/${a.id}/policy`, { body, revision: a.revision }), blocked ? 'Blocked' : 'Unblocked')
  await load()
}

function buildMenu(a: AccountView): DropdownMenuItem[] {
  return [
    { label: 'Edit', icon: 'i-lucide-pencil', onSelect: () => editPolicy(a) },
    {
      label: a.blocked ? 'Unblock' : 'Block',
      icon: 'i-lucide-ban',
      // The server refuses to let administrators block themselves.
      disabled: a.id === session.value?.account_id,
      onSelect: () => setBlocked(a, !a.blocked),
    },
  ]
}

const columns: TableColumn<AccountView>[] = [
  { accessorKey: 'display_name', header: 'Name' },
  { id: 'status', header: 'Status' },
  { id: 'ipv4', header: 'IPv4' },
  { id: 'ipv6', header: 'IPv6' },
  { accessorKey: 'created_at', header: 'Since' },
  { id: 'actions' },
]
</script>

<template>
  <div class="space-y-6">
    <div class="flex items-center justify-between">
      <h1 class="text-2xl font-semibold">Accounts</h1>
      <UTooltip text="Fetch account status from identity provider now">
        <UButton
          label="Check status"
          icon="i-lucide-refresh-cw"
          color="neutral"
          variant="outline"
          @click="run(() => callApi('POST', '/accounts/refresh'), 'Status check started')"
        />
      </UTooltip>
    </div>
    <UTable :data="accounts" :columns="columns">
      <template #display_name-cell="{ row: { original: a } }">
        <div class="font-medium text-highlighted">
          {{ a.display_name }}
          <UBadge v-if="a.id === session?.account_id" label="You" color="neutral" variant="subtle" size="sm" />
        </div>
        <div class="font-mono text-xs text-muted">{{ a.subject }}</div>
      </template>
      <template #status-cell="{ row: { original: a } }">
        <AccountStatus :account="a" />
        <UTooltip v-if="a.idp_check_error" text="Last identity provider status fetch failed">
          <UIcon name="i-lucide-triangle-alert" class="ms-2 align-middle text-warning" />
        </UTooltip>
      </template>
      <template #ipv4-cell="{ row: { original: a } }">
        <QuotaUsage :used="a.usage.ipv4" :limit="a.limits.ipv4" :bits="32" />
      </template>
      <template #ipv6-cell="{ row: { original: a } }">
        <QuotaUsage :used="a.usage.ipv6" :limit="a.limits.ipv6" :bits="128" />
      </template>
      <template #created_at-cell="{ row: { original: a } }">
        {{ new Date(a.created_at).toLocaleDateString() }}
      </template>
      <template #actions-cell="{ row: { original: a } }">
        <div class="flex justify-end">
          <UDropdownMenu :items="buildMenu(a)" :content="{ align: 'end' }">
            <UButton icon="i-lucide-ellipsis-vertical" color="neutral" variant="ghost" aria-label="More actions" />
          </UDropdownMenu>
        </div>
      </template>
    </UTable>
  </div>
</template>
