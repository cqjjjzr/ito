<script setup lang="ts">
import { ref } from 'vue'
import { callApi, type AccountView } from '../api'
import { useRun } from '../run'

const props = defineProps<{ account: AccountView }>()
/** Closes with `true` once saved, so the opener reloads. */
const emit = defineEmits<{ close: [saved?: true] }>()
const run = useRun()

const blocked = ref(props.account.blocked)
const ipv4 = ref(props.account.quota_ipv4)
const ipv6 = ref(props.account.quota_ipv6)
const busy = ref(false)

async function save() {
  busy.value = true
  const { id, revision } = props.account
  const body = { blocked: blocked.value, quota: { ipv4: ipv4.value, ipv6: ipv6.value } }
  const account = await run(() => callApi<AccountView>('PUT', `/accounts/${id}/policy`, { body, revision }))
  busy.value = false
  if (account) emit('close', true)
}
</script>

<template>
  <UModal :title="`Edit ${account.display_name}`">
    <template #body>
      <form class="space-y-4" @submit.prevent="save">
        <p class="text-sm text-muted">
          A limit is an address count (such as 16) or a prefix length (such as /64), across all of the account's devices.
          Leave empty for the default limit.
        </p>
        <div class="grid gap-4 sm:grid-cols-2">
          <UFormField label="IPv4 limit">
            <UInput v-model="ipv4" placeholder="Default" class="w-full" />
          </UFormField>
          <UFormField label="IPv6 limit">
            <UInput v-model="ipv6" placeholder="Default" class="w-full" />
          </UFormField>
        </div>
        <USwitch v-model="blocked" label="Blocked" description="Signs out the account and disables WireGuard keys and agent logins for all of its devices." />
        <div class="flex justify-end">
          <UButton type="submit" label="Save" :loading="busy" />
        </div>
      </form>
    </template>
  </UModal>
</template>
