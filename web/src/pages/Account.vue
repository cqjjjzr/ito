<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { callApi, type AccountView } from '../api'
import AccountStatus from '../components/AccountStatus.vue'
import QuotaUsage from '../components/QuotaUsage.vue'
import { useRun } from '../run'
import { session } from '../session'

const run = useRun()
const account = ref<AccountView>()

onMounted(async () => {
  account.value = await run(() => callApi<AccountView>('GET', `/accounts/${session.value!.account_id}`))
})
</script>

<template>
  <div v-if="account && session" class="max-w-2xl space-y-8">
    <div>
      <div class="flex items-center gap-3">
        <h1 class="text-2xl font-semibold">{{ account.display_name }}</h1>
        <AccountStatus :account="account" />
        <UBadge v-if="session.admin" label="Administrator" color="neutral" variant="subtle" />
      </div>
      <p class="mt-1 font-mono text-sm text-muted">{{ account.subject }}</p>
    </div>
    <dl class="grid gap-6 sm:grid-cols-2">
      <div>
        <dt class="mb-1 text-sm text-muted">IPv4 addresses</dt>
        <dd><QuotaUsage :used="account.usage.ipv4" :limit="account.limits.ipv4" :bits="32" /></dd>
      </div>
      <div>
        <dt class="mb-1 text-sm text-muted">IPv6 addresses</dt>
        <dd><QuotaUsage :used="account.usage.ipv6" :limit="account.limits.ipv6" :bits="128" /></dd>
      </div>
      <div>
        <dt class="mb-1 text-sm text-muted">Member since</dt>
        <dd>{{ new Date(account.created_at).toLocaleDateString() }}</dd>
      </div>
      <div>
        <dt class="mb-1 text-sm text-muted">Session ends</dt>
        <dd>{{ new Date(session.expires_at).toLocaleString() }}</dd>
      </div>
    </dl>
  </div>
</template>
