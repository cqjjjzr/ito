<script setup lang="ts">
import { onMounted, ref } from 'vue'
import { callApi, type Interface } from '../api'
import CopyField from '../components/CopyField.vue'
import PoolList from '../components/PoolList.vue'
import { useRun } from '../run'

const run = useRun()
const interfaces = ref<Interface[]>([])

onMounted(async () => {
  interfaces.value = (await run(() => callApi<Interface[]>('GET', '/interfaces'))) ?? []
})

function describeState(i: Interface) {
  if (i.disabled) return { label: 'Disabled', color: 'neutral' as const }
  if (i.apply_error) return { label: 'Apply failed', color: 'error' as const }
  return i.applied ? { label: 'Ready', color: 'success' as const } : { label: 'Applying', color: 'info' as const }
}
</script>

<template>
  <div class="space-y-6">
    <h1 class="text-2xl font-semibold">Networks</h1>
    <section v-for="i in interfaces" :key="i.name" class="space-y-5 rounded-lg border border-default p-5">
      <div class="flex items-center gap-2">
        <h2 class="font-mono text-lg font-medium">{{ i.name }}</h2>
        <UBadge v-bind="describeState(i)" variant="subtle" size="sm" />
      </div>
      <p v-if="i.apply_error" class="text-sm text-error">{{ i.apply_error }}</p>
      <dl class="grid gap-x-8 gap-y-3 text-sm sm:grid-cols-2 lg:grid-cols-3">
        <div>
          <dt class="text-muted">Endpoint</dt>
          <dd class="font-mono">{{ i.endpoint }}</dd>
        </div>
        <div>
          <dt class="text-muted">Server addresses</dt>
          <dd class="font-mono">{{ i.addresses.join(', ') || '—' }}</dd>
        </div>
        <div>
          <dt class="text-muted">MTU</dt>
          <dd>{{ i.mtu }} on the server, {{ i.client_mtu || 'automatic' }} on clients</dd>
        </div>
        <div>
          <dt class="text-muted">DNS servers</dt>
          <dd class="font-mono">{{ i.dns.join(', ') || '—' }}</dd>
        </div>
        <div>
          <dt class="text-muted">DNS zone</dt>
          <dd class="font-mono">{{ i.dns_zone || '—' }}</dd>
        </div>
        <div>
          <dt class="text-muted">Search domains</dt>
          <dd class="font-mono">{{ i.dns_search.join(', ') || '—' }}</dd>
        </div>
        <div>
          <dt class="text-muted">Keepalive</dt>
          <dd>{{ i.keepalive ? `${i.keepalive} s` : 'None' }}</dd>
        </div>
        <div class="sm:col-span-2">
          <dt class="mb-1 text-muted">Server public key</dt>
          <dd><CopyField :value="i.public_key" /></dd>
        </div>
      </dl>
      <div>
        <h3 class="mb-1 text-sm font-medium">Route profiles</h3>
        <ul class="space-y-0.5 text-sm text-muted">
          <li v-for="p in i.route_profiles" :key="p.id">
            <span class="text-default">{{ p.name }}</span>
            <UBadge v-if="p.id === i.default_profile_id" label="Default" color="neutral" variant="subtle" size="sm" class="mx-1" />:
            <span class="font-mono">{{ p.allowed_ips.join(', ') }}</span>
          </li>
          <li v-if="!i.route_profiles.length">None; clients route all interface pools.</li>
        </ul>
      </div>
      <div>
        <h3 class="mb-1 text-sm font-medium">Pools</h3>
        <PoolList :pools="i.pools" />
      </div>
    </section>
  </div>
</template>
