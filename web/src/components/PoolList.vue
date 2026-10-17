<script setup lang="ts">
import type { Interface } from '../api'
import { countAddressBits } from '../wireguard'

defineProps<{ pools: Interface['pools'] }>()
</script>

<template>
  <ul class="space-y-0.5 text-sm text-muted">
    <li v-for="p in pools" :key="p.prefix">
      <span class="font-mono text-default">{{ p.prefix }}</span>:
      blocks of /{{ p.min_prefix_length ?? countAddressBits(p.prefix) }} to /{{ countAddressBits(p.prefix) }},
      up to {{ p.max_prefixes }} per device<template v-if="p.exclusions?.length">, excluding {{ p.exclusions?.join(', ') }}</template>
    </li>
    <li v-if="!pools.length">No pools.</li>
  </ul>
</template>
