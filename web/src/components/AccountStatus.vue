<script setup lang="ts">
import { computed } from 'vue'
import type { AccountView } from '../api'

const props = defineProps<{ account: AccountView }>()

const badge = computed(() => {
  const a = props.account
  if (a.blocked) return { label: 'Blocked', color: 'error' as const }
  if (a.idp_status === 'disabled') return { label: 'Disabled at provider', color: 'error' as const }
  if (a.idp_status === 'missing') return { label: 'Missing at provider', color: 'error' as const }
  return { label: 'Active', color: 'success' as const }
})
</script>

<template>
  <UBadge :label="badge.label" :color="badge.color" variant="subtle" />
</template>
