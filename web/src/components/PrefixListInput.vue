<script setup lang="ts">
const prefixes = defineModel<string[]>({ required: true })
defineProps<{ placeholder?: string }>()
</script>

<template>
  <div class="space-y-2">
    <div v-for="(_, i) in prefixes" :key="i" class="flex gap-2">
      <UInput v-model="prefixes[i]" :placeholder="placeholder" class="flex-1" :ui="{ base: 'font-mono' }" />
      <UButton icon="i-lucide-x" color="neutral" variant="ghost" aria-label="Remove" @click="prefixes.splice(i, 1)" />
    </div>
    <UButton label="Add" icon="i-lucide-plus" color="neutral" variant="outline" size="sm" @click="prefixes.push('')" />
  </div>
</template>
