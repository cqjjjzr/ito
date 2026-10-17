<script setup lang="ts">
defineProps<{ title: string; description: string; confirm: string }>()
const emit = defineEmits<{ close: [boolean] }>()
</script>

<template>
  <UModal :title="title" :description="description">
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton label="Cancel" color="neutral" variant="ghost" @click="emit('close', false)" />
        <UButton :label="confirm" color="error" @click="emit('close', true)" />
      </div>
    </template>
  </UModal>
</template>
