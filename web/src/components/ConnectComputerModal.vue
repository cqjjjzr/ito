<script setup lang="ts">
import type { Device } from '../api'
import CopyField from './CopyField.vue'

const props = defineProps<{ device: Device }>()
const portal = location.origin
const link = `ito-wg://connect?portal=${encodeURIComponent(portal)}&device=${props.device.id}`
const command = `ito-agent login ${portal} --device ${props.device.id}`
</script>

<template>
  <UModal :title="`Connect a computer as ${device.name}`">
    <template #body>
      <div class="space-y-5">
        <p class="text-sm text-muted">
          The computer displays a confirmation code and opens this portal to approve it. A computer already connected as {{ device.name }} will be <strong>disconnected</strong>.
        </p>
        <UFormField label="Windows, with the Ito tray">
          <UButton :to="link" external label="Open in the Ito tray" icon="i-lucide-external-link" color="neutral" variant="outline" />
        </UFormField>
        <UFormField label="Linux or Windows command" description="Run as root on Linux or in an administrator terminal on Windows.">
          <CopyField :value="command" />
        </UFormField>
      </div>
    </template>
  </UModal>
</template>
