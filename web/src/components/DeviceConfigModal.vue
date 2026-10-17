<script setup lang="ts">
import { renderSVG } from 'uqr'
import { computed, ref } from 'vue'
import type { DeviceConfig } from '../api'
import { buildConfigFileName, buildWgConfig } from '../wireguard'
import CopyButton from './CopyButton.vue'

const props = defineProps<{ name: string; config: DeviceConfig; privateKey: string }>()
const emit = defineEmits<{ close: [] }>()

const profileId = ref(props.config.default_profile_id)
const text = computed(() => buildWgConfig(props.config, props.privateKey, profileId.value))
const qrCode = computed(() => renderSVG(text.value))
const fileName = buildConfigFileName(props.name)

function download() {
  const link = document.createElement('a')
  link.href = URL.createObjectURL(new Blob([text.value], { type: 'text/plain' }))
  link.download = fileName
  link.click()
  URL.revokeObjectURL(link.href)
}
</script>

<template>
  <UModal :title="`Configuration for ${name}`" :dismissible="false" :close="false">
    <template #body>
      <div class="space-y-4">
        <UAlert
          color="warning"
          variant="subtle"
          icon="i-lucide-triangle-alert"
          title="This is shown only once"
          description="The private key is stored only in this browser and cannot be recovered later. Download, scan, or copy the configuration before closing."
        />
        <UFormField v-if="config.route_profiles.length > 1" label="Routes">
          <URadioGroup
            v-model="profileId"
            :items="config.route_profiles.map((p) => ({ label: p.name, value: p.id }))"
            orientation="horizontal"
          />
        </UFormField>
        <UAccordion
          :items="[
            { label: 'Show QR code', slot: 'qr' as const },
            { label: 'Show configuration', slot: 'config' as const },
          ]"
        >
          <template #qr>
            <!-- Scanners need dark modules on a light ground, whatever the color mode. -->
            <div class="mx-auto w-64 rounded-md bg-white p-2 [&>svg]:size-full" v-html="qrCode" />
          </template>
          <template #config>
            <div class="relative">
              <pre class="overflow-x-auto rounded-md bg-elevated p-3 text-xs">{{ text }}</pre>
              <CopyButton :value="text" class="absolute end-1 top-1" />
            </div>
          </template>
        </UAccordion>
        <p v-if="!config.ready" class="text-sm text-muted">The server is applying this device to the kernel. Tunnels will connect once ready.</p>
      </div>
    </template>
    <template #footer>
      <div class="flex w-full justify-end gap-2">
        <UButton label="Done" color="neutral" variant="ghost" @click="emit('close')" />
        <UButton :label="`Download ${fileName}`" icon="i-lucide-download" @click="download" />
      </div>
    </template>
  </UModal>
</template>
