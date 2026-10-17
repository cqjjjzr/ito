<script setup lang="ts">
import { watch } from 'vue'
import { buildDnsLabel } from '../dns'

const label = defineModel<string>({ required: true })
const props = defineProps<{
  /** Device display name used to generate a default DNS label. */
  name: string
  /** Whether to update the DNS label automatically while `name` changes until edited manually. */
  follow?: boolean
}>()

let following = props.follow && label.value === buildDnsLabel(props.name)
watch(
  () => props.name,
  (name) => {
    if (following) label.value = buildDnsLabel(name)
  },
)
watch(label, (value) => {
  following = props.follow && value === buildDnsLabel(props.name)
})
</script>

<template>
  <UInput v-model="label" maxlength="63" pattern="[A-Za-z0-9]([A-Za-z0-9\-]*[A-Za-z0-9])?" class="w-full">
    <template #trailing>
      <UTooltip text="Generate from the name">
        <UButton
          icon="i-lucide-wand-sparkles"
          aria-label="Generate from the name"
          color="neutral"
          variant="link"
          size="sm"
          @click="label = buildDnsLabel(name)"
        />
      </UTooltip>
    </template>
  </UInput>
</template>
