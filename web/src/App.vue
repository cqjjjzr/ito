<script setup lang="ts">
import { computed } from 'vue'
import { useRoute } from 'vue-router'
import Problem from './pages/Problem.vue'
import { pageProblem } from './problem'
import { session, signOut } from './session'

const route = useRoute()
const links = computed(() => [
  { label: 'Devices', to: '/devices' },
  { label: 'Networks', to: '/networks' },
  ...(session.value?.admin ? [{ label: 'Accounts', to: '/accounts' }] : []),
  { label: 'Account', to: '/account' },
])
</script>

<template>
  <UApp>
    <Problem v-if="pageProblem" :problem="pageProblem" />
    <RouterView v-else-if="route.meta.public" />
    <template v-else-if="session">
      <header class="border-b border-default">
        <div class="mx-auto flex h-14 max-w-6xl items-center gap-6 px-4">
          <RouterLink to="/" class="flex items-center gap-2 font-semibold">
            <img src="/logo.svg" alt="" class="size-7">
            Ito
          </RouterLink>
          <nav class="flex gap-1">
            <UButton
              v-for="link in links"
              :key="link.to"
              v-bind="link"
              color="neutral"
              variant="ghost"
              active-color="neutral"
              active-variant="soft"
            />
          </nav>
          <div class="ms-auto flex gap-1">
            <UColorModeButton />
            <UTooltip text="Sign out">
              <UButton icon="i-lucide-log-out" color="neutral" variant="ghost" aria-label="Sign out" @click="signOut" />
            </UTooltip>
          </div>
        </div>
      </header>
      <main class="mx-auto max-w-6xl px-4 py-8">
        <RouterView />
      </main>
    </template>
  </UApp>
</template>
