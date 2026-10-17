<template>
  <div class="relative flex min-h-dvh flex-col items-center justify-center overflow-hidden px-4">
    <div class="glow" aria-hidden="true" />
    <svg class="thread" viewBox="0 0 1200 800" preserveAspectRatio="xMidYMid slice" aria-hidden="true">
      <path d="M-40 640C160 520 220 760 420 640S560 300 600 330 700 520 820 420 980 120 1240 180" />
    </svg>
    <UColorModeButton class="absolute end-4 top-4" />
    <img src="/logo.svg" alt="" class="ball size-32">
    <h1 class="mt-6 text-6xl font-semibold tracking-tight">Ito</h1>
    <p class="mt-3 text-muted">WireGuard self-service</p>
    <UButton to="/api/v1/auth/login" external size="xl" class="mt-10 px-8" label="Sign in" trailing-icon="i-lucide-arrow-right" />
  </div>
</template>

<style scoped>
.glow {
  position: absolute;
  inset: -20%;
  z-index: -1;
  background:
    radial-gradient(40% 35% at 30% 30%, color-mix(in oklab, var(--color-ito-400) 45%, transparent), transparent),
    radial-gradient(35% 30% at 75% 70%, color-mix(in oklab, var(--color-ito-600) 30%, transparent), transparent);
  filter: blur(40px);
}

.thread {
  position: absolute;
  inset: 0;
  z-index: -1;
  width: 100%;
  height: 100%;
  fill: none;
  stroke: var(--color-ito-400);
  stroke-width: 3;
  stroke-linecap: round;
  stroke-dasharray: 2400;
  stroke-dashoffset: 2400;
  opacity: 0.6;
  animation: unwind 3s ease-out forwards;
}

.ball {
  animation: roll 3s ease-out;
}

@keyframes unwind {
  to { stroke-dashoffset: 0; }
}

@keyframes roll {
  from { transform: translateX(-30vw) rotate(-540deg); }
}

@media (prefers-reduced-motion: reduce) {
  .thread, .ball { animation: none; stroke-dashoffset: 0; }
}
</style>
