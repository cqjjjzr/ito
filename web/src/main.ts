import ui from '@nuxt/ui/vue-plugin'
import { createApp } from 'vue'
import App from './App.vue'
import './main.css'
import { pageProblem, readEmbeddedProblem } from './problem'
import { router } from './router'

pageProblem.value = readEmbeddedProblem()
createApp(App).use(router).use(ui).mount('#app')
