<script setup lang="ts">
import { onMounted } from "vue";
import { store, actions } from "./store";
import GraphCanvas from "./components/GraphCanvas.vue";
import LeftRail from "./components/LeftRail.vue";
import SearchTab from "./components/SearchTab.vue";
import QueriesTab from "./components/QueriesTab.vue";
import FiltersTab from "./components/FiltersTab.vue";
import InfoTab from "./components/InfoTab.vue";
import ContextMenu from "./components/ContextMenu.vue";
import AdvancedDrawer from "./components/AdvancedDrawer.vue";
import PathDock from "./components/PathDock.vue";

// BloodHound CE v5 shell: a 44px top bar over a work area split into a 48px
// icon rail, a 320px tabbed left panel, and the full-width graph canvas. The
// Orca analytic layer (objective / foothold / advisories / chokepoints / ranked
// paths / path inspector) slides over the canvas as an Advanced drawer, so the
// core BloodHound flow stays pure. Node info lives in the Info tab, not a modal.
onMounted(actions.refresh);
</script>

<template>
  <div class="app-shell">
    <header class="topbar">
      <div class="brand">
        <div class="brand-mark">ORCA</div>
        <span class="brand-sub">BloodHound-compatible attack-path view</span>
      </div>

      <div class="top-stats">
        {{ store.stats?.nodes ?? "-" }} nodes · {{ store.stats?.facts ?? "-" }} facts
      </div>

      <div class="status-line" v-if="store.error">{{ store.error }}</div>
      <div class="status-line busy" v-else-if="store.findingsLoading || store.graphLoading || store.searching">
        Processing latest view
      </div>

      <div class="top-spacer"></div>

      <button class="adv-btn" :class="{ on: store.advancedOpen }" @click="actions.toggleAdvanced()" title="Toggle the Orca Advanced drawer">
        ⚙ Advanced
      </button>
      <button class="icon-btn refresh" @click="actions.refresh" :disabled="store.loading" title="Refresh analysis">
        <span class="spin-dot" v-if="store.loading"></span>
        <span v-else>↻</span>
      </button>
    </header>

    <div class="work-area">
      <LeftRail />

      <aside class="left-panel">
        <SearchTab v-if="store.activeTab === 'search'" />
        <QueriesTab v-else-if="store.activeTab === 'queries'" />
        <FiltersTab v-else-if="store.activeTab === 'filters'" />
        <InfoTab v-else />
      </aside>

      <section class="canvas-stage">
        <GraphCanvas />
        <AdvancedDrawer />
        <PathDock />
      </section>
    </div>

    <ContextMenu />
  </div>
</template>