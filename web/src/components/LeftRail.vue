<script setup lang="ts">
import { store, actions } from "../store";

// BloodHound CE v5 left icon rail: a 48px vertical nav that swaps the 320px
// panel between Search / Queries / Filters / Info, plus an Advanced toggle that
// slides the Orca analytic drawer over the canvas.
const tabs = [
  { id: "search", icon: "🔍", label: "Search" },
  { id: "queries", icon: "📋", label: "Queries" },
  { id: "filters", icon: "🎛", label: "Filters" },
  { id: "info", icon: "ℹ", label: "Info" },
] as const;
</script>

<template>
  <nav class="left-rail">
    <button
      v-for="t in tabs"
      :key="t.id"
      class="rail-btn"
      :class="{ on: store.activeTab === t.id }"
      :title="t.label"
      @click="actions.setActiveTab(t.id)"
    >
      <span class="ic">{{ t.icon }}</span>
      <span class="lbl">{{ t.label }}</span>
    </button>

    <div class="spacer"></div>

    <button
      class="rail-btn adv"
      :class="{ on: store.advancedOpen }"
      title="Advanced — Orca analytic layer (objective, foothold, advisories, chokepoints, ranked paths)"
      @click="actions.toggleAdvanced()"
    >
      <span class="ic">⚙</span>
      <span class="lbl">Advanced</span>
    </button>
  </nav>
</template>

<style scoped>
.left-rail {
  display: flex;
  flex-direction: column;
  align-items: stretch;
  width: 48px;
  background: var(--panel-2);
  border-right: 1px solid var(--line);
  padding: 8px 0;
}
.rail-btn {
  position: relative;
  display: flex;
  flex-direction: column;
  align-items: center;
  gap: 2px;
  height: 56px;
  border: none;
  background: transparent;
  color: var(--muted);
  cursor: pointer;
  padding: 0;
}
.rail-btn .ic { font-size: 17px; line-height: 1; }
.rail-btn .lbl { font-size: 9px; letter-spacing: .3px; }
.rail-btn:hover { color: var(--fg); background: rgba(255, 255, 255, 0.03); }
.rail-btn.on { color: var(--accent); }
.rail-btn.on::before {
  content: "";
  position: absolute;
  left: 0; top: 8px; bottom: 8px;
  width: 3px;
  background: var(--accent);
  border-radius: 0 2px 2px 0;
}
.rail-btn.adv { color: var(--warn); }
.rail-btn.adv.on { color: var(--warn); }
.rail-btn.adv.on::before { background: var(--warn); }
.spacer { flex: 1; }
</style>