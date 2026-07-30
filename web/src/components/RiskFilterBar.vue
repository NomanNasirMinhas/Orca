<script setup lang="ts">
import { computed } from "vue";
import { store, actions, availableRisks, riskFilterActive, nodeMatchesRiskFilter } from "../store";

// `inline` renders the bar statically inside FiltersTab (no absolute overlay)
// instead of floating over the canvas. The overlay mode is no longer used after
// the BloodHound CE redesign but the prop keeps the component reusable.
defineProps<{ inline?: boolean }>();

const risks = computed(() => availableRisks());
const active = computed(() => riskFilterActive());

// Count of nodes the "hide non-matching" toggle would remove under the current
// combine mode. Shown as a badge on the toggle so the operator sees the impact
// before flipping it.
const hiddenByRisk = computed(() => {
  if (!store.graph || !active.value) return 0;
  let n = 0;
  for (const node of store.graph.nodes) if (!nodeMatchesRiskFilter(node)) n++;
  return n;
});

function isOn(r: string) {
  return store.riskFilter.has(r);
}
</script>

<template>
  <div class="risk-bar" :class="{ inline }">
    <div class="risk-header">
      <span class="risk-title">Risk filter</span>
      <div class="combine" title="Combine selected chips: OR = match any, AND = match all">
        <button class="mini" :class="{ on: store.riskCombine === 'any' }" @click="actions.setRiskCombine('any')">OR</button>
        <button class="mini" :class="{ on: store.riskCombine === 'all' }" @click="actions.setRiskCombine('all')">AND</button>
      </div>
      <button v-if="active" class="mini clear" @click="actions.clearRisks()" title="Clear all risk chips">clear</button>
    </div>

    <div class="chips" v-if="risks.length">
      <button
        v-for="r in risks"
        :key="r.risk"
        class="chip"
        :class="{ on: isOn(r.risk) }"
        @click="actions.toggleRisk(r.risk)"
        :title="`${r.count} node(s)`"
      >
        {{ r.risk }} <span class="cnt">{{ r.count }}</span>
      </button>
    </div>
    <div v-else class="empty">No risk facets in this graph.</div>

    <button
      class="hide-toggle"
      :class="{ on: store.riskHideNonMatching && active }"
      :disabled="!active"
      @click="actions.toggleRiskHideNonMatching()"
      :title="'Hide nodes not matching the active risk chips'"
    >
      {{ store.riskHideNonMatching ? "Showing matches only" : "Hide non-matching" }}
      <span v-if="store.riskHideNonMatching && active" class="cnt">{{ hiddenByRisk }}</span>
    </button>
  </div>
</template>

<style scoped>
.risk-bar {
  position: absolute;
  top: 84px;            /* below the hide-boring toggle (top: 48px) */
  left: 12px;
  z-index: 7;
  background: rgba(18, 24, 41, 0.92);
  border: 1px solid var(--line);
  border-radius: 8px;
  padding: 8px 10px;
  font-size: 12px;
  width: min(260px, 70%);
}
/* Static placement inside FiltersTab (no canvas overlay). */
.risk-bar.inline {
  position: static;
  width: auto;
  background: transparent;
  border: none;
  padding: 0;
  z-index: auto;
}
.risk-header { display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
.risk-title { font-weight: 600; color: var(--fg); }
.combine { display: inline-flex; gap: 2px; margin-left: auto; }
.mini {
  font-size: 11px;
  padding: 2px 7px;
  border-radius: 4px;
  border: 1px solid var(--line);
  background: transparent;
  color: var(--muted);
  cursor: pointer;
}
.mini.on { color: var(--accent); border-color: var(--accent); background: rgba(76, 201, 240, 0.1); }
.mini.clear { margin-left: 4px; }
.chips { display: flex; flex-wrap: wrap; gap: 5px; margin-bottom: 6px; }
.chip {
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 20px;
  border: 1px solid var(--line);
  color: var(--muted);
  background: transparent;
  cursor: pointer;
}
.chip .cnt { opacity: 0.6; margin-left: 3px; font-variant-numeric: tabular-nums; }
.chip.on { color: var(--accent); border-color: var(--accent); background: rgba(76, 201, 240, 0.1); }
.empty { color: var(--muted); font-size: 11px; margin-bottom: 6px; }
.hide-toggle {
  width: 100%;
  font-size: 11px;
  padding: 4px 8px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: transparent;
  color: var(--muted);
  cursor: pointer;
  display: flex;
  align-items: center;
  justify-content: center;
  gap: 6px;
}
.hide-toggle.on { border-color: var(--accent); color: var(--accent); }
.hide-toggle:disabled { opacity: 0.5; cursor: default; }
.hide-toggle .cnt {
  background: var(--accent);
  color: #121629;
  border-radius: 8px;
  padding: 0 6px;
  font-size: 10px;
  font-variant-numeric: tabular-nums;
}
</style>