<script setup lang="ts">
import { computed } from "vue";
import { store, actions, availableKinds, availablePreds } from "../store";
import RiskFilterBar from "./RiskFilterBar.vue";

// BloodHound-style filters: node labels, edges, and risk/visibility. A kind or
// pred is HIDDEN when present in the set (so "all" = empty set), matching BH's
// "unchecked = hidden" semantics. Counts come from the loaded graph.

const kinds = computed(() => availableKinds());
const preds = computed(() => availablePreds());

function kindShown(k: string): boolean { return !store.hiddenKinds.has(k); }
function predShown(p: string): boolean { return !store.hiddenPreds.has(p); }
</script>

<template>
  <div class="tab">
    <h3>Filters</h3>

    <section class="fsect">
      <div class="fhead">
        <span>Node labels</span>
        <span class="fmini">
          <button @click="actions.selectAllKinds()">All</button>
          <button @click="actions.clearKinds()">None</button>
        </span>
      </div>
      <label v-for="k in kinds" :key="k.kind" class="frow">
        <input type="checkbox" :checked="kindShown(k.kind)" @change="actions.toggleKind(k.kind)" />
        <span class="fname">{{ k.kind }}</span>
        <span class="fcnt">{{ k.count }}</span>
      </label>
      <div v-if="!kinds.length" class="muted">No graph loaded.</div>
    </section>

    <section class="fsect">
      <div class="fhead">
        <span>Edges</span>
        <span class="fmini">
          <button @click="actions.selectAllPreds()">All</button>
          <button @click="actions.clearPreds()">None</button>
        </span>
      </div>
      <label v-for="p in preds" :key="p.pred" class="frow">
        <input type="checkbox" :checked="predShown(p.pred)" @change="actions.togglePred(p.pred)" />
        <span class="fname">{{ p.pred }}</span>
        <span class="fcnt">{{ p.count }}</span>
      </label>
      <div v-if="!preds.length" class="muted">No edges in the loaded graph.</div>
    </section>

    <section class="fsect">
      <div class="fhead"><span>Risk &amp; visibility</span></div>
      <label class="frow">
        <input type="checkbox" v-model="store.hideBoring" />
        <span class="fname">Hide nodes not on an attack path</span>
      </label>
      <RiskFilterBar inline />
    </section>
  </div>
</template>

<style scoped>
.fsect { padding: 4px 0 12px; border-bottom: 1px solid var(--line); margin-bottom: 8px; }
.fsect:last-child { border-bottom: none; }
.fhead {
  display: flex;
  align-items: center;
  justify-content: space-between;
  font-size: 11px;
  text-transform: uppercase;
  letter-spacing: .5px;
  color: var(--muted);
  margin-bottom: 6px;
}
.fmini { display: inline-flex; gap: 4px; }
.fmini button {
  font-size: 10px;
  padding: 1px 6px;
  border-radius: 4px;
  border: 1px solid var(--line);
  background: transparent;
  color: var(--muted);
  cursor: pointer;
}
.fmini button:hover { color: var(--fg); border-color: var(--accent); }
.frow {
  display: flex;
  align-items: center;
  gap: 8px;
  padding: 4px 4px;
  font-size: 12px;
  color: var(--fg);
  cursor: pointer;
}
.frow:hover { background: var(--panel); border-radius: 4px; }
.frow .fname { flex: 1; }
.frow .fcnt { color: var(--muted); font-variant-numeric: tabular-nums; font-size: 11px; }
.muted { color: var(--muted); font-size: 12px; padding: 6px 4px; }
</style>