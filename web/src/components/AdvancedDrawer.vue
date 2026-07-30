<script setup lang="ts">
import { computed } from "vue";
import { store, actions, footholdChips } from "../store";
import type { Objective } from "../api";
import AdvisoriesPanel from "./AdvisoriesPanel.vue";
import FindingsPanel from "./FindingsPanel.vue";

// Orca's analytic layer, hidden behind the rail's Advanced toggle so the core
// BloodHound flow (search → query → graph → info) stays uncluttered. Holds the
// cost-objective selector, the multi-foothold "owned nodes" set, graph scope +
// hops, the chokepoints overlay, advisories, the ranked findings list, and the
// path inspector — everything BloodHound doesn't have but Orca operators need.

const chips = computed(() => footholdChips());
const objectives: Objective[] = ["practical", "balanced", "fastest", "quietest", "reliable"];
const scopes = [
  { id: "priority", label: "Priority" },
  { id: "highvalue", label: "High-value" },
  { id: "focus", label: "Focus" },
  { id: "all", label: "All" },
] as const;

function setObjective(e: Event) {
  actions.setObjective((e.target as HTMLSelectElement).value as Objective);
}
type Scope = "priority" | "highvalue" | "all" | "focus";
function setScope(s: Scope) {
  if (s === "focus" && store.selectedNode) {
    actions.focusGraphOn(store.selectedNode, store.graphHops);
    return;
  }
  actions.setGraphScope(s);
}
</script>

<template>
  <aside class="advanced-drawer" :class="{ open: store.advancedOpen }">
    <div class="adv-head">
      <h3>Advanced · Orca</h3>
      <button class="x" @click="actions.toggleAdvanced()" title="Close">✕</button>
    </div>

    <div class="adv-body">
      <section class="adv-sect">
        <label class="field">
          <span class="field-label">Objective</span>
          <select :value="store.objective" @change="setObjective" :disabled="store.findingsLoading">
            <option v-for="o in objectives" :key="o" :value="o">{{ o }}</option>
          </select>
        </label>
      </section>

      <section class="adv-sect">
        <div class="sec-h">Foothold · owned nodes</div>
        <div v-if="chips.length" class="chips">
          <span v-for="c in chips" :key="c.sid" class="chip">
            {{ c.name }}
            <button class="chip-x" @click="actions.removeFoothold(c.sid)" :disabled="store.footholdLoading" title="Remove">×</button>
          </span>
          <button class="chip-clear" @click="actions.clearFoothold()" :disabled="store.footholdLoading">Clear all</button>
        </div>
        <div v-else class="muted">
          No foothold. Right-click a node → Set as Start Node, or use a node's
          "Add to Foothold" action. Paths recompute on every change.
        </div>
      </section>

      <section class="adv-sect">
        <div class="sec-h">Graph scope</div>
        <div class="scope-btns">
          <button
            v-for="s in scopes"
            :key="s.id"
            :class="{ on: store.graphScope === s.id }"
            @click="setScope(s.id)"
          >{{ s.label }}</button>
        </div>
        <div v-if="store.graphScope === 'focus'" class="hops">
          hops
          <button :class="{ on: store.graphHops === 1 }" @click="actions.setGraphHops(1)">1</button>
          <button :class="{ on: store.graphHops === 2 }" @click="actions.setGraphHops(2)">2</button>
        </div>
      </section>

      <section class="adv-sect">
        <div class="sec-h">Overlays</div>
        <button
          class="toggle-btn"
          :class="{ on: store.chokepointsEnabled }"
          @click="actions.toggleChokepoints(20)"
          :disabled="store.chokepointsLoading"
        >
          {{ store.chokepointsLoading ? "Computing…" : "Chokepoints" }}
          <span v-if="store.chokepointsEnabled" class="cnt">{{ store.chokepoints.length }}</span>
        </button>
      </section>

      <section class="adv-sect">
        <AdvisoriesPanel />
      </section>

      <section class="adv-sect">
        <div class="sec-h">Ranked attack paths</div>
        <FindingsPanel />
      </section>
    </div>
  </aside>
</template>

<style scoped>
.advanced-drawer {
  position: absolute;
  top: 0; right: 0; bottom: 0;
  width: 420px;
  max-width: 90vw;
  background: var(--panel);
  border-left: 1px solid var(--line);
  transform: translateX(100%);
  transition: transform 0.18s ease;
  display: flex;
  flex-direction: column;
  z-index: 20;
  box-shadow: -10px 0 30px rgba(0, 0, 0, 0.35);
}
.advanced-drawer.open { transform: translateX(0); }
.adv-head {
  display: flex; align-items: center; justify-content: space-between;
  padding: 10px 14px; border-bottom: 1px solid var(--line);
}
.adv-head h3 { font-size: 13px; color: var(--warn); }
.adv-head .x { background: transparent; border: none; color: var(--muted); cursor: pointer; font-size: 14px; }
.adv-head .x:hover { color: var(--fg); }
.adv-body { overflow-y: auto; flex: 1; }
.adv-sect { padding: 10px 14px; border-bottom: 1px solid var(--line); }
.sec-h { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); margin-bottom: 6px; }
.field { display: flex; flex-direction: column; gap: 4px; }
.field-label { font-size: 11px; color: var(--muted); }
.field select {
  background: var(--panel-2); color: var(--fg); border: 1px solid var(--line);
  border-radius: 6px; padding: 6px 8px; font-size: 13px;
}
.chips { display: flex; flex-wrap: wrap; gap: 5px; align-items: center; }
.chip {
  display: inline-flex; align-items: center; gap: 4px;
  font-size: 11px; padding: 3px 8px; border-radius: 999px;
  border: 1px solid var(--warn); color: var(--warn); background: rgba(255, 209, 102, 0.06);
}
.chip-x { background: transparent; border: none; color: var(--warn); cursor: pointer; font-size: 13px; line-height: 1; }
.chip-x:hover { color: var(--fg); }
.chip-clear { font-size: 11px; background: transparent; border: 1px solid var(--line); border-radius: 6px; color: var(--muted); cursor: pointer; padding: 3px 8px; }
.chip-clear:hover { color: var(--fg); }
.scope-btns { display: flex; gap: 6px; flex-wrap: wrap; }
.scope-btns button {
  font-size: 11px; padding: 4px 10px; border-radius: 6px;
  border: 1px solid var(--line); background: transparent; color: var(--muted); cursor: pointer;
}
.scope-btns button.on { color: var(--accent); border-color: var(--accent); background: rgba(76, 201, 240, 0.1); }
.hops { margin-top: 6px; font-size: 11px; color: var(--muted); display: flex; gap: 6px; align-items: center; }
.hops button { font-size: 11px; width: 26px; height: 24px; border-radius: 5px; border: 1px solid var(--line); background: transparent; color: var(--muted); cursor: pointer; }
.hops button.on { color: var(--accent); border-color: var(--accent); }
.toggle-btn {
  width: 100%; font-size: 12px; padding: 7px 10px; border-radius: 6px;
  border: 1px solid var(--line); background: transparent; color: var(--muted); cursor: pointer;
  display: flex; align-items: center; justify-content: center; gap: 6px;
}
.toggle-btn.on { color: var(--warn); border-color: var(--warn); }
.toggle-btn .cnt { background: var(--warn); color: #121629; border-radius: 8px; padding: 0 6px; font-size: 10px; font-variant-numeric: tabular-nums; }
.muted { color: var(--muted); font-size: 12px; line-height: 1.5; }
.ghost.cancel {
  width: 100%; font-size: 11px; padding: 5px 8px; border-radius: 6px;
  border: 1px solid var(--line); background: transparent; color: var(--muted); cursor: pointer;
  margin-bottom: 8px;
}
.ghost.cancel:hover { color: var(--hi); border-color: var(--hi); }
</style>