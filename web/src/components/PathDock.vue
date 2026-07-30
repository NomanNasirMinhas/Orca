<script setup lang="ts">
import { computed } from "vue";
import { store, actions } from "../store";
import PathInspector from "./PathInspector.vue";

// Wide bottom dock for the currently-selected attack path, shown across the
// canvas (much wider than the Advanced sidebar so the step chain reads
// horizontally). Appears only when a path is active (an inspected path or a
// findings-list selection); the header carries the goal + a Cancel button so
// the operator can clear the selection and return to the full graph.
const finding = computed(() =>
  store.inspectedPath ?? (store.selected !== null ? store.findings[store.selected] : null),
);
const active = computed(() => !!finding.value);
const isInspected = computed(() => !!store.inspectedPath);
</script>

<template>
  <section v-if="active" class="path-dock">
    <div class="dock-head">
      <div class="dock-title">
        <span class="dock-label">{{ isInspected ? "Inspected path to" : "Selected path to" }}</span>
        <strong>{{ finding?.goalName }}</strong>
        <span class="dock-meta" v-if="finding">
          objective {{ store.objective }} · cost {{ finding.cost.toFixed(2) }} · {{ finding.steps?.length ?? 0 }} steps
        </span>
      </div>
      <button class="cancel" @click="actions.clearPath()" title="Clear this path and return to the full graph">
        ✕ Cancel path
      </button>
    </div>
    <div class="dock-body">
      <PathInspector inline />
    </div>
  </section>
</template>

<style scoped>
.path-dock {
  position: absolute;
  left: 0;
  right: 0;
  bottom: 0;
  height: 240px;
  z-index: 15;
  display: flex;
  flex-direction: column;
  background: rgba(8, 11, 18, 0.98);
  border-top: 1px solid var(--line);
  box-shadow: 0 -10px 30px rgba(0, 0, 0, 0.35);
}
.dock-head {
  display: flex;
  align-items: center;
  gap: 12px;
  padding: 6px 14px;
  border-bottom: 1px solid var(--line);
  background: rgba(114, 135, 253, 0.06);
  flex-shrink: 0;
}
.dock-title { display: flex; align-items: baseline; gap: 8px; min-width: 0; }
.dock-label { color: var(--muted); font-size: 12px; white-space: nowrap; }
.dock-title strong { color: var(--fg); font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.dock-meta { color: var(--muted); font-size: 11px; white-space: nowrap; font-variant-numeric: tabular-nums; }
.cancel {
  margin-left: auto;
  font-size: 12px;
  padding: 4px 11px;
  border-radius: 6px;
  border: 1px solid var(--line);
  background: transparent;
  color: var(--accent);
  cursor: pointer;
  white-space: nowrap;
}
.cancel:hover { background: rgba(76, 201, 240, 0.12); border-color: var(--accent); }
.dock-body { flex: 1; min-height: 0; overflow: hidden; }
</style>