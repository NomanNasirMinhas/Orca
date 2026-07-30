<script setup lang="ts">
import { ref, computed } from "vue";
import { store, actions } from "../store";
import { QUERIES, findingByGoal, type QueryRow } from "../queries";
import { graphController } from "../graphController";

// BloodHound-style pre-built query catalog. The catalog is grouped by category;
// clicking a query runs it (over the existing Orca API) and the panel swaps to
// a results list with a back button. Row click focuses the node on the graph
// and opens Info; path-carrying rows (HV/DCSync) also highlight the cached path.

const shown = ref<string | null>(null); // id whose results are displayed, null = catalog

const grouped = computed(() => {
  const m: Record<string, typeof QUERIES> = {};
  for (const q of QUERIES) (m[q.category] ??= []).push(q);
  return Object.entries(m).map(([cat, qs]) => ({ cat, qs }));
});

const shownDef = computed(() => QUERIES.find((q) => q.id === shown.value) ?? null);
const rows = computed<QueryRow[]>(() => (shown.value ? store.queryResults[shown.value] ?? [] : []));

function run(id: string) {
  shown.value = id;
  void actions.runPrebuiltQuery(id);
}
function back() {
  shown.value = null;
}

function rowClick(r: QueryRow) {
  const f = findingByGoal.get(r.sid);
  actions.selectNode(r.sid);
  actions.setActiveTab("info");
  graphController.focus(r.sid);
  if (f) actions.showPath(f);
}
</script>

<template>
  <div class="tab">
    <h3>Queries</h3>

    <template v-if="!shown">
      <div v-for="g in grouped" :key="g.cat" class="qgroup">
        <div class="qcat">{{ g.cat }}</div>
        <button
          v-for="q in g.qs"
          :key="q.id"
          class="qrow"
          :class="{ loading: store.queryLoading === q.id }"
          :disabled="store.queryLoading === q.id"
          @click="run(q.id)"
        >
          <span class="qrun">▸</span>{{ q.label }}
        </button>
      </div>
    </template>

    <template v-else>
      <button class="back" @click="back">← All queries</button>
      <div class="qtitle">{{ shownDef?.label }}</div>

      <div v-if="store.queryLoading === shown" class="muted">Running query…</div>
      <div v-else-if="!rows.length" class="muted">No results.</div>
      <div v-else class="hits">
        <div class="rcount">{{ rows.length }} result{{ rows.length === 1 ? "" : "s" }}</div>
        <div
          v-for="r in rows.slice(0, 500)"
          :key="r.sid"
          class="hit"
          :class="{ path: findingByGoal.has(r.sid) }"
          @click="rowClick(r)"
        >
          <span class="hit-name">{{ r.name }}</span>
          <span class="hit-meta">
            <span class="hit-kind">{{ r.kind }}</span>
            <span v-if="r.highValue" class="hit-hv">HV</span>
            <span v-if="findingByGoal.has(r.sid)" class="hit-path">path</span>
          </span>
        </div>
        <div v-if="rows.length > 500" class="muted more">
          +{{ rows.length - 500 }} more — narrow via Search.
        </div>
      </div>
    </template>
  </div>
</template>

<style scoped>
.qgroup { margin-bottom: 4px; }
.qcat {
  font-size: 10px;
  text-transform: uppercase;
  letter-spacing: .5px;
  color: var(--muted);
  padding: 10px 4px 4px;
}
.qrow {
  display: flex;
  align-items: center;
  gap: 6px;
  width: 100%;
  text-align: left;
  background: transparent;
  border: none;
  border-radius: 6px;
  color: var(--fg);
  font-size: 13px;
  padding: 7px 10px;
  cursor: pointer;
}
.qrow:hover { background: var(--panel); }
.qrow:disabled { opacity: 0.6; cursor: progress; }
.qrow .qrun { color: var(--accent); font-size: 10px; }
.qrow.loading { color: var(--accent); }
.back {
  background: transparent;
  border: 1px solid var(--line);
  border-radius: 6px;
  color: var(--muted);
  padding: 5px 10px;
  font-size: 12px;
  cursor: pointer;
  margin-bottom: 6px;
}
.back:hover { color: var(--fg); border-color: var(--accent); }
.qtitle { font-weight: 600; font-size: 13px; padding: 2px 4px 8px; color: var(--fg); }
.rcount { font-size: 11px; color: var(--muted); padding: 0 4px 6px; }
.hits { display: flex; flex-direction: column; }
.hit {
  display: flex;
  justify-content: space-between;
  align-items: center;
  gap: 8px;
  padding: 7px 10px;
  border-radius: 6px;
  cursor: pointer;
  font-size: 13px;
}
.hit:hover { background: var(--panel); }
.hit.path { border-left: 2px solid var(--accent); }
.hit-name { color: var(--fg); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hit-meta { display: inline-flex; align-items: center; gap: 6px; flex-shrink: 0; }
.hit-kind { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .3px; }
.hit-hv { font-size: 9px; color: var(--ok); border: 1px solid var(--ok); border-radius: 3px; padding: 0 4px; }
.hit-path { font-size: 9px; color: var(--accent); border: 1px solid var(--accent); border-radius: 3px; padding: 0 4px; }
.muted { color: var(--muted); font-size: 12px; padding: 6px 4px; }
.more { padding: 6px 10px; }
</style>