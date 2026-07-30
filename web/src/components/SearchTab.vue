<script setup lang="ts">
import { store, actions, nextSearchToken } from "../store";
import { graphController } from "../graphController";

// BloodHound-style node search. The input lives in the panel (not a canvas
// overlay); results render as a clickable list. Picking a row selects the node,
// flips to the Info tab, and pans the graph to it — the same flow as a graph
// click, minus the modal (BH shows node info in the Info panel).
function onInput() {
  void actions.runGraphSearch(nextSearchToken());
}

function pick(sid: string) {
  actions.selectNode(sid);
  actions.setActiveTab("info");
  graphController.focus(sid);
}
</script>

<template>
  <div class="tab">
    <h3>Search</h3>
    <input
      class="search"
      type="text"
      v-model="store.graphQuery"
      @input="onInput"
      placeholder="Search by name or SID…"
    />

    <div v-if="store.searching" class="muted">Searching…</div>

    <div v-else-if="store.graphQuery && store.searchHits.length" class="hits">
      <div
        v-for="h in store.searchHits.slice(0, 100)"
        :key="h.sid"
        class="hit"
        @click="pick(h.sid)"
      >
        <span class="hit-name">{{ h.name }}</span>
        <span class="hit-meta">
          <span class="hit-kind">{{ h.kind }}</span>
          <span v-if="h.highValue" class="hit-hv">HV</span>
        </span>
      </div>
      <div v-if="store.searchHits.length > 100" class="muted more">
        +{{ store.searchHits.length - 100 }} more — refine your search.
      </div>
    </div>

    <div v-else-if="store.graphQuery && !store.searching" class="muted">
      No matches.
    </div>

    <div v-else class="muted hint">
      Type to find nodes by name or SID. Click a result to focus it on the graph
      and open its info.
    </div>
  </div>
</template>

<style scoped>
.search {
  width: 100%;
  background: var(--panel-2);
  color: var(--fg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 8px 10px;
  font-size: 13px;
  margin-bottom: 8px;
}
.search:focus { outline: none; border-color: var(--accent); }
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
.hit-name { color: var(--fg); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.hit-meta { display: inline-flex; align-items: center; gap: 6px; flex-shrink: 0; }
.hit-kind { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .3px; }
.hit-hv { font-size: 9px; color: var(--ok); border: 1px solid var(--ok); border-radius: 3px; padding: 0 4px; }
.muted { color: var(--muted); font-size: 12px; padding: 6px 4px; }
.more { padding: 6px 10px; }
.hint { line-height: 1.5; }
</style>