<script setup lang="ts">
import { computed } from "vue";
import { store, actions, filteredFindings, availableCategories, dominantCategory, selectedGoalSid } from "../store";

// AdvisoriesPanel now lives directly in the Advanced drawer (avoiding a
// duplicate render here), so this panel is just the ranked findings list.
const cats = computed(() => availableCategories());

function isCatOn(c: string): boolean {
  return store.categoryFilter.has(c);
}

function countForCat(c: string): number {
  let n = 0;
  for (const f of store.findings) if (f.categories.includes(c)) n++;
  return n;
}
</script>

<template>
  <div class="col">
    <h2>Targets & attack paths</h2>

    <div class="filters">
      <input
        class="search"
        type="text"
        v-model="store.findingsQuery"
        placeholder="Filter by goal name / SID…"
      />

      <div class="chips" v-if="cats.length">
        <button
          v-for="c in cats"
          :key="c"
          class="chip"
          :class="{ on: isCatOn(c) }"
          @click="actions.toggleCategory(c)"
          :title="`${countForCat(c)} path(s)`"
        >
          {{ c }} <span class="cnt">{{ countForCat(c) }}</span>
        </button>
      </div>

      <div class="toggles">
        <label class="toggle">
          <input type="checkbox" v-model="store.escOnly" /> AD CS only
        </label>
        <label class="toggle">
          <input type="checkbox" v-model="store.hvOnly" /> High-value only
        </label>
        <label class="toggle">
          Sort
          <select v-model="store.sortBy" class="sortsel">
            <option value="cost">cost</option>
            <option value="goal">goal name</option>
          </select>
        </label>
      </div>
    </div>

    <div v-if="store.findingsLoading" class="panel-loading"><span class="tiny-spinner"></span>Ranking attack paths</div>

    <div v-if="!store.findingsLoading && !store.foothold.length" class="empty foothold-hint">
      Add a compromised account or machine to the foothold to see attack paths.
    </div>
    <div v-else-if="!store.findingsLoading && !store.findings.length" class="empty">
      No exploitable paths to high-value targets.
    </div>
    <div v-else-if="!store.findingsLoading && !filteredFindings().length" class="empty">
      No paths match the current filters.
    </div>

    <div
      v-for="f in filteredFindings()"
      :key="f.goal"
      class="finding"
      :class="{ active: f.goal === selectedGoalSid() }"
    >
      <div class="head" @click="actions.select(store.findings.indexOf(f))">
        <span class="badge">GOAL</span>
        <span class="goal">{{ f.goalName }}</span>
        <span class="cost">
          cost {{ f.cost.toFixed(2) }}<br />{{ f.steps.length }} steps
        </span>
      </div>
      <div class="tags">
        <span class="cat" :data-cat="dominantCategory(f)">{{ dominantCategory(f) }}</span>
        <span v-for="e in f.escs" :key="e" class="esc-pill">{{ e }}</span>
        <span v-if="f.goalHighValue" class="hv">high-value</span>
      </div>
    </div>
  </div>
</template>

<style scoped>
.panel-loading {
  display: flex;
  align-items: center;
  gap: 8px;
  color: var(--accent);
  padding: 10px 14px;
  border-bottom: 1px solid var(--line);
  font-size: 12px;
}
.tiny-spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(145, 160, 182, 0.25);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: orcaspin 0.9s linear infinite;
}

.filters {
  padding: 8px 12px 10px;
  border-bottom: 1px solid var(--line);
  display: flex;
  flex-direction: column;
  gap: 8px;
}
.search {
  background: var(--panel-2);
  color: var(--fg);
  border: 1px solid var(--line);
  border-radius: 6px;
  padding: 7px 9px;
  font-size: 13px;
}
.search:focus { outline: none; border-color: var(--accent); }
.chips { display: flex; flex-wrap: wrap; gap: 5px; }
.chip {
  font-size: 11px;
  padding: 3px 8px;
  border-radius: 999px;
  border: 1px solid var(--line);
  color: var(--muted);
  background: transparent;
  cursor: pointer;
}
.chip .cnt { opacity: 0.6; margin-left: 3px; }
.chip.on { color: var(--accent); border-color: var(--accent); background: rgba(76,201,240,.1); }
.toggles { display: flex; flex-wrap: wrap; gap: 10px; align-items: center; font-size: 12px; color: var(--muted); }
.toggle { display: inline-flex; gap: 4px; align-items: center; cursor: pointer; }
.toggle input { cursor: pointer; }
.sortsel { padding: 2px 4px; font-size: 12px; }
.seedbar { display: flex; gap: 6px; align-items: center; }
.foothold { color: var(--warn); border-color: var(--warn); }
.mini { font-size: 11px; padding: 2px 7px; }

.finding { border-bottom: 1px solid var(--line); }
.finding .head {
  display: flex; align-items: center; gap: 10px; padding: 11px 14px; cursor: pointer;
}
.finding.active { background: linear-gradient(90deg, rgba(76, 201, 240, 0.11), rgba(16, 23, 34, 0.55)); }
.finding .head:hover { background: var(--panel); }
.tags { padding: 0 16px 10px; display: flex; flex-wrap: wrap; gap: 5px; }
.cat {
  font-size: 10px; padding: 1px 7px; border-radius: 4px;
  border: 1px solid var(--line); color: var(--muted);
}
.cat[data-cat="AD CS"] { color: #b892ff; border-color: #b892ff; }
.cat[data-cat="Kerberos"] { color: var(--accent); border-color: var(--accent); }
.cat[data-cat="AS-REP"] { color: var(--accent); border-color: var(--accent); }
.cat[data-cat="Delegation"] { color: var(--warn); border-color: var(--warn); }
.cat[data-cat="DCSync"] { color: var(--hi); border-color: var(--hi); }
.cat[data-cat="ACL/Control"] { color: #ff8fa3; border-color: #ff8fa3; }
.esc-pill { font-size: 10px; padding: 1px 6px; border-radius: 4px; color: var(--hi); border: 1px solid var(--hi); }
.hv { font-size: 10px; padding: 1px 6px; border-radius: 4px; color: var(--ok); border: 1px solid var(--ok); }
</style>