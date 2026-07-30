<script setup lang="ts">
import { computed } from "vue";
import { store } from "../store";

// `inline` hides the panel heading (the dock supplies its own header bar). The
// chain itself renders identically either way.
defineProps<{ inline?: boolean }>();

const finding = computed(() =>
  store.inspectedPath ?? (store.selected !== null ? store.findings[store.selected] : null)
);

// Max per-step cost in this path, used to scale the cost bars. Guard against
// zero so a path of all-zero-cost steps (e.g. pure membership) doesn't NaN.
const maxStepCost = computed(() => {
  const f = finding.value;
  if (!f || !f.steps || !f.steps.length) return 0.001;
  return Math.max(0.001, ...f.steps.map((s) => s.cost));
});

function costPct(c: number): number {
  return Math.min(100, (c / maxStepCost.value) * 100);
}

function copy(text: string) {
  navigator.clipboard?.writeText(text);
}
</script>

<template>
  <div class="col">
    <h2 v-if="!inline">Path inspector</h2>
    <div v-if="store.findingsLoading" class="empty loading-line"><span class="tiny-spinner"></span>Loading ranked paths</div>
    <div v-else-if="!finding" class="empty">Select a finding to see the attack path.</div>
    <template v-else>
      <div class="goal-head">
        <div class="goal-name">⇒ {{ finding.goalName }}</div>
        <div class="goal-meta">
          Minimum-cost path · objective: {{ store.objective }} · total cost
          {{ finding.cost.toFixed(2) }} · {{ (finding.steps?.length ?? 0) }} steps
        </div>
      </div>

      <ol class="chain">
        <li v-for="(s, i) in (finding.steps ?? [])" :key="i" class="step">
          <div class="rail">
            <span class="n">{{ i + 1 }}</span>
          </div>
          <div class="body">
            <div class="head-row">
              <span class="cat" :data-cat="s.category">{{ s.category }}</span>
              <span v-if="s.esc" class="esc">{{ s.esc }}</span>
              <span class="cost-chip">cost {{ s.cost.toFixed(2) }}</span>
            </div>
            <div class="narrative">{{ s.narrative || s.technique || s.rule }}</div>
            <div class="chain-line">
              <span v-if="s.actor" class="actor">{{ s.actor }}</span>
              <span v-if="s.actor" class="arrow">→</span>
              <span class="from">{{ s.from }}</span>
              <template v-if="s.to">
                <span class="arrow">→</span>
                <span class="to">{{ s.to }}</span>
              </template>
            </div>
            <div class="costbar">
              <div class="bar" :style="{ width: costPct(s.cost) + '%' }"></div>
            </div>
            <div v-if="s.inputs && s.inputs.length" class="inputs">
              <span class="ilabel">consumes:</span>
              <span v-for="(io, j) in s.inputs" :key="j" class="irow">
                <span class="ipred">{{ io.pred }}</span>
                <span class="iname">{{ io.aName }}<template v-if="io.bName"> → {{ io.bName }}</template></span>
              </span>
            </div>
            <div v-if="s.command" class="cmd">
              {{ s.command }}
              <button @click="copy(s.command!)">copy</button>
            </div>
            <div v-if="s.remediation" class="rem">✚ {{ s.remediation }}</div>
          </div>
        </li>
      </ol>
    </template>
  </div>
</template>

<style scoped>
.loading-line {
  display: flex;
  align-items: center;
  gap: 8px;
}
.tiny-spinner {
  width: 14px;
  height: 14px;
  border: 2px solid rgba(145, 160, 182, 0.25);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: orcaspin 0.9s linear infinite;
}
.goal-head {
  padding: 10px 16px;
  border-bottom: 1px solid var(--line);
  background: var(--bg);
}
.goal-name { font-weight: 600; font-size: 14px; }
.goal-meta { color: var(--muted); font-size: 12px; margin-top: 3px; }

.chain { list-style: none; margin: 0; padding: 0; display: grid; grid-auto-flow: column; grid-auto-columns: minmax(280px, 360px); overflow-x: auto; overflow-y: hidden; }
.step {
  display: flex;
  border-right: 1px solid var(--line);
  border-bottom: 0;
  position: relative;
  min-width: 0;
}
/* Vertical chain connector down the left rail. */
.step:not(:first-child)::before {
  content: "";
  position: absolute;
  left: 23px;
  top: -10px;
  width: 2px;
  height: 10px;
  background: var(--line);
}
.rail {
  flex-shrink: 0;
  width: 46px;
  padding: 10px 0 0 12px;
}
.rail .n {
  display: inline-flex;
  align-items: center;
  justify-content: center;
  width: 24px;
  height: 24px;
  border-radius: 50%;
  background: var(--panel-2);
  border: 1px solid var(--accent);
  color: var(--accent);
  font-size: 12px;
  font-weight: 700;
}
.body { flex: 1; min-width: 0; padding: 10px 16px 10px 0; }
.head-row { display: flex; align-items: center; gap: 6px; flex-wrap: wrap; }
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
.esc {
  font-size: 10px; color: var(--hi); border: 1px solid var(--hi);
  border-radius: 4px; padding: 0 5px;
}
.cost-chip {
  font-size: 10px; color: var(--warn); border: 1px solid var(--warn);
  border-radius: 4px; padding: 0 5px; margin-left: auto;
  font-variant-numeric: tabular-nums;
}
.narrative {
  font-size: 13px; font-weight: 600; margin: 5px 0 3px;
  color: var(--fg); line-height: 1.35;
}
.chain-line {
  font-size: 12px; color: var(--muted); display: flex;
  align-items: center; gap: 5px; flex-wrap: wrap;
}
.chain-line .actor { color: var(--accent); font-weight: 600; }
.chain-line .from { color: var(--fg); }
.chain-line .to { color: var(--hi); font-weight: 600; }
.chain-line .arrow { color: var(--muted); }
.costbar {
  height: 4px; background: var(--panel-2); border-radius: 2px;
  margin: 6px 0 0; overflow: hidden;
}
.costbar .bar { height: 100%; background: var(--warn); }
.inputs {
  font-size: 11px; margin-top: 6px; display: flex; flex-wrap: wrap;
  gap: 4px 10px; align-items: center;
}
.ilabel { color: var(--muted); }
.irow { display: inline-flex; align-items: center; gap: 4px; }
.ipred {
  font-size: 10px; color: var(--accent); border: 1px solid var(--line);
  border-radius: 3px; padding: 0 4px;
}
.iname { color: var(--fg); }
</style>