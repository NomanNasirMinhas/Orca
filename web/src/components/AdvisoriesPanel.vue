<script setup lang="ts">
import { ref } from "vue";
import { store, actions } from "../store";

// Collapsible; loads on first expand. Advisories are exposure conditions
// (e.g. ESC8 NTLM relay via web enrollment) that are NOT compromise paths —
// they surface separately from the ranked findings list.
const open = ref(false);

async function toggle() {
  open.value = !open.value;
  if (open.value && store.advisories.length === 0 && !store.advisoriesLoading) {
    await actions.loadAdvisories();
  }
}
</script>

<template>
  <div class="adv">
    <div class="adv-head" @click="toggle">
      <span class="adv-title">Advisories</span>
      <span class="adv-count" v-if="store.advisories.length">{{ store.advisories.length }}</span>
      <span class="adv-chev">{{ open ? "▾" : "▸" }}</span>
    </div>
    <div v-if="open" class="adv-body">
      <div v-if="store.advisoriesLoading" class="empty">Loading…</div>
      <div v-else-if="!store.advisories.length" class="empty">
        No advisory exposures. (ESC8 web-enrollment relay requires CA flag atoms
        from a certipy import or live CA collection.)
      </div>
      <div v-for="(a, i) in store.advisories" :key="i" class="adv-item">
        <div class="adv-name">{{ a.goalName }}</div>
        <div class="adv-tags">
          <span v-for="e in a.escs" :key="e" class="esc-pill">{{ e }}</span>
          <span class="adv-cat" v-for="c in a.categories" :key="c">{{ c }}</span>
        </div>
        <div class="adv-step" v-for="(s, j) in a.steps" :key="j">
          <div class="adv-tech">{{ s.technique }}</div>
          <div class="adv-rem" v-if="s.remediation">
            <span class="rem-label">Remediation:</span> {{ s.remediation }}
          </div>
        </div>
      </div>
    </div>
  </div>
</template>

<style scoped>
.adv { border-bottom: 1px solid var(--line); }
.adv-head {
  display: flex; align-items: center; gap: 8px; cursor: pointer;
  padding: 10px 16px; background: var(--bg);
}
.adv-head:hover { background: var(--panel); }
.adv-title { font-size: 13px; font-weight: 600; color: var(--warn); }
.adv-count {
  font-size: 11px; color: var(--warn); border: 1px solid var(--warn);
  border-radius: 10px; padding: 0 7px;
}
.adv-chev { margin-left: auto; color: var(--muted); font-size: 12px; }
.adv-body { padding: 4px 16px 10px; }
.empty { color: var(--muted); font-size: 12px; padding: 6px 0; }
.adv-item {
  padding: 8px 0; border-bottom: 1px solid var(--line);
}
.adv-item:last-child { border-bottom: none; }
.adv-name { font-weight: 600; font-size: 13px; }
.adv-tags { display: flex; gap: 5px; flex-wrap: wrap; margin: 4px 0; }
.esc-pill { font-size: 10px; padding: 1px 6px; border-radius: 4px; color: var(--hi); border: 1px solid var(--hi); }
.adv-cat { font-size: 10px; padding: 1px 7px; border-radius: 4px; border: 1px solid var(--line); color: var(--muted); }
.adv-step { font-size: 12px; margin-top: 4px; }
.adv-tech { color: var(--fg); }
.adv-rem { color: var(--muted); margin-top: 2px; }
.rem-label { color: var(--ok); }
</style>