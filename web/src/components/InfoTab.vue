<script setup lang="ts">
import { computed, ref, watch } from "vue";
import { store, actions } from "../store";
import { useNodeDetail } from "../composables/useNodeDetail";
import { graphController } from "../graphController";
import { api, type NeighborData, type NeighborView } from "../api";

// BloodHound Info panel. With no selection it shows database stats; with a
// selected node it shows the node's head + full name, attributes, and in/out
// edge-type sections that expand into a clickable list of the connected
// principals (BloodHound's grouped-neighbor view). Expanding a section also
// merges those neighbors onto the live graph. Reuses useNodeDetail for logic.

const {
  node, degree, sid, outDeg, inDeg, props, kpathsReady,
  inFoothold, copySid, loadK, showKPath, toggleFoothold,
} = useNodeDetail(
  () => store.selectedNode ?? "",
  () => store.nodeDetail,
);

// Human-readable full name from props (displayName preferred, then the CN RDN).
// The node's `name` is sAMAccountName (e.g. "fatma"); this is the full display
// name collected/imported into Props. Empty until the dataset is (re-)imported
// with the full-name capture.
const fullName = computed(() => {
  const p = node.value?.props ?? {};
  return p["displayName"] || p["cn"] || "";
});

// ---- Edge-section expansion ----
// One fetch of /api/neighbors per selected node, cached so toggling between
// pred sections is instant. openKey is "out:<pred>" or "in:<pred>" for the
// currently-expanded section (one at a time). nbLoading guards the first fetch.
// sectionKeys maps `${sid}:${dir}:${pred}` to the exact live-graph edge keys
// that section added, so toggling the section closed can collapse just that
// section's expansion (keeping other open sections' nodes on the graph) and keep
// store.expandedEdges in sync with the live graph. Keyed per-node so the keys
// survive inspecting other nodes and returning — the live-graph expansion is
// additive and persists across node selection (matches BloodHound), and without
// the per-node key a re-opened section would record no keys (the controller
// dedups already-present edges) and its close would fail to collapse them.
const nbCache = ref<NeighborData | null>(null);
const nbLoading = ref(false);
const openKey = ref<string | null>(null);
const sectionKeys = ref<Map<string, string[]>>(new Map());

// Reset the cache + open section whenever the selected node changes. The live
// graph's additive expansion (and its mirrored keys in store.expandedEdges /
// sectionKeys) persists across node selection; only the per-node neighbor cache
// and the accordion's open section reset.
watch(sid, () => {
  nbCache.value = null;
  openKey.value = null;
});
// If a global "Collapse expanded" clears every expansion, close any open section
// and drop the stale per-section key map so the panel reflects the empty graph.
watch(() => store.expandedEdges.size, (n) => {
  if (n === 0) {
    openKey.value = null;
    sectionKeys.value = new Map();
  }
});

// name → NeighborView lookup from the cached neighbor payload.
function viewByName(): Map<string, NeighborView> {
  const m = new Map<string, NeighborView>();
  if (nbCache.value) for (const n of nbCache.value.neighbors) if (n.name) m.set(n.name, n);
  return m;
}

// The connected principals for a (direction, pred) section: the endpoint that is
// NOT the source, resolved to its NeighborView. out = source is the edge `from`;
// in = source is the edge `to`. Edges carry display names (= node.Name).
function neighborsFor(dir: "out" | "in", pred: string): NeighborView[] {
  const nb = nbCache.value;
  if (!nb || !node.value) return [];
  const srcName = node.value.name;
  const byName = viewByName();
  const seen = new Set<string>();
  const out: NeighborView[] = [];
  for (const e of nb.edges) {
    if (e.pred !== pred) continue;
    const isOut = dir === "out" && e.from === srcName;
    const isIn = dir === "in" && e.to === srcName;
    if (!isOut && !isIn) continue;
    const otherName = isOut ? e.to : e.from;
    const v = byName.get(otherName);
    if (!v || seen.has(v.sid)) continue;
    seen.add(v.sid);
    out.push(v);
  }
  return out;
}

async function toggleSection(dir: "out" | "in", pred: string) {
  const key = `${dir}:${pred}`;
  const s = sid.value;
  const mapKey = s ? `${s}:${key}` : key;
  // Toggling an already-open section closed: collapse just that section's
  // expansion on the live graph and drop its mirrored keys, so the graph and
  // the panel stay in sync (clicking the inbound/outbound link again removes
  // what the first click added).
  if (openKey.value === key) {
    openKey.value = null;
    const keys = sectionKeys.value.get(mapKey);
    if (keys && keys.length) {
      graphController.collapseSection(keys);
      const next = new Set(store.expandedEdges);
      for (const k of keys) next.delete(k);
      store.expandedEdges = next;
    }
    sectionKeys.value.delete(mapKey);
    return;
  }
  openKey.value = key;
  if (!s) return;
  // Fetch the neighbor payload once per node (cache), then merge this pred's
  // neighbors onto the live graph additively and mirror the exact added edge
  // keys for later per-section collapse.
  if (!nbCache.value) {
    nbLoading.value = true;
    try {
      nbCache.value = await api.neighbors(s);
    } catch {
      nbCache.value = null;
    } finally {
      nbLoading.value = false;
    }
  }
  const nb = nbCache.value;
  if (nb) {
    const added = graphController.expandNeighbors(s, nb, pred);
    // Re-opening an already-expanded section adds no new edges (the controller
    // dedups), so merge with any previously-recorded keys for this section.
    const prev = sectionKeys.value.get(mapKey);
    const merged = prev ? [...new Set([...prev, ...added])] : added;
    sectionKeys.value.set(mapKey, merged);
    const keys = new Set(store.expandedEdges);
    for (const k of added) keys.add(k);
    store.expandedEdges = keys;
  }
}

// Click a neighbor row → inspect it (stays in Info) and focus it on the graph.
function gotoNeighbor(nsid: string) {
  actions.selectNode(nsid);
  graphController.focus(nsid);
}

const graphCounts = computed(() =>
  store.graph ? { nodes: store.graph.nodes.length, edges: store.graph.edges.length } : null,
);
</script>

<template>
  <div class="tab">
    <!-- No selection: database info -->
    <template v-if="!sid">
      <h3>Database info</h3>
      <div class="info-rows">
        <div class="irow"><span>Nodes</span><strong>{{ store.stats?.nodes ?? "—" }}</strong></div>
        <div class="irow"><span>Facts</span><strong>{{ store.stats?.facts ?? "—" }}</strong></div>
        <div class="irow"><span>Foothold</span><strong>{{ store.foothold.length }}</strong></div>
        <div v-if="graphCounts" class="irow"><span>Graph nodes</span><strong>{{ graphCounts.nodes }}</strong></div>
        <div v-if="graphCounts" class="irow"><span>Graph edges</span><strong>{{ graphCounts.edges }}</strong></div>
      </div>
      <div v-if="store.expandedEdges.size" class="collapse-row">
        <button @click="actions.collapseExpansion()">
          Collapse expanded ({{ store.expandedEdges.size }})
        </button>
      </div>
      <div class="muted hint">
        Click a node on the graph or a Search/Query result to inspect it here.
      </div>
    </template>

    <!-- Loading -->
    <div v-else-if="store.nodeLoading" class="muted loading-line">
      <span class="tiny-spinner"></span>Loading node detail
    </div>

    <!-- Node detail -->
    <template v-else-if="node">
      <div class="node-head">
        <span class="nkind">{{ node.kind }}</span>
        <span v-if="node.highValue" class="hv-pill">high-value</span>
        <button class="clear-x" title="Clear selection" @click="actions.clearNode()">✕</button>
      </div>
      <div class="nname">{{ node.name }}</div>
      <div v-if="fullName && fullName !== node.name" class="nfullname" :title="fullName">
        {{ fullName }}
      </div>
      <div class="nsid" @click="copySid" title="click to copy">
        {{ node.sid }} <span class="copy">copy</span>
      </div>

      <div class="actions">
        <button @click="actions.findPathTo(sid)">Find Shortest Path to Here</button>
        <button @click="actions.setStartNode(sid)">Set as Start Node</button>
        <button @click="actions.setEndNode(sid)">Set as End Node</button>
        <button
          @click="actions.runStartEndPath()"
          :disabled="!store.pathEndNode"
          :title="store.pathEndNode ? 'Run Start→End shortest path' : 'Set an end node first'"
        >
          Run Start→End Path
        </button>
        <button @click="actions.focusGraphOn(sid, store.graphHops)" :disabled="store.graphLoading">
          {{ store.graphLoading ? "Loading graph…" : "Show Neighborhood" }}
        </button>
        <button @click="loadK" :disabled="store.kpathsLoading">
          {{ store.kpathsLoading ? "Loading…" : "k Shortest Paths" }}
        </button>
        <button @click="toggleFoothold" :disabled="store.footholdLoading">
          {{ store.footholdLoading ? "…" : inFoothold ? "Remove from Foothold" : "Add to Foothold" }}
        </button>
        <button class="ghost" @click="actions.removeNodeFromGraph(sid)">Remove Node</button>
      </div>

      <div v-if="store.expandedEdges.size" class="collapse-row">
        <button @click="actions.collapseExpansion()">
          Collapse expanded ({{ store.expandedEdges.size }})
        </button>
      </div>

      <div class="kpaths" v-if="kpathsReady || store.kpathsLoading">
        <div class="deg-h">k shortest paths ({{ store.kpaths.length }})</div>
        <div v-if="store.kpathsLoading" class="deg-none">Loading…</div>
        <div v-else class="kpath-row" v-for="(p, i) in store.kpaths" :key="i" @click="showKPath(i)">
          <span class="kpath-i">#{{ i + 1 }}</span>
          <span class="kpath-cost">cost {{ p.cost.toFixed(2) }}</span>
          <span class="kpath-steps">{{ p.steps.length }} steps</span>
          <span class="kpath-esc" v-for="e in p.escs" :key="e">{{ e }}</span>
        </div>
        <div class="kpath-hint">click a row to highlight it on the graph</div>
      </div>

      <div class="deg" v-if="degree">
        <div class="deg-h">Outbound edges ({{ outDeg.length }})</div>
        <div v-if="!outDeg.length" class="deg-none">none</div>
        <div v-for="d in outDeg" :key="'o' + d.pred" class="deg-group">
          <div
            class="deg-row"
            :class="{ open: openKey === 'out:' + d.pred }"
            @click="toggleSection('out', d.pred)"
          >
            <span class="deg-pred">{{ d.pred }}</span>
            <span class="deg-n">{{ d.n }}</span>
            <span class="chev">{{ openKey === 'out:' + d.pred ? "▾" : "▸" }}</span>
          </div>
          <div v-if="openKey === 'out:' + d.pred" class="nb-list">
            <div v-if="nbLoading" class="deg-none">Loading…</div>
            <div v-else-if="!neighborsFor('out', d.pred).length" class="deg-none">none</div>
            <div
              v-for="nb in neighborsFor('out', d.pred)"
              :key="nb.sid"
              class="nb-row"
              :title="nb.sid"
              @click.stop="gotoNeighbor(nb.sid)"
            >
              <span class="nb-name">{{ nb.name }}</span>
              <span class="nb-meta">
                <span class="nb-kind">{{ nb.kind }}</span>
                <span v-if="nb.highValue" class="nb-hv">HV</span>
              </span>
            </div>
          </div>
        </div>

        <div class="deg-h">Inbound edges ({{ inDeg.length }})</div>
        <div v-if="!inDeg.length" class="deg-none">none</div>
        <div v-for="d in inDeg" :key="'i' + d.pred" class="deg-group">
          <div
            class="deg-row"
            :class="{ open: openKey === 'in:' + d.pred }"
            @click="toggleSection('in', d.pred)"
          >
            <span class="deg-pred">{{ d.pred }}</span>
            <span class="deg-n">{{ d.n }}</span>
            <span class="chev">{{ openKey === 'in:' + d.pred ? "▾" : "▸" }}</span>
          </div>
          <div v-if="openKey === 'in:' + d.pred" class="nb-list">
            <div v-if="nbLoading" class="deg-none">Loading…</div>
            <div v-else-if="!neighborsFor('in', d.pred).length" class="deg-none">none</div>
            <div
              v-for="nb in neighborsFor('in', d.pred)"
              :key="nb.sid"
              class="nb-row"
              :title="nb.sid"
              @click.stop="gotoNeighbor(nb.sid)"
            >
              <span class="nb-name">{{ nb.name }}</span>
              <span class="nb-meta">
                <span class="nb-kind">{{ nb.kind }}</span>
                <span v-if="nb.highValue" class="nb-hv">HV</span>
              </span>
            </div>
          </div>
        </div>
        <div class="deg-hint">click a section to list its neighbors and add them to the graph; click a neighbor to inspect it</div>
      </div>

      <div class="props" v-if="props.length">
        <div class="deg-h">Attributes</div>
        <div v-for="p in props" :key="p.k" class="prop-row">
          <span class="prop-k">{{ p.k }}</span>
          <span class="prop-v">{{ p.v }}</span>
        </div>
      </div>
    </template>

    <div v-else class="muted">No detail for {{ sid }}.</div>
  </div>
</template>

<style scoped>
.info-rows { display: flex; flex-direction: column; padding: 0 4px; }
.irow { display: flex; justify-content: space-between; font-size: 12px; padding: 5px 6px; border-bottom: 1px solid var(--line); }
.irow strong { color: var(--fg); font-variant-numeric: tabular-nums; }
.node-head { display: flex; gap: 6px; align-items: center; padding: 8px 10px 0; }
.nkind { font-size: 11px; color: var(--muted); text-transform: uppercase; letter-spacing: .5px; }
.hv-pill { font-size: 10px; color: var(--ok); border: 1px solid var(--ok); border-radius: 4px; padding: 0 5px; }
.clear-x { margin-left: auto; background: transparent; border: none; color: var(--muted); cursor: pointer; font-size: 13px; }
.clear-x:hover { color: var(--fg); }
.nname { font-weight: 600; padding: 0 10px; font-size: 14px; }
.nfullname {
  padding: 0 10px 2px;
  font-size: 13px;
  color: var(--accent);
  overflow: hidden;
  text-overflow: ellipsis;
  white-space: nowrap;
}
.nsid {
  color: var(--muted); font-size: 11px; padding: 2px 10px 8px; cursor: pointer;
  font-family: ui-monospace, Menlo, Consolas, monospace; word-break: break-all;
}
.nsid .copy { color: var(--accent); margin-left: 6px; }
.loading-line { display: flex; align-items: center; gap: 8px; padding: 10px; }
.tiny-spinner {
  width: 14px; height: 14px;
  border: 2px solid rgba(145, 160, 182, 0.25);
  border-top-color: var(--accent);
  border-radius: 50%;
  animation: orcaspin 0.9s linear infinite;
}
.actions { display: flex; flex-direction: column; gap: 6px; padding: 8px 10px; border-bottom: 1px solid var(--line); }
.actions button { text-align: left; }
.actions button.ghost { color: var(--muted); }
.collapse-row { padding: 6px 10px; border-bottom: 1px solid var(--line); }
.collapse-row button {
  width: 100%; font-size: 11px; padding: 5px 8px; border-radius: 6px;
  border: 1px solid var(--warn); background: transparent; color: var(--warn); cursor: pointer;
}
.deg, .props, .kpaths { padding: 10px; border-bottom: 1px solid var(--line); }
.deg-h { font-size: 11px; text-transform: uppercase; letter-spacing: .5px; color: var(--muted); margin: 8px 0 4px; }
.deg-h:first-child { margin-top: 0; }
.deg-row {
  display: flex; align-items: center; gap: 6px; font-size: 12px; padding: 5px 6px;
  border-radius: 4px; cursor: pointer;
}
.deg-row:hover { background: var(--panel); }
.deg-row.open { color: var(--accent); }
.deg-pred { color: var(--accent); flex: 1; }
.deg-n { color: var(--muted); font-variant-numeric: tabular-nums; }
.chev { color: var(--muted); font-size: 10px; }
.deg-none { color: var(--muted); font-size: 12px; padding: 2px 6px; }
.deg-hint { color: var(--muted); font-size: 10px; padding: 6px 6px 0; line-height: 1.4; }
/* Inline neighbor list inside an expanded section. */
.nb-list { padding: 2px 0 6px 16px; display: flex; flex-direction: column; }
.nb-row {
  display: flex; justify-content: space-between; align-items: center; gap: 8px;
  padding: 4px 8px; border-radius: 4px; cursor: pointer; font-size: 12px;
}
.nb-row:hover { background: var(--panel); }
.nb-name { color: var(--fg); overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
.nb-meta { display: inline-flex; align-items: center; gap: 6px; flex-shrink: 0; }
.nb-kind { font-size: 10px; color: var(--muted); text-transform: uppercase; letter-spacing: .3px; }
.nb-hv { font-size: 9px; color: var(--ok); border: 1px solid var(--ok); border-radius: 3px; padding: 0 4px; }
.kpath-row {
  display: flex; gap: 8px; align-items: center; cursor: pointer;
  font-size: 12px; padding: 4px 6px; border-radius: 4px;
}
.kpath-row:hover { background: var(--panel); }
.kpath-i { color: var(--muted); font-variant-numeric: tabular-nums; min-width: 24px; }
.kpath-cost { color: var(--accent); font-variant-numeric: tabular-nums; }
.kpath-steps { color: var(--fg); }
.kpath-esc { font-size: 10px; color: var(--warn); border: 1px solid var(--warn); border-radius: 3px; padding: 0 4px; }
.kpath-hint { color: var(--muted); font-size: 11px; margin-top: 4px; }
.prop-row { display: flex; justify-content: space-between; font-size: 12px; padding: 2px 6px; gap: 12px; }
.prop-k { color: var(--accent); }
.prop-v { color: var(--fg); text-align: right; word-break: break-all; }
.muted { color: var(--muted); font-size: 12px; padding: 6px 4px; }
.hint { line-height: 1.5; }
</style>