import { reactive } from "vue";
import {
  api,
  type Finding,
  type GraphData,
  type Objective,
  type Stats,
  type DeconflictEntry,
  type SearchHit,
  type NodeDetail,
  type Chokepoint,
} from "./api";
import { graphController } from "./graphController";
import { QUERIES, type QueryCtx, type QueryRow } from "./queries";

// QueryRow is re-exported here so component authors can import it from the
// store (the canonical UI surface) without reaching into queries.ts directly.
export type { QueryRow };

// Lightweight reactive store (a Pinia-style singleton without the dependency).
interface State {
  stats: Stats | null;
  findings: Finding[];
  graph: GraphData | null;
  deconflict: DeconflictEntry[];
  objective: Objective;
  selected: number | null; // index into findings for the path inspector
  loading: boolean;
  bootLoading: boolean;
  findingsLoading: boolean;
  graphLoading: boolean;
  graphScope: "priority" | "highvalue" | "all" | "focus";
  graphLimit: number;
  graphFocus: string | null;
  graphHops: number;
  error: string | null;

  // Findings search/filter controls (Phase 1.2).
  findingsQuery: string;
  categoryFilter: Set<string>; // empty = no category filter
  escOnly: boolean;
  hvOnly: boolean;
  sortBy: "cost" | "goal";

  // Graph search + node selection (Phase 1.3).
  graphQuery: string;
  searchHits: SearchHit[];
  searching: boolean;
  selectedNode: string | null; // SID of node clicked in the graph / search
  nodeDetail: NodeDetail | null;
  nodeLoading: boolean;

  // Live multi-foothold: the set of compromised SIDs managed through the API.
  // Empty = no foothold (server starts with zero); the operator adds/removes
  // accounts/machines from the UI and attack paths re-compute each change.
  foothold: string[];
  footholdNames: string[]; // parallel display names from the server
  footholdLoading: boolean;

  // k-shortest paths to the selected node (Phase 3).
  kpaths: Finding[];
  kpathsGoal: string | null;
  kpathsLoading: boolean;

  // Chokepoints overlay (Phase 3).
  chokepoints: Chokepoint[];
  chokepointsLoading: boolean;
  chokepointsEnabled: boolean;

  // Advisory findings, kept separate from compromise findings (Phase 3).
  advisories: Finding[];
  advisoriesLoading: boolean;

  // ---- BloodHound CE v5 shell ----
  // activeTab selects the left-panel tab; advancedOpen slides the Orca analytic
  // drawer (objective / foothold / advisories / chokepoints / ranked paths) over
  // the canvas. hiddenKinds/hiddenPreds are the node-label and edge filters — a
  // kind/pred is HIDDEN when present in the set (so "select all" = empty set).
  activeTab: "search" | "queries" | "filters" | "info";
  advancedOpen: boolean;
  hiddenKinds: Set<string>;
  hiddenPreds: Set<string>;
  // Right-click "Set as Start/End Node" picks for explicit shortest-path runs.
  pathStartNode: string | null;
  pathEndNode: string | null;
  // Pre-built query results keyed by query id; queryLoading is the id of the
  // in-flight query (else null).
  queryResults: Record<string, QueryRow[]>;
  queryLoading: string | null;
  // Additive-expansion UI state: edge keys added by expandNeighbors, so InfoTab
  // can show a "Collapse all" control. The live graphology tracking is renderer-
  // local (graphController); this set mirrors it for the UI.
  expandedEdges: Set<string>;
  // Right-click context menu on graph nodes.
  menu: { sid: string; x: number; y: number; open: boolean };

  // "Hide boring nodes" filter (Phase 3). interestingSids is the on-any-attack-
  // path set from /api/interesting; interestingSet() unions it with HV nodes,
  // chokepoints, and the current selection to decide what stays visible.
  interestingSids: Set<string>;
  interestingError: boolean;
  hideBoring: boolean;

  // Risk filter (node risk-attribute filter bar). riskFilter empty = no-op (full
  // graph shown as today). riskCombine toggles OR/AND over the selected chips so
  // operators can build permutations. riskHideNonMatching reuses the hide-boring
  // nodeReducer to drop nodes that do not match the active chips.
  riskFilter: Set<string>;
  riskCombine: "any" | "all";
  riskHideNonMatching: boolean;

  // Transient path shown in the path inspector from "Find path to this" or a
  // k-shortest click. Separate from findings so the ranked list is preserved.
  inspectedPath: Finding | null;
}

export const store = reactive<State>({
  stats: null,
  findings: [],
  graph: null,
  deconflict: [],
  objective: "practical",
  selected: null,
  loading: false,
  bootLoading: false,
  findingsLoading: false,
  graphLoading: false,
  graphScope: "priority",
  graphLimit: 900,
  graphFocus: null,
  graphHops: 1,
  error: null,

  findingsQuery: "",
  categoryFilter: new Set(),
  escOnly: false,
  hvOnly: false,
  sortBy: "cost",

  graphQuery: "",
  searchHits: [],
  searching: false,
  selectedNode: null,
  nodeDetail: null,
  nodeLoading: false,

  foothold: [],
  footholdNames: [],
  footholdLoading: false,

  kpaths: [],
  kpathsGoal: null,
  kpathsLoading: false,

  chokepoints: [],
  chokepointsLoading: false,
  chokepointsEnabled: false,

  advisories: [],
  advisoriesLoading: false,

  activeTab: "search",
  advancedOpen: false,
  hiddenKinds: new Set(),
  hiddenPreds: new Set(),
  pathStartNode: null,
  pathEndNode: null,
  queryResults: {},
  queryLoading: null,
  expandedEdges: new Set(),
  menu: { sid: "", x: 0, y: 0, open: false },

  interestingSids: new Set(),
  interestingError: false,
  hideBoring: false,

  riskFilter: new Set(),
  riskCombine: "any",
  riskHideNonMatching: false,

  inspectedPath: null,
});

// The categories present across the current findings — drives which filter
// chips are shown (only facets that actually exist).
export function availableCategories(): string[] {
  const set = new Set<string>();
  for (const f of store.findings) for (const c of f.categories) set.add(c);
  return [...set].sort();
}

// ---- BloodHound CE label/edge filter facets ----
// Discovered client-side from the loaded graph (which ships unpaginated, so
// counting is free relative to payload transfer). Drives the FiltersTab
// checkboxes with counts. Sorted by count desc then name asc for stable order.

export function availableKinds(): { kind: string; count: number }[] {
  if (!store.graph) return [];
  const counts = new Map<string, number>();
  for (const n of store.graph.nodes) counts.set(n.kind, (counts.get(n.kind) ?? 0) + 1);
  const out = [...counts.entries()].map(([kind, count]) => ({ kind, count }));
  out.sort((a, b) => b.count - a.count || a.kind.localeCompare(b.kind));
  return out;
}

export function availablePreds(): { pred: string; count: number }[] {
  if (!store.graph) return [];
  const counts = new Map<string, number>();
  for (const e of store.graph.edges) counts.set(e.pred, (counts.get(e.pred) ?? 0) + 1);
  const out = [...counts.entries()].map(([pred, count]) => ({ pred, count }));
  out.sort((a, b) => b.count - a.count || a.pred.localeCompare(b.pred));
  return out;
}

// firstHighValueGoalSid is the default end node for "Find Shortest Path from
// Here" when no explicit end node is set: the goal of the cheapest high-value
// finding, falling back to the first high-value node in the loaded graph.
function firstHighValueGoalSid(): string | null {
  for (const f of store.findings) if (f.goalHighValue) return f.goal;
  if (store.graph) for (const n of store.graph.nodes) if (n.highValue) return n.sid;
  return null;
}

// ---- Risk filter (node risk-attribute filter bar) ----
// Mirrors availableCategories() but over GNode.risks with counts, so chips
// render with the number of nodes carrying each flag. Facets are discovered
// client-side from the loaded graph (the full graph ships unpaginated, so
// counting is free relative to payload transfer).

export function riskFilterActive(): boolean {
  return store.riskFilter.size > 0;
}

// availableRisks discovers risk facets across the loaded graph, sorted by
// count desc then name asc. Each entry drives one chip.
export function availableRisks(): { risk: string; count: number }[] {
  if (!store.graph) return [];
  const counts = new Map<string, number>();
  for (const n of store.graph.nodes) {
    for (const r of n.risks ?? []) counts.set(r, (counts.get(r) ?? 0) + 1);
  }
  const out = [...counts.entries()].map(([risk, count]) => ({ risk, count }));
  out.sort((a, b) => b.count - a.count || a.risk.localeCompare(b.risk));
  return out;
}

// nodeMatchesRiskFilter tests a node under the active combine mode. No active
// filter → true (no-op). "all" → every selected flag must be present;
// "any" → at least one selected flag must be present.
export function nodeMatchesRiskFilter(n: { risks?: string[] }): boolean {
  if (!riskFilterActive()) return true;
  const nodeRisks = new Set(n.risks ?? []);
  if (store.riskCombine === "all") {
    for (const r of store.riskFilter) if (!nodeRisks.has(r)) return false;
    return true;
  }
  for (const r of store.riskFilter) if (nodeRisks.has(r)) return true;
  return false;
}

// riskKeepSet returns the SIDs matching the active risk filter, or null when
// the filter is inactive. null is the sentinel for "no constraint" — an empty
// Set would mean "keep nothing", which is wrong for the no-op case. Call sites
// must guard with riskFilterActive().
export function riskKeepSet(): Set<string> | null {
  if (!riskFilterActive() || !store.graph) return null;
  const s = new Set<string>();
  for (const n of store.graph.nodes) if (nodeMatchesRiskFilter(n)) s.add(n.sid);
  return s;
}

// filteredFindings applies the search box + category chips + ESC-only / HV-only
// toggles + sort. All client-side over the already-fetched findings list.
export function filteredFindings(): Finding[] {
  const q = store.findingsQuery.trim().toLowerCase();
  let out = store.findings.filter((f) => {
    if (q) {
      const hay = (f.goalName + " " + f.goal).toLowerCase();
      if (!hay.includes(q)) return false;
    }
    if (store.escOnly && f.escs.length === 0) return false;
    if (store.hvOnly && !f.goalHighValue) return false;
    if (store.categoryFilter.size > 0) {
      // Path must include at least one selected category.
      let hit = false;
      for (const c of f.categories) if (store.categoryFilter.has(c)) { hit = true; break; }
      if (!hit) return false;
    }
    return true;
  });
  out = out.sort((a, b) =>
    store.sortBy === "cost"
      ? a.cost - b.cost
      : a.goalName.localeCompare(b.goalName),
  );
  return out;
}

// dominantCategory returns the non-membership category to badge a row with
// (membership is present on nearly every path so it's not informative). Falls
// back to Membership if that's all the path has.
export function dominantCategory(f: Finding): string {
  for (const c of f.categories) if (c !== "Membership") return c;
  return f.categories[0] ?? "";
}

export const actions = {
  async refresh() {
    store.loading = true;
    store.bootLoading = true;
    store.error = null;
    store.findingsLoading = true;
    store.graphLoading = true;
    try {
      const [stats, findings, graph, deconflict, fh] = await Promise.all([
        api.stats(),
        api.findings(store.objective, footholdSeedParam()),
        api.graph(graphParams()),
        api.deconflict(),
        api.foothold(),
      ]);
      store.stats = stats;
      store.findings = findings;
      store.graph = graph;
      store.deconflict = deconflict;
      store.foothold = fh.seeds ?? [];
      store.footholdNames = fh.names ?? [];
      store.selected = findings.length ? 0 : null;
    } catch (e) {
      store.error = String(e);
    } finally {
      store.loading = false;
      store.bootLoading = false;
      store.findingsLoading = false;
      store.graphLoading = false;
    }
    void actions.loadInteresting();
  },

  async setObjective(o: Objective) {
    store.objective = o;
    store.findingsLoading = true;
    try {
      store.findings = await api.findings(o, footholdSeedParam());
      store.selected = store.findings.length ? 0 : null;
    } catch (e) {
      store.error = String(e);
    } finally {
      store.findingsLoading = false;
    }
    void actions.loadInteresting();
  },

  async loadGraph() {
    store.graphLoading = true;
    try {
      store.graph = await api.graph(graphParams());
    } catch (e) {
      store.error = String(e);
    } finally {
      store.graphLoading = false;
    }
  },

  async setGraphScope(scope: State["graphScope"]) {
    store.graphScope = scope;
    if (scope !== "focus") store.graphFocus = null;
    await actions.loadGraph();
  },

  async setGraphLimit(limit: number) {
    store.graphLimit = limit;
    if (store.graphScope === "priority" || store.graphScope === "all") await actions.loadGraph();
  },

  async focusGraphOn(sid: string, hops = store.graphHops) {
    store.graphScope = "focus";
    store.graphFocus = sid;
    store.graphHops = hops;
    await actions.loadGraph();
  },

  async setGraphHops(hops: number) {
    store.graphHops = hops;
    if (store.graphScope === "focus" && store.graphFocus) await actions.loadGraph();
  },
  select(i: number) {
    store.selected = i;
    store.selectedNode = null; // finding selection takes the right column
    store.inspectedPath = null; // clear any transient inspected path
  },

  // Graph search: debounce-driven; caller cancels stale searches via the token.
  async runGraphSearch(token: number) {
    const query = store.graphQuery.trim();
    if (!query) {
      store.searchHits = [];
      store.searching = false;
      return;
    }
    store.searching = true;
    try {
      const hits = await api.search(query);
      // Only commit if this search is still the latest one issued. Normalize
      // null→[] so the template can always read .length safely.
      if (token === searchToken) store.searchHits = hits ?? [];
    } catch {
      if (token === searchToken) store.searchHits = [];
    } finally {
      if (token === searchToken) store.searching = false;
    }
  },

  // Select a graph node (by SID) and load its detail for the inspector.
  async selectNode(sid: string) {
    if (store.selectedNode !== sid) actions.clearKPaths();
    store.selectedNode = sid;
    store.selected = null; // node selection takes the right column
    store.nodeLoading = true;
    try {
      store.nodeDetail = await api.node(sid);
    } catch {
      store.nodeDetail = null;
    } finally {
      store.nodeLoading = false;
    }
  },

  clearNode() {
    store.selectedNode = null;
    store.nodeDetail = null;
  },

  // ---- BloodHound CE v5 shell actions ----

  setActiveTab(t: State["activeTab"]) {
    store.activeTab = t;
  },

  toggleAdvanced() {
    store.advancedOpen = !store.advancedOpen;
  },

  // Node-label filter: a kind is HIDDEN when present in the set, so "select all"
  // = empty set (matches BloodHound, where unchecked = hidden).
  toggleKind(kind: string) {
    const next = new Set(store.hiddenKinds);
    if (next.has(kind)) next.delete(kind);
    else next.add(kind);
    store.hiddenKinds = next; // clone-and-reassign for Vue reactivity
  },
  togglePred(pred: string) {
    const next = new Set(store.hiddenPreds);
    if (next.has(pred)) next.delete(pred);
    else next.add(pred);
    store.hiddenPreds = next;
  },
  selectAllKinds() {
    store.hiddenKinds = new Set(); // nothing hidden = all shown
  },
  clearKinds() {
    // "Deselect all" labels = hide every known kind.
    store.hiddenKinds = new Set(availableKinds().map((k) => k.kind));
  },
  selectAllPreds() {
    store.hiddenPreds = new Set();
  },
  clearPreds() {
    store.hiddenPreds = new Set(availablePreds().map((p) => p.pred));
  },

  // Run a pre-built query from the catalog and cache its rows under the id.
  // The query's run() reads only the API (passed objective + seeds via ctx); the
  // Finding cache for path-carrying rows lives in queries.ts (findingByGoal).
  async runPrebuiltQuery(id: string) {
    const def = QUERIES.find((q) => q.id === id);
    if (!def) return;
    const ctx: QueryCtx = { objective: store.objective, seeds: footholdSeedParam() };
    store.queryLoading = id;
    try {
      const rows = await def.run(ctx);
      store.queryResults = { ...store.queryResults, [id]: rows };
    } catch (e) {
      store.error = String(e);
      store.queryResults = { ...store.queryResults, [id]: [] };
    } finally {
      store.queryLoading = null;
    }
  },

  // Right-click "Set as Start/End Node" picks for explicit shortest-path runs.
  setStartNode(sid: string) {
    store.pathStartNode = sid;
  },
  setEndNode(sid: string) {
    store.pathEndNode = sid;
  },

  // Shortest path Start→End, driven by the explicit picks. Reuses api.path with
  // the start node as the single seed; falls back to the live foothold if only
  // the end is set. Surfaces unreachable as an error (no empty-path crash).
  async runStartEndPath() {
    const end = store.pathEndNode;
    const start = store.pathStartNode;
    if (!end) {
      store.error = "Set an end node first (right-click → Set as End Node).";
      return;
    }
    const seeds = start ? [start] : footholdSeedParam();
    try {
      const f = await api.path(end, store.objective, seeds);
      if (!f || !f.steps || !f.steps.length) {
        store.inspectedPath = null;
        store.error = "No attack path between the selected start and end nodes.";
        return;
      }
      store.inspectedPath = f;
      store.selected = null;
      store.selectedNode = null;
    } catch (e) {
      store.error = String(e);
    }
  },

  // "Find Shortest Path from Here": min-cost path FROM sid to a high-value goal.
  // Reuses api.path with sid as the seed and the current end-node (or the first
  // high-value goal) as the target.
  async findPathFrom(sid: string) {
    const end = store.pathEndNode ?? firstHighValueGoalSid();
    if (!end) {
      store.error = "No high-value target available to path to.";
      return;
    }
    try {
      const f = await api.path(end, store.objective, [sid]);
      if (!f || !f.steps || !f.steps.length) {
        store.inspectedPath = null;
        store.error = "No attack path from this node to a high-value target.";
        return;
      }
      store.inspectedPath = f;
      store.selected = null;
      store.selectedNode = null;
    } catch (e) {
      store.error = String(e);
    }
  },

  // Additive expansion: fetch neighbors and merge into the live graph WITHOUT
  // mutating store.graph (which would trigger a full relayout). The merge itself
  // is renderer-local, performed through the graphController bridge.
  async expandNeighbors(sid: string, pred?: string) {
    try {
      const nb = await api.neighbors(sid);
      // Mirror the edge keys actually added to the live graph (returned by the
      // controller) so the "Collapse expanded" count matches reality.
      const added = graphController.expandNeighbors(sid, nb, pred);
      const keys = new Set<string>(store.expandedEdges);
      for (const k of added) keys.add(k);
      store.expandedEdges = keys;
    } catch (e) {
      store.error = String(e);
    }
  },

  collapseExpansion() {
    graphController.collapseExpansion();
    store.expandedEdges = new Set();
  },

  // Remove a node from the live graph. If it was additively expanded, drop it;
  // otherwise hide it via the nodeReducer (recoverable by re-loading the scope).
  removeNodeFromGraph(sid: string) {
    graphController.removeNode(sid);
  },

  // Load the on-any-attack-path SID set from the server. Called on refresh and
  // whenever the objective/foothold changes (the path set depends on both).
  async loadInteresting() {
    try {
      const r = await api.interesting(store.objective, footholdSeedParam());
      store.interestingSids = new Set(r.sids);
      store.interestingError = false;
    } catch {
      store.interestingSids = new Set();
      store.interestingError = true;
    }
  },

  toggleHideBoring() {
    store.hideBoring = !store.hideBoring;
  },

  // "Find path to this": fetch the min-cost path to this node and show it in
  // the path inspector without overwriting the ranked findings list. If the
  // target isn't reachable from the current foothold, the server returns a
  // finding with no steps — surface that as an error instead of storing a
  // non-iterable path that would crash the path inspector / graph highlight.
  async findPathTo(sid: string) {
    try {
      const f = await api.path(sid, store.objective, footholdSeedParam());
      if (!f || !f.steps || !f.steps.length) {
        store.inspectedPath = null;
        store.error = "No attack path to this target from the current foothold.";
        return;
      }
      store.inspectedPath = f;
      store.selected = null;
      store.selectedNode = null;
    } catch (e) {
      store.error = String(e);
    }
  },

  // Show an already-fetched path (e.g. a k-shortest alternate) in the path
  // inspector without overwriting the ranked findings list.
  showPath(f: Finding) {
    store.inspectedPath = f;
    store.selected = null;
    store.selectedNode = null;
  },

  // Clear the inspected path and return to the findings list view.
  clearInspectedPath() {
    store.inspectedPath = null;
  },

  // Cancel the current path inspector entirely — drop both the transient
  // inspected path and the findings-list selection — so the graph returns to
  // its default (unfiltered) view rather than showing only the path's nodes.
  clearPath() {
    store.inspectedPath = null;
    store.selected = null;
  },

  // Add a compromised account/machine to the live foothold. The server owns the
  // set (atomic, deconfliction-logged); we mirror its response and re-compute
  // attack paths. No-op if the SID is already in the foothold.
  async addFoothold(sid: string) {
    if (!sid || store.foothold.includes(sid) || store.footholdLoading) return;
    store.footholdLoading = true;
    try {
      const r = await api.updateFoothold({ add: [sid] });
      store.foothold = r.seeds ?? [];
      store.footholdNames = r.names ?? [];
      if (store.stats) store.stats = { ...store.stats, seeds: r.seeds ?? [] };
      await actions.recomputeFromFoothold();
    } catch (e) {
      store.error = String(e);
    } finally {
      store.footholdLoading = false;
    }
  },

  // Remove a single compromised SID from the foothold and re-compute.
  async removeFoothold(sid: string) {
    if (!sid || store.footholdLoading) return;
    store.footholdLoading = true;
    try {
      const r = await api.updateFoothold({ remove: [sid] });
      store.foothold = r.seeds ?? [];
      store.footholdNames = r.names ?? [];
      if (store.stats) store.stats = { ...store.stats, seeds: r.seeds ?? [] };
      await actions.recomputeFromFoothold();
    } catch (e) {
      store.error = String(e);
    } finally {
      store.footholdLoading = false;
    }
  },

  // Clear the entire foothold (back to the zero-foothold empty state).
  async clearFoothold() {
    if (store.footholdLoading) return;
    store.footholdLoading = true;
    try {
      const r = await api.updateFoothold({ set: [] });
      store.foothold = r.seeds ?? [];
      store.footholdNames = r.names ?? [];
      if (store.stats) store.stats = { ...store.stats, seeds: [] };
      await actions.recomputeFromFoothold();
    } catch (e) {
      store.error = String(e);
    } finally {
      store.footholdLoading = false;
    }
  },

  // Single re-compute path called after every foothold change (and reusable by
  // other flows): re-fetch findings + graph together, drop any inspected path
  // since the reachable set just changed, then refresh the interesting set.
  async recomputeFromFoothold() {
    const sp = footholdSeedParam();
    store.findingsLoading = true;
    store.graphLoading = true;
    try {
      const [findings, graph] = await Promise.all([
        api.findings(store.objective, sp),
        api.graph(graphParams()),
      ]);
      store.findings = findings;
      store.selected = findings.length ? 0 : null;
      store.inspectedPath = null;
      store.graph = graph;
    } catch (e) {
      store.error = String(e);
    } finally {
      store.findingsLoading = false;
      store.graphLoading = false;
    }
    void actions.loadInteresting();
  },

  // k-shortest distinct paths to a goal node. Loaded on demand from the node
  // inspector; cleared whenever the selected node changes.
  async loadKPaths(sid: string, k = 5) {
    store.kpathsGoal = sid;
    store.kpathsLoading = true;
    try {
      store.kpaths = await api.paths(sid, k, store.objective, footholdSeedParam());
    } catch (e) {
      store.error = String(e);
      store.kpaths = [];
    } finally {
      store.kpathsLoading = false;
    }
  },

  clearKPaths() {
    store.kpaths = [];
    store.kpathsGoal = null;
  },

  // Chokepoints overlay toggle. Enabling loads the top-N high-betweenness facts;
  // disabling clears the overlay. The objective/seed changes re-fetch when on.
  async toggleChokepoints(n = 20) {
    store.chokepointsEnabled = !store.chokepointsEnabled;
    if (store.chokepointsEnabled) {
      await actions.loadChokepoints(n);
    } else {
      store.chokepoints = [];
    }
  },

  async loadChokepoints(n = 20) {
    store.chokepointsLoading = true;
    try {
      store.chokepoints = await api.chokepoints(n, store.objective, footholdSeedParam());
    } catch (e) {
      store.error = String(e);
      store.chokepoints = [];
    } finally {
      store.chokepointsLoading = false;
    }
  },

  // Advisory findings (exposures, not compromise paths). Loaded once on demand.
  async loadAdvisories() {
    store.advisoriesLoading = true;
    try {
      store.advisories = await api.advisories(store.objective, footholdSeedParam());
    } catch (e) {
      store.error = String(e);
      store.advisories = [];
    } finally {
      store.advisoriesLoading = false;
    }
  },

  toggleCategory(cat: string) {
    const next = new Set(store.categoryFilter);
    if (next.has(cat)) next.delete(cat);
    else next.add(cat);
    store.categoryFilter = next;
  },

  // ---- Risk filter actions ----
  // Clone-and-reassign the Set so Vue 3 reactivity triggers (Set mutation
  // alone is not reactive), mirroring toggleCategory.
  toggleRisk(risk: string) {
    const next = new Set(store.riskFilter);
    if (next.has(risk)) next.delete(risk);
    else next.add(risk);
    store.riskFilter = next;
  },
  setRiskCombine(mode: "any" | "all") {
    store.riskCombine = mode;
  },
  toggleRiskHideNonMatching() {
    store.riskHideNonMatching = !store.riskHideNonMatching;
  },
  clearRisks() {
    store.riskFilter = new Set();
    store.riskHideNonMatching = false;
  },
};
function graphParams(): Parameters<typeof api.graph>[0] {
  const seeds = footholdSeedParam();
  const withSeeds = <T extends Parameters<typeof api.graph>[0]>(p: T): T =>
    (seeds?.length ? { ...p, seeds } : p) as T;
  // No node cap: every scope returns all matching nodes so the layout processes
  // the full graph. (highvalue → all HV nodes; focus → full n-hop BFS; priority/
  // all → the entire graph.)
  switch (store.graphScope) {
    case "highvalue":
      return withSeeds({ highvalue: true });
    case "all":
      return withSeeds({});
    case "focus":
      if (store.graphFocus) {
        return withSeeds({ focus: store.graphFocus, hoop: store.graphHops });
      }
      return withSeeds({});
    case "priority":
    default:
      return withSeeds({});
  }
}

// footholdSeedParam returns the live foothold as a seeds array for the API, or
// undefined when empty (so the request omits the param and the server uses its
// own — possibly empty — foothold).
function footholdSeedParam(): string[] | undefined {
  return store.foothold.length ? store.foothold : undefined;
}

// footholdChips returns the live foothold as {sid, name} pairs for the topbar
// chips. Names come from the server's footholdView (parallel to seeds); any
// seed lacking a server name falls back to the loaded graph, then the SID.
export function footholdChips(): { sid: string; name: string }[] {
  const sidToName: Record<string, string> = {};
  if (store.graph) for (const n of store.graph.nodes) sidToName[n.sid] = n.name;
  return store.foothold.map((sid, i) => ({
    sid,
    name: store.footholdNames[i] || sidToName[sid] || sid,
  }));
}
// searchToken guards against out-of-order search responses (older, slower
// queries overwriting newer results). Incremented each time a search fires.
let searchToken = 0;
export function nextSearchToken(): number {
  searchToken++;
  return searchToken;
}

// selectedGoalSid returns the goal SID of the currently selected finding, or
// null when nothing is selected. Used by FindingsPanel for O(1) active-class
// comparison instead of O(n) indexOf.
export function selectedGoalSid(): string | null {
  if (store.selected === null) return null;
  return store.findings[store.selected]?.goal ?? null;
}

// The SIDs on the currently selected finding's path, for graph highlighting.
// Steps carry display names; we resolve them to SIDs via the graph's node list
// so highlighting is robust to duplicate display names (keyed by SID).
export function selectedPathSids(): Set<string> {
  const s = new Set<string>();
  // Prefer the inspected path (from "Find path to this" / k-shortest click)
  // over the findings list selection.
  const f = store.inspectedPath ?? (store.selected !== null ? store.findings[store.selected] : null);
  if (!f) return s;
  for (const seed of store.foothold) s.add(seed);
  const byName = nodeNameToSid();
  for (const st of f.steps ?? []) {
    if (st.from && byName[st.from]) s.add(byName[st.from]);
    if (st.to && byName[st.to]) s.add(byName[st.to]);
    // Actor and tail-input principals extend the chain (unary Compromised(X)
    // steps carry the compromiser only via actor/inputs, not from/to).
    if (st.actor && byName[st.actor]) s.add(byName[st.actor]);
    for (const io of st.inputs ?? []) {
      if (io.a) s.add(io.a);
      if (io.b) s.add(io.b);
    }
  }
  s.add(f.goal);
  return s;
}

// interestingSet is the keep-set when "hide boring" is on: on-any-attack-path
// SIDs (server) ∪ high-value nodes ∪ chokepoints ∪ the current path ∪ the
// selected node + its one-hop neighbors. Recomputed each call so dynamic
// selections (path/node/chokepoint toggles) are reflected immediately.
export function interestingSet(): Set<string> {
  const s = new Set<string>(store.interestingSids);
  if (store.graph) for (const n of store.graph.nodes) if (n.highValue) s.add(n.sid);
  if (store.chokepointsEnabled) for (const c of store.chokepoints) if (c.a) s.add(c.a);
  for (const sid of selectedPathSids()) s.add(sid);
  for (const sid of selectedNodeSids()) s.add(sid);
  // Compose with the risk filter when hide-non-matching is on: a node must
  // satisfy BOTH the keep-set above AND the active risk chips to stay visible.
  if (store.riskHideNonMatching && riskFilterActive()) {
    const rk = riskKeepSet()!;
    for (const sid of [...s]) if (!rk.has(sid)) s.delete(sid);
  }
  return s;
}

// One-hop neighbor SIDs of the selected node, for highlight-dimming.
export function selectedNodeSids(): Set<string> {
  const s = new Set<string>();
  if (!store.selectedNode || !store.graph) return s;
  const sid = store.selectedNode;
  s.add(sid);
  for (const e of store.graph.edges) {
    if (e.from === sid) s.add(e.to);
    else if (e.to === sid) s.add(e.from);
  }
  return s;
}

// nodeNameToSid builds a display-name → SID lookup from the current graph. If a
// name maps to multiple SIDs we keep the first; paths generally reference unique
// principals and the goal SID is added directly by selectedPathSids().
// The result is cached and invalidated only when store.graph changes, since
// highlight() calls this on every state change (via selectedPathSids).
let _nodeNameToSidCache: Record<string, string> | null = null;
let _nodeNameToSidCacheGraph: import("./api").GraphData | null = null;

function nodeNameToSid(): Record<string, string> {
  if (_nodeNameToSidCache && _nodeNameToSidCacheGraph === store.graph) {
    return _nodeNameToSidCache;
  }
  const m: Record<string, string> = {};
  if (store.graph) {
    for (const n of store.graph.nodes) {
      if (n.name && !(n.name in m)) m[n.name] = n.sid;
    }
  }
  _nodeNameToSidCache = m;
  _nodeNameToSidCacheGraph = store.graph;
  return m;
}