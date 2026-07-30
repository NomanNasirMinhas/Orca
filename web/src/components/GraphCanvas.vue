<script setup lang="ts">
import { onMounted, onBeforeUnmount, ref, watch, computed, nextTick } from "vue";
import Graphology from "graphology";
import Sigma from "sigma";
import { store, actions, selectedPathSids, selectedNodeSids, interestingSet, riskKeepSet, riskFilterActive } from "../store";
import { register, unregister } from "../graphController";
import type { NeighborData, NeighborView } from "../api";

const el = ref<HTMLDivElement | null>(null);
const status = ref<string>(""); // non-empty while layout/render is in progress
const stats = ref<{ nodes: number; edges: number; ms: number } | null>(null);
const hoverTip = ref<{ x: number; y: number; text: string; sub: string; hv: boolean } | null>(null);
let renderer: Sigma | null = null;
let graph: Graphology | null = null;
let resizeObs: ResizeObserver | null = null;
let worker: Worker | null = null;
let resizeRaf = 0;
let lastW = 0;
let lastH = 0;
// Guard against a stale worker callback racing with a newer build().
let buildToken = 0;
// True while a build is in progress; highlight() skips when set to avoid
// operating on a partially-built graph.
let building = false;

// Additively-expanded node SIDs and edge keys (renderer-local). Tracked so
// "Collapse expansion" / "Remove Node" (via graphController) can drop only what
// expansion added without touching the base graph from store.graph. Reset on
// every full rebuild in build().
let expandedNodes = new Set<string>();
let expandedEdgesLocal = new Set<string>();

const CHOKEPOINT_COLOR = "#ffd166"; // gold — distinct from every kind/HV color
const RISK_COLOR = "#a78bfa";      // purple ring for risk-matched nodes (distinct from chokepoint gold)

const KIND_COLOR: Record<string, string> = {
  Domain: "#f72585",
  Group: "#ffb703",
  User: "#4cc9f0",
  Computer: "#43d17a",
  CertTemplate: "#b892ff",
  EnterpriseCA: "#ff8fa3",
  RootCA: "#ff5d8f",
  ForeignPrincipal: "#9a86c9",
  OU: "#5a7d9a",
  GPO: "#6b8f71",
  Container: "#5a7d9a",
};

function baseColor(kind: string, highValue: boolean): string {
  if (highValue) return "#f72585";
  return KIND_COLOR[kind] || "#4cc9f0";
}

// BloodHound CE edge colors (verified from SpecterOps/BloodHound cmd/ui/ducks/graph/colors.ts
// and bloodhoundgraph conversions.go): default relationship #3a5464, high-grade
// #e84a49, low-grade #faf263. The active attack path uses the high-grade red so it
// reads like BloodHound's highlighted shortest path. Node fills keep Orca's
// per-type palette: CE renders nodes as white circles with colored FontAwesome
// icons (the icon color is dynamic HSL), so a per-type fill is closer to the
// recognizable BloodHound type-coding than CE's per-node rainbow.
const DEFAULT_EDGE_COLOR = "#3a5464";
const PATH_EDGE_COLOR = "#e84a49";
const DIM_EDGE_COLOR = "#22304a";

// chokepointSids returns the SIDs of the top betweenness facts (Compromised(X)
// → a = X) when the overlay is enabled, so highlight() can ring them.
function chokepointSids(): Set<string> {
  if (!store.chokepointsEnabled) return new Set();
  const s = new Set<string>();
  for (const c of store.chokepoints) if (c.a) s.add(c.a);
  return s;
}

function killRenderer() {
  renderer?.kill();
  renderer = null;
  graph = null;
}

const busyText = computed(() => {
  if (store.graphLoading) return "Loading scoped graph payload...";
  return status.value;
});

const scopeLabel = computed(() => {
  if (store.graphScope === "highvalue") return "high-value scope";
  if (store.graphScope === "focus") return `focus scope · ${store.graphHops} hop${store.graphHops === 1 ? "" : "s"}`;
  if (store.graphScope === "all") return "all graph scope";
  return "priority scope";
});

function build() {
  if (!el.value || !store.graph) return;
  const g = store.graph;

  building = true;
  // Cancel any in-flight layout without terminating the worker.
  if (worker) {
    worker.postMessage({ type: "cancel" });
  }
  killRenderer();
  // A full rebuild discards any additively-expanded nodes/edges.
  expandedNodes = new Set();
  expandedEdgesLocal = new Set();
  store.expandedEdges = new Set();
  lastFitSig = ""; // force a re-fit on the freshly laid-out graph
  // Disconnect the resize observer while we rebuild; it is re-armed on success.
  resizeObs?.disconnect();

  buildToken++;
  const token = buildToken;
  stats.value = null;

  const big = g.nodes.length > 1200;
  status.value = big
    ? `Laying out ${g.nodes.length.toLocaleString()} nodes (Barnes-Hut in background)…`
    : `Laying out ${g.nodes.length.toLocaleString()} nodes…`;

  // Reuse the layout worker instead of terminating/recreating it on every
  // graph scope change. Vite bundles this as a separate chunk.
  if (!worker) {
    worker = new Worker(new URL("../layoutWorker.ts", import.meta.url), {
      type: "module",
    });
  }
  worker.onmessage = (ev: MessageEvent) => {
    if (token !== buildToken) return; // a newer build() superseded us
    const { positions, elapsedMs } = ev.data as {
      positions: Record<string, { x: number; y: number }>;
      iterations: number;
      elapsedMs: number;
    };
    building = false;
    renderWith(positions, g, elapsedMs);
  };
  worker.onerror = (err) => {
    if (token !== buildToken) return;
    building = false;
    // Fallback: circle placement is already finite and safe; render with that.
    const positions: Record<string, { x: number; y: number }> = {};
    const N = g.nodes.length || 1;
    g.nodes.forEach((n, i) => {
      const a = (2 * Math.PI * i) / N;
      positions[n.sid] = { x: Math.cos(a), y: Math.sin(a) };
    });
    renderWith(positions, g, 0);
    status.value = "";
    void err;
  };

  worker.postMessage({
    nodes: g.nodes.map((n) => ({ sid: n.sid, highValue: n.highValue })),
    edges: g.edges.map((e) => ({ from: e.from, to: e.to })),
  });
}

function renderWith(
  positions: Record<string, { x: number; y: number }>,
  g: NonNullable<typeof store.graph>,
  elapsedMs: number,
) {
  if (!el.value) return;
  graph = new Graphology();
  for (const n of g.nodes) {
    const p = positions[n.sid] ?? { x: 0, y: 0 };
    graph!.addNode(n.sid, {
      label: n.name || n.sid,
      x: p.x,
      y: p.y,
      size: n.highValue ? 10 : 5,
      color: baseColor(n.kind, n.highValue),
      kind: n.kind,
      nodeName: n.name || n.sid,
      highValue: n.highValue,
    });
  }
  let ei = 0;
  for (const e of g.edges) {
    if (graph!.hasNode(e.from) && graph!.hasNode(e.to) && !graph!.hasEdge(e.from, e.to)) {
      graph!.addEdgeWithKey(`e${ei++}`, e.from, e.to, {
        size: 1,
        color: DEFAULT_EDGE_COLOR,
        label: e.pred,
        type: "arrow",
      });
    }
  }

  renderer?.kill();
  renderer = new Sigma(graph, el.value, {
    renderEdgeLabels: false,
    defaultEdgeType: "arrow",
    labelColor: { color: "#8b9bb4" },
    labelSize: 11,
    // Cull labels for small nodes so thousands of low-degree accounts don't
    // flood the canvas each frame. Only larger (high-value) nodes get labels.
    labelRenderedSizeThreshold: 10,
    labelDensity: 0.3,
    labelGridCellSize: 100,
    // The container may be measured at 0px on first paint inside an embedded
    // iframe; allow it and refresh once it gains real dimensions.
    allowInvalidContainer: true,
    // Required for PNG export: without it the WebGL canvas is cleared between
    // frames and toDataURL() captures an empty buffer.
    preserveDrawingBuffer: true,
  });
  // nodeReducer hides nodes flagged `hidden` (the "hide boring" + node-label
  // filters) without dropping them from the graphology instance — positions/
  // layout are preserved and toggling is just a refresh. Sigma v3 also skips
  // incident edges of hidden nodes automatically.
  renderer.setSetting("nodeReducer", (node, data) =>
    graph!.getNodeAttribute(node, "hidden") ? { ...data, hidden: true } : data,
  );
  // edgeReducer hides edges flagged `hidden` (the edge-pred filter) the same way.
  // The `hidden` attribute alone is NOT consulted for edges without a reducer —
  // the reducer is required (this mirrors the node-hiding pattern above).
  renderer.setSetting("edgeReducer", (edge, data) =>
    graph!.getEdgeAttribute(edge, "hidden") ? { ...data, hidden: true } : data,
  );
  highlight();
  wireInteractions();

  stats.value = { nodes: g.nodes.length, edges: ei, ms: elapsedMs };
  status.value = "";

  // Re-arm a debounced resize observer now that render is done.
  lastW = el.value.clientWidth;
  lastH = el.value.clientHeight;
  resizeObs?.observe(el.value);
}

// wireInteractions binds click + hover handlers. Sigma node ids ARE SIDs.
function wireInteractions() {
  if (!renderer || !graph) return;
  // BloodHound single-click: select the node and surface it in the Info tab (no
  // modal — the Info panel IS the node inspector). No camera pan on plain click;
  // explicit focus (search/query row) pans via graphController.focus.
  renderer.on("clickNode", ({ node }: { node: string }) => {
    actions.selectNode(node);
    actions.setActiveTab("info");
  });
  renderer.on("clickStage", () => {
    // Clicking empty space clears node selection (but not a finding selection)
    // and dismisses the right-click context menu.
    if (store.selectedNode) actions.clearNode();
    if (store.menu.open) store.menu = { ...store.menu, open: false };
  });
  // Right-click a node → context menu (Set as Start/End, Find Shortest Path
  // to/from, Remove, Expand). Coords are viewport pixels for teleport positioning.
  renderer.on("rightClickNode", ({ node, x, y, event }: { node: string; x: number; y: number; event?: MouseEvent }) => {
    event?.preventDefault?.();
    store.menu = { sid: node, x, y, open: true };
  });
  renderer.on("rightClickStage", ({ event }: { event?: MouseEvent }) => {
    event?.preventDefault?.();
    if (store.menu.open) store.menu = { ...store.menu, open: false };
  });
  renderer.on("hoverNode", ({ node, x, y }: { node: string; x: number; y: number }) => {
    if (!graph) return;
    const label = graph.getNodeAttribute(node, "label") as string;
    const kind = graph.getNodeAttribute(node, "kind") as string;
    const hv = graph.getNodeAttribute(node, "highValue") as boolean;
    hoverTip.value = { x, y, text: label, sub: kind, hv: !!hv };
  });
  renderer.on("leaveNode", () => {
    hoverTip.value = null;
  });
}

// Bring a searched/clicked node into view. Sigma's camera x/y live in
// *normalized* (framed) space — createNormalizationFunction maps the graph's
// current bbox to ~[0,1] centered at 0.5, and the camera centers that space —
// so we must NOT feed raw graph coordinates to cam.animate (that was the bug:
// the node's raw coord, say 500, became a normalized-space translate of -500,
// flinging the graph out of the viewport on every focus/neighbor-click). We
// convert the node's raw position to framed via the SAME bbox Sigma is
// currently normalizing over (custom bbox if a filter refit is active, else the
// full graph extent), then pan to it while preserving the operator's zoom.
// Centering the node matches BloodHound's focus behavior; the graph stays
// roughly in view because the normalized graph spans ~[0,1] around the node.
function rawToFramed(rawX: number, rawY: number): { x: number; y: number } {
  const cb = renderer?.getCustomBBox();
  let bx0: number, bx1: number, by0: number, by1: number;
  if (cb) {
    bx0 = cb.x[0]; bx1 = cb.x[1]; by0 = cb.y[0]; by1 = cb.y[1];
  } else if (graph) {
    bx0 = Infinity; bx1 = -Infinity; by0 = Infinity; by1 = -Infinity;
    graph.forEachNode((n) => {
      const nx = graph!.getNodeAttribute(n, "x") as number;
      const ny = graph!.getNodeAttribute(n, "y") as number;
      if (nx < bx0) bx0 = nx; if (nx > bx1) bx1 = nx;
      if (ny < by0) by0 = ny; if (ny > by1) by1 = ny;
    });
  } else {
    return { x: rawX, y: rawY };
  }
  const dX = (bx0 + bx1) / 2, dY = (by0 + by1) / 2;
  let R = Math.max(bx1 - bx0, by1 - by0);
  if (!R || !isFinite(R)) R = 1;
  return { x: 0.5 + (rawX - dX) / R, y: 0.5 + (rawY - dY) / R };
}

function focusNode(sid: string) {
  if (!renderer || !graph || !graph.hasNode(sid)) return;
  const x = graph.getNodeAttribute(sid, "x") as number;
  const y = graph.getNodeAttribute(sid, "y") as number;
  const cam = renderer.getCamera();
  const f = rawToFramed(x, y);
  cam.animate({ x: f.x, y: f.y, ratio: cam.ratio }, { duration: 500 });
  // BloodHound: focusing a node (search/query result) selects it and surfaces it
  // in the Info tab — no modal.
  actions.selectNode(sid);
  actions.setActiveTab("info");
}

// applyVisibility decides which nodes are visible. An attack path no longer
// hides off-path nodes — they are kept on the canvas and merely de-colored by
// highlight() so the path reads as a prominent overlay over full context. The
// only things that hide nodes here are the node-label (kind) filter and the
// "hide boring" keep-set. It only toggles the `hidden` attribute (read by the
// nodeReducer) — positions/layout are untouched, so there is no re-layout
// flicker.
function applyVisibility() {
  if (!graph) return;
  let keep: Set<string> | null = null;
  if (store.hideBoring) {
    keep = interestingSet(); // includes the current path's nodes when a path is on
  }
  const hiddenKinds = store.hiddenKinds;
  graph.forEachNode((node) => {
    const kind = graph!.getNodeAttribute(node, "kind") as string;
    const kindHidden = hiddenKinds.has(kind);
    // Additively-expanded nodes are always kept (the operator just asked to see
    // them) — only the node-label filter can hide them, never hide-boring.
    const forced = expandedNodes.has(node);
    graph!.setNodeAttribute(node, "hidden", kindHidden || (!forced && keep !== null && !keep.has(node)));
  });
}

// applyEdgeVisibility hides edges whose predicate is in store.hiddenPreds (the
// FiltersTab edge filter). Hiding edges does NOT hide endpoint nodes — matches
// BloodHound, where an edge filter only removes relationships, not the nodes.
function applyEdgeVisibility() {
  if (!graph) return;
  const hiddenPreds = store.hiddenPreds;
  if (hiddenPreds.size === 0) {
    // Fast path: nothing filtered → unhide everything (e.g. after toggling back).
    graph.forEachEdge((edge) => graph!.setEdgeAttribute(edge, "hidden", false));
    return;
  }
  graph.forEachEdge((edge) => {
    const pred = graph!.getEdgeAttribute(edge, "label") as string;
    graph!.setEdgeAttribute(edge, "hidden", hiddenPreds.has(pred));
  });
}

// De-color (dim) everything except the currently selected attack path or the
// selected node + its one-hop neighbors, and make the active path's nodes and
// edges more prominent (full color, larger size, thicker red edges, labels).
// Off-path nodes are NOT hidden — they stay on the canvas as dim context, so
// viewing a path reads as an overlay over the full graph rather than an
// isolated subgraph. Graphology nodes are keyed by SID, so this is robust to
// duplicate display names. When the risk filter is active, risk-matched nodes
// get a purple ring (like chokepoints get gold); non-matched nodes dim unless
// on-path/selected/chokepoint.
function highlight() {
  if (!graph || building) return; // skip during build to avoid partial-graph highlight
  applyVisibility();
  applyEdgeVisibility();
  const path = selectedPathSids();
  const nodeNb = selectedNodeSids();
  const chokes = chokepointSids();
  const riskActive = riskFilterActive();
  const riskMatch = riskActive ? riskKeepSet()! : null;
  const activePath = path.size > 0;
  const activeNode = nodeNb.size > 0;
  const active = activePath || activeNode || riskActive;
  // Accumulate the bounding box of non-hidden nodes (and whether anything is
  // hidden at all) so highlight() can re-fit via Sigma's normalization when the
  // visible set changes. Computed in the same node pass — no extra iteration.
  let vMinX = Infinity, vMaxX = -Infinity, vMinY = Infinity, vMaxY = -Infinity, visN = 0;
  let hasHidden = false;
  graph.forEachNode((node, attr) => {
    const onPath = activePath && path.has(node);
    const inNb = activeNode && nodeNb.has(node);
    const isChoke = chokes.has(node);
    const isRiskMatch = riskMatch !== null && riskMatch.has(node);
    const lit = !active || onPath || inNb || isRiskMatch;
    graph!.setNodeAttribute(node, "highlighted", lit || isChoke || isRiskMatch);
    // Chokepoints keep their gold ring even when dimmed, so the overlay reads
    // as a distinct layer over the path/selection highlight. Risk-matched nodes
    // get purple; chokepoint gold takes precedence when both apply.
    let color = lit ? baseColor(attr.kind, attr.highValue) : "#33405e";
    if (isRiskMatch) color = RISK_COLOR;
    if (isChoke) color = CHOKEPOINT_COLOR;
    graph!.setNodeAttribute(node, "color", color);
    // On-path nodes are drawn larger so the path reads as prominent over the
    // dimmed context (and crosses Sigma's label-render threshold so path nodes
    // stay labeled while dimmed off-path ones drop their labels).
    const boost = isChoke || isRiskMatch ? 9 : onPath ? 12 : attr.highValue ? 10 : 5;
    graph!.setNodeAttribute(node, "size", Math.max(attr.size, boost));
    if (graph!.getNodeAttribute(node, "hidden") as boolean) {
      hasHidden = true;
    } else {
      visN++;
      const nx = attr.x as number, ny = attr.y as number;
      if (nx < vMinX) vMinX = nx; if (nx > vMaxX) vMaxX = nx;
      if (ny < vMinY) vMinY = ny; if (ny > vMaxY) vMaxY = ny;
    }
  });
  graph.forEachEdge((edge, _a, s, t) => {
    const onPath = activePath && path.has(s) && path.has(t);
    const inNb = activeNode && (nodeNb.has(s) && nodeNb.has(t));
    const lit = !active || onPath || inNb;
    graph!.setEdgeAttribute(edge, "color", lit ? (onPath ? PATH_EDGE_COLOR : DEFAULT_EDGE_COLOR) : DIM_EDGE_COLOR);
    // Path edges are thicker so the chain reads clearly over dimmed context.
    graph!.setEdgeAttribute(edge, "size", onPath ? 3 : 1);
  });
  // Refit via Sigma's normalization. Sigma's camera lives in *normalized* space
  // — it auto-centers/scales the graph to ~[0,1] via createNormalizationFunction
  // — so its default camera {0.5, 0.5, 1} already fits the WHOLE graph on load
  // (0.5 is the graph's center under that normalization). We must NOT animate the
  // camera with raw graph coordinates (that throws the graph out of the viewport,
  // which is the bug we're fixing). Instead, when nodes are hidden (filters /
  // hide-boring / risk-hide) we set a custom bbox over just the visible nodes so
  // Sigma re-normalizes to fit them; when nothing is hidden we clear it so Sigma
  // fits the full graph. The custom bbox change is what triggers the refit; we
  // snap the camera to its default so the new normalization takes effect cleanly.
  // Selecting a path/node does not hide anything, so the signature is unchanged
  // and the operator's pan/zoom is preserved — the path reads as a de-colored
  // overlay, not a camera jump.
  const targetBBox = hasHidden && visN > 0
    ? { x: [vMinX, vMaxX] as [number, number], y: [vMinY, vMaxY] as [number, number] }
    : null;
  const fitSig = targetBBox
    ? `c:${visN}:${vMinX.toFixed(2)},${vMinY.toFixed(2)},${vMaxX.toFixed(2)},${vMaxY.toFixed(2)}`
    : "full";
  if (fitSig !== lastFitSig) {
    lastFitSig = fitSig;
    renderer?.setCustomBBox(targetBBox);
    // Snap (not animate) to the default camera: the normalization changes
    // instantly on setCustomBBox's render, so an animated camera would sweep
    // across the jump. Snapping yields a clean, predictable refit. The camera's
    // default {0.5, 0.5, 1} centers normalized coord 0.5 — the graph's center
    // under Sigma's ~[0,1] normalization (NOT {0,0}, which centers the graph's
    // min-corner and shoves it off-screen — the original viewport bug).
    renderer?.getCamera().setState({ x: 0.5, y: 0.5, ratio: 1 });
  }
  renderer?.refresh();
}

// ---- graphController impl ----
// These close over the module-local graph/renderer so store actions can drive
// the live graph (focus, additive expansion, remove, export) without mutating
// store.graph (which would trigger a full relayout). Registered in onMounted.

// Signature of the last fit applied via setCustomBBox (see highlight()). Reset
// to "" in build() so a freshly laid-out graph re-fits on first highlight.
let lastFitSig = "";

function resetCamera() {
  // Sigma's default camera {0.5, 0.5, 1} centers normalized 0.5 = graph center.
  // {0,0} would center the graph's min-corner and push it off-screen.
  renderer?.getCamera().animate({ x: 0.5, y: 0.5, ratio: 1 }, { duration: 420 });
}

// Zoom in/out via camera ratio (ratio is the zoom factor; smaller = zoomed in).
function zoomIn() {
  const cam = renderer?.getCamera();
  if (cam) cam.animate({ ratio: cam.ratio * 0.7 }, { duration: 200 });
}
function zoomOut() {
  const cam = renderer?.getCamera();
  if (cam) cam.animate({ ratio: cam.ratio * 1.4 }, { duration: 200 });
}

// Merge a /api/neighbors payload into the live graph additively. New nodes are
// placed on a small ring around the source (v1 — simplest robust approach,
// matches BloodHound's "drop new neighbors near the source"; an incremental
// ForceAtlas2 pass on just the new subgraph is a documented v2 upgrade). Edges
// use unique `exp_` keys so they never collide with the base `e${i}` keys.
//
// /api/neighbors emits edges with display names (not SIDs), so we resolve the
// other endpoint via the neighbor list. Edge direction is preserved.
function expandNeighborsImpl(sourceSid: string, nb: NeighborData, pred?: string): string[] {
  if (!graph || !renderer) return [];
  if (!graph.hasNode(sourceSid)) return [];
  const srcX = graph.getNodeAttribute(sourceSid, "x") as number;
  const srcY = graph.getNodeAttribute(sourceSid, "y") as number;
  const meName = graph.getNodeAttribute(sourceSid, "nodeName") as string;

  const viewBySid = new Map<string, NeighborView>();
  const nameToSid = new Map<string, string>();
  for (const n of nb.neighbors) {
    viewBySid.set(n.sid, n);
    if (n.name) nameToSid.set(n.name, n.sid);
  }

  const edges = pred ? nb.edges.filter((e) => e.pred === pred) : nb.edges;
  // Track the edge keys actually added so callers (InfoTab sections, the
  // ContextMenu Expand action) can mirror the precise live-graph expansion into
  // store.expandedEdges and later collapse a single section by its keys.
  const addedKeys: string[] = [];
  let placed = 0;
  const denom = Math.max(1, edges.length);
  // Ring radius scaled to the graph's coordinate extent so new neighbors are
  // visibly separated from the source (a fixed 0.05 was sub-pixel on a full
  // graph and read as "nothing expanded"). Use ~12% of the bbox, with a sane
  // floor for single-node/trivial graphs.
  let minX = Infinity, maxX = -Infinity, minY = Infinity, maxY = -Infinity;
  graph.forEachNode((n) => {
    const nx = graph!.getNodeAttribute(n, "x") as number;
    const ny = graph!.getNodeAttribute(n, "y") as number;
    if (nx < minX) minX = nx; if (nx > maxX) maxX = nx;
    if (ny < minY) minY = ny; if (ny > maxY) maxY = ny;
  });
  const bbox = Math.max(maxX - minX, maxY - minY);
  const r = Math.max(0.08, bbox * 0.12);
  edges.forEach((e, i) => {
    if (e.from !== meName && e.to !== meName) return; // not incident to source
    const otherName = e.from === meName ? e.to : e.from;
    const nsid = nameToSid.get(otherName) ?? otherName;
    if (!nsid || nsid === sourceSid) return;

    // Add the neighbor node if it isn't already on the canvas.
    if (!graph!.hasNode(nsid)) {
      const v = viewBySid.get(nsid);
      const angle = (2 * Math.PI * placed) / denom;
      graph!.addNode(nsid, {
        label: v?.name ?? otherName,
        x: srcX + r * Math.cos(angle),
        y: srcY + r * Math.sin(angle),
        size: v?.highValue ? 10 : 5,
        color: baseColor(v?.kind ?? "", !!v?.highValue),
        kind: v?.kind ?? "",
        nodeName: v?.name ?? otherName,
        highValue: !!v?.highValue,
        hidden: false,
      });
      expandedNodes.add(nsid);
      placed++;
    }

    // Add the edge (preserve direction), keyed uniquely.
    const fromSid = e.from === meName ? sourceSid : nsid;
    const toSid = e.to === meName ? sourceSid : nsid;
    const key = `exp_${e.from}_${e.to}_${e.pred}_${i}`;
    if (graph!.hasNode(fromSid) && graph!.hasNode(toSid) && !graph!.hasEdge(fromSid, toSid)) {
      graph!.addEdgeWithKey(key, fromSid, toSid, {
        size: 1,
        color: DEFAULT_EDGE_COLOR,
        label: e.pred,
        type: "arrow",
        hidden: false,
      });
      expandedEdgesLocal.add(key);
      addedKeys.push(key);
    }
  });
  highlight();
  renderer.refresh();
  return addedKeys;
}

function collapseExpansionImpl() {
  if (!graph) return;
  for (const k of expandedEdgesLocal) {
    if (graph.hasEdge(k)) graph.dropEdge(k);
  }
  expandedEdgesLocal.clear();
  for (const n of expandedNodes) {
    if (graph.hasNode(n)) graph.dropNode(n);
  }
  expandedNodes.clear();
  highlight();
  renderer?.refresh();
}

// Collapse a single section's expansion: drop only the given expanded edge
// keys, then drop any additively-added nodes that are no longer incident to a
// remaining expanded edge (so a node shared with another still-open section is
// kept). Used by InfoTab when an inbound/outbound edge section is toggled closed
// so the live graph and the panel stay in sync.
function collapseSectionImpl(keys: string[]) {
  if (!graph || keys.length === 0) return;
  for (const k of keys) {
    if (graph.hasEdge(k)) graph.dropEdge(k);
    expandedEdgesLocal.delete(k);
  }
  for (const n of [...expandedNodes]) {
    let keep = false;
    for (const k of expandedEdgesLocal) {
      if (graph.hasEdge(k)) {
        const [s, t] = graph.extremities(k);
        if (s === n || t === n) { keep = true; break; }
      }
    }
    if (!keep) {
      if (graph.hasNode(n)) graph.dropNode(n);
      expandedNodes.delete(n);
    }
  }
  highlight();
  renderer?.refresh();
}

// Remove a node: if it was additively expanded, drop it (and its incident
// edges); otherwise hide it via the nodeReducer (recoverable by reloading the
// scope).
function removeNodeImpl(sid: string) {
  if (!graph) return;
  if (expandedNodes.has(sid)) {
    if (graph.hasNode(sid)) graph.dropNode(sid);
    expandedNodes.delete(sid);
  } else if (graph.hasNode(sid)) {
    graph.setNodeAttribute(sid, "hidden", true);
  }
  highlight();
  renderer?.refresh();
}

// Export the current canvas to PNG. Requires preserveDrawingBuffer (set on the
// renderer) so the WebGL buffer survives toDataURL().
function exportPngImpl() {
  if (!renderer) return;
  const main = (renderer.getCanvases() as { main?: HTMLCanvasElement }).main;
  if (!main) return;
  const a = document.createElement("a");
  a.href = main.toDataURL("image/png");
  a.download = "orca-graph.png";
  a.click();
}

onMounted(() => {
  // Register the graphController impl so store actions can drive the live
  // graph (focus, expansion, remove, export) without mutating store.graph.
  register({
    focus: focusNode,
    expandNeighbors: expandNeighborsImpl,
    collapseExpansion: collapseExpansionImpl,
    collapseSection: collapseSectionImpl,
    removeNode: removeNodeImpl,
    resetCamera,
    exportPng: exportPngImpl,
  });
  // build() is called by watch(() => store.graph, build) when data arrives;
  // calling it here would be a no-op since store.graph is null on mount.
  if (el.value) {
    resizeObs = new ResizeObserver((entries) => {
      const cr = entries[0]?.contentRect;
      if (!cr) return;
      // Ignore sub-pixel churn (scrollbar appear/disappear, sub-pixel rounding)
      // that would otherwise re-render in a tight loop — the jitter symptom.
      if (Math.abs(cr.width - lastW) < 1 && Math.abs(cr.height - lastH) < 1) return;
      lastW = cr.width;
      lastH = cr.height;
      if (resizeRaf) cancelAnimationFrame(resizeRaf);
      resizeRaf = requestAnimationFrame(() => {
        resizeRaf = 0;
        // refresh() recomputes the normalization from the current custom bbox
        // (or the full node extent), so the fit is maintained across resizes.
        renderer?.refresh();
      });
    });
    // Initial observe happens after first render in renderWith(); keep one here
    // too so a pre-render resize is still handled.
    resizeObs.observe(el.value);
  }
});
onBeforeUnmount(() => {
  unregister();
  if (resizeRaf) cancelAnimationFrame(resizeRaf);
  resizeObs?.disconnect();
  worker?.terminate();
  renderer?.kill();
});
watch(() => store.graph, build);

// Composite highlight key: a single watcher replaces 10 individual watchers so
// that a refresh (which sets multiple values) triggers highlight() exactly once
// after all reactive state has settled.
const highlightKey = computed(() => ({
  selected: store.selected,
  selectedNode: store.selectedNode,
  chokepoints: store.chokepoints,
  chokepointsEnabled: store.chokepointsEnabled,
  hideBoring: store.hideBoring,
  interestingSids: store.interestingSids,
  riskFilter: store.riskFilter,
  riskCombine: store.riskCombine,
  riskHideNonMatching: store.riskHideNonMatching,
  inspectedPath: store.inspectedPath,
  hiddenKinds: store.hiddenKinds,
  hiddenPreds: store.hiddenPreds,
}));

let highlightPending = false;
watch(highlightKey, () => {
  if (highlightPending) return;
  highlightPending = true;
  nextTick(() => {
    highlightPending = false;
    highlight();
  });
});
</script>

<template>
  <div class="col mid">
    <h2>{{ scopeLabel }}</h2>

    <!-- Top-right canvas toolbar (BloodHound-style): zoom, reset, export, settings. -->
    <div class="graph-tools">
      <button @click="zoomIn" title="Zoom in">+</button>
      <button @click="zoomOut" title="Zoom out">−</button>
      <button @click="resetCamera" title="Reset graph camera">⌂</button>
      <button @click="actions.loadGraph" :disabled="store.graphLoading" title="Reload current graph scope">↻</button>
      <button @click="exportPngImpl" title="Export graph as PNG">⤓</button>
      <button @click="actions.toggleAdvanced" :class="{ on: store.advancedOpen }" title="Toggle the Advanced (Orca) drawer">⚙</button>
    </div>

    <div id="sigma" ref="el"></div>

    <!-- Hover tooltip: follows the pointer, shows node name/kind. -->
    <div
      v-if="hoverTip"
      class="hover-tip"
      :style="{ left: hoverTip.x + 12 + 'px', top: hoverTip.y + 12 + 'px' }"
    >
      <div class="ht-name">{{ hoverTip.text }}</div>
      <div class="ht-sub">{{ hoverTip.sub }}<span v-if="hoverTip.hv" class="ht-hv"> · high-value</span></div>
    </div>

    <div v-if="busyText" class="overlay">
      <div class="spinner"></div>
      <div>{{ busyText }}</div>
    </div>
    <div class="legend">
      <div><span class="dot" style="background:#f72585"></span>High-value / Domain</div>
      <div><span class="dot" style="background:#ffb703"></span>Group</div>
      <div><span class="dot" style="background:#4cc9f0"></span>User</div>
      <div><span class="dot" style="background:#43d17a"></span>Computer</div>
      <div><span class="dot" style="background:#b892ff"></span>Cert template</div>
      <div><span class="dot" style="background:#ff8fa3"></span>CA</div>
      <div><span class="dot edge" style="background:#e84a49"></span>Attack path</div>
      <div v-if="store.chokepointsEnabled"><span class="dot" style="background:#ffd166"></span>Chokepoint</div>
      <div v-if="riskFilterActive()"><span class="dot" style="background:#a78bfa"></span>Risk-matched</div>
      <div v-if="stats" class="gstats">
        {{ stats.nodes.toLocaleString() }} nodes · {{ stats.edges.toLocaleString() }} edges ·
        {{ scopeLabel }} · layout {{ stats.ms }} ms
      </div>
    </div>
  </div>
</template>

<style scoped>
#sigma {
  position: absolute;
  inset: 0;
  overflow: hidden;
}
.graph-tools {
  position: absolute;
  top: 12px;
  right: 12px;
  z-index: 7;
  display: flex;
  gap: 6px;
}
.graph-tools button {
  width: 32px;
  height: 30px;
  display: grid;
  place-items: center;
  padding: 0;
  background: rgba(10, 14, 22, 0.9);
  border: 1px solid var(--line);
  border-radius: 6px;
  font-size: 15px;
}
.graph-tools button:hover { border-color: var(--accent); }
.graph-tools button.on { border-color: var(--accent); color: var(--accent); }
.graph-tools button:disabled { opacity: 0.6; cursor: default; }

/* Legend "edge" swatch is a short bar rather than a round dot. */
.legend .dot.edge {
  width: 14px; height: 3px; border-radius: 2px; vertical-align: middle;
}

.hover-tip {
  position: absolute; z-index: 8; pointer-events: none;
  background: rgba(10,14,26,.95); border: 1px solid var(--line); border-radius: 6px;
  padding: 5px 9px; font-size: 12px;
}
.ht-name { font-weight: 600; }
.ht-sub { color: var(--muted); font-size: 11px; }
.ht-hv { color: var(--hi); }

.overlay {
  position: absolute;
  inset: 0;
  display: flex;
  flex-direction: column;
  align-items: center;
  justify-content: center;
  gap: 14px;
  color: var(--muted, #8b9bb4);
  background: rgba(7, 10, 16, 0.68); backdrop-filter: blur(2px);
  z-index: 6;
  font-size: 13px;
}
.spinner {
  width: 26px;
  height: 26px;
  border: 3px solid rgba(139, 155, 180, 0.25);
  border-top-color: #4cc9f0;
  border-radius: 50%;
  animation: orcaspin 0.9s linear infinite;
}
@keyframes orcaspin {
  to {
    transform: rotate(360deg);
  }
}
.gstats {
  margin-top: 6px;
  font-variant-numeric: tabular-nums;
  opacity: 0.8;
}
</style>