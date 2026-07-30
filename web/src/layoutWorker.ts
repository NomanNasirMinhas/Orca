/// <reference lib="webworker" />
// Heavy graph layout off the main thread so the SPA stays responsive while
// large datasets (thousands of nodes) are being laid out. We use Barnes-Hut
// repulsion (O(N log N) instead of O(N^2)) for big graphs and clamp every
// coordinate to a finite range so Sigma never receives NaN/Infinity positions
// (which is what makes the canvas jitter continuously).

import Graphology from "graphology";
import forceAtlas2 from "graphology-layout-forceatlas2";

export interface LayoutRequest {
  nodes: { sid: string; highValue: boolean }[];
  edges: { from: string; to: string }[];
}

export interface LayoutResponse {
  positions: Record<string, { x: number; y: number }>;
  iterations: number;
  elapsedMs: number;
}

const BARNES_HUT_THRESHOLD = 1200; // nodes above this get Barnes-Hut repulsion

// Run counter for cancellation: each new layout request increments the counter;
// a "cancel" message also increments it. The worker only posts results for the
// most recent run, so stale layouts are silently dropped.
let currentRun = 0;

self.onmessage = (e: MessageEvent<LayoutRequest | { type: string }>) => {
  if ("type" in e.data && e.data.type === "cancel") {
    currentRun++;
    return;
  }
  const runId = ++currentRun;
  const started = performance.now();
  const { nodes, edges } = e.data as LayoutRequest;
  const N = nodes.length || 1;
  const g = new Graphology();

  // Initial placement on a circle so the layout starts from a sane baseline.
  for (let i = 0; i < nodes.length; i++) {
    const angle = (2 * Math.PI * i) / N;
    g.addNode(nodes[i].sid, {
      x: Math.cos(angle),
      y: Math.sin(angle),
      size: nodes[i].highValue ? 10 : 5,
    });
  }
  let edgeIdx = 0;
  for (const edge of edges) {
    if (g.hasNode(edge.from) && g.hasNode(edge.to) && !g.hasEdge(edge.from, edge.to)) {
      g.addEdgeWithKey(`e${edgeIdx++}`, edge.from, edge.to, { size: 1 });
    }
  }

  const big = N > BARNES_HUT_THRESHOLD;
  const iterations = big ? 150 : 300;
  try {
    forceAtlas2.assign(g, {
      iterations,
      settings: {
        gravity: 0.6,
        // Higher scalingRatio spreads large graphs; Barnes-Hut needs it larger.
        scalingRatio: big ? 200 : 45,
        slowDown: big ? 4 : 2,
        barnesHutOptimize: big,
        barnesHutTheta: 0.9,
        linLogMode: false,
        adjustSizes: false,
        strongGravityMode: big,
      },
    });
  } catch {
    // Layout failures (rare) leave the circle placement — still finite & usable.
  }

  // Clamp + normalize: Sigma jitter is caused by NaN/Infinity coords; replace
  // them and rescale any runaway values into a bounded canvas range.
  const positions: Record<string, { x: number; y: number }> = {};
  let maxAbs = 0;
  g.forEachNode((id, attr) => {
    const x = Number.isFinite(attr.x as number) ? (attr.x as number) : 0;
    const y = Number.isFinite(attr.y as number) ? (attr.y as number) : 0;
    positions[id] = { x, y };
    const m = Math.max(Math.abs(x), Math.abs(y));
    if (m > maxAbs) maxAbs = m;
  });
  const SCALE_LIMIT = 1e4;
  const scale = maxAbs > SCALE_LIMIT ? SCALE_LIMIT / maxAbs : 1;
  if (scale !== 1) {
    for (const k in positions) {
      positions[k].x *= scale;
      positions[k].y *= scale;
    }
  }

  // Only post if this run hasn't been superseded by a cancel or newer request.
  if (runId !== currentRun) return;

  const resp: LayoutResponse = {
    positions,
    iterations,
    elapsedMs: Math.round(performance.now() - started),
  };
  (self as DedicatedWorkerGlobalScope).postMessage(resp);
};