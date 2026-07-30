// Bridge between store actions and the live Graphology/Sigma instances owned by
// GraphCanvas.vue. The renderer/graph are module-local to GraphCanvas (not held
// in the store), and mutating `store.graph` would trigger `watch(() =>
// store.graph, build)` → a full relayout. So store actions that need to drive the
// live graph — focus a node, additively expand neighbors, remove a node, export
// PNG — call through here instead of touching the renderer directly.
//
// GraphCanvas registers an implementation on mount (closing over its local
// `graph`/`renderer`) and unregisters on unmount. Store actions call the
// pass-through methods; if no graph is mounted the calls are no-ops (the store
// never throws because the canvas briefly isn't there).

import type { NeighborData } from "./api";

export interface GraphControllerImpl {
  /** Pan/zoom the camera to a node (no modal — Info tab is driven by the store). */
  focus(sid: string): void;
  /** Merge a neighbor payload into the live graph additively (no relayout).
   *  Returns the live-graph edge keys actually added (for UI mirroring). */
  expandNeighbors(sid: string, nb: NeighborData, pred?: string): string[];
  /** Drop a single section's expanded edges (and now-isolated expanded nodes). */
  collapseSection(keys: string[]): void;
  /** Drop all additively-expanded nodes/edges. */
  collapseExpansion(): void;
  /** Remove a node from the live graph (or hide it if it was in the base graph). */
  removeNode(sid: string): void;
  /** Reset the camera to the default framed view. */
  resetCamera(): void;
  /** Export the current canvas to a downloaded PNG. */
  exportPng(): void;
}

let impl: GraphControllerImpl | null = null;

export function register(i: GraphControllerImpl): void {
  impl = i;
}

export function unregister(): void {
  impl = null;
}

// graphController is the store-facing facade. Every method is a safe no-op when
// no graph is mounted, so store actions can call unconditionally.
export const graphController = {
  focus: (sid: string): void => impl?.focus(sid),
  expandNeighbors: (sid: string, nb: NeighborData, pred?: string): string[] =>
    impl?.expandNeighbors(sid, nb, pred) ?? [],
  collapseSection: (keys: string[]): void => impl?.collapseSection(keys),
  collapseExpansion: (): void => impl?.collapseExpansion(),
  removeNode: (sid: string): void => impl?.removeNode(sid),
  resetCamera: (): void => impl?.resetCamera(),
  exportPng: (): void => impl?.exportPng(),
};