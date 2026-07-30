// Typed client for the Orca Go API.

export type Objective = "practical" | "balanced" | "fastest" | "quietest" | "reliable";

export interface Stats {
  nodes: number;
  facts: number;
  seeds: string[];
}

export interface FactView {
  pred: string;
  a: string;
  b: string;
  aName: string;
  bName: string;
}

export interface Step {
  rule: string;
  technique: string;
  esc?: string;
  category: string;
  from: string;
  to: string;
  actor?: string;
  narrative?: string;
  cost: number;
  inputs?: FactView[];
  command?: string;
  remediation?: string;
}

export interface Finding {
  goal: string;
  goalName: string;
  goalHighValue: boolean;
  cost: number;
  categories: string[];
  escs: string[];
  steps: Step[];
}

export interface GNode {
  sid: string;
  name: string;
  kind: string;
  highValue: boolean;
  props?: Record<string, string>;
  risks?: string[]; // normalized risk flags (kerberoastable / asrep-roastable / ...)
}

export interface GEdge {
  pred: string;
  from: string;
  to: string;
}

export interface GraphData {
  nodes: GNode[];
  edges: GEdge[];
}

export interface DeconflictEntry {
  seq: number;
  time: string;
  operator: string;
  action: string;
  target: string;
  detail: string;
  profile: string;
}

export interface SearchHit {
  sid: string;
  name: string;
  kind: string;
  highValue: boolean;
  risks?: string[];
}

export interface NodeDetail {
  node: GNode;
  degree: { out: Record<string, number>; in: Record<string, number> };
}

export interface NeighborView {
  sid: string;
  name: string;
  kind?: string;
  highValue?: boolean;
  risks?: string[];
}

export interface NeighborData {
  neighbors: NeighborView[];
  edges: { pred: string; from: string; to: string }[];
}

// Chokepoint is a high-betweenness fact on the justification DAG — a node many
// attack paths traverse, so controlling/monitoring it breaks many routes.
export interface Chokepoint {
  pred: string;
  a: string;
  b: string;
  aName: string;
  bName: string;
  score: number;
}

// Foothold is the live, multi-element set of compromised SIDs managed server-side.
export interface FootholdView {
  seeds: string[];
  names: string[]; // parallel display names
}

async function get<T>(url: string): Promise<T> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return (await r.json()) as T;
}

// getArr is get<> for array endpoints. The Go server marshals a nil slice as
// JSON `null` (not `[]`), which would assign null to the store and crash later
// `.filter`/`.length` reads. Coerce null → [] at this boundary so consumers
// always see an array.
async function getArr<T>(url: string): Promise<T[]> {
  const r = await fetch(url);
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  const v = await r.json();
  return Array.isArray(v) ? (v as T[]) : [];
}

async function post<T>(url: string, body: unknown): Promise<T> {
  const r = await fetch(url, {
    method: "POST",
    headers: { "Content-Type": "application/json" },
    body: JSON.stringify(body),
  });
  if (!r.ok) throw new Error(`${url}: ${r.status}`);
  return (await r.json()) as T;
}

// q escapes a value for a query string without depending on URLSearchParams at
// every call site (keeps template literals readable).
function q(v: string): string {
  return encodeURIComponent(v);
}

// seedParam renders the live foothold as the comma-separated `seeds` query param.
// Returns "" when there are no seeds so analysis endpoints fall back to the
// server-side foothold (which may also be empty → no paths).
function seedParam(seeds?: string[]): string {
  return seeds?.length ? `&seeds=${q(seeds.join(","))}` : "";
}

export const api = {
  stats: () => get<Stats>("/api/stats"),
  foothold: () => get<FootholdView>("/api/foothold"),
  updateFoothold: (body: { add?: string[]; remove?: string[]; set?: string[] }) =>
    post<FootholdView>("/api/foothold", body),
  findings: (o: Objective, seeds?: string[]) =>
    getArr<Finding>(`/api/findings?objective=${o}${seedParam(seeds)}`),
  graph: (params?: {
    q?: string;
    kinds?: string[];
    preds?: string[];
    highvalue?: boolean;
    limit?: number;
    focus?: string;
    hoop?: number;
    seeds?: string[];
  }) => {
    const p = new URLSearchParams();
    if (params?.q) p.set("q", params.q);
    if (params?.kinds?.length) p.set("kinds", params.kinds.join(","));
    if (params?.preds?.length) p.set("preds", params.preds.join(","));
    if (params?.highvalue) p.set("highvalue", "1");
    if (params?.limit) p.set("limit", String(params.limit));
    if (params?.focus) p.set("focus", params.focus);
    if (params?.hoop) p.set("hoop", String(params.hoop));
    if (params?.seeds?.length) p.set("seeds", params.seeds.join(","));
    const s = p.toString();
    return get<GraphData>(`/api/graph${s ? `?${s}` : ""}`);
  },
  deconflict: () => getArr<DeconflictEntry>("/api/deconflict"),
  search: (query: string, kind?: string, limit = 50) => {
    const p = new URLSearchParams({ q: query, limit: String(limit) });
    if (kind) p.set("kind", kind);
    return getArr<SearchHit>(`/api/search?${p.toString()}`);
  },
  node: (sid: string) => get<NodeDetail>(`/api/node/${q(sid)}`),
  neighbors: (sid: string) => get<NeighborData>(`/api/neighbors/${q(sid)}`),
  path: (goal: string, o: Objective, seeds?: string[]) =>
    get<Finding>(`/api/path?goal=${q(goal)}&objective=${o}${seedParam(seeds)}`),
  // k-shortest distinct derivations of goal (Yen-style over hyperedge alternatives).
  paths: (goal: string, k: number, o: Objective, seeds?: string[]) =>
    getArr<Finding>(
      `/api/paths?goal=${q(goal)}&k=${k}&objective=${o}${seedParam(seeds)}`,
    ),
  // top-N chokepoints by betweenness centrality (highest = most paths traverse it).
  chokepoints: (n: number, o: Objective, seeds?: string[]) =>
    getArr<Chokepoint>(
      `/api/chokepoints?n=${n}&objective=${o}${seedParam(seeds)}`,
    ),
  // advisory findings (exposures that are not compromise paths, e.g. ESC8 relay).
  advisories: (o: Objective, seeds?: string[]) =>
    getArr<Finding>(`/api/advisories?objective=${o}${seedParam(seeds)}`),
  // SIDs on any minimum-cost attack path to a high-value/DCSync goal, plus all
  // high-value nodes. The SPA unions this with chokepoints + the current
  // selection to decide which nodes to keep when "hide boring" is on.
  interesting: (o: Objective, seeds?: string[]) =>
    get<{ sids: string[] }>(
      `/api/interesting?objective=${o}${seedParam(seeds)}`,
    ),
};