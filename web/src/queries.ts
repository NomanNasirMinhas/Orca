// Pre-built BloodHound-style query catalog. Each query is implemented over the
// EXISTING Orca API (no backend support for canned queries) plus client-side
// filtering. results are QueryRow (= SearchHit shape) so QueriesTab and SearchTab
// render them identically.
//
// This module imports ONLY the API (not the store) to avoid a circular import:
// the store imports QUERIES from here, and passes the live objective + seeds to
// each run() via QueryCtx. Path-carrying queries cache their Finding in
// findingByGoal so a row click can actions.showPath(cached) without a refetch.

import { api, type Finding, type Objective, type SearchHit } from "./api";

export type QueryRow = SearchHit;

export interface QueryCtx {
  objective: Objective;
  seeds?: string[];
}

export interface QueryDef {
  id: string;
  label: string;
  category: string;
  run(ctx: QueryCtx): Promise<QueryRow[]>;
}

// Shared cache: goal SID → cheapest Finding that produced it. Path-carrying
// queries (hv-shortest-paths, dcsync-paths) populate this; row-click handlers in
// QueriesTab/InfoTab read it to showPath() the cached path.
export const findingByGoal = new Map<string, Finding>();

// Map a compromise-path Finding to a list row. The Finding is cached so the row
// click can highlight the path on the graph.
function findingRows(findings: Finding[]): QueryRow[] {
  findingByGoal.clear();
  const rows: QueryRow[] = [];
  for (const f of findings) {
    findingByGoal.set(f.goal, f);
    rows.push({
      sid: f.goal,
      name: f.goalName,
      kind: "Goal",
      highValue: f.goalHighValue,
      risks: [],
    });
  }
  return rows;
}

// Members of a group: the group's one-hop neighbors linked by a MemberOf edge.
// /api/neighbors emits edges with display names (not SIDs), so we resolve the
// member name → SID via the neighbor list. MemberOf is (member → group), so the
// member is whichever edge endpoint is NOT the group name.
async function groupMembers(groupSid: string, groupName: string): Promise<QueryRow[]> {
  const nb = await api.neighbors(groupSid);
  const nameToView = new Map<string, QueryRow>();
  for (const n of nb.neighbors) {
    nameToView.set(n.name, {
      sid: n.sid,
      name: n.name,
      kind: n.kind ?? "",
      highValue: !!n.highValue,
      risks: n.risks ?? [],
    });
  }
  const seen = new Set<string>();
  const rows: QueryRow[] = [];
  for (const e of nb.edges) {
    if (e.pred !== "MemberOf") continue;
    const memberName = e.to === groupName ? e.from : e.from === groupName ? e.to : null;
    if (!memberName) continue;
    const view = nameToView.get(memberName);
    if (!view || seen.has(view.sid)) continue;
    seen.add(view.sid);
    rows.push(view);
  }
  return rows;
}

export const QUERIES: QueryDef[] = [
  {
    id: "hv-shortest-paths",
    label: "Shortest Paths to High-Value Targets",
    category: "Paths",
    async run(ctx) {
      const findings = await api.findings(ctx.objective, ctx.seeds);
      return findingRows(findings);
    },
  },
  {
    id: "dcsync-paths",
    label: "Principals with DCSync Rights",
    category: "Paths",
    async run(ctx) {
      const findings = await api.findings(ctx.objective, ctx.seeds);
      return findingRows(findings.filter((f) => f.categories.includes("DCSync")));
    },
  },
  {
    id: "domain-admins",
    label: "Find All Domain Admins",
    category: "Principals",
    async run() {
      const groups = await api.search("Domain Admins", "Group", 50);
      const rows: QueryRow[] = [];
      const seen = new Set<string>();
      for (const g of groups) {
        const members = await groupMembers(g.sid, g.name);
        for (const m of members) {
          if (seen.has(m.sid)) continue;
          seen.add(m.sid);
          rows.push(m);
        }
      }
      return rows;
    },
  },
  {
    id: "kerberoastable-users",
    label: "Kerberoastable Users",
    category: "Principals",
    async run() {
      const users = await api.search("", "User", 5000);
      return users.filter((u) => u.risks?.includes("kerberoastable"));
    },
  },
  {
    id: "asrep-roastable-users",
    label: "AS-REP Roastable Users",
    category: "Principals",
    async run() {
      const users = await api.search("", "User", 5000);
      return users.filter((u) => u.risks?.includes("asrep-roastable"));
    },
  },
  {
    id: "unconstrained-delegation-computers",
    label: "Computers with Unconstrained Delegation",
    category: "Computers",
    async run() {
      const computers = await api.search("", "Computer", 5000);
      return computers.filter((c) => c.risks?.includes("unconstrained-delegation"));
    },
  },
  {
    id: "constrained-delegation-computers",
    label: "Computers with Constrained Delegation",
    category: "Computers",
    async run() {
      const computers = await api.search("", "Computer", 5000);
      return computers.filter((c) => c.risks?.includes("constrained-delegation"));
    },
  },
  {
    id: "rbcd-computers",
    label: "Computers with RBCD",
    category: "Computers",
    async run() {
      const computers = await api.search("", "Computer", 5000);
      return computers.filter((c) => c.risks?.includes("rbcd"));
    },
  },
  {
    id: "high-value-nodes",
    label: "All High-Value Targets",
    category: "Principals",
    async run() {
      const g = await api.graph({ highvalue: true });
      return g.nodes.map((n) => ({
        sid: n.sid,
        name: n.name,
        kind: n.kind,
        highValue: true,
        risks: n.risks ?? [],
      }));
    },
  },
  {
    id: "adcs-templates",
    label: "All Cert Templates",
    category: "AD CS",
    async run() {
      return api.search("", "CertTemplate", 5000);
    },
  },
];