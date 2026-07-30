# Orca — Unified AD Attack-Path Mapping Platform

> **Authorized red-team use only.** Orca *maps and advises*; it does not execute
> exploits. It keeps a hash-chained deconfliction log of its own activity so blue
> teams can attribute what it did.

Orca fuses the data that today lives across BloodHound/SharpHound, Certipy, and
`ldapsearch` into a single embedded attack graph, then runs a fixpoint / AND-OR
hyperpath engine to find the cheapest exploitable path to high-value targets —
ranked by your chosen objective (fastest, quietest, most reliable, balanced,
practical).

It builds to **one self-contained Go binary** that also serves the operator UI.

---

## Why the path engine is different

Naive attack graphs are cyclic (A resets B, B resets A) and can't express
attacks needing *multiple simultaneous preconditions* (e.g. ESC1 = Enroll **and**
template misconfig **and** CA reachable). Certipy's ESC output in particular
reads as circular and doesn't compose with ACL abuse.

Orca models every abuse primitive as a **Horn rule** whose head is a derived
capability and whose body is a conjunction of atomic facts, then:

1. **Semi-naive Datalog fixpoint** over collected facts. Capabilities are
   monotonic and the fact domain is finite, so the least fixpoint **always
   terminates** regardless of cycles — this is the formal property that kills
   circular dependencies. ESC chains (ESC4 → ESC1) *compose themselves* from
   atoms instead of being hard-coded.
2. **Knuth's min-cost hyperpath** (Dijkstra generalized to hypergraphs) over the
   recorded justification hypergraph. A fact settles at its final minimal cost
   and a hyperedge is only relaxed once all its tails are settled, so every
   extracted path is provably **acyclic**.
3. **Cost model** per primitive blends difficulty, reliability, and OPSEC noise;
   switching objective re-weights and re-ranks the same graph.

See [`internal/analysis`](internal/analysis) — the rule pack is in `rules.go`,
the evaluator in `datalog.go`, the miner in `hyperpath.go`.

---

## Quick start

```sh
go build -buildvcs=false -o orca.exe ./cmd/orca

# Fuse output you already have from other tools into one dataset:
orca import  --bloodhound ./sharphound.zip --certipy ./certipy.json \
             --ldapsearch ./dump.ldif --seed S-1-5-21-...-1105 --out corp.json
orca serve   --data corp.json

# Or collect live from a DC (authorized engagements only):
orca collect --dc 10.0.0.1 --domain corp.local --user jdoe --password '***' \
             --profile stealth --seed S-1-5-21-...-1105 --out corp.json
orca serve   --data corp.json

# Or print ranked exploitable paths from any collected dataset:
orca analyze --data testdata/sample-domain.json --objective fastest

# Serve the operator UI (localhost) with a stealth OPSEC profile:
orca serve   --data testdata/sample-domain.json --addr 127.0.0.1:8666 --profile stealth

# Compare OPSEC profiles:
orca profiles
```

On `serve`, open `http://127.0.0.1:8666` in a browser. A fresh engagement starts
with **zero foothold** (dataset seeds are ignored on serve); add compromised
accounts/machines from the UI top bar and attack paths re-compute live. Use
`--seeds S-1,S-2` to pre-populate for scripted/headless runs.

---

## CLI reference

All subcommands live in [`cmd/orca/main.go`](cmd/orca/main.go).

### `orca import` — fuse other tools' output into one dataset

```sh
orca import --bloodhound <zip|dir|json>  [--bloodhound ...]
            --ldapsearch <ldif>          [--ldapsearch ...]
            --ldapdomaindump <json|dir>  [--ldapdomaindump ...]
            --certipy <json>             [--certipy ...]
            --seed <SID>                 [--seed ...]
            [--no-implicit]
            --out <dataset.json>
```

SID-based sources are ordered first so Certipy's name-based principals resolve
against them. Implicit-membership enrichment (Authenticated Users / Everyone /
Domain Users) runs by default — drop it with `--no-implicit`.

### `orca collect` — authenticate to a DC and collect live

```sh
orca collect --dc <host> --domain <fqdn> --user <name>
             (--password <pw> | --nt-hash <hex>)
             [--ldaps] [--insecure]
             [--profile stealth|balanced|fast]
             --out <dataset.json>
             [--operator <id>] [--deconflict-log <path>]
             [--seed <SID>]
```

Gathers users, computers, groups, membership, ACLs, RBCD, and AS-REP exposure
into a dataset. Requires a reachable DC.

### `orca analyze` — print ranked exploitable paths to stdout

```sh
orca analyze --data <dataset.json> [--objective practical|balanced|fastest|quietest|reliable]
```

### `orca serve` — serve the operator UI + HTTP API

```sh
orca serve --data <dataset.json>
           [--addr 127.0.0.1:8666]
           [--profile stealth|balanced|fast]
           [--operator <id>] [--deconflict-log <path>]
           [--seeds <sid1,sid2>]
```

### `orca profiles` — print the OPSEC profile table

---

## HTTP API

Go 1.22 method-pattern routes served from [`internal/api/server.go`](internal/api/server.go):

| Method/Route | Purpose |
|---|---|
| `GET /api/stats` | node/fact counts + current seeds |
| `GET /api/findings?objective=&seeds=` | ranked exploitable paths |
| `GET /api/graph?kinds=&preds=&highvalue=1&q=&focus=&hoop=&limit=` | filtered subgraph for the canvas |
| `GET /api/search?q=&kind=&limit=` | name/SID substring search |
| `GET /api/node/{sid}` | full node detail + in/out degree |
| `GET /api/neighbors/{sid}` | one-hop neighbors grouped by predicate |
| `GET /api/path?goal=&objective=&seeds=` | single min-cost path to a goal |
| `GET /api/paths?goal=&k=&objective=&seeds=` | k shortest distinct paths (default k=5) |
| `GET /api/advisories?objective=&seeds=` | advisory findings (e.g. ESC8 relay exposure) |
| `GET /api/chokepoints?n=&objective=&seeds=` | top-N facts by betweenness centrality |
| `GET /api/interesting?objective=&seeds=` | SIDs on any min-cost path to a high-value/CanDCSync goal |
| `GET /api/foothold` · `POST /api/foothold` | read / incrementally update (`{add,remove,set}`) the operator foothold |
| `GET /api/deconflict` | deconfliction log entries |
| `GET /` | SPA (embedded `web/dist`) or the no-build dashboard fallback |

---

## Layout

| Path | Role |
|------|------|
| `internal/model` | canonical node/edge schema + fact vocabulary |
| `internal/graph` | embedded graph store, AES-256-GCM encrypted persistence |
| `internal/analysis` | **fixpoint + hyperpath path engine (the crown jewel)** — `datalog.go`, `rules.go`, `hyperpath.go`, `engine.go`, `centrality.go`, `category.go`, `risk.go` |
| `internal/opsec` | stealth/balanced/fast profiles, jitter, filter mutation, hash-chained deconfliction log |
| `internal/collect` | collector interface + OPSEC-aware runner (noise gating, throttle, logging) |
| `internal/collect/secdesc` | binary `SECURITY_DESCRIPTOR`/ACL/ACE + SID/GUID parser |
| `internal/collect/acl` | ACE → capability-fact normalizer (WriteDacl, DCSync, shadow-creds, …) |
| `internal/collect/adcs` | certificate-template flags/EKUs → ESC atom facts |
| `internal/collect/ldap` | live LDAP collector + entry→node/fact mapper (membership, ACLs, RBCD, high-value) |
| `internal/collect/transport` | go-ldap wire session (LDAP/LDAPS, NTLM/PtH/simple bind, paging, SD_FLAGS) |
| `internal/importer` | parse & fuse BloodHound / ldapsearch (LDIF) / ldapdomaindump / Certipy output, with name→SID resolution and implicit-membership enrichment |
| `internal/ingest` | collector-output JSON schema + loader |
| `internal/api` | HTTP JSON API + SPA serving (with built-in dashboard fallback) |
| `cmd/orca` | CLI (`import`, `collect`, `analyze`, `serve`, `profiles`) |
| `web/` | production Vue 3 + Sigma.js SPA; `web/embed.go` embeds `web/dist` into the binary |
| `scripts/gen_dataset.py` | interactive synthetic-AD dataset generator (with secure decoys) |
| `testdata/` | sample datasets + per-importer fixtures (local-only, git-ignored) |

---

## The operator UI

A BloodHound-CE-style SPA (Vue 3 + Sigma.js + Graphology) embedded directly into
the Go binary via `//go:embed all:dist`. The core BloodHound flow — search,
canned queries, filters, node info, graph navigation — stays front and center;
Orca's analytic extras slide over the canvas as an **Advanced drawer**:

- **Ranked findings** with category/ESC/high-value badges, sortable.
- **k-shortest paths** per target, click-to-highlight on the graph.
- **Chokepoints** (Brandes betweenness) ringed gold on the canvas.
- **Advisories** (e.g. ESC8 relay exposure) separate from compromise findings.
- **Path inspector** with per-step cost bars, narrative, actor/inputs, and
  copy-paste commands + remediation.
- **Objective switcher** (fastest / quietest / reliable / balanced / practical).
- **Multi-foothold** "owned nodes" that re-compute the graph live.
- **Risk-filter** bar (kerberoastable / AS-REP / delegation / RBCD / …) with
  OR/AND combine and a hide-non-matching toggle.

### Building the UI

```sh
cd web && npm install && npm run build   # emits web/dist (embedded by Go)
cd .. && go build -buildvcs=false -o orca.exe ./cmd/orca
```

### Frontend dev (hot reload)

```sh
# Terminal 1 — backend
orca serve --data testdata/sample-domain.json --addr 127.0.0.1:8666
# Terminal 2 — Vite dev server (proxies /api → 127.0.0.1:8666)
cd web && npm run dev
```

---

## Synthetic dataset generator

[`scripts/gen_dataset.py`](scripts/gen_dataset.py) interactively builds a
synthetic AD in Orca's `Dataset` JSON format with **dependency-aware, multi-step**
exploit chains (ESC4, ESC6, ESC3 a→b, ESC5→domain, ESC13, DCSync, nested
AddMember, ESC8) plus **secure decoys** — chains that *look* vulnerable but are
neutralized by one omitted base fact, testing the engine's false-positive
resistance.

```sh
python scripts/gen_dataset.py [--seed N] [--out PATH]
# then:
orca serve --data orca_dataset.json --seeds <foothold-sid>
```

Synthetic data only — fabricated names, random SIDs, no real credentials, no
live systems, no exploitation.

---

## OPSEC (authorized engagements)

Profiles gate collectors by declared noise, apply jittered throttling, randomize
LDAP attribute order and page sizes, decompose signatured filters, prefer ADWS
(9389) over raw LDAP, and skip likely MDI honeytokens. Every action is written
to a tamper-evident, hash-chained deconfliction log (`--deconflict-log`).

---

## Status

- **Engine:** model, encrypted graph store, and the fixpoint + hyperpath
  engine with golden tests (ESC1, ESC4→ESC1, RBCD, shadow-creds, DCSync,
  nested-group→DA, and cyclic-graph termination). Kerberoasting is deliberately
  **excluded** from attack paths (offline crack is not a reliable primitive);
  AS-REP roasting is kept as a first-class primitive with crack-dependent
  reliability so it ranks below deterministic routes.
- **Collection:** binary security-descriptor/ACL/ADCS parsers and their fact
  normalizers (fully unit-tested against crafted blobs), plus an OPSEC-aware
  collector runner. `orca collect` does live LDAP/LDAPS collection (NTLM /
  pass-the-hash / simple bind).
- **Import:** `orca import` fuses BloodHound, ldapsearch, ldapdomaindump, and
  Certipy into one dataset with name→SID resolution and implicit-membership
  enrichment — surfacing cross-tool chains (e.g. BloodHound membership → Certipy
  ESC template) that neither tool finds alone.
- **UI:** production Vue 3 + Sigma.js SPA, ranked findings, WebGL graph with
  live attack-path highlighting, path inspector, objective switcher,
  multi-foothold re-computation. Built to `web/dist` and embedded into the
  binary; the `internal/api/assets` dashboard is the no-build fallback.
- **Next:** AD CS network collection, GPO/SYSVOL, trust traversal, and
  BloodHound/Certipy interop *export*.

---

## Testing

```sh
go test ./...
```

Tests cover the engine (`internal/analysis`), encrypted persistence
(`internal/graph`), OPSEC profiles + deconfliction log (`internal/opsec`), the
binary secdesc/ACL/ADCS parsers and LDAP mapper (`internal/collect/**`), and the
importers (`internal/importer`). `testdata/` holds sample datasets + per-importer
fixtures (local-only, git-ignored).

## License

Authorized red-team use only. Orca maps and advises; it does not execute
exploits, and it keeps a hash-chained deconfliction log of its own activity.