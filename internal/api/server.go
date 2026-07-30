// Package api serves Orca's HTTP JSON API and the embedded operator UI. The
// production UI is a Vue 3 SPA built into web/dist; this package embeds a
// lightweight dashboard so the single binary is usable out of the box.
package api

import (
	"embed"
	"encoding/json"
	"io/fs"
	"net/http"
	"net/url"
	"slices"
	"sort"
	"strconv"
	"strings"
	"sync"

	"orca/internal/analysis"
	"orca/internal/graph"
	"orca/internal/model"
	"orca/internal/opsec"
	"orca/web"
)

//go:embed assets/index.html
var assets embed.FS

// Server exposes a graph and its analysis over HTTP, bound to localhost.
type Server struct {
	g      *graph.Graph
	engine *analysis.Engine
	seeds  []string
	seedMu sync.RWMutex // guards seeds (mutated by the foothold endpoints)
	log    *opsec.DeconflictLog

	// risks is the lazily-computed per-SID risk-flag map (sid → sorted flags),
	// used by the SPA's risk filter bar. The graph is immutable after load so the
	// cache never needs invalidation; sync.Once makes first use concurrency-safe.
	risksOnce sync.Once
	risks     map[string][]string
}

// New builds a server over the given graph and foothold seeds.
func New(g *graph.Graph, seeds []string, log *opsec.DeconflictLog) *Server {
	return &Server{g: g, engine: analysis.New(), seeds: dedupSeeds(seeds), log: log}
}

// Seeds returns a copy of the current foothold seeds (concurrency-safe).
func (s *Server) Seeds() []string {
	s.seedMu.RLock()
	defer s.seedMu.RUnlock()
	return append([]string(nil), s.seeds...)
}

// setSeeds replaces the foothold seeds with a deduplicated copy (write-locked).
func (s *Server) setSeeds(seeds []string) {
	s.seedMu.Lock()
	defer s.seedMu.Unlock()
	s.seeds = dedupSeeds(seeds)
}

// dedupSeeds preserves order while dropping duplicates.
func dedupSeeds(seeds []string) []string {
	seen := map[string]bool{}
	out := make([]string, 0, len(seeds))
	for _, s := range seeds {
		if s == "" || seen[s] {
			continue
		}
		seen[s] = true
		out = append(out, s)
	}
	return out
}

// riskFlags returns the cached per-SID risk flags, computing once on first use.
// Safe to call concurrently; the graph is immutable after load.
func (s *Server) riskFlags() map[string][]string {
	s.risksOnce.Do(func() { s.risks = analysis.RiskFlags(s.g) })
	return s.risks
}

// Handler returns the HTTP mux for the API and UI.
func (s *Server) Handler() http.Handler {
	mux := http.NewServeMux()
	// Go 1.22+ method-pattern routing keeps per-resource handlers tidy.
	mux.HandleFunc("GET /api/stats", s.handleStats)
	mux.HandleFunc("GET /api/findings", s.handleFindings)
	mux.HandleFunc("GET /api/graph", s.handleGraph)
	mux.HandleFunc("GET /api/search", s.handleSearch)
	mux.HandleFunc("GET /api/node/{sid}", s.handleNode)
	mux.HandleFunc("GET /api/neighbors/{sid}", s.handleNeighbors)
	mux.HandleFunc("GET /api/path", s.handlePath)
	mux.HandleFunc("GET /api/paths", s.handlePaths)
	mux.HandleFunc("GET /api/advisories", s.handleAdvisories)
	mux.HandleFunc("GET /api/chokepoints", s.handleChokepoints)
	mux.HandleFunc("GET /api/interesting", s.handleInteresting)
	mux.HandleFunc("GET /api/foothold", s.handleGetFoothold)
	mux.HandleFunc("POST /api/foothold", s.handlePostFoothold)
	mux.HandleFunc("GET /api/deconflict", s.handleDeconflict)
	mux.Handle("/", s.uiHandler())
	return mux
}

// uiHandler serves the built Vue SPA if it was embedded, otherwise the built-in
// single-file dashboard. The SPA handler falls back to index.html for client
// routes so deep links work.
func (s *Server) uiHandler() http.Handler {
	if dist, ok := web.Dist(); ok {
		return spaHandler(dist)
	}
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/" {
			http.NotFound(w, r)
			return
		}
		b, _ := assets.ReadFile("assets/index.html")
		w.Header().Set("Content-Type", "text/html; charset=utf-8")
		w.Write(b)
	})
}

func spaHandler(dist fs.FS) http.Handler {
	fileServer := http.FileServer(http.FS(dist))
	return http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		p := strings.TrimPrefix(r.URL.Path, "/")
		if p == "" {
			p = "index.html"
		}
		if _, err := fs.Stat(dist, p); err != nil {
			// Unknown non-API path: serve the SPA entrypoint (client routing).
			b, _ := fs.ReadFile(dist, "index.html")
			w.Header().Set("Content-Type", "text/html; charset=utf-8")
			w.Write(b)
			return
		}
		fileServer.ServeHTTP(w, r)
	})
}

// solutionFor re-solves the engine for a given objective and an optional
// per-request seed override. The base path uses s.seeds; endpoints that let
// the operator pick a different foothold pass their own seed list.
func (s *Server) solutionFor(objective string, seeds []string) *analysis.Solution {
	o := analysis.Objective(objective)
	if o == "" {
		o = analysis.Balanced
	}
	use := seeds
	if len(use) == 0 {
		use = s.Seeds()
	}
	sol := s.engine.Solve(s.g.Facts(), use, o)
	sol.SetNames(s.g.Names())
	return sol
}

func (s *Server) handleStats(w http.ResponseWriter, r *http.Request) {
	n, f := s.g.Stats()
	writeJSON(w, map[string]any{"nodes": n, "facts": f, "seeds": s.Seeds()})
}

// footholdView is the API shape for the operator's live foothold: parallel
// slices of SIDs and resolved display names.
type footholdView struct {
	Seeds []string `json:"seeds"`
	Names []string `json:"names"`
}

func (s *Server) footholdView() footholdView {
	seeds := s.Seeds()
	names := s.g.Names()
	out := footholdView{Seeds: seeds, Names: make([]string, len(seeds))}
	for i, sd := range seeds {
		if n, ok := names[sd]; ok && n != "" {
			out.Names[i] = n
		} else {
			out.Names[i] = sd
		}
	}
	if out.Seeds == nil {
		out.Seeds = []string{}
	}
	if out.Names == nil {
		out.Names = []string{}
	}
	return out
}

// handleGetFoothold returns the operator's current foothold seeds + names.
func (s *Server) handleGetFoothold(w http.ResponseWriter, r *http.Request) {
	writeJSON(w, s.footholdView())
}

// footholdReq is an incremental update to the foothold: Set replaces the whole
// list; otherwise Add/Remove are applied in order against the current seeds.
type footholdReq struct {
	Add    []string `json:"add"`
	Remove []string `json:"remove"`
	Set    []string `json:"set"`
}

// handlePostFoothold mutates the server's live foothold. Unknown SIDs are
// rejected with 400 so the SPA never adds a node the graph doesn't know about.
func (s *Server) handlePostFoothold(w http.ResponseWriter, r *http.Request) {
	var req footholdReq
	if err := json.NewDecoder(r.Body).Decode(&req); err != nil {
		http.Error(w, "invalid JSON body", http.StatusBadRequest)
		return
	}
	// Validate every referenced SID exists in the graph.
	for _, sid := range append(append([]string{}, req.Add...), append(req.Remove, req.Set...)...) {
		if sid == "" {
			continue
		}
		if _, ok := s.g.Node(sid); !ok {
			http.Error(w, "unknown sid: "+sid, http.StatusBadRequest)
			return
		}
	}

	var next []string
	if req.Set != nil {
		next = req.Set
		if s.log != nil {
			s.log.Record("foothold.set", strings.Join(req.Set, ","), "replace foothold")
		}
	} else {
		next = s.Seeds()
		// Add (dedup handled by setSeeds).
		next = append(next, req.Add...)
		// Remove.
		if len(req.Remove) > 0 {
			rm := map[string]bool{}
			for _, sid := range req.Remove {
				rm[sid] = true
			}
			filtered := next[:0]
			for _, sid := range next {
				if !rm[sid] {
					filtered = append(filtered, sid)
				}
			}
			next = filtered
		}
		if s.log != nil {
			if len(req.Add) > 0 {
				s.log.Record("foothold.add", strings.Join(req.Add, ","), "add to foothold")
			}
			if len(req.Remove) > 0 {
				s.log.Record("foothold.remove", strings.Join(req.Remove, ","), "remove from foothold")
			}
		}
	}
	s.setSeeds(next)
	writeJSON(w, s.footholdView())
}

// finding is the API view of an attack path, with SIDs resolved to names.
type finding struct {
	Goal          string     `json:"goal"`
	GoalName      string     `json:"goalName"`
	GoalHighValue bool       `json:"goalHighValue"`
	Cost          float64    `json:"cost"`
	Categories    []string   `json:"categories"`
	ESCs          []string   `json:"escs"`
	Steps         []stepView `json:"steps"`
}

type stepView struct {
	Rule        string     `json:"rule"`
	Technique   string     `json:"technique"`
	ESC         string     `json:"esc,omitempty"`
	Category    string     `json:"category"`
	From        string     `json:"from"`
	To          string     `json:"to"`
	Actor       string     `json:"actor,omitempty"`
	Narrative   string     `json:"narrative,omitempty"`
	Cost        float64    `json:"cost"`
	Inputs      []factView `json:"inputs,omitempty"`
	Command     string     `json:"command,omitempty"`
	Remediation string     `json:"remediation,omitempty"`
}

// factView is a resolved tail fact: the capabilities/relationships a step
// consumes. Pure property/typing atoms (HasSPN, IsUser, template flags, ...) are
// filtered out so the chain lists only the meaningful inputs.
type factView struct {
	Pred  string `json:"pred"`
	A     string `json:"a"`
	B     string `json:"b"`
	AName string `json:"aName"`
	BName string `json:"bName"`
}

// findingFromPath builds the API view from an engine Path, resolving SIDs to
// display names and computing the category/ESC facet sets the UI filters on.
func (s *Server) findingFromPath(p analysis.Path, nm func(string) string) finding {
	fv := finding{
		Goal:     p.Goal.A,
		GoalName: nm(p.Goal.A),
		Cost:     p.TotalCost,
	}
	if n, ok := s.g.Node(p.Goal.A); ok {
		fv.GoalHighValue = n.HighValue
	}
	catSet := map[string]bool{}
	escSet := map[string]bool{}
	for _, st := range p.Steps {
		cat := string(analysis.CategoryLabelOf(st.Rule, st.ESC))
		catSet[cat] = true
		if st.ESC != "" {
			escSet[st.ESC] = true
		}
		fv.Steps = append(fv.Steps, stepView{
			Rule:        st.Rule,
			Technique:   st.Technique,
			ESC:         st.ESC,
			Category:    cat,
			From:        nm(st.Head.A),
			To:          nm(st.Head.B),
			Actor:       nm(actorSid(st.Tails)),
			Narrative:   st.Narrative,
			Cost:        st.Cost,
			Inputs:      stepInputs(st.Tails, nm),
			Command:     st.Command,
			Remediation: st.Remediation,
		})
	}
	fv.Categories = sortedSet(catSet)
	fv.ESCs = sortedSet(escSet)
	return fv
}

func sortedSet(m map[string]bool) []string {
	if len(m) == 0 {
		return []string{}
	}
	out := make([]string, 0, len(m))
	for k := range m {
		out = append(out, k)
	}
	sort.Strings(out)
	return out
}

func (s *Server) handleFindings(w http.ResponseWriter, r *http.Request) {
	obj := r.URL.Query().Get("objective")
	seeds := seedsFromQuery(r.URL.Query())
	sol := s.solutionFor(obj, seeds)
	names := s.g.Names()
	nm := func(sid string) string {
		if n, ok := names[sid]; ok {
			return n
		}
		return sid
	}
	var out []finding
	for _, p := range sol.Findings() {
		out = append(out, s.findingFromPath(p, nm))
	}
	if s.log != nil {
		s.log.Record("analysis.findings", "local", obj)
	}
	writeJSON(w, out)
}

// handlePath returns the single minimum-cost path to a requested goal SID,
// reusing the finding shape so the SPA's path inspector renders it unchanged.
func (s *Server) handlePath(w http.ResponseWriter, r *http.Request) {
	goal := r.URL.Query().Get("goal")
	if goal == "" {
		http.Error(w, "missing goal", http.StatusBadRequest)
		return
	}
	obj := r.URL.Query().Get("objective")
	seeds := seedsFromQuery(r.URL.Query())
	sol := s.solutionFor(obj, seeds)
	names := s.g.Names()
	nm := func(sid string) string {
		if n, ok := names[sid]; ok {
			return n
		}
		return sid
	}
	p := sol.Path(analysis.GroundFact{Pred: model.Compromised, A: goal})
	if !p.Reachable {
		writeJSON(w, finding{Goal: goal, GoalName: nm(goal)})
		return
	}
	writeJSON(w, s.findingFromPath(p, nm))
}

// handlePaths returns the k shortest distinct paths to a goal SID, for the
// "alternate paths" view. k defaults to 5.
func (s *Server) handlePaths(w http.ResponseWriter, r *http.Request) {
	goal := r.URL.Query().Get("goal")
	if goal == "" {
		http.Error(w, "missing goal", http.StatusBadRequest)
		return
	}
	k := atoiDefault(r.URL.Query().Get("k"), 5)
	obj := r.URL.Query().Get("objective")
	seeds := seedsFromQuery(r.URL.Query())
	sol := s.solutionFor(obj, seeds)
	names := s.g.Names()
	nm := func(sid string) string {
		if n, ok := names[sid]; ok {
			return n
		}
		return sid
	}
	var out []finding
	for _, p := range sol.KPaths(analysis.GroundFact{Pred: model.Compromised, A: goal}, k) {
		if !p.Reachable {
			continue
		}
		out = append(out, s.findingFromPath(p, nm))
	}
	if out == nil {
		out = []finding{}
	}
	writeJSON(w, out)
}

// handleAdvisories returns advisory findings (ESC8 relay exposure) that are not
// compromise paths but still warrant operator attention.
func (s *Server) handleAdvisories(w http.ResponseWriter, r *http.Request) {
	obj := r.URL.Query().Get("objective")
	seeds := seedsFromQuery(r.URL.Query())
	sol := s.solutionFor(obj, seeds)
	names := s.g.Names()
	nm := func(sid string) string {
		if n, ok := names[sid]; ok {
			return n
		}
		return sid
	}
	var out []finding
	for _, p := range sol.Advisories() {
		out = append(out, s.findingFromPath(p, nm))
	}
	if out == nil {
		out = []finding{}
	}
	writeJSON(w, out)
}

// handleChokepoints returns the top-N facts by betweenness centrality — single
// capabilities whose removal would break many attack paths. n defaults to 20.
func (s *Server) handleChokepoints(w http.ResponseWriter, r *http.Request) {
	n := atoiDefault(r.URL.Query().Get("n"), 20)
	obj := r.URL.Query().Get("objective")
	seeds := seedsFromQuery(r.URL.Query())
	sol := s.solutionFor(obj, seeds)
	names := s.g.Names()
	nm := func(sid string) string {
		if n, ok := names[sid]; ok {
			return n
		}
		return sid
	}
	type cp struct {
		Pred  string  `json:"pred"`
		A     string  `json:"a"`
		B     string  `json:"b"`
		AName string  `json:"aName"`
		BName string  `json:"bName"`
		Score float64 `json:"score"`
	}
	var out []cp
	for _, c := range sol.Centrality(n) {
		out = append(out, cp{
			Pred: string(c.Fact.Pred), A: c.Fact.A, B: c.Fact.B,
			AName: nm(c.Fact.A), BName: nm(c.Fact.B), Score: c.Score,
		})
	}
	if out == nil {
		out = []cp{}
	}
	writeJSON(w, out)
}

// handleInteresting returns the SIDs that participate in any minimum-cost
// derivation of a high-value or CanDCSync goal (the "on an attack path" set),
// plus every high-value node. The SPA unions this with chokepoints and the
// current selection to decide which nodes to keep when "hide boring" is on.
func (s *Server) handleInteresting(w http.ResponseWriter, r *http.Request) {
	obj := r.URL.Query().Get("objective")
	seeds := seedsFromQuery(r.URL.Query())
	sol := s.solutionFor(obj, seeds)
	sids := sol.PathSids()
	for _, n := range s.g.Nodes() {
		if n.HighValue {
			sids[n.SID] = true
		}
	}
	out := make([]string, 0, len(sids))
	for sid := range sids {
		out = append(out, sid)
	}
	sort.Strings(out)
	writeJSON(w, map[string]any{"sids": out})
}

// nodeView is the graph node shape used by /api/graph, /api/search and
// /api/neighbors. Props are only populated by /api/node (full detail). Risks is
// the per-node risk-flag list (kerberoastable / asrep / disabled / ...) computed
// by analysis.RiskFlags; shipped on every node view so the SPA can filter and
// badge without an extra round-trip.
type nodeView struct {
	SID       string            `json:"sid"`
	Name      string            `json:"name"`
	Kind      string            `json:"kind"`
	HighValue bool              `json:"highValue"`
	Props     map[string]string `json:"props,omitempty"`
	Risks     []string          `json:"risks,omitempty"`
}

type edgeView struct {
	Pred string `json:"pred"`
	From string `json:"from"`
	To   string `json:"to"`
}

func (n nodeView) fromNode(m model.Node, risks map[string][]string) nodeView {
	return nodeView{SID: m.SID, Name: m.Name, Kind: string(m.Kind),
		HighValue: m.HighValue, Props: m.Props, Risks: risks[m.SID]}
}

// handleGraph returns nodes and edges for the UI graph canvas. Without query
// params it returns the whole graph; with filters it returns a focused subgraph
// so large datasets do not ship a multi-MB payload every load.
func (s *Server) handleGraph(w http.ResponseWriter, r *http.Request) {
	q := r.URL.Query()
	wantKinds := splitCSV(q.Get("kinds"))
	wantPreds := splitCSV(q.Get("preds"))
	hvOnly := q.Get("highvalue") == "1"
	query := strings.ToLower(q.Get("q"))
	focus := q.Get("focus")
	hoop := atoiDefault(q.Get("hoop"), 1)
	limit := atoiDefault(q.Get("limit"), 0) // 0 = no cap

	allNodes := s.g.Nodes()
	// nameLower for substring search.
	nameLower := map[string]string{}
	for _, n := range allNodes {
		nameLower[n.SID] = strings.ToLower(n.Name + " " + n.SID)
	}

	// Decide which SIDs to keep. Only apply the node-side filter (q/kinds/hv)
	// when at least one is set — matchesNode returns true for every node when no
	// filter is active, which would seed `keep` with the whole graph.
	nodeFilter := query != "" || len(wantKinds) > 0 || hvOnly
	keep := map[string]bool{}
	if nodeFilter {
		for _, n := range allNodes {
			if matchesNode(n, query, wantKinds, hvOnly) {
				keep[n.SID] = true
			}
		}
	}

	// Focus neighborhood: BFS over edges touching `focus` up to hoop hops.
	if focus != "" {
		nb := s.bfsNeighborhood(focus, hoop)
		for sid := range nb {
			keep[sid] = true
		}
	}

	// No node-side filter and no focus: start from the full graph so the
	// unfiltered SPA graph canvas renders every node and a bare limit=N
	// returns the top-N by degree (not just HV+seeds).
	hasFilter := nodeFilter || focus != ""
	if !hasFilter {
		for _, n := range allNodes {
			keep[n.SID] = true
		}
	}

	// A query/kind/hv filter that matched nothing: fall back to the full set so
	// the operator still gets a usable graph rather than an empty one.
	if hasFilter && len(keep) == 0 {
		for _, n := range allNodes {
			keep[n.SID] = true
		}
	}

	// Always include operator seeds + high-value targets so paths still render.
	// Use both the server's live foothold and any per-request seeds (the SPA
	// sends its foothold set so the keep-set reflects the current view).
	reqSeeds := seedsFromQuery(q)
	for _, sd := range append(s.Seeds(), reqSeeds...) {
		keep[sd] = true
	}
	for _, n := range allNodes {
		if n.HighValue {
			keep[n.SID] = true
		}
	}

	// If a node limit is set, rank by degree and trim to the cap while always
	// preserving seeds + HV + focus-neighborhood + query matches.
	if limit > 0 && len(keep) > limit {
		deg := s.degreeMap()
		mustKeep := map[string]bool{}
		for sid := range keep {
			if query != "" && strings.Contains(nameLower[sid], query) {
				mustKeep[sid] = true
			}
		}
		for _, sd := range append(s.Seeds(), reqSeeds...) {
			mustKeep[sd] = true
		}
		for _, n := range allNodes {
			if n.HighValue {
				mustKeep[n.SID] = true
			}
		}
		if focus != "" {
			mustKeep[focus] = true
		}
		type cand struct {
			sid string
			d   int
		}
		var cands []cand
		for sid := range keep {
			cands = append(cands, cand{sid, deg[sid]})
		}
		sort.Slice(cands, func(i, j int) bool { return cands[i].d > cands[j].d })
		kept := map[string]bool{}
		for sid := range mustKeep {
			kept[sid] = true
		}
		for _, c := range cands {
			if len(kept) >= limit {
				break
			}
			kept[c.sid] = true
		}
		keep = kept
	}

	var nodes []nodeView
	riskMap := s.riskFlags()
	for _, n := range allNodes {
		if keep[n.SID] {
			nodes = append(nodes, nodeView{SID: n.SID, Name: n.Name, Kind: string(n.Kind),
				HighValue: n.HighValue, Risks: riskMap[n.SID]})
		}
	}
	var edges []edgeView
	for _, f := range s.g.Facts() {
		if f.B == "" || isTypingPred(f.Pred) {
			continue
		}
		if len(wantPreds) > 0 && !containsStr(wantPreds, string(f.Pred)) {
			continue
		}
		if !keep[f.A] || !keep[f.B] {
			continue
		}
		edges = append(edges, edgeView{Pred: string(f.Pred), From: f.A, To: f.B})
	}
	writeJSON(w, map[string]any{"nodes": nodes, "edges": edges})
}

// matchesNode applies the q/kinds/highvalue node-side filters.
func matchesNode(n model.Node, query string, kinds []string, hvOnly bool) bool {
	if hvOnly && !n.HighValue {
		return false
	}
	if len(kinds) > 0 && !containsStr(kinds, string(n.Kind)) {
		return false
	}
	if query != "" {
		hay := strings.ToLower(n.Name + " " + n.SID)
		if !strings.Contains(hay, query) {
			return false
		}
	}
	return true
}

// bfsNeighborhood returns SIDs within `hoop` hops of `sid` over any non-typing
// predicate (treating the fact graph as undirected for neighborhood expansion).
func (s *Server) bfsNeighborhood(sid string, hoop int) map[string]bool {
	out := map[string]bool{sid: true}
	if hoop <= 0 {
		return out
	}
	type entry struct {
		sid  string
		hops int
	}
	queue := []entry{{sid, 0}}
	for len(queue) > 0 {
		cur := queue[0]
		queue = queue[1:]
		if cur.hops >= hoop {
			continue
		}
		_, edges := s.g.Neighbors(cur.sid)
		for _, e := range edges {
			other := e.A
			if e.A == cur.sid {
				other = e.B
			}
			if !out[other] {
				out[other] = true
				queue = append(queue, entry{other, cur.hops + 1})
			}
		}
	}
	return out
}

func (s *Server) degreeMap() map[string]int {
	d := map[string]int{}
	for _, f := range s.g.Facts() {
		if f.B == "" || isTypingPred(f.Pred) {
			continue
		}
		d[f.A]++
		d[f.B]++
	}
	return d
}

// handleSearch returns nodes matching a name/SID substring (optional kind
// filter), capped to a sane default. Used by the graph search overlay.
func (s *Server) handleSearch(w http.ResponseWriter, r *http.Request) {
	q := strings.ToLower(r.URL.Query().Get("q"))
	kind := r.URL.Query().Get("kind")
	limit := atoiDefault(r.URL.Query().Get("limit"), 50)
	type hit struct {
		SID       string   `json:"sid"`
		Name      string   `json:"name"`
		Kind      string   `json:"kind"`
		HighValue bool     `json:"highValue"`
		Risks     []string `json:"risks,omitempty"`
	}
	riskMap := s.riskFlags()
	var out []hit
	for _, n := range s.g.Nodes() {
		if q != "" {
			hay := strings.ToLower(n.Name + " " + n.SID)
			if !strings.Contains(hay, q) {
				continue
			}
		}
		if kind != "" && string(n.Kind) != kind {
			continue
		}
		out = append(out, hit{SID: n.SID, Name: n.Name, Kind: string(n.Kind),
			HighValue: n.HighValue, Risks: riskMap[n.SID]})
		if len(out) >= limit {
			break
		}
	}
	if out == nil {
		out = []hit{} // emit [] not null so clients can read .length safely
	}
	writeJSON(w, out)
}

// handleNode returns full detail for one node: props plus per-predicate in/out
// degree, which the NodeInspector surfaces.
func (s *Server) handleNode(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	n, ok := s.g.Node(sid)
	if !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	d := s.g.Degree(sid)
	writeJSON(w, map[string]any{
		"node":   nodeView{}.fromNode(n, s.riskFlags()),
		"degree": map[string]any{"out": d.Out, "in": d.In},
	})
}

// handleNeighbors returns one-hop neighbors and the edges touching a node,
// grouped by predicate with counts for the inspector's summary.
func (s *Server) handleNeighbors(w http.ResponseWriter, r *http.Request) {
	sid := r.PathValue("sid")
	if _, ok := s.g.Node(sid); !ok {
		http.Error(w, "not found", http.StatusNotFound)
		return
	}
	sids, edges := s.g.Neighbors(sid)
	names := s.g.Names()
	nm := func(s string) string {
		if n, ok := names[s]; ok {
			return n
		}
		return s
	}
	type nbView struct {
		SID       string   `json:"sid"`
		Name      string   `json:"name"`
		Kind      string   `json:"kind"`
		HighValue bool     `json:"highValue"`
		Risks     []string `json:"risks,omitempty"`
	}
	riskMap := s.riskFlags()
	var nbs []nbView
	for _, s2 := range sids {
		if n, ok := s.g.Node(s2); ok {
			nbs = append(nbs, nbView{SID: n.SID, Name: n.Name, Kind: string(n.Kind),
				HighValue: n.HighValue, Risks: riskMap[n.SID]})
		} else {
			nbs = append(nbs, nbView{SID: s2, Name: nm(s2)})
		}
	}
	type edgeRow struct {
		Pred string `json:"pred"`
		From string `json:"from"`
		To   string `json:"to"`
	}
	var ev []edgeRow
	for _, e := range edges {
		ev = append(ev, edgeRow{Pred: string(e.Pred), From: nm(e.A), To: nm(e.B)})
	}
	writeJSON(w, map[string]any{"neighbors": nbs, "edges": ev})
}

func (s *Server) handleDeconflict(w http.ResponseWriter, r *http.Request) {
	if s.log == nil {
		writeJSON(w, []any{})
		return
	}
	writeJSON(w, s.log.Entries())
}

func isTypingPred(p model.Pred) bool {
	switch p {
	case model.IsUser, model.IsComputer, model.IsGroup, model.IsDomain,
		model.IsTemplate, model.HighValue:
		return true
	}
	return false
}

// isPropertyPred reports whether a predicate is a pure property/attribute
// assertion on a single entity (unary typing or a template/CA flag). Such tails
// are excluded from step Inputs so the chain shows only the relationships and
// capabilities a step actually consumes.
func isPropertyPred(p model.Pred) bool {
	switch p {
	case model.IsUser, model.IsComputer, model.IsGroup, model.IsDomain,
		model.IsTemplate, model.IsCA, model.HighValue,
		model.HasSPN, model.ASREPRoastable,
		model.TemplateEnrolleeSuppliesSubject, model.TemplateAuthEKU,
		model.TemplateNoManagerApproval, model.CAReachable,
		model.TemplateAnyEKU, model.TemplateEnrollmentAgentEKU,
		model.TemplateRequiresAgentSignature,
		model.CAEditfSan2, model.WebEnrollmentEnabled,
		model.HttpRelayCapable, model.NoSignatureEnforcement:
		return true
	}
	return false
}

// actorSid resolves the actor principal SID for a step's tails — the
// compromiser/enroller that drives a unary Compromised(X) head. Mirrors the
// engine's {P} narrative resolution.
func actorSid(tails []analysis.GroundFact) string {
	for _, t := range tails {
		if t.Pred == model.Compromised {
			return t.A
		}
	}
	if len(tails) > 0 {
		return tails[0].A
	}
	return ""
}

// stepInputs renders the meaningful tail facts (relationships/capabilities) of a
// step as resolved factViews, skipping pure property/typing atoms.
func stepInputs(tails []analysis.GroundFact, nm func(string) string) []factView {
	var out []factView
	for _, t := range tails {
		if isPropertyPred(t.Pred) {
			continue
		}
		out = append(out, factView{
			Pred:  string(t.Pred),
			A:     t.A,
			B:     t.B,
			AName: nm(t.A),
			BName: nm(t.B),
		})
	}
	return out
}

func writeJSON(w http.ResponseWriter, v any) {
	w.Header().Set("Content-Type", "application/json")
	json.NewEncoder(w).Encode(v)
}

func splitCSV(s string) []string {
	if s == "" {
		return nil
	}
	parts := strings.Split(s, ",")
	out := make([]string, 0, len(parts))
	for _, p := range parts {
		p = strings.TrimSpace(p)
		if p != "" {
			out = append(out, p)
		}
	}
	return out
}

// seedsFromQuery extracts the foothold seeds from a request. Accepts the
// multi-seed `seeds` (comma-separated) form and, for backward compatibility,
// the single `seed` form. Returns nil when neither is present so the caller
// falls back to the server's live foothold.
func seedsFromQuery(q url.Values) []string {
	if s := q.Get("seeds"); s != "" {
		return splitCSV(s)
	}
	if s := q.Get("seed"); s != "" {
		return []string{s}
	}
	return nil
}

func containsStr(s []string, v string) bool {
	return slices.Contains(s, v)
}

func atoiDefault(s string, def int) int {
	if s == "" {
		return def
	}
	n, err := strconv.Atoi(s)
	if err != nil {
		return def
	}
	return n
}
