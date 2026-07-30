package analysis

import (
	"maps"
	"sort"
	"strings"

	"orca/internal/model"
)

// Engine holds a compiled rule program and evaluates attack paths against a
// set of collected facts.
type Engine struct {
	prog Program
}

// New returns an Engine loaded with Orca's rule pack.
func New() *Engine { return &Engine{prog: Program{Rules: RulePack()}} }

// NewWithRules lets tests or a future external rule loader supply rules.
func NewWithRules(rules []Rule) *Engine { return &Engine{prog: Program{Rules: rules}} }

// Solution is the result of solving for one or more goals.
type Solution struct {
	all           factIndex
	edges         []Hyperedge
	cost          map[string]float64
	best          map[string]Hyperedge
	names         map[string]string // SID -> display name, for rendering
	o             Objective          // objective the costs were computed under
	combine       func(float64, float64) float64
	highValueSIDs map[string]bool // SIDs of high-value principals for target-value-aware costing
}

// Solve evaluates the program over base facts (collected facts plus the
// operator's foothold seeds) and precomputes minimum costs under an objective.
func (e *Engine) Solve(facts []model.Fact, seeds []string, o Objective) *Solution {
	base := make([]GroundFact, 0, len(facts)+len(seeds))
	names := map[string]string{}
	for _, f := range facts {
		base = append(base, GroundFact{Pred: f.Pred, A: f.A, B: f.B})
	}
	for _, s := range seeds {
		base = append(base, GroundFact{Pred: model.Compromised, A: s})
	}
	all, edges := e.prog.Evaluate(base)
	combine := SumCombine
	if o == Quietest {
		combine = MaxCombine // quietest = minimize the loudest single step
	}
	// Build the set of high-value SIDs for target-value-aware edge weighting.
	hvSIDs := map[string]bool{}
	all.each(model.HighValue, func(g GroundFact) {
		hvSIDs[g.A] = true
	})
	cost, best := MinCost(edges, o, combine, hvSIDs)
	return &Solution{all: all, edges: edges, cost: cost, best: best, names: names, o: o, combine: combine, highValueSIDs: hvSIDs}
}

// SetNames supplies SID->name mappings so rendered steps read well.
func (s *Solution) SetNames(n map[string]string) { s.names = n }

// Derived reports whether a fact was derived (reachable) at all.
func (s *Solution) Derived(f GroundFact) bool { return s.all.has(f) }

// Path extracts the minimum-cost acyclic derivation of the goal fact. If the
// goal is a base/seed fact it returns a trivial reachable path.
func (s *Solution) Path(goal GroundFact) Path {
	gk := goal.Key()
	if _, ok := s.cost[gk]; !ok {
		return Path{Goal: goal, Reachable: false}
	}
	p := Path{Goal: goal, Reachable: true, TotalCost: s.cost[gk]}
	seen := map[string]bool{}
	var walk func(fk string)
	walk = func(fk string) {
		if seen[fk] {
			return
		}
		seen[fk] = true
		e, ok := s.best[fk]
		if !ok || len(e.Tails) == 0 {
			return // base fact: no step to emit
		}
		// Emit prerequisites first (post-order) for a runnable action sequence.
		for _, t := range e.Tails {
			walk(t.Key())
		}
		st := Step{
			Rule:  e.Rule,
			Head:  e.Head,
			Tails: e.Tails,
			Cost:  edgeWeight(e, s.o, s.highValueSIDs), // objective-weighted marginal cost
		}
		if e.Meta != nil {
			st.Technique = e.Meta.Technique
			st.ESC = e.Meta.ESC
			st.Command = s.fill(e.Meta.CommandTmpl, e.Head)
			st.Remediation = s.fill(e.Meta.Remediation, e.Head)
			st.Narrative = s.fillNarrative(e.Meta.NarrativeTmpl, e.Head, e.Tails)
		}
		p.Steps = append(p.Steps, st)
	}
	walk(gk)
	return p
}

// fill substitutes {A}/{B} in a template with display names for the head fact.
func (s *Solution) fill(tmpl string, head GroundFact) string {
	if tmpl == "" {
		return ""
	}
	r := strings.NewReplacer("{A}", s.name(head.A), "{B}", s.name(head.B))
	return r.Replace(tmpl)
}

// fillNarrative fills {A}/{B} (head args) and {P} (the actor principal) in a
// narrative template. The actor is the compromiser/enroller, which for unary
// Compromised(X) heads lives in a tail rather than the head: it is the A of the
// first tail whose predicate is Compromised, falling back to the first tail's A.
func (s *Solution) fillNarrative(tmpl string, head GroundFact, tails []GroundFact) string {
	if tmpl == "" {
		return ""
	}
	actor := ""
	for _, t := range tails {
		if t.Pred == model.Compromised {
			actor = t.A
			break
		}
	}
	if actor == "" && len(tails) > 0 {
		actor = tails[0].A
	}
	r := strings.NewReplacer(
		"{A}", s.name(head.A),
		"{B}", s.name(head.B),
		"{P}", s.name(actor),
	)
	return r.Replace(tmpl)
}

// actorSid resolves the actor principal SID for a step (the compromiser/
// enroller), mirroring fillNarrative's {P} resolution. Used by the API to
// expose the chain's "from" principal on unary Compromised(X) steps.
func (s *Solution) actorSid(tails []GroundFact) string {
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

// KPaths returns up to K distinct minimum-cost derivations of goal, ordered by
// ascending cost. It is a Yen's-style best-first enumerator over the
// justification hypergraph: each fact's top-K alternative hyperedges (from
// minCostK) are swap candidates, and we expand the lowest-cost distinct
// acyclic derivation we have not yet emitted. k=1 reproduces Path().
func (s *Solution) KPaths(goal GroundFact, K int) []Path {
	gk := goal.Key()
	if _, ok := s.cost[gk]; !ok || K <= 0 {
		return nil
	}
	// Index a generous pool of alternatives per fact so the enumerator has room
	// to find K distinct derivations even when some facts share justifiers.
	bestK := minCostK(s.edges, s.o, s.combine, s.cost, K+8, s.highValueSIDs)

	// A derivation is an assignment factKey -> chosen hyperedge index. We
	// represent it by the map of choices; cost + acyclicity are derived.

	// closureOf returns the set of fact keys reachable from goal under choices
	// (following each fact's chosen hyperedge to its tails), or ok=false if a
	// chosen index is missing/out-of-range or a cycle is detected.
	closureOf := func(choices map[string]int) (map[string]bool, bool) {
		visited := map[string]bool{}
		var walk func(fk string) bool
		walk = func(fk string) bool {
			if visited[fk] {
				return true
			}
			visited[fk] = true
			alts := bestK[fk]
			idx, has := choices[fk]
			if !has || idx < 0 || idx >= len(alts) {
				return false
			}
			for _, t := range alts[idx].Tails {
				if !walk(t.Key()) {
					return false
				}
			}
			return true
		}
		if !walk(gk) {
			return nil, false
		}
		// Cycle check: in a functional graph (one chosen hyperedge per fact) a
		// cycle exists iff some fact's DFS revisits an ancestor.
		_, ok := s.derivCost(gk, bestK, choices, map[string]float64{}, map[string]bool{})
		return visited, ok
	}

	// canonical key: sorted concatenation of chosen hyperedge ids.
	keyOf := func(choices map[string]int) string {
		var parts []string
		for fk, idx := range choices {
			if alts := bestK[fk]; idx >= 0 && idx < len(alts) {
				parts = append(parts, alts[idx].key())
			}
		}
		sort.Strings(parts)
		return strings.Join(parts, "|")
	}

	// Initial derivation: index 0 for every reachable fact (the min-cost choice).
	initChoices := map[string]int{}
	{ // assign 0 to each reachable fact using index 0 greedily
		var fill func(fk string)
		fill = func(fk string) {
			if _, seen := initChoices[fk]; seen {
				return
			}
			initChoices[fk] = 0
			alts := bestK[fk]
			if len(alts) == 0 {
				return
			}
			for _, t := range alts[0].Tails {
				fill(t.Key())
			}
		}
		fill(gk)
	}
	_, ok := closureOf(initChoices)
	if !ok {
		// Should not happen — the all-min derivation equals Path() and is acyclic.
		return []Path{s.buildPathFromChoices(goal, bestK, initChoices)}
	}
	initMemo := map[string]float64{}
	initCost, _ := s.derivCost(gk, bestK, initChoices, initMemo, map[string]bool{})
	initKey := keyOf(initChoices)

	// Best-first priority queue over distinct derivations.
	type item struct {
		choices map[string]int
		cost    float64
		key     string
	}
	pq := []item{{initChoices, initCost, initKey}}
	seen := map[string]bool{initKey: true}
	var paths []Path
	for len(pq) > 0 && len(paths) < K {
		// pop min-cost
		mini := 0
		for i := 1; i < len(pq); i++ {
			if pq[i].cost < pq[mini].cost {
				mini = i
			}
		}
		cur := pq[mini]
		pq = append(pq[:mini], pq[mini+1:]...)

		paths = append(paths, s.buildPathFromChoices(goal, bestK, cur.choices))

		// Neighbor derivations: for each fact in the closure, bump its index to
		// the next available alternative and recompute.
		cl, _ := closureOf(cur.choices)
		for fk := range cl {
			alts := bestK[fk]
			next := cur.choices[fk] + 1
			if next >= len(alts) {
				continue
			}
			nb := map[string]int{}
			maps.Copy(nb, cur.choices)
			nb[fk] = next
			// Expand closure: the swap may pull in new facts; fill them at index 0.
			var fill func(f string)
			fill = func(f string) {
				if _, has := nb[f]; has {
					return
				}
				nb[f] = 0
				alts2 := bestK[f]
				if len(alts2) == 0 {
					return
				}
				for _, t := range alts2[0].Tails {
					fill(t.Key())
				}
			}
			// Re-derive any facts now reachable via the swapped hyperedge's tails.
			for _, t := range alts[next].Tails {
				fill(t.Key())
			}
			visited, ok := closureOf(nb)
			if !ok {
				continue
			}
			_ = visited
			memo := map[string]float64{}
			cost, ok := s.derivCost(gk, bestK, nb, memo, map[string]bool{})
			if !ok {
				continue
			}
			k := keyOf(nb)
			if seen[k] {
				continue
			}
			seen[k] = true
			pq = append(pq, item{nb, cost, k})
		}
	}
	return paths
}

// buildPathFromChoices walks the chosen hyperedges post-order to build a Path
// with Steps (mirroring Path()'s rendering), pruning already-emitted facts.
func (s *Solution) buildPathFromChoices(goal GroundFact, bestK map[string][]Hyperedge, choices map[string]int) Path {
	p := Path{Goal: goal, Reachable: true}
	seen := map[string]bool{}
	var walk func(fk string)
	walk = func(fk string) {
		if seen[fk] {
			return
		}
		seen[fk] = true
		alts := bestK[fk]
		idx, has := choices[fk]
		if !has || idx < 0 || idx >= len(alts) {
			return
		}
		e := alts[idx]
		if len(e.Tails) == 0 {
			return // base fact: no step to emit (mirrors Path())
		}
		for _, t := range e.Tails {
			walk(t.Key())
		}
		st := Step{
			Rule:  e.Rule,
			Head:  e.Head,
			Tails: e.Tails,
			Cost:  edgeWeight(e, s.o, s.highValueSIDs), // objective-weighted marginal cost
		}
		if e.Meta != nil {
			st.Technique = e.Meta.Technique
			st.ESC = e.Meta.ESC
			st.Command = s.fill(e.Meta.CommandTmpl, e.Head)
			st.Remediation = s.fill(e.Meta.Remediation, e.Head)
			st.Narrative = s.fillNarrative(e.Meta.NarrativeTmpl, e.Head, e.Tails)
		}
		p.Steps = append(p.Steps, st)
		p.TotalCost = s.cost[goal.Key()] // overwritten below
	}
	walk(goal.Key())
	// Recompute the true total cost for this derivation from the choices.
	memo := map[string]float64{}
	if c, ok := s.derivCost(goal.Key(), bestK, choices, memo, map[string]bool{}); ok {
		p.TotalCost = c
	} else {
		p.TotalCost = s.cost[goal.Key()]
	}
	return p
}

// derivCost is the recursive cost evaluator used by buildPathFromChoices.
func (s *Solution) derivCost(fk string, bestK map[string][]Hyperedge, choices map[string]int, memo map[string]float64, stack map[string]bool) (float64, bool) {
	if c, ok := memo[fk]; ok {
		return c, true
	}
	if stack[fk] {
		return 0, false
	}
	stack[fk] = true
	defer func() { delete(stack, fk) }()
	alts := bestK[fk]
	idx, has := choices[fk]
	if !has || idx < 0 || idx >= len(alts) {
		return 0, false
	}
	e := alts[idx]
	c := edgeWeight(e, s.o, s.highValueSIDs)
	for _, t := range e.Tails {
		tc, ok := s.derivCost(t.Key(), bestK, choices, memo, stack)
		if !ok {
			return 0, false
		}
		c = s.combine(c, tc)
	}
	memo[fk] = c
	return c, true
}

func (s *Solution) name(sid string) string {
	if n, ok := s.names[sid]; ok && n != "" {
		return n
	}
	return sid
}

// Findings mines every high-value goal reachable from the seeds and returns the
// paths sorted by cost (cheapest/most-exploitable first). A goal is any
// Compromised(X) where X is flagged HighValue, plus any principal holding
// CanDCSync (a worthwhile finding even without a HighValue tag).
func (s *Solution) Findings() []Path {
	var goals []GroundFact
	seen := map[string]bool{}
	add := func(g GroundFact) {
		if !seen[g.Key()] {
			seen[g.Key()] = true
			goals = append(goals, g)
		}
	}
	s.all.each(model.HighValue, func(g GroundFact) {
		add(GroundFact{Pred: model.Compromised, A: g.A})
	})
	s.all.each(model.CanDCSync, func(g GroundFact) {
		// A principal that can DCSync a domain is itself a finding: report the
		// compromise of that principal as the goal.
		add(GroundFact{Pred: model.Compromised, A: g.A})
	})

	var paths []Path
	for _, g := range goals {
		p := s.Path(g)
		if p.Reachable && len(p.Steps) > 0 {
			paths = append(paths, p)
		}
	}
	sort.SliceStable(paths, func(i, j int) bool { return paths[i].TotalCost < paths[j].TotalCost })
	return paths
}

// Advisories returns advisory findings that are NOT compromise paths — exposure
// conditions the operator should know about even though no foothold is
// required to reach them. Today this is ESC8 (NTLM relay exposure on a CA with
// web enrollment). Each advisory is returned as a Path with a synthetic Step so
// the UI can reuse the finding shape.
func (s *Solution) Advisories() []Path {
	var out []Path
	s.all.each(model.RelayExposure, func(g GroundFact) {
		// Find the esc8-advisory hyperedge that derived this RelayExposure to
		// attach its meta; fall back to a bare step if not found.
		var meta *RuleMeta
		var tails []GroundFact
		for _, e := range s.edges {
			if e.Rule == "esc8-advisory" && e.Head.Key() == g.Key() {
				meta = e.Meta
				tails = e.Tails
				break
			}
		}
		st := Step{Rule: "esc8-advisory", Head: g, Tails: tails}
		if meta != nil {
			st.Technique = meta.Technique
			st.ESC = meta.ESC
			st.Command = s.fill(meta.CommandTmpl, g)
			st.Remediation = s.fill(meta.Remediation, g)
			st.Narrative = s.fillNarrative(meta.NarrativeTmpl, g, tails)
		}
		out = append(out, Path{Goal: g, Reachable: true, Steps: []Step{st}})
	})
	sort.SliceStable(out, func(i, j int) bool { return out[i].Goal.A < out[j].Goal.A })
	return out
}

// PathSids returns the set of SIDs that participate in any minimum-cost
// derivation of a high-value or CanDCSync goal. For each goal it walks s.best
// post-order (mirroring Path) and collects Head.A/Head.B plus every Tail.A/
// Tail.B. Read-only over the existing fixpoint; no new rules, no re-solve.
func (s *Solution) PathSids() map[string]bool {
	out := map[string]bool{}
	seen := map[string]bool{} // fact keys already walked, to avoid re-traversal
	add := func(g GroundFact) {
		if g.A != "" {
			out[g.A] = true
		}
		if g.B != "" {
			out[g.B] = true
		}
	}
	var walk func(fk string)
	walk = func(fk string) {
		if seen[fk] {
			return
		}
		seen[fk] = true
		e, ok := s.best[fk]
		if !ok {
			return
		}
		add(e.Head)
		for _, t := range e.Tails {
			add(t)
			walk(t.Key())
		}
	}
	// Goal set mirrors Findings: every Compromised(X) where X is HighValue, plus
	// every principal holding CanDCSync.
	s.all.each(model.HighValue, func(g GroundFact) {
		walk(GroundFact{Pred: model.Compromised, A: g.A}.Key())
	})
	s.all.each(model.CanDCSync, func(g GroundFact) {
		walk(GroundFact{Pred: model.Compromised, A: g.A}.Key())
	})
	return out
}
