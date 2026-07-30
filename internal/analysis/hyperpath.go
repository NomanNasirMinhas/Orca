package analysis

import (
	"container/heap"
	"math"
	"sort"
)

// Step is one action in an extracted attack path.
type Step struct {
	Rule      string
	Technique string
	ESC       string    // set for AD CS steps
	Head      GroundFact
	Tails     []GroundFact
	Cost      float64   // objective-weighted marginal cost of this hyperedge
	Command   string    // copy-paste exploitation command (placeholders filled)
	Remediation string
	Narrative string  // operator-facing one-line description (placeholders filled)
}

// Path is a minimum-cost, acyclic derivation of a goal fact.
type Path struct {
	Goal      GroundFact
	Reachable bool
	TotalCost float64
	Steps     []Step // ordered so prerequisites precede dependents
}

// pqItem/priorityQueue implement a min-heap keyed by cost for Knuth's algorithm.
type pqItem struct {
	fact string
	cost float64
	idx  int
}
type priorityQueue []*pqItem

func (p priorityQueue) Len() int            { return len(p) }
func (p priorityQueue) Less(i, j int) bool  { return p[i].cost < p[j].cost }
func (p priorityQueue) Swap(i, j int)       { p[i], p[j] = p[j], p[i]; p[i].idx = i; p[j].idx = j }
func (p *priorityQueue) Push(x any) { it := x.(*pqItem); it.idx = len(*p); *p = append(*p, it) }
func (p *priorityQueue) Pop() any {
	old := *p
	n := len(old)
	it := old[n-1]
	*p = old[:n-1]
	return it
}

// MinCost runs Knuth's generalization of Dijkstra to hypergraphs: it computes
// the minimum cost to derive every fact and the best (cheapest) hyperedge for
// each. Because a fact is settled at its final minimal cost and a hyperedge is
// only relaxed once all its tails are settled, the recovered derivations are
// guaranteed acyclic — no fact can depend on a costlier version of itself.
func MinCost(edges []Hyperedge, o Objective, combine func(float64, float64) float64, highValueSIDs map[string]bool) (map[string]float64, map[string]Hyperedge) {
	cost := map[string]float64{}
	best := map[string]Hyperedge{}
	settled := map[string]bool{}

	// Index hyperedges by each tail fact so we can relax when a tail settles.
	byTail := map[string][]int{}
	remaining := make([]int, len(edges)) // count of unsettled tails per edge
	for i, e := range edges {
		remaining[i] = len(e.Tails)
		for _, t := range e.Tails {
			byTail[t.Key()] = append(byTail[t.Key()], i)
		}
	}

	pq := &priorityQueue{}
	heap.Init(pq)
	relax := func(fk string, c float64, e Hyperedge) {
		if cur, ok := cost[fk]; !ok || c < cur {
			cost[fk] = c
			best[fk] = e
			heap.Push(pq, &pqItem{fact: fk, cost: c})
		}
	}

	// Seed from tail-less hyperedges (base facts and empty-body rules).
	for _, e := range edges {
		if len(e.Tails) == 0 {
			relax(e.Head.Key(), edgeWeight(e, o, highValueSIDs), e)
		}
	}

	for pq.Len() > 0 {
		it := heap.Pop(pq).(*pqItem)
		if settled[it.fact] || it.cost > cost[it.fact] {
			continue
		}
		settled[it.fact] = true
		for _, ei := range byTail[it.fact] {
			remaining[ei]--
			if remaining[ei] != 0 {
				continue
			}
			e := edges[ei]
			c := edgeWeight(e, o, highValueSIDs)
			for _, t := range e.Tails {
				c = combine(c, cost[t.Key()])
			}
			relax(e.Head.Key(), c, e)
		}
	}
	return cost, best
}

func edgeWeight(e Hyperedge, o Objective, highValueSIDs map[string]bool) float64 {
	if e.Meta == nil {
		return 0 // base fact
	}
	w := e.Meta.weight(o)
	// Apply target-value penalty: low-reliability primitives cost more when
	// the derived fact involves a high-value principal (e.g. Kerberoasting
	// a Domain Admin's service account is much harder than a regular user).
	if e.Meta.TargetValuePenalty > 1.0 && isHighValueHead(e.Head, highValueSIDs) {
		w *= e.Meta.TargetValuePenalty
	}
	return w
}

// isHighValueHead returns true when the head fact's subject (A) or object (B)
// is a high-value principal.
func isHighValueHead(h GroundFact, hv map[string]bool) bool {
	return hv[h.A] || hv[h.B]
}

// minCostK is a post-pass over settled min-costs: for each head fact it returns
// the up-to-K cheapest hyperedges that derive it (using the min cost of each
// tail). This is the alternative-justification index the k-shortest enumerator
// swaps among. It is an approximation of true k-shortest (tail costs are fixed
// at their minima) but yields distinct, acyclic, cost-ordered derivations —
// exactly what an operator wants when asking "what other paths exist?".
func minCostK(edges []Hyperedge, o Objective, combine func(float64, float64) float64, cost map[string]float64, K int, highValueSIDs map[string]bool) map[string][]Hyperedge {
	type cand struct {
		c float64
		e Hyperedge
	}
	pools := map[string][]cand{}
	for _, e := range edges {
		c := edgeWeight(e, o, highValueSIDs)
		if len(e.Tails) == 0 {
			pools[e.Head.Key()] = append(pools[e.Head.Key()], cand{c, e})
			continue
		}
		ok := true
		for _, t := range e.Tails {
			tc, settled := cost[t.Key()]
			if !settled {
				ok = false
				break
			}
			c = combine(c, tc)
		}
		if !ok {
			continue
		}
		pools[e.Head.Key()] = append(pools[e.Head.Key()], cand{c, e})
	}
	out := map[string][]Hyperedge{}
	for fk, cs := range pools {
		sort.SliceStable(cs, func(i, j int) bool { return cs[i].c < cs[j].c })
		if len(cs) > K {
			cs = cs[:K]
		}
		hs := make([]Hyperedge, len(cs))
		for i, c := range cs {
			hs[i] = c.e
		}
		out[fk] = hs
	}
	return out
}

// SumCombine adds tail costs (path length / total noise). MaxCombine takes the
// worst tail (bottleneck). Sum is the default.
func SumCombine(a, b float64) float64 { return a + b }
func MaxCombine(a, b float64) float64 { return math.Max(a, b) }
