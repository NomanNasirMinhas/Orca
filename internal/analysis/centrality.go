package analysis

import (
	"sort"
	"strings"

	"orca/internal/model"
)

// Chokepoint is a fact that lies on many minimum-cost derivations — a single
// capability whose removal would break a large fraction of attack paths. The
// Score is its betweenness centrality in the justification DAG.
type Chokepoint struct {
	Fact  GroundFact
	Score float64
}

// Centrality computes betweenness centrality over the justification DAG and
// returns the top-N facts by score. The DAG is the reverse of the derivation
// graph: an edge goes from each tail fact to the head fact it supports (tail →
// head), so a fact with high betweenness sits "upstream" of many goal facts.
// We run Brandes from each seed (Compromised(seedSid)); only facts reachable
// from a seed get nonzero score, which keeps the result meaningful for the
// operator's actual foothold.
func (s *Solution) Centrality(topN int) []Chokepoint {
	if topN <= 0 {
		return nil
	}

	// Build forward adjacency over the justification DAG: tail fact -> heads
	// it supports (i.e. hyperedges where it is a tail).
	fwd := map[string][]string{}
	for _, e := range s.edges {
		if len(e.Tails) == 0 {
			continue
		}
		hk := e.Head.Key()
		for _, t := range e.Tails {
			tk := t.Key()
			fwd[tk] = append(fwd[tk], hk)
		}
	}

	// Seed roots: base Compromised facts (the operator's foothold). A fact is a
	// root when its best hyperedge has no tails (i.e. it is a seed/base fact, not
	// a downstream derivation). If none qualify, fall back to all Compromised
	// facts so the metric is still defined.
	var roots []string
	s.all.each(model.Compromised, func(g GroundFact) {
		if e, ok := s.best[g.Key()]; ok && len(e.Tails) == 0 {
			roots = append(roots, g.Key())
		}
	})
	if len(roots) == 0 {
		s.all.each(model.Compromised, func(g GroundFact) { roots = append(roots, g.Key()) })
	}

	score := map[string]float64{}
	for _, root := range roots {
		brandes(root, fwd, score)
	}

	out := make([]Chokepoint, 0, len(score))
	for fk, sc := range score {
		out = append(out, Chokepoint{Fact: parseKey(fk), Score: sc})
	}
	sort.SliceStable(out, func(i, j int) bool { return out[i].Score > out[j].Score })
	if len(out) > topN {
		out = out[:topN]
	}
	return out
}

// brandes computes a single-source betweenness accumulation from root over the
// DAG described by fwd (fact -> successors). It is the DAG specialization of
// Brandes' algorithm: dependencies accumulate via shortest-path DAG counts.
func brandes(root string, fwd map[string][]string, score map[string]float64) {
	// BFS in topological order over the shortest-path DAG from root. Because the
	// justification DAG is already acyclic (the engine guarantees this), a BFS
	// ordered by distance works.
	type node struct {
		key  string
		dist int
	}
	dist := map[string]int{root: 0}
	sigma := map[string]float64{root: 1} // shortest-path count
	pred := map[string][]string{}        // predecessors on shortest paths
	var stack []string                    // topological order (BFS discovery)
	visited := map[string]bool{root: true}
	queue := []string{root}
	for len(queue) > 0 {
		v := queue[0]
		queue = queue[1:]
		stack = append(stack, v)
		for _, w := range fwd[v] {
			if _, seen := dist[w]; !seen {
				dist[w] = dist[v] + 1
				queue = append(queue, w)
				visited[w] = true
			}
			if dist[w] == dist[v]+1 {
				sigma[w] += sigma[v]
				pred[w] = append(pred[w], v)
			}
		}
	}
	// Accumulate dependencies in reverse topological order.
	delta := map[string]float64{}
	for i := len(stack) - 1; i >= 0; i-- {
		w := stack[i]
		for _, v := range pred[w] {
			// contribution of v via w
			delta[v] += (sigma[v] / sigma[w]) * (1 + delta[w])
		}
		if w != root {
			score[w] += delta[w]
		}
	}
}

// parseKey reverses GroundFact.Key() to recover the GroundFact for the result.
// The key format is "Pred|A|B"; none of the components contain "|".
func parseKey(k string) GroundFact {
	parts := strings.Split(k, "|")
	if len(parts) != 3 {
		return GroundFact{Pred: model.Pred(k)}
	}
	return GroundFact{Pred: model.Pred(parts[0]), A: parts[1], B: parts[2]}
}