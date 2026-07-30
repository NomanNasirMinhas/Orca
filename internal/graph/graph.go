// Package graph is Orca's embedded attack-graph store: an in-memory typed
// property graph with a SID index and adjacency, persisted to a single
// AES-GCM-encrypted file so collected client data never rests in plaintext.
package graph

import (
	"sync"

	"orca/internal/model"
)

// Graph holds nodes and facts collected from a domain. It implements
// model.FactSink so collectors can write into it directly.
type Graph struct {
	mu    sync.RWMutex
	nodes map[string]model.Node // SID -> node
	facts map[string]model.Fact // Fact.Key() -> fact (dedup)
	// adjacency: predicate -> A -> list of B (forward, for traversal/queries)
	adj map[model.Pred]map[string][]string
	// reverse adjacency: predicate -> B -> list of A (for inbound degree/neighbors)
	radj map[model.Pred]map[string][]string
}

// New returns an empty graph.
func New() *Graph {
	return &Graph{
		nodes: map[string]model.Node{},
		facts: map[string]model.Fact{},
		adj:   map[model.Pred]map[string][]string{},
		radj:  map[model.Pred]map[string][]string{},
	}
}

// AddNode inserts or merges a node, preserving HighValue and known props.
func (g *Graph) AddNode(n model.Node) {
	g.mu.Lock()
	defer g.mu.Unlock()
	if ex, ok := g.nodes[n.SID]; ok {
		if n.Name == "" {
			n.Name = ex.Name
		}
		n.HighValue = n.HighValue || ex.HighValue
		if ex.Props != nil && n.Props == nil {
			n.Props = ex.Props
		}
	}
	g.nodes[n.SID] = n
}

// AddFact inserts a fact (deduplicated) and updates adjacency.
func (g *Graph) AddFact(f model.Fact) {
	g.mu.Lock()
	defer g.mu.Unlock()
	k := f.Key()
	if _, ok := g.facts[k]; ok {
		return
	}
	g.facts[k] = f
	if f.B != "" {
		// Forward adjacency: A -> B.
		m := g.adj[f.Pred]
		if m == nil {
			m = map[string][]string{}
			g.adj[f.Pred] = m
		}
		m[f.A] = append(m[f.A], f.B)
		// Reverse adjacency: B -> A (skip unary facts where B is empty).
		rm := g.radj[f.Pred]
		if rm == nil {
			rm = map[string][]string{}
			g.radj[f.Pred] = rm
		}
		rm[f.B] = append(rm[f.B], f.A)
	}
}

// Degree summarizes a node's edge counts grouped by predicate, in both
// directions. Used by the node inspector and chokepoint ranking.
type Degree struct {
	Out map[string]int // outbound count per pred (A == sid)
	In  map[string]int // inbound count per pred (B == sid)
}

// Degree returns the per-predicate in/out edge counts for a SID. Unary facts
// (B empty) are not counted as edges.
func (g *Graph) Degree(sid string) Degree {
	g.mu.RLock()
	defer g.mu.RUnlock()
	d := Degree{Out: map[string]int{}, In: map[string]int{}}
	for pred, m := range g.adj {
		if bs, ok := m[sid]; ok {
			d.Out[string(pred)] = len(bs)
		}
	}
	for pred, m := range g.radj {
		if as, ok := m[sid]; ok {
			d.In[string(pred)] = len(as)
		}
	}
	return d
}

// Neighbors returns the distinct SIDs adjacent to sid via any predicate, plus
// the edges (predicate + from + to) that touch sid. Used by /api/neighbors.
func (g *Graph) Neighbors(sid string) (sids []string, edges []model.Fact) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	seen := map[string]bool{}
	for _, f := range g.facts {
		if f.B == "" {
			continue
		}
		if f.A == sid || f.B == sid {
			edges = append(edges, f)
			// Pick the endpoint that is NOT sid (the neighbor).
			other := f.B
			if f.B == sid {
				other = f.A
			}
			if other != sid && !seen[other] {
				seen[other] = true
				sids = append(sids, other)
			}
		}
	}
	return sids, edges
}

// Facts returns a snapshot of all facts for the analysis engine.
func (g *Graph) Facts() []model.Fact {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]model.Fact, 0, len(g.facts))
	for _, f := range g.facts {
		out = append(out, f)
	}
	return out
}

// Names returns a SID->display-name map for rendering paths.
func (g *Graph) Names() map[string]string {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make(map[string]string, len(g.nodes))
	for sid, n := range g.nodes {
		name := n.Name
		if name == "" {
			name = sid
		}
		out[sid] = name
	}
	return out
}

// Nodes returns a snapshot of all nodes.
func (g *Graph) Nodes() []model.Node {
	g.mu.RLock()
	defer g.mu.RUnlock()
	out := make([]model.Node, 0, len(g.nodes))
	for _, n := range g.nodes {
		out = append(out, n)
	}
	return out
}

// Node returns the node for a SID and whether it exists.
func (g *Graph) Node(sid string) (model.Node, bool) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	n, ok := g.nodes[sid]
	return n, ok
}

// Stats returns node and fact counts, shown in the CLI/UI after collection.
func (g *Graph) Stats() (nodes, facts int) {
	g.mu.RLock()
	defer g.mu.RUnlock()
	return len(g.nodes), len(g.facts)
}
