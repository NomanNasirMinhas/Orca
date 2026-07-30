// Package analysis is Orca's path-analysis engine. It evaluates a Horn-rule
// program over collected facts to a least fixpoint (semi-naive Datalog),
// recording every ground derivation as a hyperedge. Because derived
// capabilities are monotonic and the fact domain is finite, the fixpoint
// always terminates regardless of cycles in the underlying entity graph —
// this is what eliminates Certipy-style circular dependencies. The resulting
// justification hypergraph is then mined for minimum-cost attack paths.
package analysis

import (
	"sort"
	"strings"

	"orca/internal/model"
)

// Term is a rule argument: either a variable (Var=true, Name holds the var)
// or a constant (Var=false, Name holds the literal SID).
type Term struct {
	Var  bool
	Name string
}

// V builds a variable term; C builds a constant term.
func V(name string) Term { return Term{Var: true, Name: name} }
func C(val string) Term  { return Term{Var: false, Name: val} }

// Atom is a predicate applied to up to two terms. Unary atoms leave B unused.
type Atom struct {
	Pred  model.Pred
	A     Term
	B     Term
	Unary bool
}

// Rule is a Horn clause: Head holds if every Body atom holds under a binding.
type Rule struct {
	Name string
	Head Atom
	Body []Atom
	Meta RuleMeta
}

// GroundFact is a fact with no provenance, used inside the engine.
type GroundFact struct {
	Pred model.Pred
	A, B string
}

func (g GroundFact) Key() string { return string(g.Pred) + "|" + g.A + "|" + g.B }

// Hyperedge records one ground derivation: applying Rule to Tails yields Head.
// A base fact is a hyperedge with no tails. Multiple hyperedges may share a
// head (the OR alternatives the path miner chooses between).
type Hyperedge struct {
	Head  GroundFact
	Tails []GroundFact
	Rule  string   // "" for base facts
	Meta  *RuleMeta
}

func (h Hyperedge) key() string {
	parts := make([]string, 0, len(h.Tails)+2)
	parts = append(parts, h.Rule, h.Head.Key())
	for _, t := range h.Tails {
		parts = append(parts, t.Key())
	}
	sort.Strings(parts[2:])
	return strings.Join(parts, "#")
}

// factIndex stores facts grouped by predicate for fast joins.
type factIndex map[model.Pred]map[string]GroundFact

func newFactIndex() factIndex { return factIndex{} }

func (fi factIndex) add(g GroundFact) bool {
	m := fi[g.Pred]
	if m == nil {
		m = map[string]GroundFact{}
		fi[g.Pred] = m
	}
	k := g.Key()
	if _, ok := m[k]; ok {
		return false
	}
	m[k] = g
	return true
}

func (fi factIndex) has(g GroundFact) bool {
	m := fi[g.Pred]
	if m == nil {
		return false
	}
	_, ok := m[g.Key()]
	return ok
}

func (fi factIndex) each(p model.Pred, fn func(GroundFact)) {
	for _, g := range fi[p] {
		fn(g)
	}
}

// Program is a rule set plus its base facts.
type Program struct {
	Rules []Rule
}

// Evaluate runs semi-naive Datalog to the least fixpoint over base and returns
// all reachable facts plus every ground hyperedge that justifies them.
func (p *Program) Evaluate(base []GroundFact) (factIndex, []Hyperedge) {
	all := newFactIndex()
	edges := map[string]Hyperedge{}

	// Seed base facts as tail-less hyperedges.
	delta := newFactIndex()
	for _, g := range base {
		if all.add(g) {
			delta.add(g)
			he := Hyperedge{Head: g}
			edges[he.key()] = he
		}
	}

	for len(delta.flat()) > 0 {
		next := newFactIndex()
		for i := range p.Rules {
			r := &p.Rules[i]
			// Semi-naive: for each body position, bind that atom from delta and
			// the rest from the full set, so every new derivation is found once.
			for pos := range r.Body {
				p.fire(r, pos, all, delta, func(head GroundFact, tails []GroundFact) {
					he := Hyperedge{Head: head, Tails: tails, Rule: r.Name, Meta: &r.Meta}
					edges[he.key()] = he
					if !all.has(head) {
						next.add(head)
					}
				})
			}
		}
		// Fold next into all; it becomes the new delta.
		nd := newFactIndex()
		for _, g := range next.flat() {
			if all.add(g) {
				nd.add(g)
			}
		}
		delta = nd
	}

	out := make([]Hyperedge, 0, len(edges))
	for _, e := range edges {
		out = append(out, e)
	}
	return all, out
}

// fire enumerates all bindings of rule r where body atom deltaPos ranges over
// deltaFacts and every other atom ranges over allFacts, invoking emit per match.
func (p *Program) fire(r *Rule, deltaPos int, all, delta factIndex, emit func(GroundFact, []GroundFact)) {
	binding := map[string]string{}
	var rec func(i int)
	rec = func(i int) {
		if i == len(r.Body) {
			head := ground(r.Head, binding)
			tails := make([]GroundFact, len(r.Body))
			for j, a := range r.Body {
				tails[j] = ground(a, binding)
			}
			emit(head, tails)
			return
		}
		src := all
		if i == deltaPos {
			src = delta
		}
		a := r.Body[i]
		src.each(a.Pred, func(g GroundFact) {
			if a.Unary && g.B != "" {
				return
			}
			saved := map[string]string{}
			if !bindTerm(a.A, g.A, binding, saved) {
				return
			}
			if !a.Unary {
				if !bindTerm(a.B, g.B, binding, saved) {
					unbind(binding, saved)
					return
				}
			}
			rec(i + 1)
			unbind(binding, saved)
		})
	}
	rec(0)
}

// bindTerm unifies a term with a value under the current binding, recording any
// newly bound variable in saved so it can be rolled back.
func bindTerm(t Term, val string, binding, saved map[string]string) bool {
	if !t.Var {
		return t.Name == val
	}
	if cur, ok := binding[t.Name]; ok {
		return cur == val
	}
	binding[t.Name] = val
	saved[t.Name] = val
	return true
}

func unbind(binding, saved map[string]string) {
	for k := range saved {
		delete(binding, k)
	}
}

func ground(a Atom, binding map[string]string) GroundFact {
	g := GroundFact{Pred: a.Pred, A: resolve(a.A, binding)}
	if !a.Unary {
		g.B = resolve(a.B, binding)
	}
	return g
}

func resolve(t Term, binding map[string]string) string {
	if t.Var {
		return binding[t.Name]
	}
	return t.Name
}

func (fi factIndex) flat() []GroundFact {
	var out []GroundFact
	for _, m := range fi {
		for _, g := range m {
			out = append(out, g)
		}
	}
	return out
}
