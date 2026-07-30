package graph

import (
	"sort"
	"testing"

	"orca/internal/model"
)

// TestDegree verifies forward + reverse adjacency counting, which the node
// inspector and graph degree-based limiting both depend on.
func TestDegree(t *testing.T) {
	g := New()
	g.AddNode(model.Node{SID: "U1", Kind: model.KindUser})
	g.AddNode(model.Node{SID: "G1", Kind: model.KindGroup})
	g.AddNode(model.Node{SID: "U2", Kind: model.KindUser})
	// U1 -> G1 (member), U1 -> U2 (controls). Plus a unary typing fact.
	g.AddFact(model.Fact{Pred: model.MemberOf, A: "U1", B: "G1"})
	g.AddFact(model.Fact{Pred: model.GenericAll, A: "U1", B: "U2"})
	g.AddFact(model.Fact{Pred: model.IsUser, A: "U1"}) // unary, not counted as edge

	d := g.Degree("U1")
	if d.Out[string(model.MemberOf)] != 1 || d.Out[string(model.GenericAll)] != 1 {
		t.Fatalf("U1 out degree = %+v, want MemberOf=1 GenericAll=1", d.Out)
	}
	if len(d.In) != 0 {
		t.Fatalf("U1 in degree = %+v, want empty", d.In)
	}

	d2 := g.Degree("U2")
	if d2.In[string(model.GenericAll)] != 1 {
		t.Fatalf("U2 in degree = %+v, want GenericAll=1", d2.In)
	}
	if len(d2.Out) != 0 {
		t.Fatalf("U2 out degree = %+v, want empty", d2.Out)
	}

	// Neighbors: U1 touches G1 and U2; dedup is per-SID.
	sids, edges := g.Neighbors("U1")
	sort.Strings(sids)
	if len(sids) != 2 || sids[0] != "G1" || sids[1] != "U2" {
		t.Fatalf("U1 neighbors = %v, want [G1 U2]", sids)
	}
	if len(edges) != 2 {
		t.Fatalf("U1 neighbor edges = %d, want 2", len(edges))
	}
}