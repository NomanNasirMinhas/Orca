package analysis

import (
	"reflect"
	"slices"
	"sort"
	"testing"

	"orca/internal/graph"
	"orca/internal/model"
)

// equalStrings compares two string slices order-independently.
func equalStrings(a, b []string) bool {
	if len(a) != len(b) {
		return false
	}
	a2 := append([]string{}, a...)
	b2 := append([]string{}, b...)
	sort.Strings(a2)
	sort.Strings(b2)
	return reflect.DeepEqual(a2, b2)
}

func contains(xs []string, s string) bool {
	return slices.Contains(xs, s)
}

// TestDecodeUAC covers each UAC bit independently plus composite values.
func TestDecodeUAC(t *testing.T) {
	cases := []struct {
		uac  string
		want []string
	}{
		{"", nil},
		{"not-a-number", nil},
		{"2", []string{RiskDisabled}},
		{"32", []string{RiskPasswordNotRequired}},               // 0x20
		{"8192", []string{RiskDomainController}},                 // 0x2000
		{"65536", []string{RiskPasswordNeverExpires}},            // 0x10000
		{"262144", []string{RiskSmartcardRequired}},             // 0x40000
		{"524288", []string{RiskUnconstrainedDelegation}},        // 0x80000
		{"2097152", []string{RiskDESOnly}},                       // 0x200000
		{"4194304", []string{RiskASREPRoastable}},                // 0x400000
		{"8388608", []string{RiskPasswordExpired}},              // 0x800000
		{"16777216", []string{RiskConstrainedDelegation}},        // 0x1000000
		// NOT_DELEGATED 0x100000 = 1048576 → not a flag → nil.
		{"1048576", nil},
		// Composite: disabled + asrep + unconstrained (0x2 + 0x400000 + 0x80000 = 4718594).
		{"4718594", []string{RiskASREPRoastable, RiskDisabled, RiskUnconstrainedDelegation}},
		// Both delegation bits set (0x80000 | 0x1000000 = 17301504).
		{"17301504", []string{RiskConstrainedDelegation, RiskUnconstrainedDelegation}},
	}
	for _, c := range cases {
		got := decodeUAC(c.uac)
		if !equalStrings(got, c.want) {
			t.Errorf("decodeUAC(%q) = %v, want %v", c.uac, got, c.want)
		}
	}
}

// TestRiskFlagsFromProps classifies nodes whose signal comes only from Props.
func TestRiskFlagsFromProps(t *testing.T) {
	g := graph.New()
	g.AddNode(model.Node{SID: "U1", Kind: model.KindUser,
		Props: map[string]string{"userAccountControl": "4194304"}}) // asrep
	g.AddNode(model.Node{SID: "U2", Kind: model.KindUser,
		Props: map[string]string{"userAccountControl": "524288", "kerberoastable": "true"}}) // unconstrained + spn prop
	got := RiskFlags(g)
	if !equalStrings(got["U1"], []string{RiskASREPRoastable}) {
		t.Errorf("U1: got %v, want [asrep-roastable]", got["U1"])
	}
	if !equalStrings(got["U2"], []string{RiskKerberoastable, RiskUnconstrainedDelegation}) {
		t.Errorf("U2: got %v, want [kerberoastable unconstrained-delegation]", got["U2"])
	}
}

// TestRiskFlagsFromFacts covers BloodHound-style nodes that set no Props but
// emit facts, and verifies RBCD lands on B (the computer), not A (the trustee).
func TestRiskFlagsFromFacts(t *testing.T) {
	g := graph.New()
	g.AddNode(model.Node{SID: "U1", Kind: model.KindUser})    // no Props
	g.AddNode(model.Node{SID: "C1", Kind: model.KindComputer}) // no Props
	g.AddFact(model.Fact{Pred: model.HasSPN, A: "U1"})
	g.AddFact(model.Fact{Pred: model.ASREPRoastable, A: "U1"})
	g.AddFact(model.Fact{Pred: model.AllowedToAct, A: "U1", B: "C1"})
	got := RiskFlags(g)
	if !contains(got["U1"], RiskKerberoastable) || !contains(got["U1"], RiskASREPRoastable) {
		t.Errorf("U1: expected kerberoastable+asrep via facts, got %v", got["U1"])
	}
	if contains(got["U1"], RiskRBCD) {
		t.Errorf("U1: must not carry rbcd (it is the trustee A), got %v", got["U1"])
	}
	if !equalStrings(got["C1"], []string{RiskRBCD}) {
		t.Errorf("C1: expected [rbcd] (configured computer = B), got %v", got["C1"])
	}
}

// TestRiskFlagsHighValue derives high-value from node.HighValue only.
func TestRiskFlagsHighValue(t *testing.T) {
	g := graph.New()
	g.AddNode(model.Node{SID: "H1", Kind: model.KindUser, HighValue: true})
	g.AddNode(model.Node{SID: "L1", Kind: model.KindUser})
	got := RiskFlags(g)
	if !equalStrings(got["H1"], []string{RiskHighValue}) {
		t.Errorf("H1: got %v, want [high-value]", got["H1"])
	}
	if _, ok := got["L1"]; ok {
		t.Errorf("L1: should have no flags, got %v", got["L1"])
	}
}

// TestRiskFlagsDedup ensures UAC-decoded and Props-derived signals for the
// same flag collapse to a single entry.
func TestRiskFlagsDedup(t *testing.T) {
	g := graph.New()
	g.AddNode(model.Node{SID: "U1", Kind: model.KindUser, Props: map[string]string{
		"userAccountControl": "4194304", // asrep via UAC
		"asrepRoastable":    "true",    // same flag via props
	}})
	got := RiskFlags(g)
	if len(got["U1"]) != 1 || got["U1"][0] != RiskASREPRoastable {
		t.Errorf("U1: expected single asrep flag after dedup, got %v", got["U1"])
	}
}

// TestRiskFlagsNoRisks checks that nodes with no signal are absent from the map.
func TestRiskFlagsNoRisks(t *testing.T) {
	g := graph.New()
	g.AddNode(model.Node{SID: "X1", Kind: model.KindOU})
	got := RiskFlags(g)
	if _, ok := got["X1"]; ok {
		t.Errorf("X1: should be absent (no risks), got %v", got["X1"])
	}
}

// TestRiskFlagsSorted verifies the per-SID flag list is sorted.
func TestRiskFlagsSorted(t *testing.T) {
	g := graph.New()
	g.AddNode(model.Node{SID: "U1", Kind: model.KindUser,
		Props: map[string]string{"userAccountControl": "4718594"}}) // asrep+disabled+unconstrained
	got := RiskFlags(g)
	if !sort.StringsAreSorted(got["U1"]) {
		t.Errorf("U1: flags not sorted: %v", got["U1"])
	}
}

// TestRiskFlagsFactAndPropsCombine ensures both signal sources contribute to
// the same node (Props UAC + a graph fact).
func TestRiskFlagsFactAndPropsCombine(t *testing.T) {
	g := graph.New()
	g.AddNode(model.Node{SID: "U1", Kind: model.KindUser,
		Props: map[string]string{"userAccountControl": "2"}}) // disabled
	g.AddFact(model.Fact{Pred: model.HasSPN, A: "U1"})       // kerberoastable via fact
	got := RiskFlags(g)
	if !equalStrings(got["U1"], []string{RiskDisabled, RiskKerberoastable}) {
		t.Errorf("U1: expected [disabled kerberoastable] from Props+fact, got %v", got["U1"])
	}
}