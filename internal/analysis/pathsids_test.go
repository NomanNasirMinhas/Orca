package analysis

import (
	"testing"

	"orca/internal/model"
)

// TestPathSids verifies that the on-any-attack-path SID set covers every
// principal participating in a minimum-cost derivation of a high-value goal,
// and excludes principals that are not on any path.
func TestPathSids(t *testing.T) {
	// foothold -> member of G1 -> G1 member of Domain Admins (high value).
	// An unrelated account and an isolated high-value target are NOT on a path.
	const (
		g1        = "S-1-G1"
		unrelated = "S-1-UNRELATED" // base IsUser, not on any path, not HV
		isolated  = "S-1-ISOLATED"  // HighValue but never compromised
	)
	facts := []model.Fact{
		f(model.MemberOf, foothold, g1),
		f(model.MemberOf, g1, da),
		u(model.HighValue, da),
		u(model.IsUser, da),
		// Noise: present in the fact base but not on any attack path.
		u(model.IsUser, unrelated),
		f(model.MemberOf, unrelated, g1), // unrelated -> G1, but unrelated is not a seed
		u(model.HighValue, isolated),     // HV goal with no derivation
	}
	sol := New().Solve(facts, []string{foothold}, Balanced)

	// Sanity: da is reachable, unrelated and isolated are not.
	if !sol.Path(GroundFact{Pred: model.Compromised, A: da}).Reachable {
		t.Fatal("expected da reachable from foothold")
	}

	sids := sol.PathSids()
	must := []string{foothold, g1, da}
	for _, sid := range must {
		if !sids[sid] {
			t.Errorf("PathSids: expected %s on an attack path", sid)
		}
	}
	if sids[unrelated] {
		t.Errorf("PathSids: unrelated node %s should not be on an attack path", unrelated)
	}
	if sids[isolated] {
		t.Errorf("PathSids: isolated HV node %s has no derivation; should not appear", isolated)
	}
}

// TestStepNarrativeAndCost checks that Step.Narrative is filled and Step.Cost
// carries the objective-weighted marginal cost (not the hardcoded 1).
func TestStepNarrativeAndCost(t *testing.T) {
	// foothold has GenericAll over daUser (high value) -> compromise-via-control.
	facts := []model.Fact{
		f(model.GenericAll, foothold, daUser),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	p := solveTo(t, facts, daUser, Balanced)
	if len(p.Steps) != 2 {
		t.Fatalf("expected 2 steps (ctrl-genericall + compromise-via-control), got %d", len(p.Steps))
	}
	// Every step should carry a narrative and an objective-weighted cost > 1
	// (under Balanced both rules cost Difficulty+Noise+-log(rel), all > 1).
	for i, st := range p.Steps {
		if st.Narrative == "" {
			t.Errorf("step %d: expected Narrative populated, got empty", i)
		}
		if st.Cost <= 1 {
			t.Errorf("step %d: expected objective-weighted Cost > 1 (was hardcoded 1), got %f", i, st.Cost)
		}
	}
	// The actor ({P}) for compromise-via-control is the foothold.
	sol := New().Solve(facts, []string{foothold}, Balanced)
	sol.SetNames(map[string]string{foothold: "foothold-name", daUser: "da-name"})
	n := sol.fillNarrative("{P} abuses its control right to compromise {A}",
		GroundFact{Pred: model.Compromised, A: daUser},
		[]GroundFact{{Pred: model.Compromised, A: foothold}, {Pred: model.CanControl, A: foothold, B: daUser}})
	if n != "foothold-name abuses its control right to compromise da-name" {
		t.Errorf("fillNarrative {P} resolution wrong: %q", n)
	}
}