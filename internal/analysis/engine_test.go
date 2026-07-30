package analysis

import (
	"testing"

	"orca/internal/model"
)

// helpers to build facts concisely.
func f(p model.Pred, a, b string) model.Fact { return model.Fact{Pred: p, A: a, B: b} }
func u(p model.Pred, a string) model.Fact    { return model.Fact{Pred: p, A: a} }

// SIDs used across fixtures.
const (
	foothold = "S-1-LOWPRIV"    // the account the operator starts with
	da       = "S-1-DA-GROUP"   // Domain Admins group (high value)
	daUser   = "S-1-DA-USER"    // a Domain Admins member (high value)
	domain   = "S-1-DOMAIN"     // the domain root (high value)
	tmpl     = "S-1-TEMPLATE"   // a cert template
)

// assertReachable solves and returns the path to Compromised(target).
func solveTo(t *testing.T, facts []model.Fact, target string, o Objective) Path {
	t.Helper()
	e := New()
	sol := e.Solve(facts, []string{foothold}, o)
	return sol.Path(GroundFact{Pred: model.Compromised, A: target})
}

// assertAcyclic verifies no step's output feeds one of its own (transitive)
// prerequisites — the core "no circular dependency" guarantee.
func assertAcyclic(t *testing.T, p Path) {
	t.Helper()
	produced := map[string]int{} // head fact -> step index that produced it
	for i, s := range p.Steps {
		for _, tail := range s.Tails {
			if j, ok := produced[tail.Key()]; ok && j >= i {
				t.Fatalf("cycle: step %d depends on tail %s produced at/after it (step %d)", i, tail.Key(), j)
			}
		}
		produced[s.Head.Key()] = i
	}
}

func TestNestedGroupToDA(t *testing.T) {
	// foothold -> member of G1 -> G1 member of Domain Admins.
	facts := []model.Fact{
		f(model.MemberOf, foothold, "S-1-G1"),
		f(model.MemberOf, "S-1-G1", da),
		u(model.HighValue, da),
	}
	p := solveTo(t, facts, da, Fastest)
	if !p.Reachable {
		t.Fatal("expected Domain Admins reachable via nested membership")
	}
	assertAcyclic(t, p)
}

func TestForceChangePasswordChain(t *testing.T) {
	// foothold can reset daUser's password; daUser is in Domain Admins.
	facts := []model.Fact{
		f(model.ForceChangePassword, foothold, daUser),
		f(model.MemberOf, daUser, da),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
		u(model.HighValue, da),
	}
	p := solveTo(t, facts, daUser, Fastest)
	if !p.Reachable {
		t.Fatal("expected daUser compromise via ForceChangePassword")
	}
	assertAcyclic(t, p)
}

func TestESC1(t *testing.T) {
	// foothold can enroll in a misconfigured template -> auth as any user.
	facts := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		u(model.TemplateEnrolleeSuppliesSubject, tmpl),
		u(model.TemplateAuthEKU, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.CAReachable, tmpl),
		u(model.IsTemplate, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	p := solveTo(t, facts, daUser, Balanced)
	if !p.Reachable {
		t.Fatal("expected ESC1 to compromise a high-value user")
	}
	assertAcyclic(t, p)
	if !hasESC(p, "ESC1") {
		t.Fatalf("expected an ESC1 step, got steps: %v", techniques(p))
	}
}

func TestESC4ComposesIntoESC1(t *testing.T) {
	// foothold has WriteDacl over the template (ESC4). The template lacks the
	// ESC1 misconfig outright, but controlling it lets the attacker rewrite it.
	facts := []model.Fact{
		f(model.WriteDacl, foothold, tmpl),
		u(model.IsTemplate, tmpl),
		u(model.CAReachable, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	p := solveTo(t, facts, daUser, Balanced)
	if !p.Reachable {
		t.Fatal("expected ESC4->ESC1 composition to compromise a high-value user")
	}
	assertAcyclic(t, p)
	if !hasESC(p, "ESC4") {
		t.Fatalf("expected an ESC4 step, got: %v", techniques(p))
	}
}

func TestRBCD(t *testing.T) {
	comp := "S-1-DC01" // a high-value computer (e.g. a DC)
	facts := []model.Fact{
		f(model.AllowedToAct, foothold, comp),
		u(model.IsComputer, comp),
		u(model.HighValue, comp),
	}
	p := solveTo(t, facts, comp, Fastest)
	if !p.Reachable {
		t.Fatal("expected RBCD impersonation to compromise the computer")
	}
	assertAcyclic(t, p)
}

func TestShadowCredentials(t *testing.T) {
	facts := []model.Fact{
		f(model.AddKeyCredentialLink, foothold, daUser),
		f(model.MemberOf, daUser, da),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	p := solveTo(t, facts, daUser, Reliable)
	if !p.Reachable {
		t.Fatal("expected shadow-credentials compromise")
	}
	assertAcyclic(t, p)
}

// Kerberoasting is intentionally excluded from attack paths (the kerberoast
// rule and the targeted WriteSPN kerberoast control rule are both omitted).
// A foothold whose only route to DA is via an SPN account must therefore NOT
// reach DA — there is no kerberoast edge to traverse.
func TestKerberoastExcluded(t *testing.T) {
	facts := []model.Fact{
		u(model.HasSPN, "S-SVC"),
		u(model.IsUser, "S-SVC"),
		f(model.MemberOf, "S-SVC", da),
		u(model.HighValue, da),
	}
	p := solveTo(t, facts, da, Balanced)
	if p.Reachable {
		t.Fatalf("kerberoast route should not exist; DA unexpectedly reachable via %v", techniques(p))
	}
	if hasRule(p, "kerberoast") {
		t.Fatalf("kerberoast step must never appear in a path, got %v", techniques(p))
	}
}

func TestASREPRoast(t *testing.T) {
	facts := []model.Fact{
		u(model.ASREPRoastable, "S-SVC"),
		u(model.IsUser, "S-SVC"),
		f(model.MemberOf, "S-SVC", da),
		u(model.HighValue, da),
	}
	p := solveTo(t, facts, da, Balanced)
	if !p.Reachable {
		t.Fatal("expected DA reachable via AS-REP roast")
	}
	assertAcyclic(t, p)
	if !hasRule(p, "asrep-roast") {
		t.Fatalf("expected an asrep-roast step, got %v", techniques(p))
	}
}

// Kerberoasting is excluded from paths under every objective. Even when a
// kerberoast-looking route exists (an SPN user in DA), the only path that
// remains is the deterministic membership route — never a kerberoast step.
func TestKerberoastNeverUsed(t *testing.T) {
	facts := []model.Fact{
		// Direct, reliable route: foothold is already a member of DA.
		f(model.MemberOf, foothold, da),
		// A kerberoast-looking route to the same goal via S-SVC (now excluded).
		u(model.HasSPN, "S-SVC"), u(model.IsUser, "S-SVC"),
		f(model.MemberOf, "S-SVC", da),
		u(model.HighValue, da),
	}
	for _, o := range []Objective{Reliable, Balanced, Practical, Fastest, Quietest} {
		p := solveTo(t, facts, da, o)
		if !p.Reachable {
			t.Fatalf("%s: expected DA reachable via membership", o)
		}
		if hasRule(p, "kerberoast") {
			t.Fatalf("%s: kerberoast step must never appear, got %v", o, techniques(p))
		}
	}
}

func TestDCSync(t *testing.T) {
	facts := []model.Fact{
		f(model.HasGetChanges, foothold, domain),
		f(model.HasGetChangesAll, foothold, domain),
		u(model.IsDomain, domain),
		u(model.HighValue, domain),
	}
	e := New()
	sol := e.Solve(facts, []string{foothold}, Balanced)
	// CanDCSync must be derived, and the domain compromised.
	if !sol.Derived(GroundFact{Pred: model.CanDCSync, A: foothold, B: domain}) {
		t.Fatal("expected CanDCSync to be derived")
	}
	p := sol.Path(GroundFact{Pred: model.Compromised, A: domain})
	if !p.Reachable {
		t.Fatal("expected domain compromise via DCSync")
	}
	assertAcyclic(t, p)
}

// TestCircularEntityGraphTerminates is the headline guarantee: a mutually
// controlling set of principals (A resets B, B resets A) must converge at the
// fixpoint and still yield an acyclic path, never loop.
func TestCircularEntityGraphTerminates(t *testing.T) {
	a, b := "S-1-A", "S-1-B"
	facts := []model.Fact{
		f(model.ForceChangePassword, a, b),
		f(model.ForceChangePassword, b, a),
		f(model.GenericAll, foothold, a), // foothold controls A
		u(model.IsUser, a), u(model.IsUser, b),
		f(model.MemberOf, b, da),
		u(model.HighValue, da),
	}
	// Should terminate (no infinite loop) and reach DA through A -> B -> DA.
	p := solveTo(t, facts, da, Fastest)
	if !p.Reachable {
		t.Fatal("expected DA reachable through the cyclic control graph")
	}
	assertAcyclic(t, p)
}

func TestFindingsRankedAndDeduped(t *testing.T) {
	facts := []model.Fact{
		f(model.MemberOf, foothold, da), // trivial 1-step win
		u(model.HighValue, da),
		f(model.AllowedToAct, foothold, "S-1-DC01"),
		u(model.IsComputer, "S-1-DC01"),
		u(model.HighValue, "S-1-DC01"),
	}
	sol := New().Solve(facts, []string{foothold}, Fastest)
	fs := sol.Findings()
	if len(fs) < 2 {
		t.Fatalf("expected at least 2 findings, got %d", len(fs))
	}
	// Cheapest (membership) first.
	for i := 1; i < len(fs); i++ {
		if fs[i-1].TotalCost > fs[i].TotalCost {
			t.Fatalf("findings not sorted by cost: %v", fs)
		}
	}
}

func hasRule(p Path, rule string) bool {
	for _, s := range p.Steps {
		if s.Rule == rule {
			return true
		}
	}
	return false
}

func hasESC(p Path, esc string) bool {
	for _, s := range p.Steps {
		if s.ESC == esc {
			return true
		}
	}
	return false
}

func techniques(p Path) []string {
	var out []string
	for _, s := range p.Steps {
		out = append(out, s.Rule)
	}
	return out
}
