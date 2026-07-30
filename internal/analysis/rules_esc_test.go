package analysis

import (
	"testing"

	"orca/internal/model"
)

// SIDs reused for the ESC fixtures.
const (
	ca    = "S-1-CA-OBJ"      // a certificate authority node
	agent = "S-1-AGENT-TMPL"  // an enrollment-agent template (ESC3a)
	tmpl2 = "S-1-TARGET-TMPL" // an ESC3b target template
	hvGrp = "S-1-HV-GROUP"    // a high-value group linked via issuance policy (ESC13)
)

// sol solves a fixture from the standard foothold and returns the solution.
func sol(t *testing.T, facts []model.Fact, o Objective) *Solution {
	t.Helper()
	return New().Solve(facts, []string{foothold}, o)
}

// reachable reports whether Compromised(target) is derivable.
func reachable(facts []model.Fact, target string, o Objective) bool {
	s := New().Solve(facts, []string{foothold}, o)
	return s.Path(GroundFact{Pred: model.Compromised, A: target}).Reachable
}

// ---------- ESC2 ----------

func TestESC2(t *testing.T) {
	base := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		u(model.TemplateAnyEKU, tmpl),
		u(model.TemplateEnrolleeSuppliesSubject, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.CAReachable, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	if !reachable(base, daUser, Balanced) {
		t.Fatal("ESC2: expected daUser reachable")
	}
	// Negative: without AnyEKU, ESC2 does not fire (ESC1 needs EnrolleeSuppliesSubject,
	// which is present, so ESC1 would fire here — instead drop the SAN flag to
	// make a clean negative: remove AnyEKU AND EnrolleeSuppliesSubject).
	neg := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.CAReachable, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	if reachable(neg, daUser, Balanced) {
		t.Fatal("ESC2 negative: should not reach without AnyEKU + SAN flag")
	}
	p := solveTo(t, base, daUser, Balanced)
	if !hasESC(p, "ESC2") {
		t.Fatalf("ESC2: expected ESC2 step, got %v", techniques(p))
	}
}

// ---------- ESC3 (two-stage) ----------

func TestESC3(t *testing.T) {
	base := []model.Fact{
		// Stage 1: foothold enrolls in an enrollment-agent template.
		f(model.CanEnroll, foothold, agent),
		u(model.TemplateEnrollmentAgentEKU, agent),
		u(model.TemplateNoManagerApproval, agent),
		u(model.CAReachable, agent),
		// Stage 2: foothold (now an agent) enrolls in a target template that
		// requires an agent signature.
		f(model.CanEnroll, foothold, tmpl2),
		u(model.TemplateRequiresAgentSignature, tmpl2),
		u(model.TemplateAuthEKU, tmpl2),
		u(model.TemplateNoManagerApproval, tmpl2),
		u(model.CAReachable, tmpl2),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	p := solveTo(t, base, daUser, Balanced)
	if !p.Reachable {
		t.Fatal("ESC3: expected daUser reachable via two-stage enrollment agent")
	}
	if !hasESC(p, "ESC3") {
		t.Fatalf("ESC3: expected ESC3 step, got %v", techniques(p))
	}
	// Negative: no enrollment-agent template → CannotActAsEnrollmentAgent → ESC3b fails.
	neg := []model.Fact{
		f(model.CanEnroll, foothold, tmpl2),
		u(model.TemplateRequiresAgentSignature, tmpl2),
		u(model.TemplateAuthEKU, tmpl2),
		u(model.TemplateNoManagerApproval, tmpl2),
		u(model.CAReachable, tmpl2),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	if reachable(neg, daUser, Balanced) {
		t.Fatal("ESC3 negative: should not reach without an enrollment-agent template")
	}
}

// ---------- ESC5 + ESC5-domain ----------

func TestESC5(t *testing.T) {
	base := []model.Fact{
		f(model.GenericAll, foothold, ca),
		u(model.IsCA, ca),
		f(model.CAInDomain, ca, domain),
		u(model.IsDomain, domain),
		u(model.HighValue, domain),
	}
	s := sol(t, base, Balanced)
	// ESC5: controlling the CA compromises the CA. The CA node itself is
	// compromised via the generic object-control rule (cheaper than the ESC5
	// primitive, which is redundant here); the ESC5 *label* surfaces on the
	// domain escalation below, which is the genuinely CA-specific step.
	pca := s.Path(GroundFact{Pred: model.Compromised, A: ca})
	if !pca.Reachable {
		t.Fatal("ESC5: expected CA reachable")
	}
	// ESC5-domain: a compromised CA compromises its domain — this carries ESC5.
	pd := s.Path(GroundFact{Pred: model.Compromised, A: domain})
	if !pd.Reachable {
		t.Fatal("ESC5-domain: expected domain reachable via CA compromise")
	}
	if !hasESC(pd, "ESC5") {
		t.Fatalf("ESC5-domain: expected ESC5 step, got %v", techniques(pd))
	}
	// Negative: without CAInDomain scoping the CA to this domain, the CA is
	// still controllable (generic object control compromises the CA node) but
	// the domain is NOT escalated via esc5-domain. ESC5's distinct contribution
	// is the domain escalation, which CAInDomain gates.
	neg := []model.Fact{
		f(model.GenericAll, foothold, ca),
		u(model.IsCA, ca),
		u(model.IsDomain, domain),
		u(model.HighValue, domain),
	}
	if reachable(neg, domain, Balanced) {
		t.Fatal("ESC5 negative: domain should not be reachable without CAInDomain")
	}
}

// ---------- ESC6 ----------

func TestESC6(t *testing.T) {
	base := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		f(model.PublishedOn, tmpl, ca),
		u(model.CAEditfSan2, ca),
		u(model.TemplateAuthEKU, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	p := solveTo(t, base, daUser, Balanced)
	if !p.Reachable {
		t.Fatal("ESC6: expected daUser reachable via SAN override")
	}
	if !hasESC(p, "ESC6") {
		t.Fatalf("ESC6: expected ESC6 step, got %v", techniques(p))
	}
	// Negative: without the CA flag, ESC6 does not fire.
	neg := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		f(model.PublishedOn, tmpl, ca),
		u(model.TemplateAuthEKU, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	if reachable(neg, daUser, Balanced) {
		t.Fatal("ESC6 negative: should not reach without EDITF_ATTRIBUTESUBJECTALTNAME2")
	}
}

// ---------- ESC8 (advisory) ----------

func TestESC8Advisory(t *testing.T) {
	base := []model.Fact{
		u(model.WebEnrollmentEnabled, ca),
		u(model.HttpRelayCapable, ca),
	}
	s := sol(t, base, Balanced)
	adv := s.Advisories()
	if len(adv) != 1 || adv[0].Goal.A != ca {
		t.Fatalf("ESC8: expected one advisory for CA, got %+v", adv)
	}
	if !hasESC(adv[0], "ESC8") {
		t.Fatalf("ESC8: advisory should carry ESC8 label, got %v", techniques(adv[0]))
	}
	// Advisories must NOT appear in Findings() (they are not compromise paths).
	for _, p := range s.Findings() {
		if p.Goal.A == ca {
			t.Fatal("ESC8: advisory CA should not appear as a compromise finding")
		}
	}
	// Negative: web enrollment without relay capability yields no advisory.
	neg := sol(t, []model.Fact{u(model.WebEnrollmentEnabled, ca)}, Balanced)
	if len(neg.Advisories()) != 0 {
		t.Fatal("ESC8 negative: no advisory without HttpRelayCapable")
	}
}

// ---------- ESC11 ----------

func TestESC11(t *testing.T) {
	base := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		f(model.PublishedOn, tmpl, ca),
		u(model.NoSignatureEnforcement, ca),
		u(model.TemplateAuthEKU, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.TemplateEnrolleeSuppliesSubject, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	p := solveTo(t, base, daUser, Balanced)
	if !p.Reachable {
		t.Fatal("ESC11: expected daUser reachable via no-signature-enforcement SAN forge")
	}
	if !hasESC(p, "ESC11") {
		t.Fatalf("ESC11: expected ESC11 step, got %v", techniques(p))
	}
	neg := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		f(model.PublishedOn, tmpl, ca),
		u(model.TemplateAuthEKU, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.TemplateEnrolleeSuppliesSubject, tmpl),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	if reachable(neg, daUser, Balanced) {
		t.Fatal("ESC11 negative: should not reach without NoSignatureEnforcement")
	}
}

// ---------- ESC13 ----------

func TestESC13(t *testing.T) {
	base := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		f(model.TemplateIssuancePolicyLinksToPrivilege, tmpl, hvGrp),
		u(model.TemplateAuthEKU, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.CAReachable, tmpl),
		u(model.HighValue, hvGrp),
	}
	s := sol(t, base, Balanced)
	p := s.Path(GroundFact{Pred: model.Compromised, A: hvGrp})
	if !p.Reachable {
		t.Fatal("ESC13: expected privileged group reachable via issuance-policy link")
	}
	if !hasESC(p, "ESC13") {
		t.Fatalf("ESC13: expected ESC13 step, got %v", techniques(p))
	}
	// Negative: a non-high-value linked group does not fire ESC13.
	neg := []model.Fact{
		f(model.CanEnroll, foothold, tmpl),
		f(model.TemplateIssuancePolicyLinksToPrivilege, tmpl, hvGrp),
		u(model.TemplateAuthEKU, tmpl),
		u(model.TemplateNoManagerApproval, tmpl),
		u(model.CAReachable, tmpl),
		// no HighValue(hvGrp)
	}
	if reachable(neg, hvGrp, Balanced) {
		t.Fatal("ESC13 negative: should not reach without HighValue on the linked group")
	}
}

// ---------- k-shortest paths ----------

func TestKPaths(t *testing.T) {
	// Two distinct control rights from foothold to daUser produce two distinct
	// derivations of Compromised(daUser): ForceChangePassword (louder) and
	// GenericAll (quieter). KPaths must return both, cost-ordered, and k=1 must
	// match Path().
	facts := []model.Fact{
		f(model.ForceChangePassword, foothold, daUser),
		f(model.GenericAll, foothold, daUser),
		u(model.IsUser, daUser),
		u(model.HighValue, daUser),
	}
	s := New().Solve(facts, []string{foothold}, Balanced)
	goal := GroundFact{Pred: model.Compromised, A: daUser}

	paths := s.KPaths(goal, 5)
	if len(paths) < 2 {
		t.Fatalf("KPaths: expected >=2 distinct paths, got %d", len(paths))
	}
	// Cost-ordered ascending.
	for i := 1; i < len(paths); i++ {
		if paths[i].TotalCost < paths[i-1].TotalCost {
			t.Fatalf("KPaths: not cost-ordered at %d: %f < %f", i, paths[i].TotalCost, paths[i-1].TotalCost)
		}
	}
	// Distinct (different first control right).
	if paths[0].Steps[0].Rule == paths[1].Steps[0].Rule {
		t.Fatalf("KPaths: top two paths share the same first step %s", paths[0].Steps[0].Rule)
	}
	// k=1 reproduces Path().
	one := s.KPaths(goal, 1)
	if len(one) != 1 {
		t.Fatalf("KPaths(k=1): expected 1 path, got %d", len(one))
	}
	single := s.Path(goal)
	if one[0].TotalCost != single.TotalCost {
		t.Fatalf("KPaths(k=1) cost %f != Path() cost %f", one[0].TotalCost, single.TotalCost)
	}
	// Each KPaths result must be acyclic.
	for _, p := range paths {
		assertAcyclic(t, p)
	}
}

// ---------- betweenness centrality (chokepoints) ----------

func TestCentrality(t *testing.T) {
	// Diamond: foothold -> C -> {A, B} -> DA. C is on every path, so it must be
	// the highest-betweenness fact.
	c := "S-1-GATEWAY"
	a := "S-1-A"
	b := "S-1-B"
	facts := []model.Fact{
		f(model.GenericAll, foothold, c),
		f(model.GenericAll, c, a),
		f(model.GenericAll, c, b),
		f(model.ForceChangePassword, a, da),
		f(model.GenericAll, b, da),
		u(model.HighValue, da),
	}
	s := New().Solve(facts, []string{foothold}, Balanced)
	// Sanity: DA is reachable.
	if !s.Path(GroundFact{Pred: model.Compromised, A: da}).Reachable {
		t.Fatal("Centrality: expected DA reachable in the diamond")
	}
	cps := s.Centrality(20)
	if len(cps) == 0 {
		t.Fatal("Centrality: expected nonzero chokepoints")
	}
	// The top chokepoint should be Compromised(C) — the gateway. Its score must
	// exceed the score of the leaf-side facts (A or B).
	top := cps[0]
	if top.Fact.Pred != model.Compromised || top.Fact.A != c {
		t.Fatalf("Centrality: top chokepoint = %s/%s, want Compromised/%s", top.Fact.Pred, top.Fact.A, c)
	}
	// Find Compromised(A)'s score for comparison.
	var aScore float64
	for _, cp := range cps {
		if cp.Fact.Pred == model.Compromised && cp.Fact.A == a {
			aScore = cp.Score
		}
	}
	if top.Score <= aScore {
		t.Fatalf("Centrality: gateway score %f should exceed A's score %f", top.Score, aScore)
	}
}