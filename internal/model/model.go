// Package model defines Orca's canonical node/edge schema and the fact
// vocabulary consumed by the analysis engine. Collectors emit Facts; the
// engine derives higher-level capability facts from them via the rule pack.
package model

// Kind is a node type in the attack graph.
type Kind string

const (
	KindDomain         Kind = "Domain"
	KindUser           Kind = "User"
	KindComputer       Kind = "Computer"
	KindGroup          Kind = "Group"
	KindOU             Kind = "OU"
	KindGPO            Kind = "GPO"
	KindContainer      Kind = "Container"
	KindCertTemplate   Kind = "CertTemplate"
	KindEnterpriseCA   Kind = "EnterpriseCA"
	KindRootCA         Kind = "RootCA"
	KindForeignPrinc   Kind = "ForeignPrincipal"
)

// Node is an AD object. Keyed by SID (or objectGUID for templates/CAs).
type Node struct {
	SID       string            // primary key
	Kind      Kind              // node type
	Name      string            // sAMAccountName / display name
	Domain    string            // FQDN of owning domain
	HighValue bool              // Tier-0 / high-value target
	Props     map[string]string // raw attributes for the report/inspector
}

// Pred is a fact predicate. Base predicates are emitted by collectors;
// derived predicates are produced by the rule engine.
type Pred string

// Base predicates (collected directly). Most are binary (A holds a right/relation over B).
const (
	// Identity / typing (unary: A set, B empty).
	IsUser     Pred = "IsUser"
	IsComputer Pred = "IsComputer"
	IsGroup    Pred = "IsGroup"
	IsDomain   Pred = "IsDomain"
	IsTemplate Pred = "IsTemplate"
	HighValue  Pred = "HighValue"

	// Group / membership.
	MemberOf Pred = "MemberOf" // A is a member of group B

	// ACL / DACL capabilities (A has the right over object B).
	Owns                Pred = "Owns"
	WriteDacl           Pred = "WriteDacl"
	WriteOwner          Pred = "WriteOwner"
	GenericAll          Pred = "GenericAll"
	GenericWrite        Pred = "GenericWrite"
	AddMember           Pred = "AddMember"           // A can add members to group B
	ForceChangePassword Pred = "ForceChangePassword" // A can reset B's password
	AddKeyCredentialLink Pred = "AddKeyCredentialLink" // A can add shadow creds to B
	WriteSPN            Pred = "WriteSPN"            // A can set an SPN on B (targeted kerberoast)
	AllExtendedRights   Pred = "AllExtendedRights"

	// Delegation.
	AllowedToAct Pred = "AllowedToAct" // A is trusted to act on behalf of others toward computer B (RBCD)

	// Credential-exposure primitives (offline-crack dependent).
	HasSPN         Pred = "HasSPN"         // A is a user account with an SPN (Kerberoastable) (unary on A)
	ASREPRoastable Pred = "ASREPRoastable" // A does not require Kerberos pre-auth (AS-REP roastable) (unary on A)

	// DCSync replication rights on domain B.
	HasGetChanges    Pred = "HasGetChanges"
	HasGetChangesAll Pred = "HasGetChangesAll"

	// AD CS atoms.
	CanEnroll                     Pred = "CanEnroll"                     // A can enroll in template B
	TemplateEnrolleeSuppliesSubject Pred = "TemplateEnrolleeSuppliesSubject" // template B: ENROLLEE_SUPPLIES_SUBJECT (unary on B)
	TemplateAuthEKU               Pred = "TemplateAuthEKU"               // template B has client-auth EKU (unary on B)
	TemplateNoManagerApproval     Pred = "TemplateNoManagerApproval"     // template B needs no manager approval (unary on B)
	CAReachable                   Pred = "CAReachable"                   // template B is published on a reachable CA (unary on B)

	// AD CS atoms — extended ESC coverage (Phase 2). Negative conditions in the
	// ESC rules (e.g. "no signature enforcement") are emitted as positive base
	// atoms at collection time, keeping every rule a monotonic Horn clause.
	TemplateAnyEKU                 Pred = "TemplateAnyEKU"                 // template B has Any Purpose / empty EKU (ESC2) (unary on B)
	TemplateEnrollmentAgentEKU     Pred = "TemplateEnrollmentAgentEKU"     // template B has Enrollment Agent EKU (ESC3) (unary on B)
	TemplateRequiresAgentSignature Pred = "TemplateRequiresAgentSignature" // template B requires an enrollment-agent signature (ESC3b) (unary on B)
	TemplateIssuancePolicyLinksToPrivilege Pred = "TemplateIssuancePolicyLinksToPrivilege" // template T's issuance policy links to privileged group G (ESC13) (binary T,G)
	IsCA            Pred = "IsCA"            // B is a certificate authority node (unary on B)
	PublishedOn     Pred = "PublishedOn"     // template T is published on CA B (binary T,CA)
	CAEditfSan2     Pred = "CAEditfSan2"     // CA B has EDITF_ATTRIBUTESUBJECTALTNAME2 set (ESC6) (unary on B)
	WebEnrollmentEnabled Pred = "WebEnrollmentEnabled" // CA B has web enrollment enabled (unary on B)
	HttpRelayCapable Pred = "HttpRelayCapable" // CA B's web enrollment is NTLM-relay-capable (no EPA) (ESC8) (unary on B)
	NoSignatureEnforcement Pred = "NoSignatureEnforcement" // CA B does not enforce request signatures (ESC11) (unary on B)
	CAInDomain      Pred = "CAInDomain"      // CA A is scoped to domain B (binary CA,D) — safe ESC5-domain join

	// Foothold seed: operator already controls principal A.
	Compromised Pred = "Compromised"
)

// Derived predicates (produced by the rule engine).
const (
	CanControl        Pred = "CanControl"        // A can take full control of object B
	CanEnrollAsAnyone Pred = "CanEnrollAsAnyone" // A can request an auth cert as an arbitrary principal via template B (ESC1/ESC2/ESC4/ESC6/ESC11)
	CanDCSync         Pred = "CanDCSync"         // A can DCSync domain B
	CanActAsEnrollmentAgent Pred = "CanActAsEnrollmentAgent" // A can act as an enrollment agent via some template (ESC3) (unary on A)
	RelayExposure     Pred = "RelayExposure"     // CA B is exposed to NTLM relay (ESC8 advisory) (unary on B)
)

// Fact is a ground tuple. B is empty for unary predicates.
type Fact struct {
	Pred Pred
	A    string
	B    string
	// Prov records where a base fact came from (collector + raw attribute).
	// Empty for derived facts (their justification lives in the hypergraph).
	Prov *Provenance
}

// Provenance ties a base fact back to its collected source for the report.
type Provenance struct {
	Collector string
	Attribute string
	Raw       string
}

// Key is the canonical string identity of a fact (ignores provenance).
func (f Fact) Key() string {
	return string(f.Pred) + "|" + f.A + "|" + f.B
}

// FactSink receives facts from collectors.
type FactSink interface {
	AddNode(Node)
	AddFact(Fact)
}
