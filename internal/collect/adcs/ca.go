package adcs

import "orca/internal/model"

// CA is the collected view of an enterprise certificate authority. Its DACL is
// expressed through the same ACL-right atoms as every other AD object so ESC5
// (control of a CA → domain compromise) composes via the existing CanControl
// rules; the CA-specific flags below feed ESC6/ESC8/ESC11.
type CA struct {
	SID    string // node id (objectGUID or synthetic)
	Name   string
	Domain string // domain FQDN this CA is scoped to (for CAInDomain)

	// Control principals (from the CA's DACL) — feed CanControl → ESC5.
	OwnerSIDs         []string
	WriteDaclSIDs     []string
	WriteOwnerSIDs    []string
	GenericAllSIDs    []string
	GenericWriteSIDs []string

	// CA flags.
	EditfSan2              bool // EDITF_ATTRIBUTESUBJECTALTNAME2 (ESC6)
	WebEnrollmentEnabled   bool // web enrollment is on
	HttpRelayCapable       bool // web enrollment accepts NTLM without EPA (ESC8 advisory)
	NoSignatureEnforcement bool // CA does not enforce request signatures (ESC11)
}

// Facts derives CA facts. Control rights are emitted as the same predicates
// the ACL normalizer uses elsewhere, so the engine's ctrl-* rules collapse them
// into CanControl(P, CA) and ESC5 fires when a compromised P controls the CA.
func (c CA) Facts() []model.Fact {
	prov := &model.Provenance{Collector: "adcs", Attribute: "CA"}
	var out []model.Fact
	add := func(p model.Pred, a, b string) {
		out = append(out, model.Fact{Pred: p, A: a, B: b, Prov: prov})
	}

	add(model.IsCA, c.SID, "")
	for _, sid := range c.OwnerSIDs {
		add(model.Owns, sid, c.SID)
	}
	for _, sid := range c.WriteDaclSIDs {
		add(model.WriteDacl, sid, c.SID)
	}
	for _, sid := range c.WriteOwnerSIDs {
		add(model.WriteOwner, sid, c.SID)
	}
	for _, sid := range c.GenericAllSIDs {
		add(model.GenericAll, sid, c.SID)
	}
	for _, sid := range c.GenericWriteSIDs {
		add(model.GenericWrite, sid, c.SID)
	}
	if c.EditfSan2 {
		add(model.CAEditfSan2, c.SID, "")
	}
	if c.WebEnrollmentEnabled {
		add(model.WebEnrollmentEnabled, c.SID, "")
	}
	if c.HttpRelayCapable {
		add(model.HttpRelayCapable, c.SID, "")
	}
	if c.NoSignatureEnforcement {
		add(model.NoSignatureEnforcement, c.SID, "")
	}
	// CAInDomain scopes ESC5-domain so a CA only compromises its own domain,
	// never a foreign one via a cross-domain join.
	if c.Domain != "" {
		add(model.CAInDomain, c.SID, c.Domain)
	}
	return out
}