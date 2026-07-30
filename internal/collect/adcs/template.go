// Package adcs interprets AD CS certificate-template and CA metadata into the
// atomic ESC facts the analysis engine composes into ESC1/ESC4/... paths. The
// mapping is pure logic over collected attributes, so it is unit-testable
// without a live CA.
package adcs

import (
	"slices"

	"orca/internal/model"
)

// msPKI-Certificate-Name-Flag bits (MS-CRTD).
const (
	ctFlagEnrolleeSuppliesSubject = 0x00000001
)

// msPKI-Enrollment-Flag bits.
const (
	ctFlagPendAllRequests = 0x00000002 // requires manager approval
)

// EKU OIDs that permit domain authentication with the issued certificate.
var authEKUs = map[string]bool{
	"1.3.6.1.5.5.7.3.2":      true, // Client Authentication
	"1.3.6.1.5.2.3.4":        true, // PKINIT Client Authentication
	"1.3.6.1.4.1.311.20.2.2": true, // Smart Card Logon
	"2.5.29.37.0":            true, // Any Purpose
}

// enrollmentAgentEKU is the Certificate Enrollment Agent OID (ESC3).
const enrollmentAgentEKU = "1.3.6.1.4.1.311.20.2.1"

// Template is the collected view of a certificate template plus its publishing
// status and enrollment principals (resolved from the template's DACL).
type Template struct {
	SID          string // node id (objectGUID)
	Name         string
	NameFlags    uint32 // msPKI-Certificate-Name-Flag
	EnrollFlags  uint32 // msPKI-Enrollment-Flag
	EKUs         []string
	Published    bool // published to at least one enterprise CA
	CAOnline     bool // that CA is reachable
	EnrolleeSIDs []string
	// ControllerSIDs are principals with write control over the template object
	// (feeds ESC4 via the ACL normalizer; included here for convenience).
	ControllerSIDs []string

	// Extended ESC coverage (Phase 2):
	// PublishedCAs are the node ids of CAs that publish this template; each
	// yields a PublishedOn(T,CA) fact used by ESC6/ESC11.
	PublishedCAs []string
	// RequiresAgentSignature is true when the template requires an enrollment
	// agent to countersign enrollment requests (ESC3b target).
	RequiresAgentSignature bool
	// IssuancePolicyPrivilegedGroups are high-value group SIDs linked to this
	// template via an issuance-policy OID-to-group link (ESC13).
	IssuancePolicyPrivilegedGroups []string
}

// Facts derives ESC atom facts for a template.
func (t Template) Facts() []model.Fact {
	prov := &model.Provenance{Collector: "adcs", Attribute: "msPKI-*"}
	var out []model.Fact
	add := func(p model.Pred, a, b string) {
		out = append(out, model.Fact{Pred: p, A: a, B: b, Prov: prov})
	}

	add(model.IsTemplate, t.SID, "")

	if t.NameFlags&ctFlagEnrolleeSuppliesSubject != 0 {
		add(model.TemplateEnrolleeSuppliesSubject, t.SID, "")
	}
	if hasAuthEKU(t.EKUs) {
		add(model.TemplateAuthEKU, t.SID, "")
	}
	if hasAnyEKU(t.EKUs) {
		add(model.TemplateAnyEKU, t.SID, "")
	}
	if hasEnrollmentAgentEKU(t.EKUs) {
		add(model.TemplateEnrollmentAgentEKU, t.SID, "")
	}
	if t.RequiresAgentSignature {
		add(model.TemplateRequiresAgentSignature, t.SID, "")
	}
	if t.EnrollFlags&ctFlagPendAllRequests == 0 {
		add(model.TemplateNoManagerApproval, t.SID, "")
	}
	if t.Published && t.CAOnline {
		add(model.CAReachable, t.SID, "")
	}
	// Publishing relationships feed ESC6/ESC11 (CA-flag-dependent rules).
	for _, ca := range t.PublishedCAs {
		add(model.PublishedOn, t.SID, ca)
	}
	// Issuance-policy links to privileged groups feed ESC13.
	for _, g := range t.IssuancePolicyPrivilegedGroups {
		add(model.TemplateIssuancePolicyLinksToPrivilege, t.SID, g)
	}
	for _, sid := range t.EnrolleeSIDs {
		add(model.CanEnroll, sid, t.SID)
	}
	return out
}

// hasAuthEKU reports whether the EKU set allows authentication. An empty EKU
// list means "no restriction", which also permits authentication.
func hasAuthEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return true
	}
	for _, e := range ekus {
		if authEKUs[e] {
			return true
		}
	}
	return false
}

// hasAnyEKU reports whether the template imposes no EKU restriction: either an
// empty EKU list or the Any Purpose OID. This is the ESC2 condition.
func hasAnyEKU(ekus []string) bool {
	if len(ekus) == 0 {
		return true
	}
	return slices.Contains(ekus, "2.5.29.37.0")
}

// hasEnrollmentAgentEKU reports whether the template grants the Enrollment
// Agent EKU (the ESC3 enrollment-agent cert).
func hasEnrollmentAgentEKU(ekus []string) bool {
	return slices.Contains(ekus, enrollmentAgentEKU)
}