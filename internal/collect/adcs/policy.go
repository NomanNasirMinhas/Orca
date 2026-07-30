package adcs

import "orca/internal/model"

// IssuancePolicy is a pKIIssuancePolicy object linked (via msDS-OIDToGroupLink)
// to a group. When a template references this policy in its issuance policy
// list, certificates issued under it are treated as conferring membership in
// that group — ESC13 when the group is privileged.
type IssuancePolicy struct {
	SID        string // node id (objectGUID of the policy object)
	GroupSID   string // the linked group's SID
	GroupHighValue bool
}

// PolicyBinding records that a template references an issuance policy. The
// engine emits TemplateIssuancePolicyLinksToPrivilege(T, G) only when the linked
// group is high-value, so ESC13 stays scoped to genuinely privileged targets.
type PolicyBinding struct {
	TemplateSID string
	Policy      IssuancePolicy
}

// Facts derives the ESC13 issuance-policy-to-privilege facts from a set of
// template↔policy bindings, deduplicated by (template, group).
func PolicyFacts(bindings []PolicyBinding) []model.Fact {
	prov := &model.Provenance{Collector: "adcs", Attribute: "msPKI-Issuance-Policy"}
	seen := map[string]bool{}
	var out []model.Fact
	for _, b := range bindings {
		if !b.Policy.GroupHighValue || b.Policy.GroupSID == "" || b.TemplateSID == "" {
			continue
		}
		key := string(model.TemplateIssuancePolicyLinksToPrivilege) + "|" + b.TemplateSID + "|" + b.Policy.GroupSID
		if seen[key] {
			continue
		}
		seen[key] = true
		out = append(out, model.Fact{
			Pred: model.TemplateIssuancePolicyLinksToPrivilege,
			A:    b.TemplateSID, B: b.Policy.GroupSID, Prov: prov,
		})
	}
	return out
}