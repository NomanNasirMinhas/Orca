package importer

import (
	"strings"

	"orca/internal/model"
)

// domainRelativeRID maps domain-relative well-known group names to their RID,
// so Certipy references like "Domain Users" resolve even when the group node
// was not exported by the SID-based source.
var domainRelativeRID = map[string]string{
	"domain users":     "513",
	"domain computers": "515",
	"domain admins":    "512",
	"domain guests":    "514",
	"enterprise admins": "519",
}

// BuildResolver builds a name→SID resolver from imported nodes, so name-based
// tools (Certipy) can be linked to SID-based data (BloodHound/LDAP). It also
// resolves domain-relative well-known groups against any imported domain SID.
func BuildResolver(nodes []model.Node) NameResolver {
	idx := make(map[string]string, len(nodes))
	var domainSID string
	for _, n := range nodes {
		if n.Name != "" {
			idx[strings.ToLower(n.Name)] = n.SID
		}
		if n.Kind == model.KindDomain && domainSID == "" {
			domainSID = n.SID
		}
	}
	if domainSID != "" {
		for name, rid := range domainRelativeRID {
			if _, exists := idx[name]; !exists {
				idx[name] = domainSID + "-" + rid
			}
		}
	}
	return func(name string) (string, bool) {
		sid, ok := idx[strings.ToLower(strings.TrimSpace(name))]
		return sid, ok
	}
}

// Implicit-membership SIDs every authenticated principal belongs to. Enrolling
// a template that grants "Authenticated Users" is thus reachable from any
// foothold once these edges exist.
const (
	sidAuthenticatedUsers = "S-1-5-11"
	sidEveryone           = "S-1-1-0"
	sidDomainUsersRID     = "513"
)

// EnrichImplicitMembership adds the implicit group memberships AD grants to
// every user/computer (Authenticated Users, Everyone), plus placeholder nodes
// for those groups. It also adds Domain Users membership when the domain SID is
// known. Returns augmented nodes and facts.
func EnrichImplicitMembership(nodes []model.Node, facts []model.Fact) ([]model.Node, []model.Fact) {
	domainSID := ""
	for _, n := range nodes {
		if n.Kind == model.KindDomain {
			domainSID = n.SID
			break
		}
	}

	have := map[string]bool{}
	for _, n := range nodes {
		have[n.SID] = true
	}
	ensure := func(sid, name string) {
		if !have[sid] {
			nodes = append(nodes, model.Node{SID: sid, Kind: model.KindGroup, Name: name})
			have[sid] = true
		}
	}
	ensure(sidAuthenticatedUsers, "Authenticated Users")
	ensure(sidEveryone, "Everyone")

	prov := &model.Provenance{Collector: "orca", Attribute: "implicit-membership"}
	seen := map[string]bool{}
	for _, f := range facts {
		seen[f.Key()] = true
	}
	add := func(a, b string) {
		f := model.Fact{Pred: model.MemberOf, A: a, B: b, Prov: prov}
		if !seen[f.Key()] {
			seen[f.Key()] = true
			facts = append(facts, f)
		}
	}

	for _, n := range nodes {
		if n.Kind != model.KindUser && n.Kind != model.KindComputer {
			continue
		}
		add(n.SID, sidAuthenticatedUsers)
		add(n.SID, sidEveryone)
		if domainSID != "" {
			du := domainSID + "-" + sidDomainUsersRID
			ensure(du, "Domain Users")
			add(n.SID, du)
		}
	}
	return nodes, facts
}
