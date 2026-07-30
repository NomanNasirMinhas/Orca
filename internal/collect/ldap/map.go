// Package ldap collects domain objects over LDAP/LDAPS and maps them to Orca
// nodes and facts. The mapping (this file) is decoupled from the go-ldap wire
// types behind the Entry interface, so it is fully unit-testable without a DC.
package ldap

import (
	"strconv"
	"strings"

	"orca/internal/collect/acl"
	"orca/internal/collect/secdesc"
	"orca/internal/model"
)

// Entry is the minimal view of an LDAP object the mapper needs. The transport
// adapts *ldap.Entry to this; tests supply a fake.
type Entry interface {
	DN() string
	Str(attr string) string       // first string value
	Strs(attr string) []string    // all string values
	Bytes(attr string) []byte     // first raw value
}

// well-known privileged RIDs / SIDs that seed the high-value set.
var highValueRID = map[string]bool{
	"500": true, "502": true, "512": true, "516": true,
	"518": true, "519": true, "520": true,
}
var highValueBuiltin = map[string]bool{
	"S-1-5-32-544": true, // Administrators
	"S-1-5-32-548": true, // Account Operators
	"S-1-5-32-549": true, // Server Operators
	"S-1-5-32-550": true, // Print Operators
	"S-1-5-32-551": true, // Backup Operators
}

// MapDomain converts a set of collected LDAP entries into nodes and facts,
// resolving group membership by distinguished name. domainSID is the domain's
// SID (for primaryGroupID resolution); domainFQDN labels the nodes.
func MapDomain(entries []Entry, domainSID, domainFQDN string) ([]model.Node, []model.Fact) {
	type info struct {
		sid   string
		kind  model.Kind
		tkind acl.TargetKind
	}
	dnToSID := map[string]string{}
	meta := map[string]info{} // sid -> info
	var nodes []model.Node
	var facts []model.Fact

	prov := func(attr string) *model.Provenance {
		return &model.Provenance{Collector: "ldap", Attribute: attr}
	}
	addFact := func(p model.Pred, a, b, attr string) {
		facts = append(facts, model.Fact{Pred: p, A: a, B: b, Prov: prov(attr)})
	}

	// --- Pass 1: nodes, DN->SID index, typing + high-value. ---
	for _, e := range entries {
		sidRaw := e.Bytes("objectSid")
		if len(sidRaw) == 0 {
			continue
		}
		sid, err := secdesc.ParseSID(sidRaw)
		if err != nil {
			continue
		}
		kind, tkind := classify(e)
		dnToSID[strings.ToLower(e.DN())] = sid
		meta[sid] = info{sid: sid, kind: kind, tkind: tkind}

		n := model.Node{
			SID: sid, Kind: kind, Name: e.Str("sAMAccountName"),
			Domain: domainFQDN, HighValue: isHighValue(sid),
			Props: nodeProps(e),
		}
		if n.Name == "" {
			n.Name = firstDNComponent(e.DN())
		}
		nodes = append(nodes, n)

		// Typing facts for the analysis engine.
		switch kind {
		case model.KindUser:
			addFact(model.IsUser, sid, "", "objectClass")
		case model.KindComputer:
			addFact(model.IsComputer, sid, "", "objectClass")
		case model.KindGroup:
			addFact(model.IsGroup, sid, "", "objectClass")
		case model.KindDomain:
			addFact(model.IsDomain, sid, "", "objectClass")
		}
		if isHighValue(sid) {
			addFact(model.HighValue, sid, "", "objectSid")
		}

		// Credential-exposure primitives. Only user accounts with an SPN are
		// usefully Kerberoastable (machine/gMSA passwords are effectively
		// uncrackable), so gate on kind.
		if kind == model.KindUser {
			if len(e.Strs("servicePrincipalName")) > 0 {
				addFact(model.HasSPN, sid, "", "servicePrincipalName")
			}
			if uac := e.Str("userAccountControl"); uac != "" {
				if v, err := strconv.Atoi(uac); err == nil && v&0x00400000 != 0 {
					addFact(model.ASREPRoastable, sid, "", "userAccountControl")
				}
			}
		}
	}

	// --- Pass 2: membership, ACLs, RBCD (needs the DN->SID index). ---
	for _, e := range entries {
		sidRaw := e.Bytes("objectSid")
		if len(sidRaw) == 0 {
			continue
		}
		sid, err := secdesc.ParseSID(sidRaw)
		if err != nil {
			continue
		}

		// memberOf: this object is a member of each listed group DN.
		for _, gdn := range e.Strs("memberOf") {
			if gsid, ok := dnToSID[strings.ToLower(gdn)]; ok {
				addFact(model.MemberOf, sid, gsid, "memberOf")
			}
		}
		// primaryGroupID: RID within the domain (e.g. 513 Domain Users).
		if pg := e.Str("primaryGroupID"); pg != "" && domainSID != "" {
			addFact(model.MemberOf, sid, domainSID+"-"+pg, "primaryGroupID")
		}

		// nTSecurityDescriptor -> ACL capability facts.
		if sd := e.Bytes("nTSecurityDescriptor"); len(sd) > 0 {
			if parsed, err := secdesc.Parse(sd); err == nil {
				tkind := meta[sid].tkind
				facts = append(facts, acl.Facts(parsed, sid, tkind)...)
			}
		}

		// msDS-AllowedToActOnBehalfOfOtherIdentity -> RBCD: its DACL lists the
		// principals allowed to act on behalf of others toward this computer.
		if rbcd := e.Bytes("msDS-AllowedToActOnBehalfOfOtherIdentity"); len(rbcd) > 0 {
			if parsed, err := secdesc.Parse(rbcd); err == nil {
				for _, a := range parsed.DACL {
					if a.Allowed() && a.Trustee != "" {
						addFact(model.AllowedToAct, a.Trustee, sid, "msDS-AllowedToActOnBehalfOfOtherIdentity")
					}
				}
			}
		}
	}

	return nodes, dedupFacts(facts)
}

func classify(e Entry) (model.Kind, acl.TargetKind) {
	classes := lowerSet(e.Strs("objectClass"))
	switch {
	case classes["computer"]:
		return model.KindComputer, acl.TargetComputer
	case classes["group"]:
		return model.KindGroup, acl.TargetGroup
	case classes["domaindns"], classes["domain"]:
		return model.KindDomain, acl.TargetDomain
	case classes["organizationalunit"]:
		return model.KindOU, acl.TargetOther
	case classes["user"]:
		return model.KindUser, acl.TargetUser
	default:
		return model.KindContainer, acl.TargetOther
	}
}

// nodeProps stashes attributes useful for the report/inspector and for future
// primitives (kerberoast, delegation) not yet in the rule pack.
func nodeProps(e Entry) map[string]string {
	p := map[string]string{}
	// Identity fields shown in the Info panel. The node's Name is sAMAccountName
	// (short); displayName/cn carry the human-readable full name, and
	// distinguishedName gives full AD context. Stored as props so they round-trip
	// through /api/node without new API surface.
	if dn := e.DN(); dn != "" {
		p["distinguishedName"] = dn
		if cn := firstDNComponent(dn); cn != "" {
			p["cn"] = cn
		}
	}
	if dp := e.Str("displayName"); dp != "" {
		p["displayName"] = dp
	}
	if spn := e.Strs("servicePrincipalName"); len(spn) > 0 {
		p["spn"] = strings.Join(spn, ", ")
		p["kerberoastable"] = "true"
	}
	if uac := e.Str("userAccountControl"); uac != "" {
		p["userAccountControl"] = uac
		if v, err := strconv.Atoi(uac); err == nil {
			if v&0x00080000 != 0 {
				p["delegation"] = "unconstrained"
			} else if v&0x01000000 != 0 {
				p["delegation"] = "constrained"
			}
			if v&0x00400000 != 0 {
				p["asrepRoastable"] = "true"
			}
		}
	}
	if len(p) == 0 {
		return nil
	}
	return p
}

func isHighValue(sid string) bool {
	if highValueBuiltin[sid] {
		return true
	}
	if i := strings.LastIndex(sid, "-"); i >= 0 {
		return highValueRID[sid[i+1:]]
	}
	return false
}

// IsHighValueSID reports whether a SID is a well-known Tier-0 / high-value
// principal (privileged RID or builtin admin group). Exported for importers.
func IsHighValueSID(sid string) bool { return isHighValue(sid) }

func lowerSet(vals []string) map[string]bool {
	m := make(map[string]bool, len(vals))
	for _, v := range vals {
		m[strings.ToLower(v)] = true
	}
	return m
}

func firstDNComponent(dn string) string {
	if _, rest, ok := strings.Cut(dn, "="); ok {
		first, _, _ := strings.Cut(rest, ",")
		return first
	}
	return dn
}

func dedupFacts(in []model.Fact) []model.Fact {
	seen := map[string]bool{}
	out := in[:0]
	for _, f := range in {
		if k := f.Key(); !seen[k] {
			seen[k] = true
			out = append(out, f)
		}
	}
	return out
}
