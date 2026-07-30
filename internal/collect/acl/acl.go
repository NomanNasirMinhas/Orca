// Package acl normalizes parsed security-descriptor ACEs into Orca capability
// facts. It maps AD access-mask bits and well-known extended-right / property
// GUIDs onto the fact vocabulary the analysis engine reasons over.
package acl

import (
	"strings"

	"orca/internal/collect/secdesc"
	"orca/internal/model"
)

// AD access-mask bits (MS-ADTS / ADS_RIGHTS_ENUM).
const (
	rightDSControlAccess = 0x00000100 // extended right (CONTROL_ACCESS)
	rightDSWriteProp     = 0x00000020 // write property
	rightDSSelf          = 0x00000008 // validated write
	rightWriteDACL       = 0x00040000 // WRITE_DAC
	rightWriteOwner      = 0x00080000 // WRITE_OWNER
	rightGenericAll      = 0x10000000 // GENERIC_ALL
	rightGenericWrite    = 0x40000000 // GENERIC_WRITE
	fullControl          = 0x000F01FF // object-specific full control
)

// Well-known GUIDs (lower-case) for extended rights and schema attributes.
const (
	guidGetChanges       = "1131f6aa-9c07-11d1-f79f-00c04fc2dcd2" // DS-Replication-Get-Changes
	guidGetChangesAll    = "1131f6ad-9c07-11d1-f79f-00c04fc2dcd2" // DS-Replication-Get-Changes-All
	guidForceChangePw    = "00299570-246d-11d0-a768-00aa006e0529" // User-Force-Change-Password
	guidWriteMember      = "bf9679c0-0de6-11d0-a285-00aa003049e2" // member attribute
	guidWriteSPN         = "f3a64788-5306-11d1-a9c5-0000f80367c1" // servicePrincipalName
	guidKeyCredentialLink = "5b47d60f-6090-40b2-9f37-2a4de88f3063" // msDS-KeyCredentialLink (shadow creds)
)

// TargetKind tells the mapper how to interpret null-GUID control/write rights.
type TargetKind int

const (
	TargetOther TargetKind = iota
	TargetUser
	TargetComputer
	TargetGroup
	TargetDomain
)

// Facts derives capability facts granted by sd over a target object of SID
// targetSID and the given kind. Deny ACEs are ignored (conservative: report
// what is grantable; deny handling is a future refinement). The provenance
// attribute is stamped for the report.
func Facts(sd *secdesc.SecurityDescriptor, targetSID string, kind TargetKind) []model.Fact {
	var out []model.Fact
	emit := func(p model.Pred, trustee string) {
		out = append(out, model.Fact{
			Pred: p, A: trustee, B: targetSID,
			Prov: &model.Provenance{Collector: "ldap", Attribute: "nTSecurityDescriptor"},
		})
	}

	// Owner implicitly can rewrite the DACL -> full control.
	if sd.Owner != "" && !isBuiltinNonAbusable(sd.Owner) {
		emit(model.Owns, sd.Owner)
	}

	for _, a := range sd.DACL {
		if !a.Allowed() || isBuiltinNonAbusable(a.Trustee) {
			continue
		}
		m := a.Mask
		guid := strings.ToLower(a.ObjectType)

		switch {
		case m&rightGenericAll != 0 || m&fullControl == fullControl:
			emit(model.GenericAll, a.Trustee)
		case m&rightWriteDACL != 0:
			emit(model.WriteDacl, a.Trustee)
		case m&rightWriteOwner != 0:
			emit(model.WriteOwner, a.Trustee)
		}

		// Extended-right (CONTROL_ACCESS) grants keyed by GUID.
		if m&rightDSControlAccess != 0 {
			switch guid {
			case guidGetChanges:
				emit(model.HasGetChanges, a.Trustee)
			case guidGetChangesAll:
				emit(model.HasGetChangesAll, a.Trustee)
			case guidForceChangePw:
				emit(model.ForceChangePassword, a.Trustee)
			case "": // all extended rights -> expand into the concrete abuses per kind
				switch kind {
				case TargetUser, TargetComputer:
					emit(model.ForceChangePassword, a.Trustee)
				case TargetDomain:
					emit(model.HasGetChanges, a.Trustee)
					emit(model.HasGetChangesAll, a.Trustee)
				}
			}
		}

		// Property writes keyed by GUID (or generic write to all properties).
		if m&(rightGenericWrite|rightDSWriteProp|rightDSSelf) != 0 {
			switch guid {
			case guidWriteMember:
				emit(model.AddMember, a.Trustee)
			case guidWriteSPN:
				emit(model.WriteSPN, a.Trustee)
			case guidKeyCredentialLink:
				emit(model.AddKeyCredentialLink, a.Trustee)
			case "":
				if m&rightGenericWrite != 0 {
					emit(model.GenericWrite, a.Trustee)
				}
			}
		}
	}
	return dedup(out)
}

// isBuiltinNonAbusable filters SIDs that never represent a useful attack edge
// (e.g. Local System, Creator Owner) to reduce graph noise.
func isBuiltinNonAbusable(sid string) bool {
	switch sid {
	case "S-1-5-18", // Local System
		"S-1-3-0",  // Creator Owner
		"S-1-5-10": // Principal Self
		return true
	}
	return false
}

func dedup(in []model.Fact) []model.Fact {
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
