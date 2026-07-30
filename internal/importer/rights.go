package importer

import (
	"strings"

	"orca/internal/model"
)

// tkind mirrors acl.TargetKind for importer-local right resolution (AllExtended
// / DCSync expand differently per target type).
type tkind int

const (
	tOther tkind = iota
	tUser
	tComputer
	tGroup
	tDomain
)

// mapRight maps a BloodHound/Certipy right name onto Orca fact predicates. Some
// rights expand into several facts (e.g. DCSync) or depend on the target kind.
func mapRight(right string, target tkind) []model.Pred {
	switch strings.ToLower(right) {
	case "owns", "owner":
		return []model.Pred{model.Owns}
	case "genericall", "allextendedrights_full":
		return []model.Pred{model.GenericAll}
	case "genericwrite":
		return []model.Pred{model.GenericWrite}
	case "writedacl":
		return []model.Pred{model.WriteDacl}
	case "writeowner":
		return []model.Pred{model.WriteOwner}
	case "addmember", "addmembers":
		return []model.Pred{model.AddMember}
	case "forcechangepassword":
		return []model.Pred{model.ForceChangePassword}
	case "addkeycredentiallink":
		return []model.Pred{model.AddKeyCredentialLink}
	case "writespn", "writeserviceprincipalname":
		return []model.Pred{model.WriteSPN}
	case "getchanges":
		return []model.Pred{model.HasGetChanges}
	case "getchangesall":
		return []model.Pred{model.HasGetChangesAll}
	case "dcsync":
		return []model.Pred{model.HasGetChanges, model.HasGetChangesAll}
	case "enroll", "enrollment", "autoenroll":
		return []model.Pred{model.CanEnroll}
	case "readlapspassword", "readgmsapassword":
		// Reading the managed/local-admin password yields control of the object.
		return []model.Pred{model.GenericAll}
	case "allextendedrights":
		switch target {
		case tDomain:
			return []model.Pred{model.HasGetChanges, model.HasGetChangesAll}
		case tUser, tComputer:
			return []model.Pred{model.ForceChangePassword}
		default:
			return nil
		}
	default:
		return nil
	}
}
