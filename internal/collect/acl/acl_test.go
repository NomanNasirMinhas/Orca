package acl

import (
	"encoding/binary"
	"testing"

	"orca/internal/collect/secdesc"
	"orca/internal/model"
)

// --- binary builders for crafting test security descriptors ---

// sidBytes encodes a simple SID "S-1-5-<sub...>".
func sidBytes(subs ...uint32) []byte {
	b := []byte{1, byte(len(subs)), 0, 0, 0, 0, 0, 5} // rev=1, authority=5
	for _, s := range subs {
		var tmp [4]byte
		binary.LittleEndian.PutUint32(tmp[:], s)
		b = append(b, tmp[:]...)
	}
	return b
}

// guidBytes encodes a canonical GUID string back to its 16-byte MS layout.
func guidBytes(g string) []byte {
	// Reuse a fixed mapping only for the GUIDs used in tests.
	m := map[string][16]byte{
		guidGetChanges:        {0xaa, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2},
		guidGetChangesAll:     {0xad, 0xf6, 0x31, 0x11, 0x07, 0x9c, 0xd1, 0x11, 0xf7, 0x9f, 0x00, 0xc0, 0x4f, 0xc2, 0xdc, 0xd2},
		guidForceChangePw:     {0x70, 0x95, 0x29, 0x00, 0x6d, 0x24, 0xd0, 0x11, 0xa7, 0x68, 0x00, 0xaa, 0x00, 0x6e, 0x05, 0x29},
		guidKeyCredentialLink: {0x0f, 0xd6, 0x47, 0x5b, 0x90, 0x60, 0xb2, 0x40, 0x9f, 0x37, 0x2a, 0x4d, 0xe8, 0x8f, 0x30, 0x63},
	}
	v := m[g]
	return v[:]
}

// objectACE builds an ACCESS_ALLOWED_OBJECT_ACE with an optional ObjectType GUID.
func objectACE(mask uint32, guid string, trustee []byte) []byte {
	var body []byte
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], mask)
	body = append(body, tmp[:]...)
	objFlags := uint32(0)
	var guidPart []byte
	if guid != "" {
		objFlags = 1
		guidPart = guidBytes(guid)
	}
	binary.LittleEndian.PutUint32(tmp[:], objFlags)
	body = append(body, tmp[:]...)
	body = append(body, guidPart...)
	body = append(body, trustee...)

	size := 4 + len(body)
	ace := []byte{secdesc.AccessAllowedObject, 0, byte(size), byte(size >> 8)}
	return append(ace, body...)
}

// basicACE builds an ACCESS_ALLOWED_ACE (no object GUID).
func basicACE(mask uint32, trustee []byte) []byte {
	var body []byte
	var tmp [4]byte
	binary.LittleEndian.PutUint32(tmp[:], mask)
	body = append(body, tmp[:]...)
	body = append(body, trustee...)
	size := 4 + len(body)
	ace := []byte{secdesc.AccessAllowed, 0, byte(size), byte(size >> 8)}
	return append(ace, body...)
}

// buildSD assembles a self-relative SECURITY_DESCRIPTOR with the given owner
// and ACEs.
func buildSD(owner []byte, aces ...[]byte) []byte {
	// Header is 20 bytes; owner follows, then DACL.
	header := make([]byte, 20)
	header[0] = 1 // revision
	offOwner := uint32(20)
	binary.LittleEndian.PutUint32(header[4:8], offOwner)

	buf := append([]byte{}, header...)
	buf = append(buf, owner...)

	offDacl := uint32(len(buf))
	binary.LittleEndian.PutUint32(buf[16:20], offDacl)

	// ACL header: rev(1) sbz1(1) size(2) count(2) sbz2(2)
	var body []byte
	for _, a := range aces {
		body = append(body, a...)
	}
	aclSize := 8 + len(body)
	acl := []byte{2, 0, byte(aclSize), byte(aclSize >> 8), byte(len(aces)), byte(len(aces) >> 8), 0, 0}
	acl = append(acl, body...)
	return append(buf, acl...)
}

func hasFact(fs []model.Fact, p model.Pred, a, b string) bool {
	for _, f := range fs {
		if f.Pred == p && f.A == a && f.B == b {
			return true
		}
	}
	return false
}

func TestParseAndMapDCSync(t *testing.T) {
	attacker := sidBytes(1001)
	owner := sidBytes(512) // Domain Admins-ish; abusable
	sd := buildSD(owner,
		objectACE(rightDSControlAccess, guidGetChanges, attacker),
		objectACE(rightDSControlAccess, guidGetChangesAll, attacker),
	)
	parsed, err := secdesc.Parse(sd)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	if len(parsed.DACL) != 2 {
		t.Fatalf("expected 2 ACEs, got %d", len(parsed.DACL))
	}
	facts := Facts(parsed, "S-DOMAIN", TargetDomain)
	if !hasFact(facts, model.HasGetChanges, "S-1-5-1001", "S-DOMAIN") {
		t.Fatalf("missing GetChanges fact: %+v", facts)
	}
	if !hasFact(facts, model.HasGetChangesAll, "S-1-5-1001", "S-DOMAIN") {
		t.Fatalf("missing GetChangesAll fact: %+v", facts)
	}
}

func TestMapWriteDaclAndForceChangePw(t *testing.T) {
	attacker := sidBytes(1001)
	sd := buildSD(nil,
		basicACE(rightWriteDACL, attacker),
		objectACE(rightDSControlAccess, guidForceChangePw, sidBytes(1002)),
	)
	parsed, err := secdesc.Parse(sd)
	if err != nil {
		t.Fatalf("parse: %v", err)
	}
	facts := Facts(parsed, "S-TARGET", TargetUser)
	if !hasFact(facts, model.WriteDacl, "S-1-5-1001", "S-TARGET") {
		t.Fatalf("missing WriteDacl: %+v", facts)
	}
	if !hasFact(facts, model.ForceChangePassword, "S-1-5-1002", "S-TARGET") {
		t.Fatalf("missing ForceChangePassword: %+v", facts)
	}
}

func TestShadowCredentialsFromKeyCredLink(t *testing.T) {
	attacker := sidBytes(1001)
	sd := buildSD(nil, objectACE(rightDSWriteProp, guidKeyCredentialLink, attacker))
	parsed, _ := secdesc.Parse(sd)
	facts := Facts(parsed, "S-TARGET", TargetUser)
	if !hasFact(facts, model.AddKeyCredentialLink, "S-1-5-1001", "S-TARGET") {
		t.Fatalf("missing AddKeyCredentialLink: %+v", facts)
	}
}

func TestBuiltinTrusteesFiltered(t *testing.T) {
	// Local System (S-1-5-18) granted GenericAll should be ignored.
	sysSID := []byte{1, 1, 0, 0, 0, 0, 0, 5, 18, 0, 0, 0}
	sd := buildSD(nil, basicACE(rightGenericAll, sysSID))
	parsed, _ := secdesc.Parse(sd)
	facts := Facts(parsed, "S-TARGET", TargetUser)
	for _, f := range facts {
		if f.A == "S-1-5-18" {
			t.Fatalf("Local System edge should be filtered: %+v", facts)
		}
	}
}
