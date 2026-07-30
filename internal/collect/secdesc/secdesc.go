// Package secdesc parses Windows self-relative SECURITY_DESCRIPTOR blobs (the
// raw nTSecurityDescriptor attribute) into owner SID and DACL ACEs. It is
// pure Go (stdlib only) so it is fully testable without a live domain.
//
// Reference layouts: SECURITY_DESCRIPTOR (self-relative), ACL, and the
// ACCESS_ALLOWED[_OBJECT]_ACE variants from MS-DTYP.
package secdesc

import (
	"encoding/binary"
	"errors"
	"fmt"
	"strconv"
	"strings"
)

// ACE types we care about (MS-DTYP 2.4.4).
const (
	AccessAllowed       = 0x00
	AccessDenied        = 0x01
	AccessAllowedObject = 0x05
	AccessDeniedObject  = 0x06
)

// Object ACE flags (which GUIDs are present).
const (
	aceObjectTypePresent         = 0x00000001
	aceInheritedObjectTypePresent = 0x00000002
)

// ACE is a normalized access-control entry.
type ACE struct {
	Type         uint8
	Flags        uint8
	Mask         uint32
	ObjectType   string // GUID string ("" if absent) — the extended right / property
	InheritedType string
	Trustee      string // SID string of the principal granted/denied
}

// Allowed reports whether this ACE grants (vs. denies) access.
func (a ACE) Allowed() bool { return a.Type == AccessAllowed || a.Type == AccessAllowedObject }

// SecurityDescriptor is the parsed result.
type SecurityDescriptor struct {
	Owner string
	Group string
	DACL  []ACE
}

// Parse decodes a self-relative SECURITY_DESCRIPTOR.
func Parse(b []byte) (*SecurityDescriptor, error) {
	if len(b) < 20 {
		return nil, errors.New("secdesc: too short for header")
	}
	// Header: Revision(1) Sbz1(1) Control(2) OffOwner(4) OffGroup(4) OffSacl(4) OffDacl(4)
	offOwner := binary.LittleEndian.Uint32(b[4:8])
	offGroup := binary.LittleEndian.Uint32(b[8:12])
	offDacl := binary.LittleEndian.Uint32(b[16:20])

	sd := &SecurityDescriptor{}
	var err error
	if offOwner != 0 {
		if sd.Owner, err = sidAt(b, int(offOwner)); err != nil {
			return nil, fmt.Errorf("secdesc: owner: %w", err)
		}
	}
	if offGroup != 0 {
		sd.Group, _ = sidAt(b, int(offGroup)) // group is non-fatal
	}
	if offDacl != 0 {
		if sd.DACL, err = parseACL(b, int(offDacl)); err != nil {
			return nil, fmt.Errorf("secdesc: dacl: %w", err)
		}
	}
	return sd, nil
}

// parseACL decodes an ACL header and its ACEs.
func parseACL(b []byte, off int) ([]ACE, error) {
	if off+8 > len(b) {
		return nil, errors.New("acl header out of bounds")
	}
	// AclRevision(1) Sbz1(1) AclSize(2) AceCount(2) Sbz2(2)
	count := binary.LittleEndian.Uint16(b[off+4 : off+6])
	pos := off + 8
	aces := make([]ACE, 0, count)
	for i := 0; i < int(count); i++ {
		if pos+4 > len(b) {
			return nil, errors.New("ace header out of bounds")
		}
		aceType := b[pos]
		aceFlags := b[pos+1]
		aceSize := int(binary.LittleEndian.Uint16(b[pos+2 : pos+4]))
		if aceSize < 4 || pos+aceSize > len(b) {
			return nil, errors.New("ace size out of bounds")
		}
		body := b[pos+4 : pos+aceSize]
		ace, err := parseACE(aceType, aceFlags, body)
		if err != nil {
			return nil, err
		}
		aces = append(aces, ace)
		pos += aceSize
	}
	return aces, nil
}

func parseACE(aceType, aceFlags uint8, body []byte) (ACE, error) {
	a := ACE{Type: aceType, Flags: aceFlags}
	switch aceType {
	case AccessAllowed, AccessDenied:
		// Mask(4) + SID
		if len(body) < 4 {
			return a, errors.New("basic ace too short")
		}
		a.Mask = binary.LittleEndian.Uint32(body[0:4])
		sid, err := parseSID(body[4:])
		if err != nil {
			return a, err
		}
		a.Trustee = sid
	case AccessAllowedObject, AccessDeniedObject:
		// Mask(4) + Flags(4) + [ObjectType(16)] + [InheritedType(16)] + SID
		if len(body) < 8 {
			return a, errors.New("object ace too short")
		}
		a.Mask = binary.LittleEndian.Uint32(body[0:4])
		objFlags := binary.LittleEndian.Uint32(body[4:8])
		p := 8
		if objFlags&aceObjectTypePresent != 0 {
			if p+16 > len(body) {
				return a, errors.New("object type guid out of bounds")
			}
			a.ObjectType = parseGUID(body[p : p+16])
			p += 16
		}
		if objFlags&aceInheritedObjectTypePresent != 0 {
			if p+16 > len(body) {
				return a, errors.New("inherited type guid out of bounds")
			}
			a.InheritedType = parseGUID(body[p : p+16])
			p += 16
		}
		sid, err := parseSID(body[p:])
		if err != nil {
			return a, err
		}
		a.Trustee = sid
	default:
		// Unknown/unsupported ACE type: keep header, skip body.
	}
	return a, nil
}

func sidAt(b []byte, off int) (string, error) {
	if off >= len(b) {
		return "", errors.New("sid offset out of bounds")
	}
	return parseSID(b[off:])
}

// ParseSID decodes a binary objectSid/SID value into "S-1-..." string form.
func ParseSID(b []byte) (string, error) { return parseSID(b) }

// ParseGUID decodes a 16-byte GUID value into canonical string form.
func ParseGUID(b []byte) string { return parseGUID(b) }

// SIDToBytes encodes a string SID ("S-1-5-21-...-rid") back into its binary
// objectSid form. It is the inverse of ParseSID, used to feed string-SID
// sources (e.g. ldapdomaindump) through the binary-oriented LDAP mapper.
func SIDToBytes(s string) ([]byte, error) {
	if !strings.HasPrefix(strings.ToUpper(s), "S-") {
		return nil, errors.New("sid: missing S- prefix")
	}
	parts := strings.Split(s, "-")
	if len(parts) < 3 {
		return nil, errors.New("sid: too few components")
	}
	rev, err := strconv.ParseUint(parts[1], 10, 8)
	if err != nil {
		return nil, fmt.Errorf("sid: revision: %w", err)
	}
	auth, err := strconv.ParseUint(parts[2], 10, 48)
	if err != nil {
		return nil, fmt.Errorf("sid: authority: %w", err)
	}
	subs := parts[3:]
	b := make([]byte, 0, 8+4*len(subs))
	b = append(b, byte(rev), byte(len(subs)))
	for i := 5; i >= 0; i-- { // 6-byte big-endian authority
		b = append(b, byte(auth>>(8*uint(i))&0xff))
	}
	for _, ss := range subs {
		v, err := strconv.ParseUint(ss, 10, 32)
		if err != nil {
			return nil, fmt.Errorf("sid: subauthority %q: %w", ss, err)
		}
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(v))
		b = append(b, tmp...)
	}
	return b, nil
}

// parseSID decodes a binary SID (MS-DTYP 2.4.2.2) into "S-1-..." string form.
func parseSID(b []byte) (string, error) {
	if len(b) < 8 {
		return "", errors.New("sid too short")
	}
	rev := b[0]
	subCount := int(b[1])
	if len(b) < 8+4*subCount {
		return "", errors.New("sid subauthorities out of bounds")
	}
	// IdentifierAuthority is 6 bytes, big-endian.
	var auth uint64
	for i := range 6 {
		auth = auth<<8 | uint64(b[2+i])
	}
	var s strings.Builder
	fmt.Fprintf(&s, "S-%d-%d", rev, auth)
	for i := range subCount {
		sub := binary.LittleEndian.Uint32(b[8+4*i : 12+4*i])
		fmt.Fprintf(&s, "-%d", sub)
	}
	return s.String(), nil
}

// parseGUID decodes a 16-byte GUID into canonical string form (mixed-endian per
// MS convention: first three fields little-endian).
func parseGUID(b []byte) string {
	if len(b) < 16 {
		return ""
	}
	d1 := binary.LittleEndian.Uint32(b[0:4])
	d2 := binary.LittleEndian.Uint16(b[4:6])
	d3 := binary.LittleEndian.Uint16(b[6:8])
	return fmt.Sprintf("%08x-%04x-%04x-%02x%02x-%02x%02x%02x%02x%02x%02x",
		d1, d2, d3, b[8], b[9], b[10], b[11], b[12], b[13], b[14], b[15])
}
