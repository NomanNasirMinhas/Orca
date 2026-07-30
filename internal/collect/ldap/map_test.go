package ldap

import (
	"encoding/binary"
	"strconv"
	"strings"
	"testing"

	"orca/internal/model"
)

// fakeEntry is a test double for Entry.
type fakeEntry struct {
	dn    string
	str   map[string]string
	strs  map[string][]string
	bytes map[string][]byte
}

func (f fakeEntry) DN() string            { return f.dn }
func (f fakeEntry) Str(a string) string   { return f.str[a] }
func (f fakeEntry) Strs(a string) []string { return f.strs[a] }
func (f fakeEntry) Bytes(a string) []byte { return f.bytes[a] }

// sidToBytes encodes "S-1-5-21-..." to its binary objectSid form.
func sidToBytes(s string) []byte {
	parts := strings.Split(s, "-")[1:] // drop leading "S"
	rev, _ := strconv.Atoi(parts[0])
	auth, _ := strconv.ParseUint(parts[1], 10, 64)
	subs := parts[2:]
	b := []byte{byte(rev), byte(len(subs))}
	ab := make([]byte, 6)
	for i := 5; i >= 0; i-- {
		ab[i] = byte(auth & 0xff)
		auth >>= 8
	}
	b = append(b, ab...)
	for _, ss := range subs {
		v, _ := strconv.ParseUint(ss, 10, 32)
		tmp := make([]byte, 4)
		binary.LittleEndian.PutUint32(tmp, uint32(v))
		b = append(b, tmp...)
	}
	return b
}

const domSID = "S-1-5-21-1-2-3"

func has(fs []model.Fact, p model.Pred, a, b string) bool {
	for _, f := range fs {
		if f.Pred == p && f.A == a && f.B == b {
			return true
		}
	}
	return false
}

func TestMapMembershipTypingHighValue(t *testing.T) {
	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	daSID := domSID + "-512"
	userSID := domSID + "-1105"

	da := fakeEntry{
		dn:    daDN,
		str:   map[string]string{"sAMAccountName": "Domain Admins"},
		strs:  map[string][]string{"objectClass": {"top", "group"}},
		bytes: map[string][]byte{"objectSid": sidToBytes(daSID)},
	}
	jdoe := fakeEntry{
		dn:   "CN=jdoe,CN=Users,DC=corp,DC=local",
		str:  map[string]string{"sAMAccountName": "jdoe", "primaryGroupID": "513"},
		strs: map[string][]string{"objectClass": {"top", "person", "user"}, "memberOf": {daDN}},
		bytes: map[string][]byte{"objectSid": sidToBytes(userSID)},
	}

	nodes, facts := MapDomain([]Entry{da, jdoe}, domSID, "corp.local")

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if !has(facts, model.IsUser, userSID, "") {
		t.Fatalf("missing IsUser: %+v", facts)
	}
	if !has(facts, model.IsGroup, daSID, "") {
		t.Fatalf("missing IsGroup: %+v", facts)
	}
	if !has(facts, model.HighValue, daSID, "") {
		t.Fatal("Domain Admins (RID 512) should be high value")
	}
	if !has(facts, model.MemberOf, userSID, daSID) {
		t.Fatal("memberOf DN should resolve to a MemberOf fact")
	}
	if !has(facts, model.MemberOf, userSID, domSID+"-513") {
		t.Fatal("primaryGroupID should yield MemberOf on the primary group")
	}
}

func TestMapKerberoastableAndDelegationProps(t *testing.T) {
	svcSID := domSID + "-1201"
	svc := fakeEntry{
		dn: "CN=svc,CN=Users,DC=corp,DC=local",
		str: map[string]string{
			"sAMAccountName":      "svc-sql",
			"userAccountControl":  strconv.Itoa(0x00080000 | 0x200), // unconstrained delegation
		},
		strs: map[string][]string{
			"objectClass":         {"top", "person", "user"},
			"servicePrincipalName": {"MSSQLSvc/db.corp.local:1433"},
		},
		bytes: map[string][]byte{"objectSid": sidToBytes(svcSID)},
	}
	nodes, _ := MapDomain([]Entry{svc}, domSID, "corp.local")
	if len(nodes) != 1 {
		t.Fatalf("expected 1 node, got %d", len(nodes))
	}
	p := nodes[0].Props
	if p["kerberoastable"] != "true" {
		t.Fatalf("expected kerberoastable prop, got %+v", p)
	}
	if p["delegation"] != "unconstrained" {
		t.Fatalf("expected unconstrained delegation prop, got %+v", p)
	}

	// The SPN user must also surface as a first-class HasSPN fact for the engine.
	_, facts := MapDomain([]Entry{svc}, domSID, "corp.local")
	if !has(facts, model.HasSPN, svcSID, "") {
		t.Fatalf("expected HasSPN fact for the SPN user: %+v", facts)
	}
}

func TestMapASREPRoastable(t *testing.T) {
	uSID := domSID + "-1301"
	usr := fakeEntry{
		dn: "CN=noauth,DC=corp,DC=local",
		str: map[string]string{
			"sAMAccountName":     "noauth",
			"userAccountControl": strconv.Itoa(0x00400000 | 0x200), // DONT_REQ_PREAUTH
		},
		strs:  map[string][]string{"objectClass": {"user"}},
		bytes: map[string][]byte{"objectSid": sidToBytes(uSID)},
	}
	_, facts := MapDomain([]Entry{usr}, domSID, "corp.local")
	if !has(facts, model.ASREPRoastable, uSID, "") {
		t.Fatalf("expected ASREPRoastable fact: %+v", facts)
	}
}

func TestMapComputerVsUser(t *testing.T) {
	compSID := domSID + "-1500"
	comp := fakeEntry{
		dn:    "CN=DC01,OU=Domain Controllers,DC=corp,DC=local",
		str:   map[string]string{"sAMAccountName": "DC01$"},
		strs:  map[string][]string{"objectClass": {"top", "computer"}},
		bytes: map[string][]byte{"objectSid": sidToBytes(compSID)},
	}
	_, facts := MapDomain([]Entry{comp}, domSID, "corp.local")
	if !has(facts, model.IsComputer, compSID, "") {
		t.Fatalf("computer should classify as IsComputer: %+v", facts)
	}
	if has(facts, model.IsUser, compSID, "") {
		t.Fatal("computer must not also be IsUser")
	}
}
