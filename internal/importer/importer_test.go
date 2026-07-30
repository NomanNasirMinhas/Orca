package importer

import (
	"encoding/base64"
	"encoding/binary"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"

	"orca/internal/analysis"
	"orca/internal/model"
)

func has(fs []model.Fact, p model.Pred, a, b string) bool {
	for _, f := range fs {
		if f.Pred == p && f.A == a && f.B == b {
			return true
		}
	}
	return false
}

func sidBytes(s string) []byte {
	parts := strings.Split(s, "-")[1:]
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

func TestBloodHoundParse(t *testing.T) {
	groups := `{"meta":{"type":"groups"},"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-512",
		 "Properties":{"samaccountname":"Domain Admins","highvalue":true},
		 "Members":[{"ObjectIdentifier":"S-1-5-21-1-2-3-1105","ObjectType":"User"}]}]}`
	users := `{"meta":{"type":"users"},"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-1105",
		 "Properties":{"samaccountname":"jdoe","hasspn":true},
		 "Aces":[{"PrincipalSID":"S-1-5-21-1-2-3-1106","RightName":"GenericAll"}]}]}`

	gn, gf, err := parseBHFile([]byte(groups))
	if err != nil {
		t.Fatal(err)
	}
	un, uf, err := parseBHFile([]byte(users))
	if err != nil {
		t.Fatal(err)
	}
	nodes := append(gn, un...)
	facts := append(gf, uf...)

	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if !has(facts, model.MemberOf, "S-1-5-21-1-2-3-1105", "S-1-5-21-1-2-3-512") {
		t.Fatal("missing membership from group Members")
	}
	if !has(facts, model.HighValue, "S-1-5-21-1-2-3-512", "") {
		t.Fatal("Domain Admins should be high value")
	}
	if !has(facts, model.GenericAll, "S-1-5-21-1-2-3-1106", "S-1-5-21-1-2-3-1105") {
		t.Fatal("missing GenericAll ACE")
	}
	if !has(facts, model.HasSPN, "S-1-5-21-1-2-3-1105", "") {
		t.Fatal("missing HasSPN from hasspn property")
	}
}

func TestLDIFParse(t *testing.T) {
	daSID := "S-1-5-21-1-2-3-512"
	userSID := "S-1-5-21-1-2-3-1105"
	ldif := "dn: CN=Domain Admins,CN=Users,DC=corp,DC=local\n" +
		"objectClass: top\n" +
		"objectClass: group\n" +
		"sAMAccountName: Domain Admins\n" +
		"objectSid:: " + base64.StdEncoding.EncodeToString(sidBytes(daSID)) + "\n" +
		"\n" +
		"dn: CN=jdoe,CN=Users,DC=corp,DC=local\n" +
		"objectClass: user\n" +
		"sAMAccountName: jdoe\n" +
		"objectSid:: " + base64.StdEncoding.EncodeToString(sidBytes(userSID)) + "\n" +
		"memberOf: CN=Domain Admins,CN=Users,DC=corp,DC=local\n"

	nodes, facts, err := ImportLDIF(strings.NewReader(ldif))
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	if !has(facts, model.MemberOf, userSID, daSID) {
		t.Fatalf("LDIF memberOf should resolve to a fact: %+v", facts)
	}
	if !has(facts, model.IsGroup, daSID, "") {
		t.Fatal("group typing missing")
	}
}

func TestCertipyParseAndResolve(t *testing.T) {
	j := `{"Certificate Templates":{"0":{
		"Template Name":"VulnUser","Enabled":true,"Client Authentication":true,
		"Enrollee Supplies Subject":true,"Requires Manager Approval":false,
		"Permissions":{
			"Enrollment Permissions":{"Enrollment Rights":["CORP.LOCAL\\Authenticated Users"]},
			"Object Control Permissions":{"Write Dacl Principals":["CORP.LOCAL\\Helpdesk"]}}}}}`

	resolve := func(name string) (string, bool) {
		if strings.EqualFold(name, "Helpdesk") {
			return "S-HELP", true
		}
		return "", false
	}
	_, facts, err := ImportCertipy(strings.NewReader(j), resolve)
	if err != nil {
		t.Fatal(err)
	}
	tid := "CERTTEMPLATE:VulnUser"
	for _, p := range []model.Pred{
		model.IsTemplate, model.TemplateEnrolleeSuppliesSubject,
		model.TemplateAuthEKU, model.TemplateNoManagerApproval, model.CAReachable,
	} {
		if !has(facts, p, tid, "") {
			t.Fatalf("missing template atom %s: %+v", p, facts)
		}
	}
	if !has(facts, model.CanEnroll, "S-1-5-11", tid) {
		t.Fatal("Authenticated Users enrollment should resolve to well-known SID")
	}
	if !has(facts, model.WriteDacl, "S-HELP", tid) {
		t.Fatal("Helpdesk write-dacl should resolve via the resolver")
	}
}

func TestLDAPDomainDumpParse(t *testing.T) {
	// ldapdomaindump renders objectSid as a string and UAC/primaryGroupID as
	// numbers, wrapped in {"dn":..., "attributes":{attr:[vals]}} arrays.
	json := `[
	  {"dn":"CN=Domain Admins,CN=Users,DC=corp,DC=local",
	   "attributes":{"sAMAccountName":["Domain Admins"],"objectSid":["S-1-5-21-7-7-7-512"],
	                 "objectClass":["top","group"]}},
	  {"dn":"CN=svc,CN=Users,DC=corp,DC=local",
	   "attributes":{"sAMAccountName":["svc"],"objectSid":["S-1-5-21-7-7-7-1109"],
	                 "objectClass":["top","person","user"],
	                 "memberOf":["CN=Domain Admins,CN=Users,DC=corp,DC=local"],
	                 "primaryGroupID":[513],"userAccountControl":[4260352],
	                 "servicePrincipalName":["HTTP/web.corp.local"]}}
	]`
	dir := t.TempDir()
	if err := os.WriteFile(filepath.Join(dir, "domain_users.json"), []byte(json), 0o600); err != nil {
		t.Fatal(err)
	}
	nodes, facts, err := ImportLDAPDomainDump(dir)
	if err != nil {
		t.Fatal(err)
	}
	if len(nodes) != 2 {
		t.Fatalf("expected 2 nodes, got %d", len(nodes))
	}
	svc := "S-1-5-21-7-7-7-1109"
	da := "S-1-5-21-7-7-7-512"
	if !has(facts, model.MemberOf, svc, da) {
		t.Fatalf("memberOf should resolve via DN index: %+v", facts)
	}
	if !has(facts, model.MemberOf, svc, "S-1-5-21-7-7-7-513") {
		t.Fatal("primaryGroupID (513) should yield a MemberOf fact")
	}
	if !has(facts, model.HighValue, da, "") {
		t.Fatal("Domain Admins (512) should be high value")
	}
	if !has(facts, model.HasSPN, svc, "") {
		t.Fatal("SPN user should surface HasSPN (Kerberoastable)")
	}
	// userAccountControl 4260352 = 0x410200 includes DONT_REQ_PREAUTH (0x400000).
	if !has(facts, model.ASREPRoastable, svc, "") {
		t.Fatalf("DONT_REQ_PREAUTH UAC should yield ASREPRoastable: %+v", facts)
	}
}

func TestEnrichImplicitMembership(t *testing.T) {
	nodes := []model.Node{{SID: "S-U", Kind: model.KindUser, Name: "jdoe"}}
	_, facts := EnrichImplicitMembership(nodes, nil)
	if !has(facts, model.MemberOf, "S-U", sidAuthenticatedUsers) {
		t.Fatal("user should implicitly belong to Authenticated Users")
	}
	if !has(facts, model.MemberOf, "S-U", sidEveryone) {
		t.Fatal("user should implicitly belong to Everyone")
	}
}

// End-to-end: a merged BloodHound + Certipy dataset must yield an ESC1 path to
// Domain Admins for any foothold, via the implicit Authenticated Users edge.
func TestMergedBloodHoundCertipyESC1Path(t *testing.T) {
	domain := `{"meta":{"type":"domains"},"data":[{"ObjectIdentifier":"S-1-5-21-1-2-3","Properties":{"name":"CORP.LOCAL"}}]}`
	groups := `{"meta":{"type":"groups"},"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-512","Properties":{"samaccountname":"Domain Admins","highvalue":true},
		 "Members":[{"ObjectIdentifier":"S-1-5-21-1-2-3-500","ObjectType":"User"}]}]}`
	users := `{"meta":{"type":"users"},"data":[
		{"ObjectIdentifier":"S-1-5-21-1-2-3-500","Properties":{"samaccountname":"administrator"}},
		{"ObjectIdentifier":"S-1-5-21-1-2-3-1105","Properties":{"samaccountname":"jdoe"}}]}`
	certipy := `{"Certificate Templates":{"0":{
		"Template Name":"VulnUser","Enabled":true,"Client Authentication":true,
		"Enrollee Supplies Subject":true,"Requires Manager Approval":false,
		"Permissions":{"Enrollment Permissions":{"Enrollment Rights":["CORP.LOCAL\\Authenticated Users"]}}}}}`

	var nodes []model.Node
	var facts []model.Fact
	for _, doc := range []string{domain, groups, users} {
		n, f, err := parseBHFile([]byte(doc))
		if err != nil {
			t.Fatal(err)
		}
		nodes = append(nodes, n...)
		facts = append(facts, f...)
	}
	cn, cf, err := ImportCertipy(strings.NewReader(certipy), BuildResolver(nodes))
	if err != nil {
		t.Fatal(err)
	}
	nodes = append(nodes, cn...)
	facts = append(facts, cf...)
	nodes, facts = EnrichImplicitMembership(nodes, facts)

	sol := analysis.New().Solve(facts, []string{"S-1-5-21-1-2-3-1105"}, analysis.Balanced)
	p := sol.Path(analysis.GroundFact{Pred: model.Compromised, A: "S-1-5-21-1-2-3-512"})
	if !p.Reachable {
		t.Fatal("expected Domain Admins reachable via merged ESC1 path")
	}
	found := false
	for _, s := range p.Steps {
		if s.ESC == "ESC1" {
			found = true
		}
	}
	if !found {
		t.Fatalf("expected an ESC1 step in the merged path; steps: %+v", p.Steps)
	}
}
