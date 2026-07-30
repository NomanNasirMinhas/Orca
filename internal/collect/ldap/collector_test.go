package ldap

import (
	"context"
	"testing"

	"orca/internal/graph"
	"orca/internal/opsec"
)

// fakeSearcher implements collect.Session + Searcher.
type fakeSearcher struct {
	entries []Entry
	filters []string
}

func (f *fakeSearcher) Target() string     { return "dc01" }
func (f *fakeSearcher) BaseDN() string      { return "DC=corp,DC=local" }
func (f *fakeSearcher) DomainSID() string   { return domSID }
func (f *fakeSearcher) DomainFQDN() string  { return "corp.local" }
func (f *fakeSearcher) Search(_ context.Context, filter string, _ []string) ([]Entry, error) {
	f.filters = append(f.filters, filter)
	return f.entries, nil
}

func TestCollectorEndToEnd(t *testing.T) {
	daSID := domSID + "-512"
	daDN := "CN=Domain Admins,CN=Users,DC=corp,DC=local"
	da := fakeEntry{
		dn: daDN, str: map[string]string{"sAMAccountName": "Domain Admins"},
		strs: map[string][]string{"objectClass": {"group"}},
		bytes: map[string][]byte{"objectSid": sidToBytes(daSID)},
	}
	jdoe := fakeEntry{
		dn: "CN=jdoe,DC=corp,DC=local", str: map[string]string{"sAMAccountName": "jdoe"},
		strs: map[string][]string{"objectClass": {"user"}, "memberOf": {daDN}},
		bytes: map[string][]byte{"objectSid": sidToBytes(domSID + "-1105")},
	}

	prof := opsec.Get("fast") // zero delay
	c := &Collector{Profile: prof}
	g := graph.New()
	s := &fakeSearcher{entries: []Entry{da, jdoe}}

	if err := c.Collect(context.Background(), s, g); err != nil {
		t.Fatalf("collect: %v", err)
	}
	if n, f := g.Stats(); n != 2 || f == 0 {
		t.Fatalf("expected 2 nodes and some facts, got %d nodes / %d facts", n, f)
	}
	if len(s.filters) == 0 {
		t.Fatal("collector issued no searches")
	}
}

func TestCollectorRejectsNonSearcherSession(t *testing.T) {
	c := &Collector{Profile: opsec.Get("fast")}
	// A session that is not a Searcher.
	type bareSession struct{}
	_ = bareSession{}
	g := graph.New()
	err := c.Collect(context.Background(), notSearcher{}, g)
	if err == nil {
		t.Fatal("expected error when session does not implement Searcher")
	}
}

// notSearcher implements collect.Session but not Searcher.
type notSearcher struct{}

func (notSearcher) Target() string { return "x" }

func TestMutateDecomposesSignaturedFilter(t *testing.T) {
	c := &Collector{Profile: opsec.Get("stealth")} // MutateFilters = true
	sig := "(|(samaccounttype=805306368)(samaccounttype=805306369))"
	parts := c.mutate(sig)
	if len(parts) != 2 {
		t.Fatalf("expected signatured filter decomposed into 2, got %v", parts)
	}
	// Fast profile should not mutate.
	if got := (&Collector{Profile: opsec.Get("fast")}).mutate(sig); len(got) != 1 {
		t.Fatalf("fast profile should not decompose, got %v", got)
	}
}
