package ldap

import (
	"context"
	"math/rand"

	"orca/internal/collect"
	"orca/internal/model"
	"orca/internal/opsec"
)

// Query is one logical LDAP search the collector issues.
type Query struct {
	Filter string
	Attrs  []string
}

// Searcher performs an LDAP search. The transport session implements this; a
// test double can too. It returns entries adapted to the mapper's Entry view.
type Searcher interface {
	Search(ctx context.Context, filter string, attrs []string) ([]Entry, error)
	// BaseDN / domain identity for mapping.
	BaseDN() string
	DomainSID() string
	DomainFQDN() string
}

// Collector gathers principals and their ACLs over LDAP and emits nodes+facts.
// It applies the OPSEC profile's filter mutation to avoid signatured queries.
type Collector struct {
	Profile opsec.Profile
	Rng     *rand.Rand
}

// Name identifies the collector.
func (c *Collector) Name() string { return "ldap" }

// Noise: LDAP directory reads are moderate-footprint (4662 on SACLed objects).
func (c *Collector) Noise() opsec.Noise { return opsec.NoiseMedium }

// principalsQuery pulls the attributes needed to build the principal graph.
func principalsQuery() Query {
	return Query{
		// Users, computers, and groups in one pass.
		Filter: "(|(samAccountType=805306368)(samAccountType=805306369)(objectCategory=group))",
		Attrs: []string{
			"sAMAccountName", "objectSid", "objectClass", "distinguishedName",
			"displayName", "memberOf", "primaryGroupID", "userAccountControl",
			"servicePrincipalName", "nTSecurityDescriptor",
			"msDS-AllowedToActOnBehalfOfOtherIdentity",
		},
	}
}

// Collect runs the collector's queries and writes results into sink. The
// Session must implement Searcher (the LDAP transport does).
func (c *Collector) Collect(ctx context.Context, s collect.Session, sink model.FactSink) error {
	searcher, ok := s.(Searcher)
	if !ok {
		return errNotLDAPSession
	}

	var entries []Entry
	for _, q := range c.queries() {
		for _, filter := range c.mutate(q.Filter) {
			if err := ctx.Err(); err != nil {
				return err
			}
			c.Profile.Throttle(c.Rng)
			attrs := q.Attrs
			if c.Profile.MutateFilters {
				attrs = opsec.ShuffleAttrs(attrs, c.Rng)
			}
			got, err := searcher.Search(ctx, filter, attrs)
			if err != nil {
				return err
			}
			entries = append(entries, got...)
		}
	}

	nodes, facts := MapDomain(entries, searcher.DomainSID(), searcher.DomainFQDN())
	for _, n := range nodes {
		sink.AddNode(n)
	}
	for _, f := range facts {
		sink.AddFact(f)
	}
	return nil
}

func (c *Collector) queries() []Query {
	return []Query{principalsQuery()}
}

// mutate decomposes a signatured filter into safer sub-queries when the profile
// asks for it; otherwise it returns the filter unchanged.
func (c *Collector) mutate(filter string) []string {
	if c.Profile.MutateFilters && opsec.IsSignatured(filter) {
		return opsec.DecomposeFilter(filter)
	}
	return []string{filter}
}

type ldapError string

func (e ldapError) Error() string { return string(e) }

const errNotLDAPSession = ldapError("ldap collector: session does not implement Searcher")
