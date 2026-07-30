package opsec

import (
	"math/rand"
	"strings"
)

// KnownSignatured lists LDAP filter substrings that common defensive tools
// (e.g. Microsoft Defender for Identity) fingerprint when emitted verbatim by
// SharpHound-style collectors. Orca avoids sending these unbroken.
var KnownSignatured = []string{
	"(&(objectCategory=person)(objectClass=user))",
	"(|(samaccounttype=805306368)(samaccounttype=805306369))",
	"(objectClass=trustedDomain)",
}

// ShuffleAttrs returns a copy of attrs in randomized order. LDAP responses are
// order-independent, but a fixed attribute request order is itself a signature.
func ShuffleAttrs(attrs []string, rng *rand.Rand) []string {
	out := append([]string(nil), attrs...)
	shuffle := func(n int, swap func(i, j int)) {
		if rng != nil {
			rng.Shuffle(n, swap)
		} else {
			rand.Shuffle(n, swap)
		}
	}
	shuffle(len(out), func(i, j int) { out[i], out[j] = out[j], out[i] })
	return out
}

// DecomposeFilter splits a broad OR filter into several narrower queries so the
// aggregate no longer matches a single known signature. It only decomposes
// top-level "(|(a)(b)...)" filters; anything else is returned unchanged.
func DecomposeFilter(filter string) []string {
	f := strings.TrimSpace(filter)
	if !strings.HasPrefix(f, "(|") || !strings.HasSuffix(f, ")") {
		return []string{filter}
	}
	inner := f[2 : len(f)-1] // strip "(|" and trailing ")"
	clauses := splitTopLevel(inner)
	if len(clauses) < 2 {
		return []string{filter}
	}
	return clauses
}

// splitTopLevel splits a concatenation of balanced "(...)" groups.
func splitTopLevel(s string) []string {
	var out []string
	depth, start := 0, 0
	for i, c := range s {
		switch c {
		case '(':
			if depth == 0 {
				start = i
			}
			depth++
		case ')':
			depth--
			if depth == 0 {
				out = append(out, s[start:i+1])
			}
		}
	}
	return out
}

// IsSignatured reports whether a filter matches a known fingerprint verbatim.
func IsSignatured(filter string) bool {
	f := strings.ToLower(strings.ReplaceAll(filter, " ", ""))
	for _, sig := range KnownSignatured {
		if strings.Contains(f, strings.ToLower(strings.ReplaceAll(sig, " ", ""))) {
			return true
		}
	}
	return false
}
