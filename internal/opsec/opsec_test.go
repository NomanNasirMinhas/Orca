package opsec

import "testing"

func TestProfileGating(t *testing.T) {
	if Get("stealth").Allows(NoiseHigh) {
		t.Fatal("stealth must not allow high-noise collectors")
	}
	if !Get("fast").Allows(NoiseHigh) {
		t.Fatal("fast must allow high-noise collectors")
	}
}

func TestDecomposeFilterDodgesSignature(t *testing.T) {
	sig := "(|(samaccounttype=805306368)(samaccounttype=805306369))"
	if !IsSignatured(sig) {
		t.Fatal("expected the SharpHound filter to be flagged as signatured")
	}
	parts := DecomposeFilter(sig)
	if len(parts) != 2 {
		t.Fatalf("expected 2 decomposed clauses, got %d: %v", len(parts), parts)
	}
	for _, p := range parts {
		if IsSignatured(p) {
			t.Fatalf("decomposed clause still signatured: %s", p)
		}
	}
}

func TestDeconflictHashChain(t *testing.T) {
	l := NewDeconflictLog("", "operator@corp", "stealth")
	l.Record("ldap.query", "dc01", "users")
	l.Record("adcs.enum", "dc01", "templates")
	if !l.Verify() {
		t.Fatal("intact log should verify")
	}
	// Tamper with an entry and confirm verification fails.
	l.entries[0].Detail = "tampered"
	if l.Verify() {
		t.Fatal("tampered log must fail verification")
	}
}
