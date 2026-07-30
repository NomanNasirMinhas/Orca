// Package analysis: risk.go — per-node risk-attribute classification.
//
// RiskFlags derives a normalized, importer-agnostic set of risk flags for every
// node, used by the SPA's risk filter bar (kerberoastable / AS-REP / delegation /
// RBCD / disabled / etc.). The signal is unified from three sources so the
// result is correct regardless of which importer produced the dataset:
//
//  1. Node.HighValue                  → "high-value" (authoritative; the bool is
//     already merged across importers by graph.AddNode).
//  2. Node.Props["userAccountControl"] → full UAC bit decode (authoritative;
//     the LDAP mapper stores the raw decimal string but decodes only 3 bits
//     into props, so the rest — disabled / pwd-not-reqd / smartcard / DES / DC /
//     password-expired / password-never-expires — are recovered here).
//  3. Node.Props derived strings      → "kerberoastable" / "asrepRoastable" /
//     "delegation" fallback for importers that set those without raw UAC.
//  4. Graph facts                     → HasSPN→kerberoastable (A),
//     ASREPRoastable→asrep-roastable (A), AllowedToAct→rbcd (B = configured
//     computer). The fact scan covers BloodHound-imported nodes, which emit
//     facts but set no Props.
//
// This is read-only: it adds no facts, no rules, and no fixpoint change. Orca
// remains a maps/advises-only tool.
package analysis

import (
	"sort"
	"strconv"
	"strings"

	"orca/internal/graph"
	"orca/internal/model"
)

// Canonical risk-flag strings (kebab-case, stable across API + SPA).
const (
	RiskKerberoastable          = "kerberoastable"
	RiskASREPRoastable          = "asrep-roastable"
	RiskUnconstrainedDelegation = "unconstrained-delegation"
	RiskConstrainedDelegation   = "constrained-delegation"
	RiskRBCD                    = "rbcd"
	RiskDisabled                = "disabled"
	RiskPasswordNotRequired     = "password-not-required"
	RiskSmartcardRequired       = "smartcard-required"
	RiskDESOnly                 = "des-only"
	RiskPasswordExpired         = "password-expired"
	RiskPasswordNeverExpires    = "password-never-expires"
	RiskDomainController        = "domain-controller"
	RiskHighValue               = "high-value"
)

// uacBits maps a userAccountControl bit mask to its risk flag. Bits are decoded
// independently (no else-if masking): an account with both TRUSTED_FOR_DELEGATION
// and TRUSTED_TO_AUTH_FOR_DELEGATION set yields both delegation flags. This
// diverges from the LDAP mapper's else-if delegation decode, intentionally.
//
// NOT_DELEGATED (0x00100000) is intentionally excluded — it is a protective flag,
// not a risk. NORMAL_ACCOUNT (0x200) and the trust-account base bits carry no
// risk signal on their own.
var uacBits = []struct {
	mask uint64
	flag string
}{
	{0x00000002, RiskDisabled},             // ACCOUNTDISABLE
	{0x00000020, RiskPasswordNotRequired},  // PASSWD_NOTREQD
	{0x00002000, RiskDomainController},      // SERVER_TRUST_ACCOUNT (DC machine)
	{0x00010000, RiskPasswordNeverExpires}, // DONT_EXPIRE_PASSWD
	{0x00040000, RiskSmartcardRequired},    // SMARTCARD_REQUIRED
	{0x00080000, RiskUnconstrainedDelegation}, // TRUSTED_FOR_DELEGATION
	{0x00200000, RiskDESOnly},              // USE_DES_KEY_ONLY
	{0x00400000, RiskASREPRoastable},       // DONT_REQ_PREAUTH
	{0x00800000, RiskPasswordExpired},      // PASSWORD_EXPIRED
	{0x01000000, RiskConstrainedDelegation}, // TRUSTED_TO_AUTH_FOR_DELEGATION
}

// decodeUAC decodes a raw UAC decimal string into risk flags. Each bit is
// decoded independently; the result is sorted for stable, testable output.
// Empty or non-decimal input yields nil.
func decodeUAC(uac string) []string {
	uac = strings.TrimSpace(uac)
	if uac == "" {
		return nil
	}
	v, err := strconv.ParseUint(uac, 10, 64)
	if err != nil {
		return nil
	}
	var out []string
	for _, b := range uacBits {
		if v&b.mask != 0 {
			out = append(out, b.flag)
		}
	}
	sort.Strings(out)
	return out
}

// RiskFlags derives a per-SID sorted unique risk-flag list from the graph. SIDs
// with no flags are absent from the map (callers treat absence as "no risks").
func RiskFlags(g *graph.Graph) map[string][]string {
	// sid → flag set (dedup across all sources).
	sets := map[string]map[string]bool{}
	add := func(sid, flag string) {
		if sid == "" || flag == "" {
			return
		}
		s, ok := sets[sid]
		if !ok {
			s = map[string]bool{}
			sets[sid] = s
		}
		s[flag] = true
	}

	// Sources 1-3: node-driven (HighValue + Props).
	for _, n := range g.Nodes() {
		if n.HighValue {
			add(n.SID, RiskHighValue)
		}
		if n.Props == nil {
			continue
		}
		if uac := n.Props["userAccountControl"]; uac != "" {
			for _, f := range decodeUAC(uac) {
				add(n.SID, f)
			}
		}
		// Props fallbacks (deduped by the set, so they never double-count with a
		// UAC-decoded flag already added above).
		if n.Props["kerberoastable"] == "true" {
			add(n.SID, RiskKerberoastable)
		}
		if n.Props["asrepRoastable"] == "true" {
			add(n.SID, RiskASREPRoastable)
		}
		switch n.Props["delegation"] {
		case "unconstrained":
			add(n.SID, RiskUnconstrainedDelegation)
		case "constrained":
			add(n.SID, RiskConstrainedDelegation)
		}
	}

	// Source 4: fact-driven (covers BloodHound-imported nodes with no Props).
	for _, f := range g.Facts() {
		switch f.Pred {
		case model.HasSPN:
			add(f.A, RiskKerberoastable)
		case model.ASREPRoastable:
			add(f.A, RiskASREPRoastable)
		case model.AllowedToAct:
			// RBCD: B is the computer configured as the delegation target.
			add(f.B, RiskRBCD)
		}
	}

	// Flatten each set to a sorted []string.
	out := make(map[string][]string, len(sets))
	for sid, s := range sets {
		flags := make([]string, 0, len(s))
		for f := range s {
			flags = append(flags, f)
		}
		sort.Strings(flags)
		out[sid] = flags
	}
	return out
}