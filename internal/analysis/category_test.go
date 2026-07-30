package analysis

import "testing"

// TestCategoryOf pins the rule→family mapping that the UI filter chips rely on.
func TestCategoryOf(t *testing.T) {
	cases := []struct {
		rule string
		esc  string
		want Category
	}{
		{"esc1", "ESC1", CategoryADCS},
		{"adcs-auth-as-anyone", "", CategoryADCS},
		{"esc8-advisory", "ESC8", CategoryADCS},
		{"kerberoast", "", CategoryKerberos},
		{"asrep-roast", "", CategoryASREP},
		{"rbcd-impersonate", "", CategoryDelegation},
		{"dcsync", "", CategoryDCSync},
		{"dcsync-domain-compromise", "", CategoryDCSync},
		{"ctrl-owns", "", CategoryACLControl},
		{"compromise-via-control", "", CategoryACLControl},
		{"compromise-via-addmember", "", CategoryACLControl},
		{"member-transitive", "", CategoryMembership},
		{"compromise-via-membership", "", CategoryMembership},
		{"unknown-rule", "", CategoryOther},
	}
	rules := RulePack()
	byName := map[string]Rule{}
	for _, r := range rules {
		byName[r.Name] = r
	}
	for _, c := range cases {
		t.Run(c.rule, func(t *testing.T) {
			var got Category
			if r, ok := byName[c.rule]; ok {
				got = CategoryOf(r)
			} else {
				// Rule not in pack (e.g. esc8-advisory lands in Phase 2): exercise
				// the label-only path so future ESC rules are categorized correctly.
				got = CategoryLabelOf(c.rule, c.esc)
			}
			if got != c.want {
				t.Fatalf("CategoryOf(%q) = %q, want %q", c.rule, got, c.want)
			}
		})
	}
}