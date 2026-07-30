package analysis

import "strings"

// Category is the attack-path family a rule belongs to. It drives the UI's
// filter chips and lets operators slice findings by technique class
// (Kerberoasting, ADCS abuse, ACL takeover, …) rather than reading every path.
type Category string

const (
	CategoryMembership Category = "Membership"
	CategoryACLControl Category = "ACL/Control"
	CategoryKerberos   Category = "Kerberos"
	CategoryASREP      Category = "AS-REP"
	CategoryDelegation Category = "Delegation"
	CategoryADCS       Category = "AD CS"
	CategoryDCSync     Category = "DCSync"
	CategoryOther      Category = "Other"
)

// CategoryOf maps a rule to its attack-path family. The mapping is by rule
// name prefix and (for AD CS) by the ESC label carried in RuleMeta, so adding a
// new ESC rule does not require touching this function as long as it follows
// the esc* naming convention.
func CategoryOf(r Rule) Category {
	name := r.Name
	esc := r.Meta.ESC
	switch {
	case strings.HasPrefix(name, "esc") || name == "adcs-auth-as-anyone" || name == "esc8-advisory":
		return CategoryADCS
	case esc != "" && strings.HasPrefix(esc, "ESC"):
		return CategoryADCS
	case name == "kerberoast":
		return CategoryKerberos
	case name == "asrep-roast":
		return CategoryASREP
	case name == "rbcd-impersonate":
		return CategoryDelegation
	case name == "dcsync" || name == "dcsync-domain-compromise":
		return CategoryDCSync
	case strings.HasPrefix(name, "ctrl-") || name == "compromise-via-control" || name == "compromise-via-addmember":
		return CategoryACLControl
	case name == "member-transitive" || name == "compromise-via-membership":
		return CategoryMembership
	default:
		return CategoryOther
	}
}

// CategoryLabelOf returns the category for a rule name alone, for serialization
// paths that only have the name (e.g. a Step recorded without its Rule struct).
func CategoryLabelOf(ruleName, esc string) Category {
	return CategoryOf(Rule{Name: ruleName, Meta: RuleMeta{ESC: esc}})
}