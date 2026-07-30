package importer

import (
	"encoding/json"
	"fmt"
	"io"
	"strings"

	"orca/internal/model"
)

// NameResolver maps a principal name (as Certipy prints it, e.g.
// "CORP.LOCAL\\Domain Admins") to a SID. Built from already-imported nodes so
// Certipy data links to the BloodHound/LDAP graph.
type NameResolver func(name string) (sid string, ok bool)

// wellKnownNames covers implicit principals Certipy commonly lists that may not
// exist as collected nodes.
var wellKnownNames = map[string]string{
	"authenticated users": "S-1-5-11",
	"everyone":            "S-1-1-0",
	"anonymous":           "S-1-5-7",
}

// ImportCertipy parses `certipy find -json` output into certificate-template
// nodes and ESC atom facts. Enrollment/control principals are resolved to SIDs
// via resolve (nil is allowed; unresolved principals are skipped).
func ImportCertipy(r io.Reader, resolve NameResolver) ([]model.Node, []model.Fact, error) {
	raw, err := io.ReadAll(r)
	if err != nil {
		return nil, nil, err
	}
	var top map[string]json.RawMessage
	if err := json.Unmarshal(raw, &top); err != nil {
		return nil, nil, fmt.Errorf("certipy: parse: %w", err)
	}

	// Find the templates section (key contains "template").
	var tmplRaw json.RawMessage
	for k, v := range top {
		if strings.Contains(strings.ToLower(k), "template") {
			tmplRaw = v
			break
		}
	}
	// Find the CA section (key contains "certificate authorit").
	var caRaw json.RawMessage
	for k, v := range top {
		if strings.Contains(strings.ToLower(k), "certificate authorit") {
			caRaw = v
			break
		}
	}
	if tmplRaw == nil && caRaw == nil {
		return nil, nil, nil // neither section present
	}
	// Templates are an object keyed by index ("0","1",...).
	var byIndex map[string]map[string]any
	if tmplRaw != nil {
		if err := json.Unmarshal(tmplRaw, &byIndex); err != nil {
			return nil, nil, fmt.Errorf("certipy: templates: %w", err)
		}
	}
	// CAs are an object keyed by index as well.
	var caIndex map[string]map[string]any
	if caRaw != nil {
		if err := json.Unmarshal(caRaw, &caIndex); err != nil {
			return nil, nil, fmt.Errorf("certipy: cas: %w", err)
		}
	}

	resolveOne := func(name string) (string, bool) {
		name = strings.TrimSpace(name)
		if name == "" {
			return "", false
		}
		if strings.HasPrefix(name, "S-1-") {
			return name, true
		}
		// Strip DOMAIN\ prefix.
		if i := strings.LastIndex(name, "\\"); i >= 0 {
			name = name[i+1:]
		}
		key := strings.ToLower(name)
		if sid, ok := wellKnownNames[key]; ok {
			return sid, true
		}
		if resolve != nil {
			return resolve(name)
		}
		return "", false
	}

	prov := &model.Provenance{Collector: "certipy"}
	var nodes []model.Node
	var facts []model.Fact
	add := func(p model.Pred, a, b string) {
		facts = append(facts, model.Fact{Pred: p, A: a, B: b, Prov: prov})
	}

	for _, t := range byIndex {
		name := str(t, "Template Name")
		if name == "" {
			name = str(t, "CA Name")
		}
		if name == "" {
			continue
		}
		tid := "CERTTEMPLATE:" + name
		nodes = append(nodes, model.Node{SID: tid, Kind: model.KindCertTemplate, Name: name})
		add(model.IsTemplate, tid, "")

		if truthy(t, "Enrollee Supplies Subject") || nameFlagHas(t, "EnrolleeSuppliesSubject") {
			add(model.TemplateEnrolleeSuppliesSubject, tid, "")
		}
		if templateAuthEKU(t) {
			add(model.TemplateAuthEKU, tid, "")
		}
		if templateAnyEKU(t) {
			add(model.TemplateAnyEKU, tid, "")
		}
		if templateEnrollmentAgentEKU(t) {
			add(model.TemplateEnrollmentAgentEKU, tid, "")
		}
		if authorizedSignaturesRequired(t) > 0 {
			add(model.TemplateRequiresAgentSignature, tid, "")
		}
		if !truthy(t, "Requires Manager Approval") {
			add(model.TemplateNoManagerApproval, tid, "")
		}
		if truthyDefault(t, "Enabled", true) {
			add(model.CAReachable, tid, "")
		}

		perms := sub(t, "Permissions")
		enroll := sub(perms, "Enrollment Permissions")
		for _, nm := range strs(enroll, "Enrollment Rights") {
			if sid, ok := resolveOne(nm); ok {
				add(model.CanEnroll, sid, tid)
			}
		}
		ctrl := sub(perms, "Object Control Permissions")
		if owner := str(ctrl, "Owner"); owner != "" {
			if sid, ok := resolveOne(owner); ok {
				add(model.Owns, sid, tid)
			}
		}
		for _, nm := range strs(ctrl, "Write Owner Principals") {
			if sid, ok := resolveOne(nm); ok {
				add(model.WriteOwner, sid, tid)
			}
		}
		for _, nm := range strs(ctrl, "Write Dacl Principals") {
			if sid, ok := resolveOne(nm); ok {
				add(model.WriteDacl, sid, tid)
			}
		}
		for _, nm := range strs(ctrl, "Write Property Principals") {
			if sid, ok := resolveOne(nm); ok {
				add(model.GenericWrite, sid, tid)
			}
		}
	}

	// CA section: emit CA nodes + IsCA + conservative CA flags + CAInDomain.
	// CA-flag fields are often "Unknown" in certipy output; we only emit a flag
	// atom when certipy positively reports it as enabled, so ESC6/ESC8/ESC11
	// never false-fire on uncertain data.
	for _, c := range caIndex {
		caName := str(c, "CA Name")
		dns := str(c, "DNS Name")
		if caName == "" {
			caName = dns
		}
		if caName == "" {
			continue
		}
		cid := "CA:" + caName
		nodes = append(nodes, model.Node{
			SID: cid, Kind: model.KindEnterpriseCA, Name: caName,
			Domain: domainFromCA(c, dns),
		})
		add(model.IsCA, cid, "")

		if strings.EqualFold(str(c, "User Specified SAN"), "Enabled") {
			add(model.CAEditfSan2, cid, "")
		}
		we := sub(c, "Web Enrollment")
		httpEn := truthyDefault(sub(we, "http"), "enabled", false)
		https := sub(we, "https")
		httpsEn := truthyDefault(https, "enabled", false)
		if httpEn || httpsEn {
			add(model.WebEnrollmentEnabled, cid, "")
		}
		// Relay-capable: plain HTTP web enrollment (no EPA) or HTTPS without
		// channel binding. A nil/empty channel_binding means no EPA → relayable.
		if httpEn {
			add(model.HttpRelayCapable, cid, "")
		} else if httpsEn {
			cb := str(https, "channel_binding")
			if cb == "" || strings.EqualFold(cb, "none") || strings.EqualFold(cb, "null") {
				add(model.HttpRelayCapable, cid, "")
			}
		}
		// NoSignatureEnforcement: certipy surfaces this as "Request Disposition"
		// or "Enforce Encryption for Requests" in some versions; only emit when
		// explicitly reported as disabled/absent (never on "Unknown").
		if rd := str(c, "Request Disposition"); strings.EqualFold(rd, "Disabled") {
			add(model.NoSignatureEnforcement, cid, "")
		}

		// CAInDomain: best-effort — resolve the domain FQDN derived from the CA's
		// DNS suffix or certificate-subject DC components to a domain SID. If it
		// does not resolve (e.g. the importer has no domain node), skip — ESC5
		// simply will not fire from certipy data alone.
		if dom := domainFromCA(c, dns); dom != "" {
			if sid, ok := resolveOne(dom); ok {
				add(model.CAInDomain, cid, sid)
			}
		}
	}
	return nodes, facts, nil
}

// templateAnyEKU reports whether the template has the Any Purpose EKU or no EKU
// restriction — the ESC2 condition. Certipy surfaces this as an "Any Purpose"
// boolean and/or an "Extended Key Usage" entry.
func templateAnyEKU(t map[string]any) bool {
	if truthy(t, "Any Purpose") {
		return true
	}
	for _, eku := range strs(t, "Extended Key Usage") {
		switch strings.ToLower(eku) {
		case "any purpose":
			return true
		}
	}
	for _, eku := range strs(t, "pKIExtendedKeyUsage") {
		if strings.EqualFold(eku, "2.5.29.37.0") {
			return true
		}
	}
	return false
}

// templateEnrollmentAgentEKU reports whether the template grants the
// Enrollment Agent EKU — the ESC3 enrollment-agent cert.
func templateEnrollmentAgentEKU(t map[string]any) bool {
	if truthy(t, "Enrollment Agent") {
		return true
	}
	for _, eku := range strs(t, "Extended Key Usage") {
		if strings.EqualFold(eku, "Enrollment Agent") {
			return true
		}
	}
	for _, eku := range strs(t, "pKIExtendedKeyUsage") {
		if strings.EqualFold(eku, "1.3.6.1.4.1.311.20.2.1") {
			return true
		}
	}
	return false
}

// authorizedSignaturesRequired parses the "Authorized Signatures Required"
// field, which certipy renders as either a number or a string like "1".
func authorizedSignaturesRequired(t map[string]any) int {
	switch v := t["Authorized Signatures Required"].(type) {
	case float64:
		return int(v)
	case int:
		return v
	case string:
		n := 0
		for _, r := range v {
			if r < '0' || r > '9' {
				break
			}
			n = n*10 + int(r-'0')
		}
		return n
	}
	return 0
}

// domainFromCA derives the domain FQDN for a CA from its DNS name (strip the
// first label) or its certificate-subject DC= components. Returns "" if none.
func domainFromCA(c map[string]any, dns string) string {
	if dns != "" {
		if i := strings.Index(dns, "."); i >= 0 && i < len(dns)-1 {
			return dns[i+1:]
		}
	}

	subj := str(c, "Certificate Subject")
	var dcs []string
	for _, part := range strings.Split(subj, ",") {
		part = strings.TrimSpace(part)
		if strings.HasPrefix(strings.ToUpper(part), "DC=") {
			dcs = append(dcs, part[3:])
		}
	}
	if len(dcs) > 0 {
		return strings.Join(dcs, ".")
	}
	return ""
}

func templateAuthEKU(t map[string]any) bool {
	if truthy(t, "Client Authentication") || truthy(t, "Any Purpose") {
		return true
	}
	for _, eku := range strs(t, "Extended Key Usage") {
		switch strings.ToLower(eku) {
		case "client authentication", "smart card logon",
			"pkinit client authentication", "any purpose":
			return true
		}
	}
	return false
}

func nameFlagHas(t map[string]any, flag string) bool {
	for _, f := range strs(t, "Certificate Name Flag") {
		if strings.EqualFold(f, flag) {
			return true
		}
	}
	return false
}

// --- flexible JSON accessors (Certipy field shapes vary across versions) ---

func sub(m map[string]any, key string) map[string]any {
	if m == nil {
		return nil
	}
	if v, ok := m[key].(map[string]any); ok {
		return v
	}
	return nil
}

func str(m map[string]any, key string) string {
	if m == nil {
		return ""
	}
	if s, ok := m[key].(string); ok {
		return s
	}
	return ""
}

func strs(m map[string]any, key string) []string {
	if m == nil {
		return nil
	}
	switch v := m[key].(type) {
	case []any:
		out := make([]string, 0, len(v))
		for _, e := range v {
			if s, ok := e.(string); ok {
				out = append(out, s)
			}
		}
		return out
	case string:
		return []string{v}
	}
	return nil
}

func truthy(m map[string]any, key string) bool { return truthyDefault(m, key, false) }

func truthyDefault(m map[string]any, key string, def bool) bool {
	if m == nil {
		return def
	}
	switch v := m[key].(type) {
	case bool:
		return v
	case string:
		return strings.EqualFold(v, "true")
	default:
		return def
	}
}
