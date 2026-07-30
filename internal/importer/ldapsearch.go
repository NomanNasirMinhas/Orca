// Package importer parses output from other AD tooling (BloodHound, ldapsearch,
// Certipy) into Orca nodes and facts, so operators can fuse data they already
// collected into one attack graph. Each parser is pure and unit-testable.
package importer

import (
	"bufio"
	"encoding/base64"
	"io"
	"strings"

	orcaldap "orca/internal/collect/ldap"
	"orca/internal/collect/secdesc"
	"orca/internal/model"
)

// ldifEntry adapts a parsed LDIF record to orcaldap.Entry so the live-LDAP
// mapper can be reused verbatim.
type ldifEntry struct {
	dn   string
	strs map[string][]string
	raws map[string][]byte // first raw (base64-decoded) value per attribute
}

func (e *ldifEntry) DN() string             { return e.dn }
func (e *ldifEntry) Str(a string) string    { if v := e.strs[a]; len(v) > 0 { return v[0] }; return "" }
func (e *ldifEntry) Strs(a string) []string { return e.strs[a] }
func (e *ldifEntry) Bytes(a string) []byte  { return e.raws[a] }

// ImportLDIF parses `ldapsearch` LDIF output and maps it through the same
// pipeline as live LDAP collection.
func ImportLDIF(r io.Reader) ([]model.Node, []model.Fact, error) {
	entries, err := parseLDIF(r)
	if err != nil {
		return nil, nil, err
	}
	ents := make([]orcaldap.Entry, len(entries))
	domainSID, domainFQDN := "", ""
	for i, e := range entries {
		ents[i] = e
		if isDomainObject(e) {
			if sid, err := secdesc.ParseSID(e.Bytes("objectSid")); err == nil {
				domainSID = sid
			}
			domainFQDN = dnToFQDN(e.dn)
		}
	}
	nodes, facts := orcaldap.MapDomain(ents, domainSID, domainFQDN)
	return nodes, facts, nil
}

func isDomainObject(e *ldifEntry) bool {
	for _, c := range e.Strs("objectClass") {
		lc := strings.ToLower(c)
		if lc == "domaindns" || lc == "domain" {
			return true
		}
	}
	return false
}

// parseLDIF decodes LDIF: blank-line-separated records, `attr: value` (string),
// `attr:: base64` (binary), leading-space line continuations, `#` comments.
func parseLDIF(r io.Reader) ([]*ldifEntry, error) {
	var entries []*ldifEntry
	var logical []string // unfolded logical lines for the current record

	sc := bufio.NewScanner(r)
	sc.Buffer(make([]byte, 1024*1024), 8*1024*1024)

	commit := func() {
		if len(logical) == 0 {
			return
		}
		e := &ldifEntry{strs: map[string][]string{}, raws: map[string][]byte{}}
		for _, ln := range logical {
			attr, val, b64, ok := splitLDIF(ln)
			if !ok {
				continue
			}
			if strings.EqualFold(attr, "dn") {
				e.dn = val
				continue
			}
			if b64 {
				if dec, err := base64.StdEncoding.DecodeString(val); err == nil {
					if _, seen := e.raws[attr]; !seen {
						e.raws[attr] = dec
					}
					// Also keep a string form for text attributes.
					e.strs[attr] = append(e.strs[attr], string(dec))
				}
				continue
			}
			e.strs[attr] = append(e.strs[attr], val)
		}
		if e.dn != "" || len(e.strs) > 0 {
			entries = append(entries, e)
		}
		logical = nil
	}

	for sc.Scan() {
		line := sc.Text()
		if line == "" {
			commit()
			continue
		}
		if strings.HasPrefix(line, "#") || strings.HasPrefix(strings.ToLower(line), "version:") {
			continue
		}
		if line[0] == ' ' { // continuation of previous logical line
			if len(logical) > 0 {
				logical[len(logical)-1] += strings.TrimPrefix(line, " ")
			}
			continue
		}
		logical = append(logical, line)
	}
	commit()
	return entries, sc.Err()
}

// splitLDIF parses one logical LDIF line into attr/value, flagging base64 (`::`).
func splitLDIF(line string) (attr, value string, b64, ok bool) {
	attr, rest, found := strings.Cut(line, ":")
	if !found {
		return "", "", false, false
	}
	if strings.HasPrefix(rest, ":") { // "attr:: base64"
		return attr, strings.TrimSpace(rest[1:]), true, true
	}
	if strings.HasPrefix(rest, "<") { // "attr:< url" — unsupported, skip
		return "", "", false, false
	}
	return attr, strings.TrimSpace(rest), false, true
}

// dnToFQDN turns "DC=corp,DC=local" into "corp.local".
func dnToFQDN(dn string) string {
	var parts []string
	for _, comp := range strings.Split(dn, ",") {
		comp = strings.TrimSpace(comp)
		if strings.HasPrefix(strings.ToLower(comp), "dc=") {
			parts = append(parts, comp[3:])
		}
	}
	return strings.ToLower(strings.Join(parts, "."))
}
