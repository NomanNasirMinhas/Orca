package importer

import (
	"encoding/base64"
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strconv"
	"strings"

	orcaldap "orca/internal/collect/ldap"
	"orca/internal/collect/secdesc"
	"orca/internal/model"
)

// lddEntry adapts an ldapdomaindump record to orcaldap.Entry so the live-LDAP
// mapper is reused. ldapdomaindump renders objectSid as a string SID and UAC /
// primaryGroupID as numbers, which this adapter normalizes.
type lddEntry struct {
	dn   string
	strs map[string][]string
	raws map[string][]byte
}

func (e *lddEntry) DN() string          { return e.dn }
func (e *lddEntry) Str(a string) string { if v := e.strs[a]; len(v) > 0 { return v[0] }; return "" }
func (e *lddEntry) Strs(a string) []string { return e.strs[a] }
func (e *lddEntry) Bytes(a string) []byte  { return e.raws[a] }

// lddRaw is one raw ldapdomaindump entry.
type lddRaw struct {
	DN         string                     `json:"dn"`
	Attributes map[string]json.RawMessage `json:"attributes"`
}

// ImportLDAPDomainDump reads ldapdomaindump JSON (a domain_*.json file or a
// directory of them) and maps entries through the same pipeline as live LDAP.
func ImportLDAPDomainDump(path string) ([]model.Node, []model.Fact, error) {
	var files []string
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	if info.IsDir() {
		// The object files ldd produces; policy/trusts are not principal graphs.
		for _, pat := range []string{"domain_users.json", "domain_computers.json", "domain_groups.json"} {
			if m, _ := filepath.Glob(filepath.Join(path, pat)); len(m) > 0 {
				files = append(files, m...)
			}
		}
		if len(files) == 0 {
			files, _ = filepath.Glob(filepath.Join(path, "*.json"))
		}
	} else {
		files = []string{path}
	}

	var raws []lddRaw
	for _, fpath := range files {
		b, err := os.ReadFile(fpath)
		if err != nil {
			return nil, nil, err
		}
		var batch []lddRaw
		if err := json.Unmarshal(b, &batch); err != nil {
			return nil, nil, fmt.Errorf("ldapdomaindump %s: %w", filepath.Base(fpath), err)
		}
		raws = append(raws, batch...)
	}

	entries := make([]orcaldap.Entry, 0, len(raws))
	domainSID, domainFQDN := "", ""
	for i := range raws {
		e := toLDDEntry(&raws[i])
		entries = append(entries, e)
		if domainFQDN == "" && e.dn != "" {
			domainFQDN = dnToFQDN(e.dn)
		}
		if domainSID == "" {
			if sid := e.Str("objectSid"); strings.HasPrefix(sid, "S-1-5-21-") {
				domainSID = stripRID(sid)
			}
		}
	}
	nodes, facts := orcaldap.MapDomain(entries, domainSID, domainFQDN)
	return nodes, facts, nil
}

// toLDDEntry normalizes one raw record: stringifies all attribute values, and
// materializes binary forms for objectSid (string SID) and any security
// descriptors (base64) so the mapper's Bytes() calls work.
func toLDDEntry(r *lddRaw) *lddEntry {
	e := &lddEntry{dn: r.DN, strs: map[string][]string{}, raws: map[string][]byte{}}
	for attr, raw := range r.Attributes {
		vals := toStrings(raw)
		if len(vals) == 0 {
			continue
		}
		e.strs[attr] = vals
		switch attr {
		case "objectSid":
			if b, err := secdesc.SIDToBytes(vals[0]); err == nil {
				e.raws[attr] = b
			}
		case "nTSecurityDescriptor", "msDS-AllowedToActOnBehalfOfOtherIdentity":
			if b, err := base64.StdEncoding.DecodeString(vals[0]); err == nil {
				e.raws[attr] = b
			}
		}
	}
	return e
}

// toStrings coerces an LDIF/JSON attribute value (array or scalar; string,
// number, or bool) into a []string.
func toStrings(raw json.RawMessage) []string {
	var arr []any
	if err := json.Unmarshal(raw, &arr); err == nil {
		out := make([]string, 0, len(arr))
		for _, v := range arr {
			out = append(out, scalarString(v))
		}
		return out
	}
	var one any
	if err := json.Unmarshal(raw, &one); err == nil {
		return []string{scalarString(one)}
	}
	return nil
}

func scalarString(v any) string {
	switch t := v.(type) {
	case string:
		return t
	case float64:
		if t == float64(int64(t)) {
			return strconv.FormatInt(int64(t), 10)
		}
		return strconv.FormatFloat(t, 'f', -1, 64)
	case bool:
		return strconv.FormatBool(t)
	default:
		return fmt.Sprint(t)
	}
}

// stripRID removes the trailing "-<rid>" to yield the domain SID.
func stripRID(sid string) string {
	if i := strings.LastIndex(sid, "-"); i >= 0 {
		return sid[:i]
	}
	return sid
}
