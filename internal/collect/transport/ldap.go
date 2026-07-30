// Package transport implements the network sessions collectors run over. The
// LDAP session dials a DC (LDAP/LDAPS), authenticates (NTLM or simple bind),
// and runs paged searches. This is the wire seam over the pure parsers/mappers
// in the collect subpackages; it requires a reachable DC to exercise.
package transport

import (
	"context"
	"crypto/tls"
	"fmt"
	"strings"

	ber "github.com/go-asn1-ber/asn1-ber"
	goldap "github.com/go-ldap/ldap/v3"

	orcaldap "orca/internal/collect/ldap"
	"orca/internal/collect/secdesc"
)

// LDAPConfig configures an LDAP session.
type LDAPConfig struct {
	Host     string // DC hostname/IP
	Port     int    // 389 (LDAP) or 636 (LDAPS); 0 => default per TLS
	UseTLS   bool
	Domain   string // NetBIOS/DNS domain for NTLM bind
	Username string
	Password string
	NTHash   string // optional: pass-the-hash (NTLM), hex NT hash
	BaseDN   string // e.g. DC=corp,DC=local; derived from Domain if empty
	Insecure bool   // skip TLS verify (lab use)
}

// LDAPSession is a live authenticated LDAP connection. It implements
// collect.Session and orcaldap.Searcher.
type LDAPSession struct {
	conn       *goldap.Conn
	cfg        LDAPConfig
	baseDN     string
	domainSID  string
	domainFQDN string
	pageSize   uint32
}

// DialLDAP connects and binds an LDAP session.
func DialLDAP(cfg LDAPConfig) (*LDAPSession, error) {
	port := cfg.Port
	scheme := "ldap"
	if cfg.UseTLS {
		scheme = "ldaps"
		if port == 0 {
			port = 636
		}
	} else if port == 0 {
		port = 389
	}
	url := fmt.Sprintf("%s://%s:%d", scheme, cfg.Host, port)

	var opts []goldap.DialOpt
	if cfg.UseTLS {
		opts = append(opts, goldap.DialWithTLSConfig(&tls.Config{InsecureSkipVerify: cfg.Insecure}))
	}
	conn, err := goldap.DialURL(url, opts...)
	if err != nil {
		return nil, fmt.Errorf("ldap dial %s: %w", url, err)
	}

	if err := bind(conn, cfg); err != nil {
		conn.Close()
		return nil, err
	}

	s := &LDAPSession{conn: conn, cfg: cfg, pageSize: 1000}
	s.baseDN = cfg.BaseDN
	if s.baseDN == "" {
		s.baseDN = domainToBaseDN(cfg.Domain)
	}
	s.domainFQDN = strings.ToLower(cfg.Domain)
	s.domainSID, _ = s.fetchDomainSID()
	return s, nil
}

func bind(conn *goldap.Conn, cfg LDAPConfig) error {
	switch {
	case cfg.NTHash != "":
		return conn.NTLMBindWithHash(cfg.Domain, cfg.Username, cfg.NTHash)
	case cfg.Domain != "":
		return conn.NTLMBind(cfg.Domain, cfg.Username, cfg.Password)
	default:
		return conn.Bind(cfg.Username, cfg.Password)
	}
}

// Target identifies the DC for the deconfliction log.
func (s *LDAPSession) Target() string { return s.cfg.Host }

// BaseDN / DomainSID / DomainFQDN satisfy orcaldap.Searcher.
func (s *LDAPSession) BaseDN() string     { return s.baseDN }
func (s *LDAPSession) DomainSID() string  { return s.domainSID }
func (s *LDAPSession) DomainFQDN() string { return s.domainFQDN }

// Search runs a paged subtree search and adapts entries to the mapper's view.
// The SD_FLAGS control requests owner+group+DACL (excluding SACL) so DACLs are
// returned without requiring SeSecurityPrivilege.
func (s *LDAPSession) Search(_ context.Context, filter string, attrs []string) ([]orcaldap.Entry, error) {
	req := goldap.NewSearchRequest(
		s.baseDN, goldap.ScopeWholeSubtree, goldap.NeverDerefAliases,
		0, 0, false, filter, attrs,
		[]goldap.Control{sdFlagsControl(0x07)},
	)
	res, err := s.conn.SearchWithPaging(req, s.pageSize)
	if err != nil {
		return nil, fmt.Errorf("ldap search %q: %w", filter, err)
	}
	out := make([]orcaldap.Entry, 0, len(res.Entries))
	for _, e := range res.Entries {
		out = append(out, entry{e})
	}
	return out, nil
}

// Close releases the connection.
func (s *LDAPSession) Close() error {
	if s.conn != nil {
		return s.conn.Close()
	}
	return nil
}

func (s *LDAPSession) fetchDomainSID() (string, error) {
	req := goldap.NewSearchRequest(
		s.baseDN, goldap.ScopeBaseObject, goldap.NeverDerefAliases,
		0, 0, false, "(objectClass=*)", []string{"objectSid"}, nil,
	)
	res, err := s.conn.Search(req)
	if err != nil || len(res.Entries) == 0 {
		return "", fmt.Errorf("fetch domain sid: %w", err)
	}
	raw := res.Entries[0].GetRawAttributeValue("objectSid")
	return secdesc.ParseSID(raw)
}

// sdFlagsControl builds the LDAP_SERVER_SD_FLAGS_OID control (1.2.840.113556.1.4.801).
func sdFlagsControl(flags int) goldap.Control {
	seq := ber.Encode(ber.ClassUniversal, ber.TypeConstructed, ber.TagSequence, nil, "SDFlagsRequestValue")
	seq.AppendChild(ber.NewInteger(ber.ClassUniversal, ber.TypePrimitive, ber.TagInteger, int64(flags), "Flags"))
	return goldap.NewControlString("1.2.840.113556.1.4.801", true, string(seq.Bytes()))
}

func domainToBaseDN(domain string) string {
	parts := strings.Split(strings.TrimSpace(domain), ".")
	if len(parts) == 0 || parts[0] == "" {
		return ""
	}
	for i := range parts {
		parts[i] = "DC=" + parts[i]
	}
	return strings.Join(parts, ",")
}

// entry adapts a go-ldap Entry to orcaldap.Entry.
type entry struct{ e *goldap.Entry }

func (a entry) DN() string             { return a.e.DN }
func (a entry) Str(attr string) string { return a.e.GetAttributeValue(attr) }
func (a entry) Strs(attr string) []string { return a.e.GetAttributeValues(attr) }
func (a entry) Bytes(attr string) []byte  { return a.e.GetRawAttributeValue(attr) }
