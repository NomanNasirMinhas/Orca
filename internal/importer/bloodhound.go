package importer

import (
	"archive/zip"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"

	orcaldap "orca/internal/collect/ldap"
	"orca/internal/model"
)

// BloodHound JSON shapes (SharpHound 4.x / CE). Only the fields Orca needs.
type bhFile struct {
	Data []bhObject `json:"data"`
	Meta bhMeta     `json:"meta"`
}
type bhMeta struct {
	Type string `json:"type"`
}
type bhObject struct {
	ObjectIdentifier string     `json:"ObjectIdentifier"`
	Properties       bhProps    `json:"Properties"`
	Aces             []bhAce    `json:"Aces"`
	Members          []bhMember `json:"Members"`
	PrimaryGroupSID  string     `json:"PrimaryGroupSID"`
	AllowedToAct     []bhMember `json:"AllowedToAct"`
}
type bhProps struct {
	Name                    string   `json:"name"`
	Domain                  string   `json:"domain"`
	Samaccountname          string   `json:"samaccountname"`
	Displayname             string   `json:"displayname"`
	Distinguishedname       string   `json:"distinguishedname"`
	Highvalue               *bool    `json:"highvalue"`
	Serviceprincipalnames   []string `json:"serviceprincipalnames"`
	Hasspn                  *bool    `json:"hasspn"`
	Dontreqpreauth          *bool    `json:"dontreqpreauth"`
	Unconstraineddelegation *bool    `json:"unconstraineddelegation"`
}
type bhAce struct {
	PrincipalSID string `json:"PrincipalSID"`
	RightName    string `json:"RightName"`
}
type bhMember struct {
	ObjectIdentifier string `json:"ObjectIdentifier"`
	ObjectType       string `json:"ObjectType"`
}

// ImportBloodHound reads a BloodHound export from a .zip, a directory of JSON
// files, or a single JSON file, and returns the combined nodes and facts.
func ImportBloodHound(path string) ([]model.Node, []model.Fact, error) {
	info, err := os.Stat(path)
	if err != nil {
		return nil, nil, err
	}
	var docs [][]byte
	switch {
	case info.IsDir():
		matches, _ := filepath.Glob(filepath.Join(path, "*.json"))
		for _, m := range matches {
			if b, err := os.ReadFile(m); err == nil {
				docs = append(docs, b)
			}
		}
	case strings.EqualFold(filepath.Ext(path), ".zip"):
		docs, err = readZipJSON(path)
		if err != nil {
			return nil, nil, err
		}
	default:
		b, err := os.ReadFile(path)
		if err != nil {
			return nil, nil, err
		}
		docs = append(docs, b)
	}

	var nodes []model.Node
	var facts []model.Fact
	for _, d := range docs {
		n, f, err := parseBHFile(d)
		if err != nil {
			return nil, nil, err
		}
		nodes = append(nodes, n...)
		facts = append(facts, f...)
	}
	return nodes, facts, nil
}

func readZipJSON(path string) ([][]byte, error) {
	zr, err := zip.OpenReader(path)
	if err != nil {
		return nil, err
	}
	defer zr.Close()
	var out [][]byte
	for _, f := range zr.File {
		if !strings.EqualFold(filepath.Ext(f.Name), ".json") {
			continue
		}
		rc, err := f.Open()
		if err != nil {
			return nil, err
		}
		b, err := io.ReadAll(rc)
		rc.Close()
		if err != nil {
			return nil, err
		}
		out = append(out, b)
	}
	return out, nil
}

// parseBHFile parses one BloodHound JSON document into nodes and facts.
func parseBHFile(b []byte) ([]model.Node, []model.Fact, error) {
	var f bhFile
	if err := json.Unmarshal(b, &f); err != nil {
		return nil, nil, fmt.Errorf("bloodhound: parse: %w", err)
	}
	kind, tkind := bhKind(f.Meta.Type)
	prov := &model.Provenance{Collector: "bloodhound", Attribute: f.Meta.Type}

	var nodes []model.Node
	var facts []model.Fact
	add := func(p model.Pred, a, b string) {
		facts = append(facts, model.Fact{Pred: p, A: a, B: b, Prov: prov})
	}

	for _, o := range f.Data {
		sid := o.ObjectIdentifier
		if sid == "" {
			continue
		}
		hv := (o.Properties.Highvalue != nil && *o.Properties.Highvalue) || orcaldap.IsHighValueSID(sid)
		name := o.Properties.Samaccountname
		if name == "" {
			name = o.Properties.Name
		}
		// Carry identity props through to the Info panel: the node's Name is the
		// short sAMAccountName, so prefer displayName (then the descriptive
		// Properties.name when it differs) plus distinguishedName for AD context.
		props := map[string]string{}
		if dn := o.Properties.Distinguishedname; dn != "" {
			props["distinguishedName"] = dn
		}
		if dp := o.Properties.Displayname; dp != "" {
			props["displayName"] = dp
		} else if pn := o.Properties.Name; pn != "" && pn != name {
			props["displayName"] = pn
		}
		if len(props) == 0 {
			props = nil
		}
		nodes = append(nodes, model.Node{
			SID: sid, Kind: kind, Name: name, Domain: strings.ToLower(o.Properties.Domain),
			HighValue: hv, Props: props,
		})

		switch kind {
		case model.KindUser:
			add(model.IsUser, sid, "")
		case model.KindComputer:
			add(model.IsComputer, sid, "")
		case model.KindGroup:
			add(model.IsGroup, sid, "")
		case model.KindDomain:
			add(model.IsDomain, sid, "")
		}
		if hv {
			add(model.HighValue, sid, "")
		}

		// ACEs: PrincipalSID holds the right over this object.
		for _, ace := range o.Aces {
			if ace.PrincipalSID == "" {
				continue
			}
			for _, p := range mapRight(ace.RightName, tkind) {
				add(p, ace.PrincipalSID, sid)
			}
		}
		// Group members are members of this group.
		for _, m := range o.Members {
			if m.ObjectIdentifier != "" {
				add(model.MemberOf, m.ObjectIdentifier, sid)
			}
		}
		if o.PrimaryGroupSID != "" {
			add(model.MemberOf, sid, o.PrimaryGroupSID)
		}
		// RBCD: principals allowed to act on behalf toward this computer.
		for _, m := range o.AllowedToAct {
			if m.ObjectIdentifier != "" {
				add(model.AllowedToAct, m.ObjectIdentifier, sid)
			}
		}
		// Credential exposure.
		if kind == model.KindUser {
			if (o.Properties.Hasspn != nil && *o.Properties.Hasspn) || len(o.Properties.Serviceprincipalnames) > 0 {
				add(model.HasSPN, sid, "")
			}
			if o.Properties.Dontreqpreauth != nil && *o.Properties.Dontreqpreauth {
				add(model.ASREPRoastable, sid, "")
			}
		}
	}
	return nodes, facts, nil
}

func bhKind(metaType string) (model.Kind, tkind) {
	switch strings.ToLower(metaType) {
	case "users":
		return model.KindUser, tUser
	case "computers":
		return model.KindComputer, tComputer
	case "groups":
		return model.KindGroup, tGroup
	case "domains":
		return model.KindDomain, tDomain
	case "gpos":
		return model.KindGPO, tOther
	case "ous":
		return model.KindOU, tOther
	case "containers":
		return model.KindContainer, tOther
	default:
		return model.KindContainer, tOther
	}
}
