// Package ingest defines Orca's collector-output JSON schema and loads it into
// a graph. Every collector (LDAP, AD CS, ...) emits a Dataset; this is also the
// import format for feeding Orca data gathered by other tooling.
package ingest

import (
	"encoding/json"
	"fmt"
	"os"

	"orca/internal/graph"
	"orca/internal/model"
)

// Dataset is the on-the-wire collection output.
type Dataset struct {
	// Seeds are SIDs the operator already controls (the foothold).
	Seeds []string    `json:"seeds"`
	Nodes []NodeJSON  `json:"nodes"`
	Facts []FactJSON  `json:"facts"`
}

type NodeJSON struct {
	SID       string            `json:"sid"`
	Kind      string            `json:"kind"`
	Name      string            `json:"name"`
	Domain    string            `json:"domain,omitempty"`
	HighValue bool              `json:"highValue,omitempty"`
	Props     map[string]string `json:"props,omitempty"`
}

type FactJSON struct {
	Pred      string `json:"pred"`
	A         string `json:"a"`
	B         string `json:"b,omitempty"`
	Collector string `json:"collector,omitempty"`
	Attribute string `json:"attribute,omitempty"`
	Raw       string `json:"raw,omitempty"`
}

// LoadFile reads and applies a Dataset file to a fresh graph, returning the
// graph and the operator seeds.
func LoadFile(path string) (*graph.Graph, []string, error) {
	b, err := os.ReadFile(path)
	if err != nil {
		return nil, nil, err
	}
	var ds Dataset
	if err := json.Unmarshal(b, &ds); err != nil {
		return nil, nil, fmt.Errorf("ingest: parse %s: %w", path, err)
	}
	g := graph.New()
	Apply(g, ds)
	return g, ds.Seeds, nil
}

// Export serializes a collected graph plus foothold seeds back into a Dataset,
// so `orca collect` output round-trips through `analyze`/`serve`.
func Export(g *graph.Graph, seeds []string) Dataset {
	ds := Dataset{Seeds: seeds}
	for _, n := range g.Nodes() {
		ds.Nodes = append(ds.Nodes, NodeJSON{
			SID: n.SID, Kind: string(n.Kind), Name: n.Name,
			Domain: n.Domain, HighValue: n.HighValue, Props: n.Props,
		})
	}
	for _, f := range g.Facts() {
		fj := FactJSON{Pred: string(f.Pred), A: f.A, B: f.B}
		if f.Prov != nil {
			fj.Collector = f.Prov.Collector
			fj.Attribute = f.Prov.Attribute
			fj.Raw = f.Prov.Raw
		}
		ds.Facts = append(ds.Facts, fj)
	}
	return ds
}

// WriteFile marshals a Dataset to path as indented JSON.
func WriteFile(path string, ds Dataset) error {
	b, err := json.MarshalIndent(ds, "", "  ")
	if err != nil {
		return err
	}
	return os.WriteFile(path, b, 0o600)
}

// Apply writes a Dataset's nodes and facts into g.
func Apply(g *graph.Graph, ds Dataset) {
	for _, n := range ds.Nodes {
		g.AddNode(model.Node{
			SID: n.SID, Kind: model.Kind(n.Kind), Name: n.Name,
			Domain: n.Domain, HighValue: n.HighValue, Props: n.Props,
		})
	}
	for _, f := range ds.Facts {
		fact := model.Fact{Pred: model.Pred(f.Pred), A: f.A, B: f.B}
		if f.Collector != "" || f.Attribute != "" || f.Raw != "" {
			fact.Prov = &model.Provenance{Collector: f.Collector, Attribute: f.Attribute, Raw: f.Raw}
		}
		g.AddFact(fact)
	}
}
