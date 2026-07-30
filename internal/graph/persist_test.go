package graph

import (
	"path/filepath"
	"testing"

	"orca/internal/model"
)

func TestEncryptedRoundTrip(t *testing.T) {
	g := New()
	g.AddNode(model.Node{SID: "S-1-DA", Kind: model.KindGroup, Name: "Domain Admins", HighValue: true})
	g.AddFact(model.Fact{Pred: model.MemberOf, A: "S-1-U", B: "S-1-DA"})
	g.AddFact(model.Fact{Pred: model.MemberOf, A: "S-1-U", B: "S-1-DA"}) // dup ignored

	path := filepath.Join(t.TempDir(), "orca.db")
	const pass = "correct horse battery staple"
	if err := g.Save(path, pass); err != nil {
		t.Fatalf("save: %v", err)
	}

	got, err := Load(path, pass)
	if err != nil {
		t.Fatalf("load: %v", err)
	}
	n, f := got.Stats()
	if n != 1 || f != 1 {
		t.Fatalf("expected 1 node / 1 fact, got %d / %d", n, f)
	}
	if names := got.Names(); names["S-1-DA"] != "Domain Admins" {
		t.Fatalf("name not preserved: %v", names)
	}

	if _, err := Load(path, "wrong pass"); err == nil {
		t.Fatal("expected decrypt failure with wrong passphrase")
	}
}
