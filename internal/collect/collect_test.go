package collect

import (
	"context"
	"math/rand"
	"testing"

	"orca/internal/graph"
	"orca/internal/model"
	"orca/internal/opsec"
)

type mockSession struct{}

func (mockSession) Target() string { return "dc01.corp.local" }

type mockCollector struct {
	name  string
	noise opsec.Noise
	facts []model.Fact
}

func (m mockCollector) Name() string       { return m.name }
func (m mockCollector) Noise() opsec.Noise { return m.noise }
func (m mockCollector) Collect(_ context.Context, _ Session, sink model.FactSink) error {
	for _, f := range m.facts {
		sink.AddFact(f)
	}
	return nil
}

func TestRunnerGatesByNoiseAndLogs(t *testing.T) {
	quiet := mockCollector{name: "ldap", noise: opsec.NoiseLow,
		facts: []model.Fact{{Pred: model.MemberOf, A: "S-U", B: "S-G"}}}
	loud := mockCollector{name: "smb-sessions", noise: opsec.NoiseHigh,
		facts: []model.Fact{{Pred: model.MemberOf, A: "S-X", B: "S-Y"}}}

	g := graph.New()
	log := opsec.NewDeconflictLog("", "op", "stealth")
	r := Runner{
		Profile: opsec.Get("stealth"), // MaxNoise = low
		Log:     log,
		Rng:     rand.New(rand.NewSource(1)), // deterministic, no real delay path
	}
	// stealth has real delays; override to fast timing for the test by using a
	// zero-delay profile but keeping the low noise budget.
	r.Profile.MinDelay, r.Profile.MaxDelay = 0, 0

	res := r.Run(context.Background(), mockSession{}, g, []Collector{quiet, loud})

	if len(res.Ran) != 1 || res.Ran[0] != "ldap" {
		t.Fatalf("expected only ldap to run, got %v", res.Ran)
	}
	if len(res.Skipped) != 1 || res.Skipped[0] != "smb-sessions" {
		t.Fatalf("expected smb-sessions skipped, got %v", res.Skipped)
	}
	if n, f := g.Stats(); f != 1 {
		t.Fatalf("expected 1 fact collected, got %d nodes / %d facts", n, f)
	}
	// Deconflict log must record the run + the skip, and verify intact.
	if len(log.Entries()) != 2 {
		t.Fatalf("expected 2 deconflict entries, got %d", len(log.Entries()))
	}
	if !log.Verify() {
		t.Fatal("deconflict log should verify")
	}
}
