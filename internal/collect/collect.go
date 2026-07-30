// Package collect defines the collector interface and an OPSEC-aware runner
// that sequences collectors under a profile's noise budget, applies jittered
// throttling, and records every action to the deconfliction log. Concrete
// collectors (LDAP, AD CS) live in subpackages and emit model.Facts via the
// shared sink.
package collect

import (
	"context"
	"math/rand"

	"orca/internal/model"
	"orca/internal/opsec"
)

// Session is a live, authenticated connection a collector queries. It is an
// interface so LDAP/LDAPS/ADWS transports (and test mocks) are interchangeable.
type Session interface {
	// Target identifies the DC/host for the deconfliction log.
	Target() string
}

// Collector gathers one class of AD data and emits facts into the sink.
type Collector interface {
	Name() string
	Noise() opsec.Noise
	Collect(ctx context.Context, s Session, sink model.FactSink) error
}

// RunResult summarizes what a collection run did.
type RunResult struct {
	Ran     []string
	Skipped []string          // gated out by the profile's noise budget
	Errors  map[string]error
}

// Runner executes collectors under an OPSEC profile.
type Runner struct {
	Profile opsec.Profile
	Log     *opsec.DeconflictLog
	Rng     *rand.Rand // nil => package default source
}

// Run executes the collectors respecting the profile: it randomizes order,
// skips collectors louder than the profile allows, throttles between them, and
// logs each action. Facts are written to sink as collectors run.
func (r Runner) Run(ctx context.Context, s Session, sink model.FactSink, collectors []Collector) RunResult {
	res := RunResult{Errors: map[string]error{}}

	order := r.shuffled(len(collectors))
	for _, idx := range order {
		c := collectors[idx]
		if !r.Profile.Allows(c.Noise()) {
			res.Skipped = append(res.Skipped, c.Name())
			if r.Log != nil {
				r.Log.Record("collector.skip", s.Target(), c.Name()+" (exceeds noise budget)")
			}
			continue
		}
		if err := ctx.Err(); err != nil {
			res.Errors[c.Name()] = err
			return res
		}
		r.Profile.Throttle(r.Rng)
		if r.Log != nil {
			r.Log.Record("collector.run", s.Target(), c.Name())
		}
		if err := c.Collect(ctx, s, sink); err != nil {
			res.Errors[c.Name()] = err
		} else {
			res.Ran = append(res.Ran, c.Name())
		}
	}
	return res
}

func (r Runner) shuffled(n int) []int {
	order := make([]int, n)
	for i := range order {
		order[i] = i
	}
	swap := func(i, j int) { order[i], order[j] = order[j], order[i] }
	if r.Rng != nil {
		r.Rng.Shuffle(n, swap)
	} else {
		rand.Shuffle(n, swap)
	}
	return order
}
