// Package opsec provides Orca's operational-security controls for authorized
// red-team engagements: collection profiles, a jittered request throttle,
// query-mutation helpers to avoid signatured LDAP filters, and an append-only
// deconfliction log so blue teams can attribute Orca's activity.
package opsec

import (
	"math/rand"
	"time"
)

// Noise is a collector's declared detection footprint, used by the scheduler to
// sequence work under a profile's budget.
type Noise int

const (
	NoiseLow    Noise = 1
	NoiseMedium Noise = 3
	NoiseHigh   Noise = 5
)

// Profile bundles the OPSEC knobs an operator selects per engagement.
type Profile struct {
	Name string
	// MinDelay/MaxDelay bound the jittered pause between requests.
	MinDelay, MaxDelay time.Duration
	// MaxNoise gates collectors: any collector whose Noise exceeds it is skipped.
	MaxNoise Noise
	// MutateFilters decomposes/randomizes LDAP queries to dodge fingerprints.
	MutateFilters bool
	// PreferADWS uses SOAP/9389 instead of raw LDAP where available.
	PreferADWS bool
	// AvoidHoneytokens skips likely MDI decoy accounts.
	AvoidHoneytokens bool
	// PageSizeJitter randomizes LDAP paging sizes around a base.
	PageSizeJitter bool
	// BusinessHoursOnly restricts collection to a working-hours window.
	BusinessHoursOnly bool
}

// Profiles returns the three built-in profiles.
func Profiles() map[string]Profile {
	return map[string]Profile{
		"stealth": {
			Name: "stealth", MinDelay: 800 * time.Millisecond, MaxDelay: 3500 * time.Millisecond,
			MaxNoise: NoiseLow, MutateFilters: true, PreferADWS: true,
			AvoidHoneytokens: true, PageSizeJitter: true, BusinessHoursOnly: true,
		},
		"balanced": {
			Name: "balanced", MinDelay: 150 * time.Millisecond, MaxDelay: 700 * time.Millisecond,
			MaxNoise: NoiseMedium, MutateFilters: true, PreferADWS: false,
			AvoidHoneytokens: true, PageSizeJitter: true, BusinessHoursOnly: false,
		},
		"fast": {
			Name: "fast", MinDelay: 0, MaxDelay: 0,
			MaxNoise: NoiseHigh, MutateFilters: false, PreferADWS: false,
			AvoidHoneytokens: false, PageSizeJitter: false, BusinessHoursOnly: false,
		},
	}
}

// Get returns a profile by name, defaulting to balanced.
func Get(name string) Profile {
	if p, ok := Profiles()[name]; ok {
		return p
	}
	return Profiles()["balanced"]
}

// Allows reports whether a collector of the given noise level may run.
func (p Profile) Allows(n Noise) bool { return n <= p.MaxNoise }

// Throttle applies the profile's jittered inter-request delay. It returns
// immediately for the fast profile. rng may be nil (a default source is used).
func (p Profile) Throttle(rng *rand.Rand) {
	if p.MaxDelay <= 0 {
		return
	}
	span := p.MaxDelay - p.MinDelay
	d := p.MinDelay
	if span > 0 {
		if rng != nil {
			d += time.Duration(rng.Int63n(int64(span)))
		} else {
			d += time.Duration(rand.Int63n(int64(span)))
		}
	}
	time.Sleep(d)
}

// PageSize returns an LDAP page size, jittered around base when enabled so the
// paging pattern is not a stable fingerprint.
func (p Profile) PageSize(base int, rng *rand.Rand) int {
	if !p.PageSizeJitter || base <= 0 {
		return base
	}
	// +/- 25% jitter.
	span := base / 2
	if span == 0 {
		return base
	}
	delta := span
	if rng != nil {
		delta = rng.Intn(span + 1)
	} else {
		delta = rand.Intn(span + 1)
	}
	return base - span/2 + delta
}
