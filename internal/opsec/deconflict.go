package opsec

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"os"
	"sync"
	"time"
)

// DeconflictEntry is one append-only record of an action Orca took, hash-chained
// to the previous entry so the log is tamper-evident for blue-team review.
type DeconflictEntry struct {
	Seq       int       `json:"seq"`
	Time      time.Time `json:"time"`
	Operator  string    `json:"operator"`
	Action    string    `json:"action"`   // e.g. "ldap.query", "adcs.enum"
	Target    string    `json:"target"`   // DC / host / DN
	Detail    string    `json:"detail"`
	Profile   string    `json:"profile"`
	PrevHash  string    `json:"prev_hash"`
	Hash      string    `json:"hash"`
}

// DeconflictLog is an append-only, hash-chained activity log. Standard practice
// on authorized engagements: it lets defenders attribute observed activity.
type DeconflictLog struct {
	mu       sync.Mutex
	path     string
	operator string
	profile  string
	seq      int
	prevHash string
	entries  []DeconflictEntry
}

// NewDeconflictLog creates a log that also appends JSON lines to path (if set).
func NewDeconflictLog(path, operator, profile string) *DeconflictLog {
	return &DeconflictLog{path: path, operator: operator, profile: profile}
}

// Record appends an action to the log and returns the created entry.
func (l *DeconflictLog) Record(action, target, detail string) DeconflictEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	l.seq++
	e := DeconflictEntry{
		Seq: l.seq, Time: time.Now().UTC(), Operator: l.operator,
		Action: action, Target: target, Detail: detail, Profile: l.profile,
		PrevHash: l.prevHash,
	}
	e.Hash = hashEntry(e)
	l.prevHash = e.Hash
	l.entries = append(l.entries, e)
	if l.path != "" {
		if b, err := json.Marshal(e); err == nil {
			if fh, err := os.OpenFile(l.path, os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600); err == nil {
				fh.Write(append(b, '\n'))
				fh.Close()
			}
		}
	}
	return e
}

// Entries returns a snapshot of the in-memory log.
func (l *DeconflictLog) Entries() []DeconflictEntry {
	l.mu.Lock()
	defer l.mu.Unlock()
	return append([]DeconflictEntry(nil), l.entries...)
}

// Verify checks the hash chain is intact (no tampering / gaps).
func (l *DeconflictLog) Verify() bool {
	l.mu.Lock()
	defer l.mu.Unlock()
	prev := ""
	for _, e := range l.entries {
		if e.PrevHash != prev {
			return false
		}
		want := e.Hash
		e.Hash = ""
		if hashEntry(e) != want {
			return false
		}
		prev = want
	}
	return true
}

func hashEntry(e DeconflictEntry) string {
	e.Hash = ""
	b, _ := json.Marshal(e)
	sum := sha256.Sum256(b)
	return hex.EncodeToString(sum[:])
}
