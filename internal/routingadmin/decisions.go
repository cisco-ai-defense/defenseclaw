// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"sync"
	"time"
)

// DecisionsSize is how many recent routing decisions a gateway keeps for
// `routing explain` and `routing status`.
const DecisionsSize = 256

// DecisionEntry is one routing decision. It holds no prompt text, headers
// or credentials.
type DecisionEntry struct {
	Time      time.Time `json:"time"`
	RequestID string    `json:"request_id"`
	// CallerKey is the verified caller id ("" when unverified); it selects
	// who may read the entry and is never shown to another user.
	CallerKey      string   `json:"-"`
	Connector      string   `json:"connector,omitempty"`
	Listener       string   `json:"listener,omitempty"`
	APIFamily      string   `json:"api_family,omitempty"`
	Category       string   `json:"category,omitempty"`
	RequestedModel string   `json:"requested_model,omitempty"`
	SelectedAlias  string   `json:"selected_alias,omitempty"`
	SelectedModel  string   `json:"selected_model,omitempty"`
	Outcome        string   `json:"outcome"`
	Source         string   `json:"source,omitempty"`
	Reasons        []string `json:"reasons,omitempty"`
	RuleIDs        []string `json:"rule_ids,omitempty"`
	Warnings       []string `json:"warnings,omitempty"`
}

// Decisions is a fixed ring of the most recent decisions of this gateway
// process. The routing engine records one entry per routed call when
// routing is enabled.
type Decisions struct {
	mu   sync.Mutex
	buf  [DecisionsSize]DecisionEntry
	next int
	n    int
}

// Record stores e, replacing the oldest entry when full.
func (d *Decisions) Record(e DecisionEntry) {
	if d == nil {
		return
	}
	e.Reasons = clone(e.Reasons)
	e.RuleIDs = clone(e.RuleIDs)
	e.Warnings = clone(e.Warnings)
	d.mu.Lock()
	d.buf[d.next] = e
	d.next = (d.next + 1) % DecisionsSize
	if d.n < DecisionsSize {
		d.n++
	}
	d.mu.Unlock()
}

// Recent returns up to limit entries, newest first, that the caller may
// read: all for an administrator, the caller's own otherwise.
func (d *Decisions) Recent(callerKey string, admin bool, limit int) []DecisionEntry {
	if d == nil || limit <= 0 {
		return nil
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	var out []DecisionEntry
	for i := 0; i < d.n && len(out) < limit; i++ {
		e := d.buf[(d.next-1-i+DecisionsSize)%DecisionsSize]
		if admin || (callerKey != "" && e.CallerKey == callerKey) {
			out = append(out, e)
		}
	}
	return out
}

// Find returns the entry for requestID if the caller may read it. Another
// user's entry is reported as not found.
func (d *Decisions) Find(requestID, callerKey string, admin bool) (DecisionEntry, bool) {
	if d == nil || requestID == "" {
		return DecisionEntry{}, false
	}
	d.mu.Lock()
	defer d.mu.Unlock()
	for i := 0; i < d.n; i++ {
		e := d.buf[(d.next-1-i+DecisionsSize)%DecisionsSize]
		if e.RequestID == requestID {
			if admin || (callerKey != "" && e.CallerKey == callerKey) {
				return e, true
			}
			return DecisionEntry{}, false
		}
	}
	return DecisionEntry{}, false
}

func clone(s []string) []string {
	if len(s) == 0 {
		return nil
	}
	return append([]string(nil), s...)
}
