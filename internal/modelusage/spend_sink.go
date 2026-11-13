// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"crypto/rand"
	"encoding/hex"
	"sync/atomic"
	"time"
)

var callIDFallback atomic.Uint64

// SpendSink is where finished calls charge routing.admin budgets: the
// routing admin runtime (routingadmin.Runtime.Add). The gateway wires it in;
// it must not block. callID makes a charge idempotent.
type SpendSink interface {
	Add(callID string, keys []string, usd float64, known bool, at time.Time)
}

type spendSinkBox struct{ sink SpendSink }

// SetSpendSink installs the budget sink (nil removes it).
func (e *Engine) SetSpendSink(sink SpendSink) {
	if e == nil {
		return
	}
	e.budgetSink.Store(&spendSinkBox{sink: sink})
}

// chargeBudgets charges a finished agent call to its budget keys with the
// resolved cost: computed, else reported (lead ruling 2026-11-12T23:38Z).
// A call that returned usage nobody can price is passed as unknown, never 0.
// A call with no usage at all (refused, failed or cancelled before the
// provider counted anything) bills nothing and is not unknown. Each call
// gets an id minted here, so a client-chosen request id cannot merge calls.
func (e *Engine) chargeBudgets(f CallFacts, rec Record) {
	if e == nil || len(f.ChargeKeys) == 0 || f.CallRole != RoleAgent {
		return
	}
	box := e.budgetSink.Load()
	if box == nil || box.sink == nil {
		return
	}
	id := newCallID()
	usd := rec.Cost.ComputedUSD
	if usd == nil {
		usd = rec.Cost.USD
	}
	// A stream cancelled after the provider started answering, before the
	// final usage, was billed by the provider for output nobody counted:
	// its cost is unknown, never the input-only (or zero) total.
	cutShort := rec.Outcome == "cancelled" && rec.TTFB > 0 && rec.Usage.Has&HasOutput == 0
	switch {
	case cutShort:
		box.sink.Add(id, f.ChargeKeys, 0, false, rec.EndedAt)
	case usd != nil:
		box.sink.Add(id, f.ChargeKeys, *usd, true, rec.EndedAt)
	case rec.Usage.Has != 0:
		box.sink.Add(id, f.ChargeKeys, 0, false, rec.EndedAt)
	}
}

// newCallID is a random id for one upstream call (the idempotency key of
// its budget charge).
func newCallID() string {
	var b [16]byte
	if _, err := rand.Read(b[:]); err != nil {
		// never an all-zero id, which would make every call a replay
		n := callIDFallback.Add(1)
		for i := 0; i < 8; i++ {
			b[i] = byte(n >> (8 * i))
		}
		b[15] = 0xff
	}
	return hex.EncodeToString(b[:])
}
