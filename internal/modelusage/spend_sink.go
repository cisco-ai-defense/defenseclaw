// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"crypto/rand"
	"encoding/hex"
	"time"
)

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
	switch {
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
	_, _ = rand.Read(b[:])
	return hex.EncodeToString(b[:])
}
