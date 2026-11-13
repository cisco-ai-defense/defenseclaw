// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import "time"

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

// chargeBudgets charges a finished call to its budget keys with the
// resolved cost: computed, else reported (lead ruling 2026-11-12T23:38Z).
// An unknown cost is passed as unknown, never as 0.
func (e *Engine) chargeBudgets(f CallFacts, rec Record) {
	if e == nil || len(f.ChargeKeys) == 0 {
		return
	}
	box := e.budgetSink.Load()
	if box == nil || box.sink == nil {
		return
	}
	usd := rec.Cost.ComputedUSD
	if usd == nil {
		usd = rec.Cost.USD
	}
	if usd == nil {
		box.sink.Add(f.RequestID, f.ChargeKeys, 0, false, rec.EndedAt)
		return
	}
	box.sink.Add(f.RequestID, f.ChargeKeys, *usd, true, rec.EndedAt)
}
