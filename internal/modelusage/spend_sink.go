// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import "time"

// SpendSink receives the computed cost of an agent call against the
// routing.admin budget keys the routing verdict gave it (CallFacts.ChargeKeys).
// The gateway wires the routing admin runtime in; it must not block.
type SpendSink interface {
	Charge(keys []string, usd float64, at time.Time)
}

type spendSinkBox struct{ sink SpendSink }

// SetSpendSink installs the budget sink (nil removes it).
func (e *Engine) SetSpendSink(sink SpendSink) {
	if e == nil {
		return
	}
	e.budgetSink.Store(&spendSinkBox{sink: sink})
}

// chargeBudgets counts a finished call against its budget keys: agent calls
// only (judge, decision model and AI Defense calls are DefenseClaw's own),
// and only the computed cost (a reported cost comes from the agent, which
// the user controls). An unknown cost charges nothing.
func (e *Engine) chargeBudgets(f CallFacts, rec Record) {
	if e == nil || len(f.ChargeKeys) == 0 || f.CallRole != RoleAgent {
		return
	}
	box := e.budgetSink.Load()
	if box == nil || box.sink == nil {
		return
	}
	usd := rec.Cost.ComputedUSD
	if usd == nil && rec.Cost.Basis == BasisComputed {
		usd = rec.Cost.USD
	}
	if usd == nil {
		return
	}
	box.sink.Charge(f.ChargeKeys, *usd, rec.EndedAt)
}
