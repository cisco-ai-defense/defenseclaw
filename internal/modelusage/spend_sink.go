// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import "time"

// SpendSink receives the resolved cost of an agent call against the
// routing.admin budget keys the routing verdict gave it (CallFacts.ChargeKeys).
// It is the only way spend leaves this package: routingadmin.SpendCounter is
// the one spend truth that budgets read and that a leader or fleet store
// fills, and the gateway wires its runtime in as the sink. modelusage keeps
// no spend ledger of its own, and imports nothing from routingadmin (the
// sink interface is the whole seam, so there is no import cycle). The sink
// must not block.
type SpendSink interface {
	Charge(keys []string, usd float64, at time.Time)
}

// IdempotentSpendSink is a SpendSink that wants the call id, so a re-delivered
// record is counted once. When a sink implements it, ChargeCall is used and
// Charge is not.
type IdempotentSpendSink interface {
	ChargeCall(id string, keys []string, usd float64, at time.Time)
}

type spendSinkBox struct{ sink SpendSink }

// SetSpendSink installs the budget sink (nil removes it).
func (e *Engine) SetSpendSink(sink SpendSink) {
	if e == nil {
		return
	}
	e.budgetSink.Store(&spendSinkBox{sink: sink})
}

// ChargedUSD is the cost a record charges to a budget: the computed cost,
// else the reported one (the one Resolve rule), and nothing when the cost is
// unknown. Unknown is never 0: the budget treats it as unknown and its fail
// mode decides.
func ChargedUSD(c Cost) (float64, bool) {
	switch {
	case c.ComputedUSD != nil:
		return *c.ComputedUSD, true
	case c.Basis == BasisComputed && c.USD != nil:
		return *c.USD, true
	case c.ReportedUSD != nil:
		return *c.ReportedUSD, true
	case c.Basis == BasisReported && c.USD != nil:
		return *c.USD, true
	}
	return 0, false
}

// chargeBudgets counts a finished call against its budget keys: agent calls
// only (judge, decision model and AI Defense calls are DefenseClaw own).
func (e *Engine) chargeBudgets(f CallFacts, rec Record) {
	if e == nil || len(f.ChargeKeys) == 0 || f.CallRole != RoleAgent {
		return
	}
	box := e.budgetSink.Load()
	if box == nil || box.sink == nil {
		return
	}
	usd, ok := ChargedUSD(rec.Cost)
	if !ok {
		return
	}
	if s, ok := box.sink.(IdempotentSpendSink); ok {
		s.ChargeCall(f.RequestID, f.ChargeKeys, usd, rec.EndedAt)
		return
	}
	box.sink.Charge(f.ChargeKeys, usd, rec.EndedAt)
}
