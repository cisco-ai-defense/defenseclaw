// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"testing"
	"time"
)

type recordingSink struct {
	ids   []string
	usd   []float64
	known []bool
}

func (r *recordingSink) Add(callID string, _ []string, usd float64, known bool, _ time.Time) {
	r.ids, r.usd, r.known = append(r.ids, callID), append(r.usd, usd), append(r.known, known)
}

func TestChargeBudgetsResolvesTheCost(t *testing.T) {
	e := NewEngine()
	sink := &recordingSink{}
	e.SetSpendSink(sink)
	computed, reported := 0.25, 9.0
	keys := []string{"user:d:*:1001"}
	agent := func(id string) CallFacts { return CallFacts{RequestID: id, CallRole: RoleAgent, ChargeKeys: keys} }
	e.chargeBudgets(agent("same"), Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	e.chargeBudgets(agent("same"), Record{Cost: Cost{USD: &reported, Basis: BasisReported, ComputedUSD: &computed}})
	e.chargeBudgets(agent("r3"), Record{Cost: Cost{USD: &reported, Basis: BasisReported}})
	e.chargeBudgets(agent("r4"), Record{Usage: Usage{Input: 10, Has: HasInput}}) // usage nobody can price
	e.chargeBudgets(agent("r5"), Record{Outcome: "failed"})                      // no usage: bills nothing
	e.chargeBudgets(CallFacts{RequestID: "r6", CallRole: "judge", ChargeKeys: keys}, Record{Cost: Cost{USD: &computed}})
	e.chargeBudgets(CallFacts{RequestID: "r7", CallRole: RoleAgent}, Record{Cost: Cost{USD: &computed}})
	if len(sink.ids) != 4 || sink.usd[0] != 0.25 || sink.usd[1] != 0.25 || sink.usd[2] != 9 || sink.known[3] || !sink.known[2] {
		t.Fatalf("computed, else reported; unpriced usage is unknown; no usage, judge and keyless calls skipped: %+v", sink)
	}
	n := len(sink.ids)
	e.chargeBudgets(agent("r8"), Record{Outcome: "cancelled", TTFB: time.Millisecond, Usage: Usage{Input: 10, Has: HasInput}, Cost: Cost{USD: &computed}})
	e.chargeBudgets(agent("r9"), Record{Outcome: "cancelled"}) // cancelled before any answer: nothing billed
	e.chargeBudgets(agent("r10"), Record{Outcome: "failed", ErrorType: "upstream_error", TTFB: time.Millisecond,
		Usage: Usage{Input: 10, Has: HasInput}, Cost: Cost{USD: &computed}})
	if len(sink.ids) != n+2 || sink.known[n] || sink.known[n+1] {
		t.Fatalf("a stream cut short after the answer started is unknown, never its partial cost: %+v", sink)
	}
	if sink.ids[0] == sink.ids[1] || sink.ids[0] == "same" {
		t.Fatal("call ids are minted per call, never the client request id")
	}
}
