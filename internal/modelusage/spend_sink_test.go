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
	e.chargeBudgets(CallFacts{RequestID: "r1", ChargeKeys: keys}, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	e.chargeBudgets(CallFacts{RequestID: "r2", ChargeKeys: keys}, Record{Cost: Cost{USD: &reported, Basis: BasisReported, ComputedUSD: &computed}})
	e.chargeBudgets(CallFacts{RequestID: "r3", ChargeKeys: keys}, Record{Cost: Cost{USD: &reported, Basis: BasisReported}})
	e.chargeBudgets(CallFacts{RequestID: "r4", ChargeKeys: keys}, Record{})
	e.chargeBudgets(CallFacts{RequestID: "r5"}, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	if len(sink.ids) != 4 || sink.usd[0] != 0.25 || sink.usd[1] != 0.25 || sink.usd[2] != 9 || sink.known[3] || !sink.known[2] {
		t.Fatalf("computed, else reported, unknown passed as unknown, keyless calls skipped: %+v", sink)
	}
}
