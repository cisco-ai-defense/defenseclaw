// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package modelusage

import (
	"testing"
	"time"
)

type recordingSink struct {
	keys []string
	usd  float64
	n    int
}

func (r *recordingSink) Charge(keys []string, usd float64, _ time.Time) {
	r.keys, r.usd, r.n = keys, usd, r.n+1
}

func TestChargeBudgetsComputedAgentCostOnly(t *testing.T) {
	e := NewEngine()
	sink := &recordingSink{}
	e.SetSpendSink(sink)
	computed, reported := 0.25, 9.0
	keys := []string{"user:d:*:1001"}
	e.chargeBudgets(CallFacts{CallRole: RoleAgent, ChargeKeys: keys}, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	if sink.n != 1 || sink.usd != 0.25 || sink.keys[0] != keys[0] {
		t.Fatalf("computed agent cost: %+v", sink)
	}
	e.chargeBudgets(CallFacts{CallRole: RoleAgent, ChargeKeys: keys}, Record{Cost: Cost{USD: &reported, Basis: BasisReported, ComputedUSD: &computed}})
	if sink.n != 2 || sink.usd != 0.25 {
		t.Fatalf("a reported cost charges the computed one: %+v", sink)
	}
	e.chargeBudgets(CallFacts{CallRole: RoleAgent, ChargeKeys: keys}, Record{Cost: Cost{USD: &reported, Basis: BasisReported}})
	e.chargeBudgets(CallFacts{CallRole: RoleAgent, ChargeKeys: keys}, Record{})
	e.chargeBudgets(CallFacts{CallRole: "judge", ChargeKeys: keys}, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	e.chargeBudgets(CallFacts{CallRole: RoleAgent}, Record{Cost: Cost{USD: &computed, Basis: BasisComputed}})
	if sink.n != 2 {
		t.Fatalf("reported-only, unknown, judge and keyless calls charge nothing: %+v", sink)
	}
}
