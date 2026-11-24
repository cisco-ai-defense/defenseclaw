// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package routingadmin

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func batchCall(ns, uid, batch, person string) Request {
	r := actorCall(ns, uid, true)
	r.Actor.BatchID = batch
	r.Caller.Key = person
	return r
}

func batchKey(id, ns, person, batch string) string {
	return "batch:" + id + ":" + shortHash(ns+"/"+person) + ":" + shortHash(batch)
}

var batchBudgets = []config.RoutingBudget{{ID: "nightly", Scope: "batch", Subject: "*", Period: "day", LimitUSD: 10, OnExceed: "deny"}}

// TestBatchBudgetKeyScopedByPerson: one limit per batch of one person in one
// atespace; two people (or atespaces) using one batch id never share it.
func TestBatchBudgetKeyScopedByPerson(t *testing.T) {
	p := Compile(nil, batchBudgets, false)
	l := seededLedger(p.BudgetIDs()...)
	l.Charge([]string{batchKey("nightly", "eng-web", testPersonKey, "run-7")}, 10, now)
	if v := p.Evaluate(batchCall("eng-web", "a1", "run-7", testPersonKey), l, now); denyCode(v) != "budget_exceeded:nightly" {
		t.Fatalf("the exhausted batch: %+v", v)
	}
	// Another actor of the same batch shares the counter.
	if v := p.Evaluate(batchCall("eng-web", "a2", "run-7", testPersonKey), l, now); denyCode(v) != "budget_exceeded:nightly" {
		t.Fatalf("a second actor in the batch: %+v", v)
	}
	for name, r := range map[string]Request{
		"other person":   batchCall("eng-web", "a1", "run-7", "p:ffffffffffffffff"),
		"other atespace": batchCall("ops", "a1", "run-7", testPersonKey),
		"other batch":    batchCall("eng-web", "a1", "run-8", testPersonKey),
	} {
		if v := p.Evaluate(r, l, now); v.Deny != nil {
			t.Errorf("%s shares the batch counter: %+v", name, v)
		}
	}
}

// TestBatchBudgetNeedsBatchID: a call that is not in a batch is not charged
// to a batch budget and a laptop call never matches it.
func TestBatchBudgetNeedsBatchID(t *testing.T) {
	p := Compile(nil, batchBudgets, false)
	l := seededLedger(p.BudgetIDs()...)
	if v := p.Evaluate(actorCall("eng-web", "a1", true), l, now); v.Deny != nil || len(v.Warnings) != 0 {
		t.Fatalf("a non-batch actor call: %+v", v)
	}
	if v := p.Evaluate(ossHost(), l, now); v.Deny != nil {
		t.Fatalf("a laptop call: %+v", v)
	}
}

// TestBatchBudgetUnknownSpend: unseeded spend warns on an OSS cluster and
// denies on a managed one, as for actor budgets (D4-2).
func TestBatchBudgetUnknownSpend(t *testing.T) {
	r := batchCall("eng-web", "a1", "run-7", testPersonKey)
	if v := Compile(nil, batchBudgets, false).Evaluate(r, testLedger(), now); v.Deny != nil || !slices.Contains(v.Warnings, "budget_spend_unknown:nightly") {
		t.Fatalf("OSS: %+v", v)
	}
	if v := Compile(nil, batchBudgets, true).Evaluate(r, testLedger(), now); denyCode(v) != "budget_unavailable:nightly" {
		t.Fatalf("managed: %+v", v)
	}
}

// TestBatchBudgetAndActorBoth: a call in a batch is charged to both a batch
// and an actor budget, and the actor limit still applies.
func TestBatchBudgetAndActorBoth(t *testing.T) {
	budgets := append([]config.RoutingBudget{{ID: "act", Scope: "actor", Subject: "*", Period: "day", LimitUSD: 5, OnExceed: "deny"}}, batchBudgets...)
	p := Compile(nil, budgets, false)
	r := batchCall("eng-web", "a1", "run-7", testPersonKey)
	l := seededLedger(p.BudgetIDs()...)
	l.Charge([]string{"actor:act:" + shortHash(r.Actor.Key)}, 5, now)
	if v := p.Evaluate(r, l, now); denyCode(v) != "budget_exceeded:act" {
		t.Fatalf("actor limit: %+v", v)
	}
	l = seededLedger(p.BudgetIDs()...)
	l.Charge([]string{batchKey("nightly", "eng-web", testPersonKey, "run-7")}, 10, now)
	if v := p.Evaluate(r, l, now); denyCode(v) != "budget_exceeded:nightly" {
		t.Fatalf("batch limit: %+v", v)
	}
}
