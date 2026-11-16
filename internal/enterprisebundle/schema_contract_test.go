// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// SPDX-License-Identifier: Apache-2.0

package enterprisebundle

import (
	"os"
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/contracttest"
)

// `enterprise bundle status --json` prints the state's current and last_good
// (Ref) and the newest receipt (Receipt) unchanged, so the closed
// bundle-status.schema.json must describe every member they can carry: a
// field added here without the schema fails status only on the path that
// sets it (GAP-0001: the confirmed delivery_id).
func TestBundleStatusSchemaDescribesStoreMembers(t *testing.T) {
	contracttest.RequireMembers(t, "bundle-status.schema.json#/$defs/ref", reflect.TypeOf(Ref{}))
	contracttest.RequireMembers(t, "bundle-status.schema.json#/$defs/receipt", reflect.TypeOf(Receipt{}))
	contracttest.RequireMembers(t, "bundle-status.schema.json#/$defs/receipt/properties/transitions/items", reflect.TypeOf(Transition{}))
}

// Two bundles confirmed with --delivery-id: the state records of current and
// last_good and the receipts validate as status prints them, and the bundle
// block keeps the delivery id once the receipts were pruned (it then comes
// from the state alone).
func TestBundleStateWithDeliveryIDMatchesTheContract(t *testing.T) {
	schemas := contracttest.Compile(t)
	s := testStore(t)
	deliveries := []string{"agent-7:d.1", "agent-7:d.2"}
	var receipts []*Receipt
	for n, delivery := range deliveries {
		r := applyThrough(t, s, n+1, uint64(n+1), StateApplied)
		r.DeliveryID, r.RestartRequired = delivery, true
		if _, err := s.Confirm(r); err != nil {
			t.Fatal(err)
		}
		schemas.ValidateValue(t, "bundle-status.schema.json#/$defs/receipt", r)
		receipts = append(receipts, r)
	}
	st, err := s.LoadState()
	if err != nil {
		t.Fatal(err)
	}
	if st.Current == nil || st.Current.DeliveryID != deliveries[1] || st.LastGood == nil || st.LastGood.DeliveryID != deliveries[0] {
		t.Fatalf("state current %+v, last_good %+v; want delivery ids %v", st.Current, st.LastGood, deliveries)
	}
	for _, ref := range []*Ref{st.Current, st.LastGood} {
		schemas.ValidateValue(t, "bundle-status.schema.json#/$defs/ref", ref)
	}

	for _, r := range receipts {
		if err := os.Remove(s.receiptPath(r.ReceiptID)); err != nil {
			t.Fatal(err)
		}
	}
	summary, err := s.CurrentSummary()
	if err != nil || summary == nil || summary.DeliveryID != deliveries[1] {
		t.Fatalf("summary after prune %+v, %v; want delivery id %s", summary, err, deliveries[1])
	}
	schemas.ValidateValue(t, "lifecycle-result.schema.json#/$defs/bundleState", summary)
}
