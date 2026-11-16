// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

// GAP-0452: the gateway's receipt reporter writes a receipt's reported
// marker once LogPolicyBundleReceipt returns nil and every remote
// destination acknowledged the offer. So a spooled receipt (record pins
// and a FinishedAt) may return nil only once its local row is past the
// power-loss barrier, its offer carries the delivery tracker the reporter
// waits on, and an offer made again after a crash keeps one local row.

type receiptDeliveryEmitter struct {
	*testRuntimeV8Emitter
	sawDelivery []bool
}

func (e *receiptDeliveryEmitter) EmitRuntimeV8(
	ctx context.Context, m router.Metadata, b RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	e.sawDelivery = append(e.sawDelivery, observability.RemoteDeliveryFrom(ctx) != nil)
	return e.testRuntimeV8Emitter.EmitRuntimeV8(ctx, m, b)
}

func spooledTestReceipt() (PolicyBundle, PolicyBundleReceipt) {
	return PolicyBundle{ID: testPolicyBundleID, Version: 5},
		PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed,
			FinishedAt: "2026-10-27T04:00:00.5Z", FirstOffer: true}
}

func TestSpooledBundleReceiptIsNotConfirmedWithoutThePowerLossBarrier(t *testing.T) {
	l := newTestLogger(t)
	l.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary))
	// The synchronous=FULL connection cannot flush: the barrier fails.
	db, err := openSQLiteWithPragmas(l.store.dbPath, auditDurablePragmas)
	if err != nil {
		t.Fatal(err)
	}
	_ = db.Close()
	l.store.checkpointMu.Lock()
	l.store.durableDB = db
	l.store.checkpointMu.Unlock()
	if err := l.store.SyncCommittedWrites(t.Context()); err == nil {
		t.Fatal("fault not in place: the barrier still succeeds")
	}
	bundle, receipt := spooledTestReceipt()
	if err := l.LogPolicyBundleReceipt("operator:root", bundle, receipt,
		observability.NewRemoteDelivery(), testConfigChangePins(t)); err == nil {
		t.Fatal("a spooled receipt was confirmed without the power-loss barrier; its marker would suppress the replay")
	}
}

func TestSpooledBundleReceiptOfferCarriesTheReportersDeliveryTracker(t *testing.T) {
	l := newTestLogger(t)
	e := &receiptDeliveryEmitter{testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary)}
	l.SetRuntimeV8Emitter(e)
	bundle, receipt := spooledTestReceipt()
	delivery := observability.NewRemoteDelivery()
	if err := l.LogPolicyBundleReceipt("operator:root", bundle, receipt, delivery, testConfigChangePins(t)); err != nil {
		t.Fatal(err)
	}
	if len(e.sawDelivery) == 0 || !e.sawDelivery[0] {
		t.Fatalf("the receipt offer carried no remote delivery tracker (%v): it would be retired after an async enqueue", e.sawDelivery)
	}
}

func TestSpooledBundleReceiptOfferedAgainAfterACrashKeepsOneLocalRow(t *testing.T) {
	l := newTestLogger(t)
	l.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, l.store, router.AdmissionOrdinary))
	bundle, receipt := spooledTestReceipt()
	pins := testConfigChangePins(t)
	for offer := 0; offer < 2; offer++ {
		receipt.FirstOffer = offer == 0
		// A restarted reporter has no delivery state: a new tracker each time.
		if err := l.LogPolicyBundleReceipt("operator:root", bundle, receipt, observability.NewRemoteDelivery(), pins); err != nil {
			t.Fatalf("offer %d: %v", offer, err)
		}
	}
	var rows int
	if err := l.store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = ?`,
		string(ActionConfigBundleReceipt)).Scan(&rows); err != nil {
		t.Fatal(err)
	}
	if rows != 1 {
		t.Fatalf("a receipt offered again left %d local rows, want 1", rows)
	}
}
