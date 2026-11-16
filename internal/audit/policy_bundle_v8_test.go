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
	"bytes"
	"errors"
	"fmt"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

const testPolicyBundleID = "b-01JAZ3Y8Q2K7V4N6M5P0R9S8T7"

func TestLogPolicyBundleReceiptRecordsReceiptAndMetrics(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	err := logger.LogPolicyBundleReceipt("control-plane:acme/alice",
		PolicyBundle{ID: testPolicyBundleID, Version: 5, SignerKeyID: "fleet-2026-10", ChangeSummary: "tighten egress"},
		PolicyBundleReceipt{ReceiptID: testPolicyBundleID, Actor: "os:uid:0:root", State: PolicyBundleFailed, ErrorCode: "not_confirmed",
			EnforcingDigest: "sha256:" + strings.Repeat("a", 64), RolledBack: true, EnforcingVersion: 4,
			WarningCodes: []string{"capability_disabled"}, DisabledByBundle: []string{"sandbox"}}, nil, nil)
	if err != nil {
		t.Fatalf("LogPolicyBundleReceipt: %v", err)
	}
	_, records := runtime.snapshot()
	if len(records) != 1 || records[0].EventName() != observability.EventName(observability.TelemetryEventConfigBundleReceipt) ||
		records[0].Outcome() != observability.OutcomeFailed {
		t.Fatalf("records = %d %v", len(records), records)
	}
	encoded, err := records[0].Bytes()
	if err != nil {
		t.Fatal(err)
	}
	for _, want := range []string{
		`"defenseclaw.policy.bundle.receipt_id":"` + testPolicyBundleID + `"`,
		`"defenseclaw.policy.bundle.state":"failed"`,
		`"defenseclaw.policy.bundle.error_code":"not_confirmed"`,
		`"defenseclaw.policy.bundle.version":5`,
		`"defenseclaw.policy.bundle.signer_key_id":"fleet-2026-10"`,
		`"defenseclaw.policy.bundle.change_summary":"tighten egress"`,
		`"defenseclaw.policy.bundle.rolled_back":true`,
		`"defenseclaw.admin.principal_ref":"control-plane:acme/alice"`,
		`"defenseclaw.admin.actor_ref":"os:uid:0:root"`,
		`capability_disabled`, `sandbox`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("receipt record lacks %s: %s", want, encoded)
		}
	}
	values := map[observability.EventName]string{}
	for _, metric := range runtime.metricSnapshot() {
		values[metric.EventName()] = fmt.Sprint(metricValue(t, metric))
	}
	if values[observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleApplies)] != "1" ||
		values[observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleVersion)] != "4" {
		t.Fatalf("bundle metrics = %v", values)
	}
	if err := logger.LogPolicyBundleReceipt("operator:root",
		PolicyBundle{ID: testPolicyBundleID, Version: 5},
		PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleConfirmed,
			Restart: true, RestartRequired: true, ConfigGeneration: 3, EnforcingVersion: 5}, nil, nil); err != nil {
		t.Fatalf("restart bundle receipt: %v", err)
	}
	_, records = runtime.snapshot()
	if len(records) != 2 || records[1].EventName() != observability.EventName(observability.TelemetryEventConfigBundleReceipt) {
		t.Fatalf("restart receipt produced %d audit records, want one additional config.bundle.receipt", len(records))
	}
	encoded, err = records[1].Bytes()
	if err != nil || !strings.Contains(string(encoded), `"defenseclaw.policy.bundle.restart":true`) ||
		!strings.Contains(string(encoded), `restart_required`) {
		t.Fatalf("restart receipt audit = %s, %v", encoded, err)
	}
	values = map[observability.EventName]string{}
	for _, metric := range runtime.metricSnapshot() {
		values[metric.EventName()] = fmt.Sprint(metricValue(t, metric))
	}
	if values[observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleApplies)] != "1" ||
		values[observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleVersion)] != "5" {
		t.Fatalf("hot bundle metrics = %v", values)
	}
	if err := logger.LogPolicyBundleReceipt("", PolicyBundle{}, PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: "applied"}, nil, nil); err == nil {
		t.Fatal("a receipt that is not terminal was recorded")
	}
}

func TestConfigChangeAppliedCarriesPolicyBundle(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogActivity(ActivityInput{
		Actor: "operator:root", Action: ActionConfigUpdate, TargetType: "config", TargetID: "config.yaml",
		Reason: "policy bundle " + testPolicyBundleID + " version 5: tighten egress",
		After:  map[string]any{"config_generation": 9},
		Bundle: &PolicyBundle{ID: testPolicyBundleID, Version: 5, SignerKeyID: "fleet-2026-10", ChangeSummary: "tighten egress"},
	}); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	_, records := runtime.snapshot()
	if len(records) != 1 || records[0].EventName() != observability.EventName(observability.TelemetryEventConfigChangeApplied) {
		t.Fatalf("records = %d", len(records))
	}
	encoded, _ := records[0].Bytes()
	for _, want := range []string{
		`"defenseclaw.policy.bundle.id":"` + testPolicyBundleID + `"`,
		`"defenseclaw.policy.bundle.change_summary":"tighten egress"`,
		`"defenseclaw.admin.principal_ref":"operator:root"`,
	} {
		if !strings.Contains(string(encoded), want) {
			t.Fatalf("config.change.applied lacks %s: %s", want, encoded)
		}
	}
	if principal, known := controlPlaneV8Principal("control-plane:acme/alice"); !known || !principal.IsPresent() {
		t.Fatal("bundle principal control-plane:<tenant>/<admin> is not a known principal")
	}
}

// GAP-0376: the reporter offers a receipt from the receipt spool until
// every sink has it. While the audit store refuses its row (SQLITE_BUSY
// for three polls) and after a restarted gateway finds the row stored,
// every offer is the same record under one id, the receipt's, so a remote
// destination that got the first offer gets no other record of it, and
// the store keeps one row. Before, each offer was a new record with a new
// id: the collector got the receipt twice under two record ids.
func TestLogPolicyBundleReceiptEveryOfferIsOneRecordUnderOneID(t *testing.T) {
	store := openTestStore(t, filepath.Join(t.TempDir(), "audit.db"))
	emitter := newTestRuntimeV8Emitter(t, store, router.AdmissionOrdinary)
	logger := NewLogger(store)
	logger.SetRuntimeV8Emitter(emitter)
	bundle := PolicyBundle{ID: testPolicyBundleID, Version: 2, SignerKeyID: "fleet-2026-10"}
	receipt := PolicyBundleReceipt{ReceiptID: testPolicyBundleID, Actor: "os:uid:0:root",
		State: PolicyBundleConfirmed, ConfigGeneration: 7, EnforcingVersion: 2,
		FinishedAt: "2026-10-26T20:00:00.123Z"}
	delivery, pins := observability.NewRemoteDelivery(), testConfigChangePins(t)
	emitter.failWrite = errors.New("database is locked (SQLITE_BUSY)")
	for offer := 0; offer < 3; offer++ {
		receipt.FirstOffer = offer == 0
		if err := logger.LogPolicyBundleReceipt("operator:root", bundle, receipt, delivery, pins); err == nil {
			t.Fatalf("offer %d succeeded although the store refused its row", offer)
		}
	}
	emitter.failWrite = nil
	receipt.FirstOffer = false
	if err := logger.LogPolicyBundleReceipt("operator:root", bundle, receipt, delivery, pins); err != nil {
		t.Fatalf("offer after the store recovered: %v", err)
	}
	// A gateway killed after the row committed, before its marker: the
	// restarted reporter has no delivery state and offers it again.
	if err := logger.LogPolicyBundleReceipt("operator:root", bundle, receipt,
		observability.NewRemoteDelivery(), pins); err != nil {
		t.Fatalf("offer after a restart: %v", err)
	}
	built := builtRecords(emitter)
	if len(built) != 5 {
		t.Fatalf("built %d records, want one per offer (5)", len(built))
	}
	want := stableOccurrenceID(string(ActionConfigBundleReceipt), testPolicyBundleID)
	first := recordBytes(t, built[0])
	for i, record := range built {
		if record.RecordID() != want {
			t.Fatalf("offer %d record id = %q, want the receipt's stable id %q", i, record.RecordID(), want)
		}
		if !bytes.Equal(recordBytes(t, record), first) {
			t.Fatalf("offer %d is another record than the first offer", i)
		}
	}
	var rows int
	if err := store.db.QueryRow(`SELECT COUNT(*) FROM audit_events WHERE action = ?`,
		string(ActionConfigBundleReceipt)).Scan(&rows); err != nil || rows != 1 {
		t.Fatalf("stored receipt rows = %d (%v), want 1", rows, err)
	}
	emitter.mu.Lock()
	skipped := append([]bool(nil), emitter.skippedLocalWrite...)
	emitter.mu.Unlock()
	if len(skipped) == 0 || !skipped[len(skipped)-1] {
		t.Fatalf("offers that skipped the local write = %v, want the restarted offer to find the row", skipped)
	}
}
