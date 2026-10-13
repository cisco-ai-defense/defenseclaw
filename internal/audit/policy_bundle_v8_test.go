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
	"fmt"
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
		PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: PolicyBundleFailed, ErrorCode: "not_confirmed",
			EnforcingDigest: "sha256:" + strings.Repeat("a", 64), RolledBack: true, EnforcingVersion: 4,
			WarningCodes: []string{"capability_disabled"}, DisabledByBundle: []string{"sandbox"}})
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
			Restart: false, ConfigGeneration: 3, EnforcingVersion: 5}); err != nil {
		t.Fatalf("hot bundle receipt: %v", err)
	}
	_, records = runtime.snapshot()
	if len(records) != 2 || records[1].EventName() != observability.EventName(observability.TelemetryEventConfigBundleReceipt) {
		t.Fatalf("hot receipt produced %d audit records, want one additional config.bundle.receipt", len(records))
	}
	values = map[observability.EventName]string{}
	for _, metric := range runtime.metricSnapshot() {
		values[metric.EventName()] = fmt.Sprint(metricValue(t, metric))
	}
	if values[observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleApplies)] != "1" ||
		values[observability.EventName(observability.TelemetryInstrumentDefenseClawPolicyBundleVersion)] != "5" {
		t.Fatalf("hot bundle metrics = %v", values)
	}
	if err := logger.LogPolicyBundleReceipt("", PolicyBundle{}, PolicyBundleReceipt{ReceiptID: testPolicyBundleID, State: "applied"}); err == nil {
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
