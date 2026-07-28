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
	"encoding/json"
	"fmt"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

type testRuntimeV8Emitter struct {
	writer    *EventHistoryWriter
	admission router.Admission
	profile   observabilityredaction.Profile

	mu       sync.Mutex
	metadata []router.Metadata
	records  []observability.Record
	metrics  []observability.Record
}

type rejectingRuntimeV8Emitter struct {
	localPersisted bool
	err            error
	calls          int
}

type metricRejectingRuntimeV8Emitter struct {
	*testRuntimeV8Emitter
	metricCalls int
}

func (emitter *metricRejectingRuntimeV8Emitter) RecordRuntimeV8GeneratedMetricBatch(
	context.Context,
	[]RuntimeV8GeneratedMetric,
) error {
	emitter.metricCalls++
	return fmt.Errorf("generated metric rejected")
}

func (emitter *rejectingRuntimeV8Emitter) EmitRuntimeV8(
	_ context.Context,
	_ router.Metadata,
	_ RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	emitter.calls++
	return RuntimeV8EmitOutcome{
		Admission: router.AdmissionOrdinary, LocalPersisted: emitter.localPersisted,
	}, emitter.err
}

func newTestRuntimeV8Emitter(
	t *testing.T,
	store *Store,
	admission router.Admission,
) *testRuntimeV8Emitter {
	t.Helper()
	profile, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	if !ok {
		t.Fatal("none redaction profile is unavailable")
	}
	writer, err := NewEventHistoryWriter(
		store, nil, nil,
		testLocalProfileResolver{
			profile: observabilityredaction.ProfileNone,
			engine:  testEventHistoryProjectionEngine,
			digest:  testEventHistoryGraphDigest,
		},
	)
	if err != nil {
		t.Fatalf("NewEventHistoryWriter: %v", err)
	}
	return &testRuntimeV8Emitter{writer: writer, admission: admission, profile: profile}
}

func (emitter *testRuntimeV8Emitter) EmitRuntimeV8(
	ctx context.Context,
	metadata router.Metadata,
	builder RuntimeV8Builder,
) (RuntimeV8EmitOutcome, error) {
	if emitter == nil || emitter.writer == nil || builder == nil {
		return RuntimeV8EmitOutcome{}, fmt.Errorf("test runtime emitter is unavailable")
	}
	if emitter.admission == router.AdmissionDrop {
		emitter.mu.Lock()
		emitter.metadata = append(emitter.metadata, metadata)
		emitter.mu.Unlock()
		return RuntimeV8EmitOutcome{Admission: router.AdmissionDrop}, nil
	}
	record, err := builder(RuntimeV8BuildContext{
		ConfigGeneration: 23,
		ConfigDigest:     testEventHistoryGraphDigest,
	}, emitter.admission)
	if err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	projection, _, err := testEventHistoryProjectionEngine.Project(record, emitter.profile)
	if err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	if err := emitter.writer.AppendContext(ctx, record, projection); err != nil {
		return RuntimeV8EmitOutcome{}, err
	}
	emitter.mu.Lock()
	emitter.metadata = append(emitter.metadata, metadata)
	emitter.records = append(emitter.records, record.Clone())
	emitter.mu.Unlock()
	return RuntimeV8EmitOutcome{Admission: emitter.admission, LocalPersisted: true}, nil
}

func (emitter *testRuntimeV8Emitter) EmitRuntimeV8LogBatch(
	ctx context.Context,
	operations []RuntimeV8LogOperation,
) ([]RuntimeV8EmitOutcome, error) {
	if emitter == nil || len(operations) == 0 || len(operations) > 65_536 {
		return nil, fmt.Errorf("test generated log batch is unavailable")
	}
	outcomes := make([]RuntimeV8EmitOutcome, 0, len(operations))
	for index := range operations {
		operation := operations[index]
		outcome, err := emitter.EmitRuntimeV8(
			operation.Context(), operation.Metadata(), operation.Build,
		)
		if err != nil {
			return outcomes, err
		}
		outcomes = append(outcomes, outcome)
	}
	return outcomes, nil
}

func (emitter *testRuntimeV8Emitter) RecordRuntimeV8GeneratedMetricBatch(
	_ context.Context,
	metrics []RuntimeV8GeneratedMetric,
) error {
	if emitter == nil || len(metrics) == 0 || len(metrics) > 65_536 {
		return fmt.Errorf("test generated metric batch is unavailable")
	}
	records := make([]observability.Record, len(metrics))
	for index, metric := range metrics {
		record, err := metric.Build(RuntimeV8BuildContext{
			ConfigGeneration: 23,
			ConfigDigest:     testEventHistoryGraphDigest,
		})
		if err != nil {
			return err
		}
		records[index] = record.Clone()
	}
	emitter.mu.Lock()
	emitter.metrics = append(emitter.metrics, records...)
	emitter.mu.Unlock()
	return nil
}

func (emitter *testRuntimeV8Emitter) snapshot() ([]router.Metadata, []observability.Record) {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	metadata := append([]router.Metadata(nil), emitter.metadata...)
	records := make([]observability.Record, len(emitter.records))
	for index := range emitter.records {
		records[index] = emitter.records[index].Clone()
	}
	return metadata, records
}

func (emitter *testRuntimeV8Emitter) metricSnapshot() []observability.Record {
	emitter.mu.Lock()
	defer emitter.mu.Unlock()
	records := make([]observability.Record, len(emitter.metrics))
	for index := range emitter.metrics {
		records[index] = emitter.metrics[index].Clone()
	}
	return records
}

func TestLogActionControlPlaneV8GeneratedFamiliesPersistOnceAndPreserveV7(t *testing.T) {
	tests := []struct {
		name      string
		action    Action
		eventName observability.EventName
		outcome   observability.Outcome
	}{
		{name: "config manager apply", action: ActionConfigUpdate, eventName: observability.EventName(observability.TelemetryEventConfigChangeApplied), outcome: observability.OutcomeApplied},
		{name: "REST config patch", action: ActionAPIConfigPatch, eventName: observability.EventName(observability.TelemetryEventConfigChangeApplied), outcome: observability.OutcomeApplied},
		{name: "guardrail config reload", action: ActionGuardrailConfigReload, eventName: observability.EventName(observability.TelemetryEventConfigChangeApplied), outcome: observability.OutcomeApplied},
		{name: "policy update", action: ActionPolicyUpdate, eventName: observability.EventName(observability.TelemetryEventPolicyUpdated), outcome: observability.OutcomeApplied},
		{name: "policy reload", action: ActionPolicyReload, eventName: observability.EventName(observability.TelemetryEventPolicyUpdated), outcome: observability.OutcomeApplied},
		{name: "protected boundary auth failure", action: ActionAPIAuthFailure, eventName: observability.EventName(observability.TelemetryEventAuthenticationFailed), outcome: observability.OutcomeRejected},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			env := CorrelationEnvelope{
				RunID: "run-control-plane", TraceID: "trace-control-plane",
				RequestID: "request-control-plane", SessionID: "session-control-plane",
				TurnID: "turn-control-plane", AgentID: "agent-control-plane",
				AgentName: "operator-agent", AgentInstanceID: "agent-instance-control-plane",
				SidecarInstanceID: "sidecar-control-plane", PolicyID: "policy-control-plane",
				Connector: "codex",
			}
			ctx := ContextWithEnvelope(context.Background(), env)
			if err := logger.LogActionCtx(ctx, string(test.action), "control-plane-target", "successful mutation"); err != nil {
				t.Fatalf("LogActionCtx: %v", err)
			}

			rows, err := logger.store.ListEvents(10)
			if err != nil {
				t.Fatalf("ListEvents: %v", err)
			}
			if len(rows) != 1 {
				t.Fatalf("audit_events count = %d, want exactly 1", len(rows))
			}
			metadata, records := runtime.snapshot()
			if len(metadata) != 1 || len(records) != 1 {
				t.Fatalf("runtime counts = metadata:%d records:%d, want 1/1", len(metadata), len(records))
			}

			legacy := rows[0]
			if legacy.Action != string(test.action) || legacy.Actor != "audit_logger" ||
				legacy.Details != string(test.eventName) ||
				legacy.Structured["defenseclaw.admin.target_ref"] != "control-plane-target" {
				t.Fatalf("canonical SQLite projection changed: %#v", legacy)
			}
			if legacy.RunID != env.RunID || legacy.TraceID != env.TraceID || legacy.RequestID != env.RequestID ||
				legacy.SessionID != env.SessionID ||
				legacy.AgentID != env.AgentID || legacy.AgentInstanceID != env.AgentInstanceID ||
				legacy.PolicyID != env.PolicyID || legacy.Connector != env.Connector ||
				legacy.SidecarInstanceID != env.SidecarInstanceID {
				t.Fatalf("legacy correlation changed: %#v", legacy)
			}

			record := records[0]
			if record.RecordID() != legacy.ID || record.EventName() != test.eventName ||
				record.Bucket() != observability.BucketComplianceActivity ||
				record.Signal() != observability.SignalLogs || record.Outcome() != test.outcome ||
				!record.Mandatory() || record.IsFloorOnly() || !record.SchemaDerivedFieldClasses() {
				t.Fatalf("generated record contract = id:%q identity:%#v outcome:%q mandatory:%t floor:%t schema-derived:%t",
					record.RecordID(), record.Identity(), record.Outcome(), record.Mandatory(),
					record.IsFloorOnly(), record.SchemaDerivedFieldClasses())
			}
			if record.Provenance().ConfigDigest != testEventHistoryGraphDigest ||
				record.Provenance().ConfigGeneration != 23 {
				t.Fatalf("record provenance = %#v", record.Provenance())
			}
			if metadata[0].Identity() != record.Identity() || metadata[0].Source() != observability.SourceOperatorAPI {
				t.Fatalf("routing metadata = identity:%#v source:%q", metadata[0].Identity(), metadata[0].Source())
			}
			assertControlPlaneCorrelation(t, record.Correlation(), env)
			body, ok := record.Body()
			if !ok {
				t.Fatal("generated record body is absent")
			}
			bodyObject, err := body.Object()
			if err != nil || bodyObject["defenseclaw.admin.operation"] != string(test.action) {
				t.Fatalf("generated body = %#v err=%v", bodyObject, err)
			}
			if _, present := bodyObject["defenseclaw.admin.principal_ref"]; present {
				t.Fatalf("process actor was fabricated as an authenticated principal: %#v", bodyObject)
			}
			if bodyObject["defenseclaw.admin.actor_ref"] != "defenseclaw" ||
				bodyObject["defenseclaw.admin.origin"] != "api" ||
				bodyObject["defenseclaw.admin.target_ref"] != "control-plane-target" {
				t.Fatalf("generated actor/origin/target evidence = %#v", bodyObject)
			}

			canonical := loadV8HistoryRow(t, logger.store, legacy.ID)
			if canonical.Bucket != string(observability.BucketComplianceActivity) ||
				canonical.EventName != string(test.eventName) || canonical.Mandatory != 1 ||
				canonical.ID != legacy.ID || canonical.Action != legacy.Action ||
				canonical.Target != legacy.Target || canonical.Actor != legacy.Actor ||
				canonical.Details != legacy.Details {
				t.Fatalf("single-row canonical/legacy projection = %#v", canonical)
			}
			var projected map[string]any
			if err := json.Unmarshal([]byte(canonical.ProjectedRecordJSON), &projected); err != nil {
				t.Fatalf("decode projected record: %v", err)
			}
			provenance, ok := projected["provenance"].(map[string]any)
			if !ok || provenance["config_digest"] != testEventHistoryGraphDigest {
				t.Fatalf("persisted canonical provenance = %#v", provenance)
			}
		})
	}
}

func TestLogActionControlPlaneV8MandatoryFloorPersistsExactlyOnce(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionFloor)
	logger.SetRuntimeV8Emitter(runtime)
	const canary = "floor-secret-canary-7f421c"
	event := Event{
		ID: "floor-control-plane-record", Timestamp: time.Now().UTC(),
		Action: string(ActionConfigUpdate), Target: "target-" + canary,
		Actor: "defenseclaw", Details: "details-" + canary, Severity: "INFO",
		RunID: "run-floor", Structured: map[string]any{"secret": canary},
	}
	stampAuditEventEnvelope(&event)
	disposition, err := logger.emitControlPlaneV8(context.Background(), event)
	if err != nil {
		t.Fatalf("emitControlPlaneV8: %v", err)
	}
	if disposition != auditV8Persisted {
		t.Fatal("mandatory floor event was not handled by v8 runtime")
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("floor audit rows = %d err=%v, want exactly 1", len(rows), err)
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 || !records[0].Mandatory() || !records[0].IsFloorOnly() {
		t.Fatalf("floor runtime result = metadata:%d records:%d mandatory:%t floor:%t",
			len(metadata), len(records), records[0].Mandatory(), records[0].IsFloorOnly())
	}
	canonical := loadV8HistoryRow(t, logger.store, rows[0].ID)
	if canonical.Mandatory != 1 || canonical.EventName != observability.TelemetryEventConfigChangeApplied {
		t.Fatalf("floor canonical row = %#v", canonical)
	}
	assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
}

func TestLogActivityControlPlaneV8PersistsOneActivityAndOneCanonicalAuditRow(t *testing.T) {
	const secret = "activity-secret-value-canary"
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogActivity(ActivityInput{
		Actor: "watcher", Action: ActionPolicyReload, TargetType: "policy", TargetID: "default",
		Reason: "filesystem update", RunID: "run-activity", TraceID: "trace-activity",
		Before: map[string]any{"credential": secret, "enabled": false},
		After:  map[string]any{"credential": secret, "enabled": true, "mode": "strict"},
		Diff: []ActivityDiffEntry{
			{Path: "credential", Op: "replace", Before: secret, After: secret},
			{Path: "enabled", Op: "replace", Before: false, After: true},
		},
		VersionFrom: "gen=7", VersionTo: "gen=8",
	}); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	activities, err := logger.store.ListActivityEvents(10)
	if err != nil || len(activities) != 0 {
		t.Fatalf("activity_events count = %d err=%v, want 0 for runtime-owned event", len(activities), err)
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 {
		t.Fatalf("audit_events count = %d err=%v, want exactly 1", len(rows), err)
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 1 || len(records) != 1 || records[0].EventName() != observability.EventName(observability.TelemetryEventPolicyUpdated) {
		t.Fatalf("activity runtime result = metadata:%d records:%d", len(metadata), len(records))
	}
	metrics := runtime.metricSnapshot()
	wantMetricFamilies := []observability.EventName{
		observability.EventName(observability.TelemetryInstrumentDefenseClawAuditEventsTotal),
		observability.EventName(observability.TelemetryInstrumentDefenseClawActivityTotal),
		observability.EventName(observability.TelemetryInstrumentDefenseClawActivityDiffEntries),
	}
	if len(metrics) != len(wantMetricFamilies) {
		t.Fatalf("activity generated metrics = %d, want %d", len(metrics), len(wantMetricFamilies))
	}
	for index, wantFamily := range wantMetricFamilies {
		if metrics[index].EventName() != wantFamily {
			t.Fatalf("activity metric[%d] = %q, want %q", index, metrics[index].EventName(), wantFamily)
		}
	}
	if fmt.Sprint(metricValue(t, metrics[0])) != "1" ||
		fmt.Sprint(metricValue(t, metrics[1])) != "1" ||
		fmt.Sprint(metricValue(t, metrics[2])) != "2" {
		t.Fatalf("activity metric values = %v/%v/%v", metricValue(t, metrics[0]), metricValue(t, metrics[1]), metricValue(t, metrics[2]))
	}
	if metadata[0].Source() != observability.SourceWatcher || rows[0].Actor != "audit_logger" ||
		rows[0].Structured["defenseclaw.admin.target_ref"] != "policy:default" {
		t.Fatalf("activity canonical/source = source:%q row:%#v", metadata[0].Source(), rows[0])
	}
	body, ok := records[0].Body()
	if !ok {
		t.Fatal("activity canonical body is absent")
	}
	bodyObject, bodyErr := body.Object()
	if bodyErr != nil {
		t.Fatalf("activity canonical body: %v", bodyErr)
	}
	if _, present := bodyObject["defenseclaw.admin.principal_ref"]; present {
		t.Fatalf("trusted watcher subsystem was fabricated as an authenticated principal: %#v", bodyObject)
	}
	want := map[string]any{
		"defenseclaw.admin.actor_ref":        "watcher",
		"defenseclaw.admin.origin":           "config_file",
		"defenseclaw.admin.target_ref":       "policy:default",
		"defenseclaw.admin.before_summary":   "object_fields=2",
		"defenseclaw.admin.after_summary":    "object_fields=3",
		"defenseclaw.admin.reason_detail":    "filesystem update",
		"defenseclaw.admin.current_revision": "generation:7",
		"defenseclaw.admin.revision":         "generation:8",
	}
	for key, expected := range want {
		if bodyObject[key] != expected {
			t.Fatalf("activity %s=%#v want %#v; body=%#v", key, bodyObject[key], expected, bodyObject)
		}
	}
	if fmt.Sprint(bodyObject["defenseclaw.admin.change_count"]) != "2" {
		t.Fatalf("activity change count=%#v want 2", bodyObject["defenseclaw.admin.change_count"])
	}
	if _, present := bodyObject["defenseclaw.admin.reason"]; present {
		t.Fatalf("free-form activity reason entered registered reason-code field: %#v", bodyObject)
	}
	encoded, encodeErr := records[0].Bytes()
	if encodeErr != nil || !strings.Contains(string(encoded), secret) || !strings.Contains(string(encoded), "credential") {
		t.Fatalf("default-unredacted activity evidence lost source config data: err=%v record=%s", encodeErr, encoded)
	}
}

func TestControlPlaneV8GeneratedAuditMetricDoesNotCallLegacyTelemetryProvider(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)

	if err := logger.LogActionSeverityConnector(
		string(ActionPolicyReload), "policy", "changed", "", "codex",
	); err != nil {
		t.Fatal(err)
	}
	metrics := runtime.metricSnapshot()
	if len(metrics) != 1 ||
		metrics[0].EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawAuditEventsTotal) ||
		fmt.Sprint(metricValue(t, metrics[0])) != "1" {
		t.Fatalf("generated audit metrics = %#v", metrics)
	}
	instrument, present := metrics[0].InstrumentData()
	if !present {
		t.Fatal("generated audit metric instrument is absent")
	}
	data, err := instrument.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, ok := data["attributes"].(map[string]any)
	if !ok || attributes["defenseclaw.metric.action"] != string(ActionPolicyReload) ||
		attributes["defenseclaw.connector.source"] != "codex" ||
		attributes["defenseclaw.security.severity"] != "INFO" {
		t.Fatalf("generated audit metric attributes = %#v", data["attributes"])
	}
}

func TestControlPlaneV8DetachIsStickyAndNeverResurrectsLegacy(t *testing.T) {
	logger := newTestLogger(t)
	logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary))
	logger.SetRuntimeV8Emitter(nil)
	if err := logger.LogAction(string(ActionPolicyReload), "policy", "changed"); err == nil {
		t.Fatal("detached authoritative v8 control-plane occurrence succeeded")
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 0 {
		t.Fatalf("detached authoritative rows = %#v err=%v", rows, err)
	}
}

func TestControlPlaneV8MetricFailureKeepsPersistedOccurrenceAndNoLegacyFallback(t *testing.T) {
	logger := newTestLogger(t)
	runtime := &metricRejectingRuntimeV8Emitter{
		testRuntimeV8Emitter: newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary),
	}
	logger.SetRuntimeV8Emitter(runtime)

	if err := logger.LogAction(string(ActionPolicyReload), "policy", "changed"); err != nil {
		t.Fatalf("persisted control-plane event failed with independent metric: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 1 || runtime.metricCalls != 1 {
		t.Fatalf("persisted rows=%d metric calls=%d err=%v", len(rows), runtime.metricCalls, err)
	}
}

func TestControlPlaneV8PrincipalIncludesOnlySchemaSafeKnownActor(t *testing.T) {
	if principal, known := controlPlaneV8Principal("cli:alice"); !known {
		t.Fatal("schema-safe actor was not marked known")
	} else if value, present := principal.Get(); !present || value != "cli:alice" {
		t.Fatalf("principal = (%q, %t), want (cli:alice, true)", value, present)
	}
	for _, actor := range []string{"", "watcher", "defenseclaw", "Alice Example", strings.Repeat("a", 257)} {
		if principal, known := controlPlaneV8Principal(actor); known || principal.IsPresent() {
			t.Fatalf("unsafe actor %q produced a principal", actor)
		}
	}
}

func TestControlPlaneV8ActivityEvidenceSeparatesSummariesFromCentrallyRedactableSourceFacts(t *testing.T) {
	evidence, err := controlPlaneV8ActivityEvidence(ActivityInput{
		Actor: "cli:alice", TargetType: "config", TargetID: "observability",
		Reason: "operator_request", Before: map[string]any{}, After: map[string]any{"secret": "never-copy"},
		Diff:        []ActivityDiffEntry{{Path: "secret", Op: "add", After: "never-copy"}},
		VersionFrom: "revision:41", VersionTo: "revision:42",
	})
	if err != nil {
		t.Fatal(err)
	}
	for name, value := range map[string]observability.Optional[string]{
		"actor": evidence.actorRef, "target": evidence.targetRef, "reason": evidence.reason,
		"before": evidence.beforeSummary, "after": evidence.afterSummary,
		"before state": evidence.beforeState, "after state": evidence.afterState,
		"diff": evidence.diff, "reason detail": evidence.reasonDetail,
		"revision": evidence.revision, "current revision": evidence.currentRevision,
	} {
		if _, present := value.Get(); !present {
			t.Fatalf("safe activity %s was absent", name)
		}
	}
	if value, _ := evidence.reason.Get(); value != "operator_request" {
		t.Fatalf("reason=%q want operator_request", value)
	}
	if value, _ := evidence.beforeSummary.Get(); value != "object_fields=0" {
		t.Fatalf("before summary=%q", value)
	}
	if value, _ := evidence.afterSummary.Get(); value != "object_fields=1" || strings.Contains(value, "secret") {
		t.Fatalf("after summary=%q", value)
	}
	if value, _ := evidence.afterState.Get(); value != `{"secret":"never-copy"}` {
		t.Fatalf("after state=%q", value)
	}
	if value, _ := evidence.diff.Get(); value != `[{"path":"secret","op":"add","after":"never-copy"}]` {
		t.Fatalf("diff=%q", value)
	}
	if count, present := evidence.changeCount.Get(); !present || count != 1 {
		t.Fatalf("change count=(%d,%t)", count, present)
	}
	unsafe, err := controlPlaneV8ActivityEvidence(ActivityInput{
		Actor: "Alice Example", TargetType: "config", TargetID: "contains space",
		Reason: "free-form reason", VersionTo: "not a revision",
	})
	if err != nil {
		t.Fatal(err)
	}
	if unsafe.actorRef.IsPresent() || unsafe.targetRef.IsPresent() || unsafe.reason.IsPresent() ||
		unsafe.revision.IsPresent() {
		t.Fatalf("unsafe activity evidence was admitted: %#v", unsafe)
	}
	if detail, present := unsafe.reasonDetail.Get(); !present || detail != "free-form reason" {
		t.Fatalf("free-form source reason detail=(%q,%t)", detail, present)
	}
}

func TestControlPlaneV8SelectedUnboundFailsAndCompatibilityActionUsesRuntime(t *testing.T) {
	t.Run("selected action without runtime fails closed", func(t *testing.T) {
		logger := newTestLogger(t)
		if err := logger.LogAction(string(ActionConfigUpdate), "config.yaml", "changed"); err == nil {
			t.Fatal("selected control-plane action used an unbound fallback")
		}
		rows, err := logger.store.ListEvents(10)
		if err != nil || len(rows) != 0 {
			t.Fatalf("unbound rows = %d err=%v", len(rows), err)
		}
	})
	t.Run("compatibility action with runtime", func(t *testing.T) {
		logger := newTestLogger(t)
		runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
		logger.SetRuntimeV8Emitter(runtime)
		if err := logger.LogAction(string(ActionInstallClean), "asset", "clean"); err != nil {
			t.Fatal(err)
		}
		rows, err := logger.store.ListEvents(10)
		metadata, records := runtime.snapshot()
		if err != nil || len(rows) != 1 || len(metadata) != 1 || len(records) != 1 {
			t.Fatalf("compatibility counts = rows:%d metadata:%d records:%d err=%v", len(rows), len(metadata), len(records), err)
		}
		if records[0].EventName() != "legacy.audit.install.clean" ||
			records[0].Bucket() != observability.BucketAssetScan ||
			metadata[0].Identity() != records[0].Identity() {
			t.Fatalf("compatibility identity metadata=%#v record=%#v", metadata[0].Identity(), records[0].Identity())
		}
	})
}

func TestControlPlaneV8FailureNeverFallsBackToDuplicateLegacyPersistence(t *testing.T) {
	for _, test := range []struct {
		name    string
		emitter *rejectingRuntimeV8Emitter
	}{
		{name: "runtime error", emitter: &rejectingRuntimeV8Emitter{err: fmt.Errorf("runtime rejected")}},
		{name: "local not persisted", emitter: &rejectingRuntimeV8Emitter{}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			logger.SetRuntimeV8Emitter(test.emitter)
			if err := logger.LogAction(string(ActionConfigUpdate), "config.yaml", "changed"); err == nil {
				t.Fatal("LogAction succeeded after canonical runtime failure")
			}
			rows, listErr := logger.store.ListEvents(10)
			if listErr != nil || len(rows) != 0 {
				t.Fatalf("runtime failure wrote rows=%d err=%v", len(rows), listErr)
			}
		})
	}
}

func assertControlPlaneCorrelation(t *testing.T, got observability.Correlation, want CorrelationEnvelope) {
	t.Helper()
	if got.RunID != want.RunID || got.TraceID != want.TraceID || got.RequestID != want.RequestID ||
		got.SessionID != want.SessionID || got.TurnID != want.TurnID || got.AgentID != want.AgentID ||
		got.AgentInstanceID != want.AgentInstanceID || got.PolicyID != want.PolicyID ||
		got.ConnectorID != want.Connector || got.SidecarInstanceID != want.SidecarInstanceID {
		t.Fatalf("canonical correlation = %#v, want envelope %#v", got, want)
	}
}

func assertAuditEventRowExcludesCanary(t *testing.T, store *Store, recordID, canary string) {
	t.Helper()
	rows, err := store.db.Query(`SELECT * FROM audit_events WHERE id = ?`, recordID)
	if err != nil {
		t.Fatalf("query floor row: %v", err)
	}
	defer rows.Close()
	columns, err := rows.Columns()
	if err != nil {
		t.Fatalf("floor row columns: %v", err)
	}
	if !rows.Next() {
		t.Fatal("floor row is absent")
	}
	values := make([]any, len(columns))
	destinations := make([]any, len(columns))
	for index := range values {
		destinations[index] = &values[index]
	}
	if err := rows.Scan(destinations...); err != nil {
		t.Fatalf("scan floor row: %v", err)
	}
	for index, value := range values {
		var text string
		switch typed := value.(type) {
		case string:
			text = typed
		case []byte:
			text = string(typed)
		default:
			continue
		}
		if strings.Contains(text, canary) {
			t.Fatalf("mandatory floor leaked canary through audit_events.%s", columns[index])
		}
	}
	if rows.Next() {
		t.Fatal("mandatory floor record id produced more than one row")
	}
	if err := rows.Err(); err != nil {
		t.Fatalf("iterate floor rows: %v", err)
	}
}
