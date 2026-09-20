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
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestApprovalResolutionGeneratedMappingsPersistExactlyOnce(t *testing.T) {
	for _, test := range []struct {
		name    string
		action  Action
		result  string
		outcome observability.Outcome
	}{
		{name: "gateway grant", action: ActionGatewayApprovalGranted, result: "approved", outcome: observability.OutcomeApproved},
		{name: "gateway denial", action: ActionGatewayApprovalDenied, result: "denied", outcome: observability.OutcomeDenied},
		{name: "generic grant", action: ActionApprovalGranted, result: "approved", outcome: observability.OutcomeApproved},
		{name: "generic denial", action: ActionApprovalDenied, result: "denied", outcome: observability.OutcomeDenied},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			env := securityActionTestEnvelope()
			if err := logger.LogActionCtx(
				ContextWithEnvelope(context.Background(), env), string(test.action),
				"approval-42", "reason=resolved",
			); err != nil {
				t.Fatalf("LogActionCtx: %v", err)
			}
			rows, err := logger.store.ListEvents(10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("audit rows = %d err=%v, want exactly 1", len(rows), err)
			}
			metadata, records := runtime.snapshot()
			if len(metadata) != 1 || len(records) != 1 {
				t.Fatalf("runtime counts = metadata:%d records:%d", len(metadata), len(records))
			}
			record := records[0]
			assertSecurityActionIdentity(t, record, rows[0], observability.BucketComplianceActivity,
				observability.EventName(observability.TelemetryEventApprovalResolved), test.outcome, true)
			if metadata[0].Source() != observability.SourceGateway || metadata[0].Identity() != record.Identity() {
				t.Fatalf("approval routing metadata = source:%q identity:%#v", metadata[0].Source(), metadata[0].Identity())
			}
			body := securityActionBody(t, record)
			if body["defenseclaw.approval.id"] != "approval-42" ||
				body["defenseclaw.approval.result"] != test.result {
				t.Fatalf("approval body = %#v", body)
			}
			severity, present := record.Severity()
			if !present || severity != observability.SeverityInfo {
				t.Fatalf("approval severity = (%q,%t), want INFO", severity, present)
			}
			assertControlPlaneCorrelation(t, record.Correlation(), env)
		})
	}
}

func TestJudgeCompletionGeneratedMappingsPersistExactlyOnce(t *testing.T) {
	for _, test := range []struct {
		name       string
		action     string
		severity   string
		failure    gatewaylog.JudgeFailureClass
		error      string
		parseError string
		outcome    observability.Outcome
		want       observability.Severity
	}{
		{name: "clean allow", action: "allow", severity: "NONE", outcome: observability.OutcomeAllowed, want: observability.SeverityInfo},
		{name: "policy block", action: "block", severity: "HIGH", outcome: observability.OutcomeBlocked, want: observability.SeverityHigh},
		{name: "provider failure", action: "error", severity: "HIGH", failure: gatewaylog.JudgeFailureProvider,
			error: "provider unavailable", outcome: observability.OutcomeFailed, want: observability.SeverityHigh},
		{name: "empty response", action: "error", severity: "HIGH", failure: gatewaylog.JudgeFailureEmptyResponse,
			error: "empty-response", outcome: observability.OutcomeFailed, want: observability.SeverityHigh},
		{name: "output parse failure", action: "error", severity: "HIGH", failure: gatewaylog.JudgeFailureOutputParse,
			error: "parse-failed", parseError: "parse-failed", outcome: observability.OutcomeFailed, want: observability.SeverityHigh},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			env := securityActionTestEnvelope()
			event := Event{
				Action: string(ActionLLMJudgeResponse), Target: "judge-model", Actor: "defenseclaw-gateway",
				Details: "legacy judge summary", Severity: test.severity, ToolID: "tool-invocation-9",
			}
			if err := logger.LogJudgeCompletion(ContextWithEnvelope(context.Background(), env), event, JudgeCompletionInput{
				Kind: "injection", Action: test.action, LatencyMS: 17, InputBytes: 2048,
				FailureClass: test.failure, ErrorSummary: test.error, ParseError: test.parseError,
			}); err != nil {
				t.Fatalf("LogJudgeCompletion: %v", err)
			}
			rows, err := logger.store.ListEvents(10)
			if err != nil || len(rows) != 1 {
				t.Fatalf("audit rows = %d err=%v, want exactly 1", len(rows), err)
			}
			metadata, records := runtime.snapshot()
			if len(metadata) != 1 || len(records) != 1 {
				t.Fatalf("runtime counts = metadata:%d records:%d", len(metadata), len(records))
			}
			record := records[0]
			assertSecurityActionIdentity(t, record, rows[0], observability.BucketGuardrailEvaluation,
				observability.EventName(observability.TelemetryEventGuardrailJudgeCompleted), test.outcome, false)
			severity, present := record.Severity()
			if !present || severity != test.want {
				t.Fatalf("judge severity = (%q,%t), want %q", severity, present, test.want)
			}
			body := securityActionBody(t, record)
			if body["defenseclaw.judge.kind"] != "injection" || body["defenseclaw.judge.action"] != test.action ||
				fmt.Sprint(body["defenseclaw.judge.latency_ms"]) != "17" ||
				fmt.Sprint(body["defenseclaw.judge.input_bytes"]) != "2048" {
				t.Fatalf("judge body = %#v", body)
			}
			if test.parseError == "" {
				if _, present := body["defenseclaw.judge.parse_error"]; present {
					t.Fatalf("clean judge emitted parse_error: %#v", body)
				}
			} else if body["defenseclaw.judge.parse_error"] != test.parseError {
				t.Fatalf("judge parse_error = %#v", body["defenseclaw.judge.parse_error"])
			}
			if test.error == "" {
				if _, present := body["defenseclaw.judge.error_summary"]; present {
					t.Fatalf("successful judge emitted error_summary: %#v", body)
				}
			} else if body["defenseclaw.judge.error_summary"] != test.error {
				t.Fatalf("judge error_summary = %#v", body["defenseclaw.judge.error_summary"])
			}
			correlation := record.Correlation()
			assertControlPlaneCorrelation(t, correlation, env)
			if correlation.ToolInvocationID != "tool-invocation-9" {
				t.Fatalf("tool invocation correlation = %q", correlation.ToolInvocationID)
			}
			if metadata[0].Source() != observability.SourceGuardrail {
				t.Fatalf("judge routing source = %q", metadata[0].Source())
			}
		})
	}
}

func TestJudgeCompletionCollectionDropDoesNotResurrectLegacySignal(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionDrop)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogJudgeCompletion(context.Background(), Event{
		Action: string(ActionLLMJudgeResponse), Severity: "LOW", Details: "must drop",
	}, JudgeCompletionInput{Kind: "pii", Action: "allow", LatencyMS: 1, InputBytes: 4}); err != nil {
		t.Fatalf("LogJudgeCompletion drop: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	metadata, records := runtime.snapshot()
	if err != nil || len(rows) != 0 || len(metadata) != 1 || len(records) != 0 {
		t.Fatalf("drop counts = rows:%d metadata:%d records:%d err=%v",
			len(rows), len(metadata), len(records), err)
	}
}

func TestEnforcementQuarantineGeneratedMappingPersistsExactlyOnce(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	env := securityActionTestEnvelope()
	event := Event{
		Action: string(ActionQuarantine), Target: "/skills/risky", Actor: "defenseclaw",
		Details: "dest=/quarantine/risky", Severity: "HIGH",
	}
	input := EnforcementQuarantineAppliedInput{
		EnforcementID: "enforcement-77", RequestedAction: "quarantine",
		EffectiveAction: "quarantine", Initiator: "defenseclaw", ResultingState: "quarantined",
		AssetID: "risky", AssetType: "skill", SourcePath: "/skills/risky",
		DestinationPath: "/quarantine/risky",
	}
	if err := logger.LogEnforcementQuarantineApplied(
		ContextWithEnvelope(context.Background(), env), event, input,
	); err != nil {
		t.Fatalf("LogEnforcementQuarantineApplied: %v", err)
	}
	rows, err := logger.store.ListEvents(10)
	if err != nil || len(rows) != 2 {
		t.Fatalf("audit rows = %d err=%v, want exactly 2", len(rows), err)
	}
	metadata, records := runtime.snapshot()
	if len(metadata) != 2 || len(records) != 2 {
		t.Fatalf("runtime counts = metadata:%d records:%d", len(metadata), len(records))
	}
	rowByID := map[string]Event{rows[0].ID: rows[0], rows[1].ID: rows[1]}
	recordByName := map[observability.EventName]observability.Record{
		records[0].EventName(): records[0], records[1].EventName(): records[1],
	}
	record := recordByName[observability.EventName(observability.TelemetryEventEnforcementQuarantineApplied)]
	assertSecurityActionIdentity(t, record, rowByID[record.RecordID()], observability.BucketEnforcementAction,
		observability.EventName(observability.TelemetryEventEnforcementQuarantineApplied),
		observability.OutcomeQuarantined, true)
	body := securityActionBody(t, record)
	for key, want := range map[string]any{
		"defenseclaw.enforcement.id":               "enforcement-77",
		"defenseclaw.enforcement.requested_action": "quarantine",
		"defenseclaw.enforcement.effective_action": "quarantine",
		"defenseclaw.enforcement.initiator":        "defenseclaw",
		"defenseclaw.enforcement.resulting_state":  "quarantined",
	} {
		if body[key] != want {
			t.Errorf("enforcement body[%q] = %#v, want %#v", key, body[key], want)
		}
	}
	if record.Correlation().EnforcementActionID != "enforcement-77" {
		t.Fatalf("enforcement correlation = %#v", record.Correlation())
	}
	severity, present := record.Severity()
	if !present || severity != observability.SeverityHigh {
		t.Fatalf("enforcement severity = (%q,%t)", severity, present)
	}
	if metadata[0].Source() != observability.SourceWatcher {
		t.Fatalf("enforcement routing source = %q", metadata[0].Source())
	}
	asset := recordByName[observability.EventName(observability.TelemetryEventAssetQuarantined)]
	assertSecurityActionIdentity(t, asset, rowByID[asset.RecordID()], observability.BucketAssetLifecycle,
		observability.EventName(observability.TelemetryEventAssetQuarantined),
		observability.OutcomeQuarantined, true)
	assetBody := securityActionBody(t, asset)
	for key, want := range map[string]any{
		"defenseclaw.asset.id":                   "risky",
		"defenseclaw.asset.type":                 "skill",
		"defenseclaw.asset.transition":           "quarantine",
		"defenseclaw.asset.resulting_state":      "quarantined",
		"defenseclaw.asset.target_path":          "/quarantine/risky",
		"defenseclaw.asset.transition_code":      "quarantine_applied",
		"defenseclaw.asset.transition_initiator": "defenseclaw",
		"defenseclaw.asset.file_action":          "quarantine",
		"defenseclaw.enforcement.id":             "enforcement-77",
	} {
		if assetBody[key] != want {
			t.Errorf("asset body[%q] = %#v, want %#v", key, assetBody[key], want)
		}
	}
	metrics := runtime.metricSnapshot()
	if len(metrics) != 1 || metrics[0].EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawQuarantineActions) {
		t.Fatalf("quarantine metrics = %#v", metrics)
	}
}

func TestApprovalAndEnforcementMandatoryFloorsRemainContentFree(t *testing.T) {
	const canary = "security-floor-secret-91ac"
	t.Run("approval", func(t *testing.T) {
		logger := newTestLogger(t)
		runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionFloor)
		logger.SetRuntimeV8Emitter(runtime)
		if err := logger.LogAction(
			string(ActionGatewayApprovalDenied), "approval-"+canary, "reason="+canary,
		); err != nil {
			t.Fatalf("approval floor: %v", err)
		}
		rows, err := logger.store.ListEvents(10)
		_, records := runtime.snapshot()
		if err != nil || len(rows) != 1 || len(records) != 1 || !records[0].IsFloorOnly() ||
			records[0].EventName() != observability.EventName(observability.TelemetryEventApprovalResolved) ||
			records[0].Outcome() != observability.OutcomeDenied {
			t.Fatalf("approval floor = rows:%d records:%d err=%v", len(rows), len(records), err)
		}
		assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
	})
	t.Run("enforcement", func(t *testing.T) {
		logger := newTestLogger(t)
		runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionFloor)
		logger.SetRuntimeV8Emitter(runtime)
		if err := logger.LogEnforcementQuarantineApplied(context.Background(), Event{
			Action: string(ActionQuarantine), Target: "target-" + canary,
			Actor: "defenseclaw", Details: "details-" + canary, Severity: "HIGH",
			Structured: map[string]any{"secret": canary},
		}, EnforcementQuarantineAppliedInput{
			EnforcementID: "enforcement-floor-1", EffectiveAction: "quarantine",
			ResultingState: "quarantined", AssetID: "target-floor", AssetType: "skill",
			SourcePath: "/skills/target-floor", DestinationPath: "/quarantine/target-floor",
		}); err != nil {
			t.Fatalf("enforcement floor: %v", err)
		}
		rows, err := logger.store.ListEvents(10)
		_, records := runtime.snapshot()
		if err != nil || len(rows) != 2 || len(records) != 2 || !records[0].IsFloorOnly() || !records[1].IsFloorOnly() ||
			records[0].EventName() != observability.EventName(observability.TelemetryEventEnforcementQuarantineApplied) ||
			records[1].EventName() != observability.EventName(observability.TelemetryEventAssetQuarantined) ||
			records[0].Outcome() != observability.OutcomeQuarantined || records[1].Outcome() != observability.OutcomeQuarantined {
			t.Fatalf("enforcement floor = rows:%d records:%d err=%v", len(rows), len(records), err)
		}
		for _, row := range rows {
			assertAuditEventRowExcludesCanary(t, logger.store, row.ID, canary)
		}
	})
}

func TestTypedSecurityActionsFailClosedWithoutBoundV8Runtime(t *testing.T) {
	for _, test := range []struct {
		name string
		log  func(*Logger) error
	}{
		{name: "judge", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Target: "judge-model", Actor: "gateway",
				Details: "judge result", Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "injection", Action: "block", LatencyMS: 1, InputBytes: 8})
		}},
		{name: "enforcement", log: func(logger *Logger) error {
			return logger.LogEnforcementQuarantineApplied(context.Background(), Event{
				Action: string(ActionQuarantine), Target: "/skill", Actor: "watcher",
				Details: "quarantine applied", Severity: "HIGH",
			}, EnforcementQuarantineAppliedInput{
				EnforcementID: "enforcement-unbound", EffectiveAction: "quarantine",
				ResultingState: "quarantined", AssetID: "skill-unbound", AssetType: "skill",
				SourcePath: "/skills/skill-unbound", DestinationPath: "/quarantine/skill-unbound",
			})
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			if err := test.log(logger); err == nil {
				t.Fatal("unbound typed security action did not fail closed")
			}
			rows, err := logger.store.ListEvents(10)
			if err != nil || len(rows) != 0 {
				t.Fatalf("unbound fail-closed rows=%d err=%v", len(rows), err)
			}
		})
	}
}

func TestEnforcementQuarantineFailsClosedWithoutV8LogBatch(t *testing.T) {
	logger := newTestLogger(t)
	runtime := &rejectingRuntimeV8Emitter{}
	logger.SetRuntimeV8Emitter(runtime)

	err := logger.LogEnforcementQuarantineApplied(context.Background(), Event{
		Action: string(ActionQuarantine), Target: "/skills/risky", Actor: "watcher",
		Details: "quarantine applied", Severity: "HIGH",
	}, EnforcementQuarantineAppliedInput{
		EnforcementID: "enforcement-no-batch", EffectiveAction: "quarantine",
		ResultingState: "quarantined", AssetID: "risky", AssetType: "skill",
		SourcePath: "/skills/risky", DestinationPath: "/quarantine/risky",
	})
	if err == nil {
		t.Fatal("quarantine without a v8 log batch did not fail closed")
	}
	rows, listErr := logger.store.ListEvents(10)
	if listErr != nil || len(rows) != 0 || runtime.calls != 0 {
		t.Fatalf("missing-batch counts = rows:%d runtime:%d err=%v", len(rows), runtime.calls, listErr)
	}
}

func TestTypedSecurityActionsFailClosedWhenRequiredV8FactsAreMissing(t *testing.T) {
	for _, test := range []struct {
		name string
		log  func(*Logger) error
	}{
		{name: "judge terminal action", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "injection", Action: "review"})
		}},
		{name: "judge error missing class", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "injection", Action: "error", ErrorSummary: "provider unavailable"})
		}},
		{name: "judge malformed failure class", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "injection", Action: "error", FailureClass: "network-ish", ErrorSummary: "provider unavailable"})
		}},
		{name: "judge provider classified as parse", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "injection", Action: "error", FailureClass: gatewaylog.JudgeFailureProvider,
				ErrorSummary: "provider unavailable", ParseError: "provider unavailable"})
		}},
		{name: "judge parse class missing parse detail", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Severity: "HIGH",
			}, JudgeCompletionInput{Kind: "injection", Action: "error", FailureClass: gatewaylog.JudgeFailureOutputParse,
				ErrorSummary: "parse-failed"})
		}},
		{name: "judge success with failure metadata", log: func(logger *Logger) error {
			return logger.LogJudgeCompletion(context.Background(), Event{
				Action: string(ActionLLMJudgeResponse), Severity: "INFO",
			}, JudgeCompletionInput{Kind: "injection", Action: "allow", FailureClass: gatewaylog.JudgeFailureProvider,
				ErrorSummary: "impossible"})
		}},
		{name: "enforcement id", log: func(logger *Logger) error {
			return logger.LogEnforcementQuarantineApplied(context.Background(), Event{
				Action: string(ActionQuarantine), Severity: "HIGH",
			}, EnforcementQuarantineAppliedInput{EffectiveAction: "quarantine"})
		}},
	} {
		test := test
		t.Run(test.name, func(t *testing.T) {
			logger := newTestLogger(t)
			runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
			logger.SetRuntimeV8Emitter(runtime)
			if err := test.log(logger); err == nil {
				t.Fatal("missing required canonical fact did not fail closed")
			}
			rows, err := logger.store.ListEvents(10)
			metadata, records := runtime.snapshot()
			if err != nil || len(rows) != 0 || len(metadata) != 0 || len(records) != 0 {
				t.Fatalf("fail-closed counts = rows:%d metadata:%d records:%d err=%v",
					len(rows), len(metadata), len(records), err)
			}
		})
	}
}

func TestRuntimeV8OutcomeConsistencyFailsClosed(t *testing.T) {
	for _, outcome := range []RuntimeV8EmitOutcome{
		{Admission: router.AdmissionDrop, LocalPersisted: true},
		{Admission: router.AdmissionOrdinary, LocalPersisted: false},
		{Admission: router.AdmissionFloor, LocalPersisted: false},
		{Admission: router.Admission(255), LocalPersisted: true},
	} {
		if _, err := runtimeV8Disposition(outcome, false); err == nil {
			t.Fatalf("inconsistent runtime outcome accepted: %#v", outcome)
		}
	}
}

func securityActionTestEnvelope() CorrelationEnvelope {
	return CorrelationEnvelope{
		RunID: "run-security", TraceID: "trace-security", RequestID: "request-security",
		SessionID: "session-security", TurnID: "turn-security", AgentID: "agent-security",
		AgentName: "agent-name", AgentInstanceID: "agent-instance-security",
		SidecarInstanceID: "sidecar-security", PolicyID: "policy-security", Connector: "codex",
	}
}

func assertSecurityActionIdentity(
	t *testing.T,
	record observability.Record,
	legacy Event,
	bucket observability.Bucket,
	eventName observability.EventName,
	outcome observability.Outcome,
	mandatory bool,
) {
	t.Helper()
	if record.RecordID() != legacy.ID || record.Bucket() != bucket || record.EventName() != eventName ||
		record.Signal() != observability.SignalLogs || record.Outcome() != outcome ||
		record.Mandatory() != mandatory || record.IsFloorOnly() || !record.SchemaDerivedFieldClasses() {
		t.Fatalf("record identity = id:%q identity:%#v outcome:%q mandatory:%t floor:%t schema-derived:%t legacy:%#v",
			record.RecordID(), record.Identity(), record.Outcome(), record.Mandatory(), record.IsFloorOnly(),
			record.SchemaDerivedFieldClasses(), legacy)
	}
	if legacy.Action != record.Action() || legacy.Actor != "audit_logger" ||
		legacy.Details != string(record.EventName()) || len(legacy.Structured) == 0 {
		t.Fatalf("canonical SQLite projection changed: %#v", legacy)
	}
}

func securityActionBody(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	body, ok := record.Body()
	if !ok {
		t.Fatal("record body is absent")
	}
	object, err := body.Object()
	if err != nil {
		t.Fatalf("record body: %v", err)
	}
	return object
}
