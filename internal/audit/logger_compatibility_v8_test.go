// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"context"
	"fmt"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestCompatibilityAuditV8OwnsGenericActionCorrelationAndMetric(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	envelope := CorrelationEnvelope{
		RunID: "run-compat", TraceID: "trace-compat", RequestID: "request-compat",
		SessionID: "session-compat", TurnID: "turn-compat", AgentID: "agent-compat",
		AgentName: "agent-name", AgentInstanceID: "agent-instance-compat",
		SidecarInstanceID: "sidecar-compat", PolicyID: "policy-compat", Connector: "codex",
	}
	if err := logger.LogActionCtx(
		ContextWithEnvelope(context.Background(), envelope),
		string(ActionInstallClean), "skill-example", "scan clean",
	); err != nil {
		t.Fatalf("LogActionCtx: %v", err)
	}

	rows, listErr := logger.store.ListEvents(10)
	metadata, records := runtime.snapshot()
	metrics := runtime.metricSnapshot()
	if listErr != nil || len(rows) != 1 || len(metadata) != 1 || len(records) != 1 || len(metrics) != 1 {
		t.Fatalf("counts rows=%d metadata=%d records=%d metrics=%d err=%v",
			len(rows), len(metadata), len(records), len(metrics), listErr)
	}
	record := records[0]
	if record.Bucket() != observability.BucketAssetScan || record.EventName() != "legacy.audit.install.clean" ||
		metadata[0].Identity() != record.Identity() || record.Mandatory() || record.IsFloorOnly() {
		t.Fatalf("compatibility record identity=%#v mandatory=%t floor=%t",
			record.Identity(), record.Mandatory(), record.IsFloorOnly())
	}
	assertControlPlaneCorrelation(t, record.Correlation(), envelope)
	if rows[0].ID != record.RecordID() || rows[0].Actor != "defenseclaw" ||
		rows[0].Target != "skill-example" || rows[0].Connector != "codex" {
		t.Fatalf("compatibility projection = %#v", rows[0])
	}
	if metrics[0].EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawAuditEventsTotal) ||
		fmt.Sprint(metricValue(t, metrics[0])) != "1" {
		t.Fatalf("generated audit metric = %#v", metrics)
	}
	attributes := generatedMetricAttributes(t, metrics[0])
	if attributes["defenseclaw.metric.action"] != string(ActionInstallClean) ||
		attributes["defenseclaw.connector.source"] != "codex" ||
		attributes["defenseclaw.security.severity"] != "INFO" {
		t.Fatalf("generated audit metric attributes = %#v", attributes)
	}
}

func TestCompatibilityAuditV8DropAndDetachNeverResurrectLegacy(t *testing.T) {
	t.Run("collection drop", func(t *testing.T) {
		logger := newTestLogger(t)
		runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionDrop)
		logger.SetRuntimeV8Emitter(runtime)
		if err := logger.LogAction(string(ActionInstallClean), "asset", "clean"); err != nil {
			t.Fatal(err)
		}
		rows, err := logger.store.ListEvents(10)
		metadata, records := runtime.snapshot()
		if err != nil || len(rows) != 0 || len(metadata) != 1 || len(records) != 0 ||
			len(runtime.metricSnapshot()) != 0 {
			t.Fatalf("drop rows=%d metadata=%d records=%d metrics=%d err=%v",
				len(rows), len(metadata), len(records), len(runtime.metricSnapshot()), err)
		}
	})

	t.Run("sticky detach", func(t *testing.T) {
		logger := newTestLogger(t)
		logger.SetRuntimeV8Emitter(newTestRuntimeV8Emitter(t, logger.store, router.AdmissionOrdinary))
		logger.SetRuntimeV8Emitter(nil)
		if err := logger.LogAction(string(ActionInstallClean), "asset", "clean"); err == nil {
			t.Fatal("detached v8 compatibility action did not fail closed")
		}
		rows, err := logger.store.ListEvents(10)
		if err != nil || len(rows) != 0 {
			t.Fatalf("detach rows=%d err=%v", len(rows), err)
		}
	})
}

func TestCompatibilityActivityRetainsMandatorySQLiteFloor(t *testing.T) {
	const canary = "activity-floor-secret"
	logger := newTestLogger(t)
	runtime := newTestRuntimeV8Emitter(t, logger.store, router.AdmissionFloor)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.LogActivity(ActivityInput{
		Actor: "cli:alice", TargetType: "config", TargetID: "observability",
		Reason: canary, After: map[string]any{"secret": canary},
		Diff: []ActivityDiffEntry{{Path: "secret", Op: "add", After: canary}},
	}); err != nil {
		t.Fatalf("LogActivity: %v", err)
	}
	activities, activityErr := logger.store.ListActivityEvents(10)
	rows, rowErr := logger.store.ListEvents(10)
	_, records := runtime.snapshot()
	if activityErr != nil || rowErr != nil || len(activities) != 0 || len(rows) != 1 || len(records) != 1 {
		t.Fatalf("floor activities=%d rows=%d records=%d errors=%v/%v",
			len(activities), len(rows), len(records), activityErr, rowErr)
	}
	if !records[0].Mandatory() || !records[0].IsFloorOnly() {
		t.Fatalf("floor mandatory=%t floor=%t", records[0].Mandatory(), records[0].IsFloorOnly())
	}
	assertAuditEventRowExcludesCanary(t, logger.store, rows[0].ID, canary)
}

func TestRuntimeAlertUsesGeneratedHealthLogAndAlertMetric(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	envelope := CorrelationEnvelope{
		RunID: "run-alert", TraceID: "trace-alert", RequestID: "request-alert",
		SessionID: "session-alert", TurnID: "turn-alert", AgentID: "agent-alert",
		AgentInstanceID: "agent-instance-alert", SidecarInstanceID: "sidecar-alert",
		PolicyID: "policy-alert", Connector: "codex",
	}
	if err := logger.LogAlertCtx(
		ContextWithEnvelope(context.Background(), envelope),
		"judge_store", "HIGH", "judge_persist.commit", map[string]any{"code": "timeout"},
	); err != nil {
		t.Fatalf("LogAlertCtx: %v", err)
	}

	logs, metrics := runtime.snapshot()
	rows, listErr := logger.store.ListEvents(10)
	if listErr != nil || len(rows) != 1 || len(logs) != 1 || len(metrics) != 2 {
		t.Fatalf("alert rows=%d logs=%d metrics=%d err=%v", len(rows), len(logs), len(metrics), listErr)
	}
	if logs[0].EventName() != observability.EventName(observability.TelemetryEventSubsystemDegraded) ||
		logs[0].Bucket() != observability.BucketPlatformHealth || logs[0].Outcome() != observability.OutcomeFailed {
		t.Fatalf("alert log identity=%#v outcome=%q", logs[0].Identity(), logs[0].Outcome())
	}
	assertControlPlaneCorrelation(t, logs[0].Correlation(), envelope)
	body, present := logs[0].Body()
	if !present {
		t.Fatal("runtime alert body is absent")
	}
	bodyObject, err := body.Object()
	if err != nil {
		t.Fatal(err)
	}
	if bodyObject["defenseclaw.schema.error_code"] != "judge_persist.commit" {
		t.Fatalf("runtime alert error code = %#v", bodyObject["defenseclaw.schema.error_code"])
	}
	if metrics[0].EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawAuditEventsTotal) ||
		metrics[1].EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawAlertCount) {
		t.Fatalf("alert metric identities = %q/%q", metrics[0].EventName(), metrics[1].EventName())
	}
	attributes := generatedMetricAttributes(t, metrics[1])
	if attributes["defenseclaw.metric.alert.severity"] != "HIGH" ||
		attributes["defenseclaw.metric.alert.source"] != "judge_store" ||
		attributes["defenseclaw.metric.alert.type"] != "runtime" ||
		attributes["defenseclaw.connector.source"] != "codex" {
		t.Fatalf("alert metric attributes = %#v", attributes)
	}
}

func TestRuntimeAlertErrorCodeAdmitsOnlyStableJSONSummary(t *testing.T) {
	valid, present := runtimeAlertErrorCode(`{"summary":"judge_persist.begin_batch","secret":"ignored"}`).Get()
	if !present || valid != "judge_persist.begin_batch" {
		t.Fatalf("stable error code = (%q,%t)", valid, present)
	}
	for _, details := range []string{
		`{"summary":"human readable failure"}`,
		`{"summary":"https://private.example/failure"}`,
		`{"summary":""}`,
		`{"summary":`,
	} {
		if value := runtimeAlertErrorCode(details); value.IsPresent() {
			t.Fatalf("unsafe alert summary was admitted from %q", details)
		}
	}
}

func generatedMetricAttributes(t *testing.T, record observability.Record) map[string]any {
	t.Helper()
	instrument, present := record.InstrumentData()
	if !present {
		t.Fatal("generated metric instrument is absent")
	}
	data, err := instrument.Object()
	if err != nil {
		t.Fatal(err)
	}
	attributes, ok := data["attributes"].(map[string]any)
	if !ok {
		t.Fatalf("generated metric attributes = %#v", data["attributes"])
	}
	return attributes
}
