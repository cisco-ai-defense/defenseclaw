// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
)

func TestSQLiteBusyMetricUsesGeneratedFamilyAndExistingDashboardLabel(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	if err := logger.RecordSQLiteBusyMetric(t.Context(), "audit_insert"); err != nil {
		t.Fatal(err)
	}
	logs, metrics := runtime.snapshot()
	if len(logs) != 0 || len(metrics) != 1 {
		t.Fatalf("generated logs/metrics = %d/%d", len(logs), len(metrics))
	}
	record := metrics[0]
	if record.EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawSqliteBusyRetries) ||
		record.Bucket() != observability.BucketPlatformHealth || record.Signal() != observability.SignalMetrics {
		t.Fatalf("metric identity = %s/%s/%s", record.Bucket(), record.Signal(), record.EventName())
	}
	value, attributes := watcherMetricValueAndAttributes(t, record)
	if value != "1" || !reflect.DeepEqual(attributes, map[string]string{
		"defenseclaw.metric.operation": "audit_insert",
	}) {
		t.Fatalf("metric value/attributes = %q/%#v", value, attributes)
	}
}

func TestSchemaViolationMetricUsesGeneratedFamilyAndExistingLabels(t *testing.T) {
	logger := newTestLogger(t)
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	logger.RecordSchemaViolationMetric(gatewaylog.EventVerdict, "invalid_schema", "ignored")

	logs, metrics := runtime.snapshot()
	if len(logs) != 0 || len(metrics) != 1 {
		t.Fatalf("generated logs/metrics = %d/%d", len(logs), len(metrics))
	}
	record := metrics[0]
	if record.EventName() != observability.EventName(observability.TelemetryInstrumentDefenseClawSchemaViolations) ||
		record.Bucket() != observability.BucketDiagnostic || record.Signal() != observability.SignalMetrics {
		t.Fatalf("metric identity = %s/%s/%s", record.Bucket(), record.Signal(), record.EventName())
	}
	value, attributes := watcherMetricValueAndAttributes(t, record)
	if value != "1" || !reflect.DeepEqual(attributes, map[string]string{
		"defenseclaw.metric.event_type": string(gatewaylog.EventVerdict),
		"defenseclaw.metric.code":       "invalid_schema",
	}) {
		t.Fatalf("metric value/attributes = %q/%#v", value, attributes)
	}
}

func TestNewLoggerBindsAndDetachFailsClosed(t *testing.T) {
	logger := newTestLogger(t)
	if logger.store.sqliteBusyObservabilityV8() != logger {
		t.Fatal("new logger did not bind the store contention observer")
	}
	runtime := newSinkHealthTestRuntime(t, logger, router.AdmissionOrdinary)
	logger.SetRuntimeV8Emitter(runtime)
	logger.SetRuntimeV8Emitter(nil)
	if err := logger.RecordSQLiteBusyMetric(t.Context(), "audit_insert"); err == nil {
		t.Fatal("detached authoritative runtime accepted SQLite contention metric")
	}
}
