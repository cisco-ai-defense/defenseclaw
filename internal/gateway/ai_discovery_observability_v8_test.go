// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"database/sql"
	"encoding/json"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

type discoveryMetricFailureRuntime struct {
	aiDiscoveryV8Runtime
	mu         sync.Mutex
	calls      []observability.EventName
	failFamily observability.EventName
}

func (runtime *discoveryMetricFailureRuntime) RecordGeneratedMetric(
	ctx context.Context,
	family observability.EventName,
	builder observabilityruntime.GeneratedMetricBuilder,
) (telemetry.V8MetricRecordResult, error) {
	runtime.mu.Lock()
	runtime.calls = append(runtime.calls, family)
	fail := family == runtime.failFamily
	runtime.mu.Unlock()
	if fail {
		return telemetry.V8MetricRecordResult{}, &sidecarObservabilityError{code: sidecarObservabilityEmitFailed}
	}
	return runtime.aiDiscoveryV8Runtime.RecordGeneratedMetric(ctx, family, builder)
}

func (runtime *discoveryMetricFailureRuntime) snapshot() []observability.EventName {
	runtime.mu.Lock()
	defer runtime.mu.Unlock()
	return append([]observability.EventName(nil), runtime.calls...)
}

type storedContinuousDiscoveryV8 struct {
	eventName string
	body      map[string]any
}

func readStoredContinuousDiscoveryV8(t *testing.T, path string) []storedContinuousDiscoveryV8 {
	t.Helper()
	database, err := sql.Open("sqlite", path)
	if err != nil {
		t.Fatal(err)
	}
	defer database.Close()
	rows, err := database.Query(`SELECT event_name, projected_record_json FROM audit_events
		WHERE action = 'ai_discovery' ORDER BY event_name`)
	if err != nil {
		t.Fatal(err)
	}
	defer rows.Close()
	var result []storedContinuousDiscoveryV8
	for rows.Next() {
		var item storedContinuousDiscoveryV8
		var projectedJSON string
		if err := rows.Scan(&item.eventName, &projectedJSON); err != nil {
			t.Fatal(err)
		}
		var projected map[string]any
		if err := json.Unmarshal([]byte(projectedJSON), &projected); err != nil {
			t.Fatal(err)
		}
		item.body, _ = projected["body"].(map[string]any)
		result = append(result, item)
	}
	if err := rows.Err(); err != nil {
		t.Fatal(err)
	}
	return result
}

func TestContinuousAIDiscoveryV8EmitsExactLogFamiliesAndAttemptsEveryMetricSibling(t *testing.T) {
	fixture := newOTLPV8MetricFixture(t)
	runtime := &discoveryMetricFailureRuntime{
		aiDiscoveryV8Runtime: fixture.runtime,
		failFamily:           observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoveryRuns),
	}
	adapter := &aiDiscoveryV8Adapter{runtime: runtime}
	report := inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{
			ScanID: "scan-1", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			DurationMs: 12, TotalSignals: 1, ActiveSignals: 1, NewSignals: 1,
			FilesScanned: 2, DedupeSuppressed: 1,
		},
		Signals: []inventory.AISignal{{
			SignalID: "ai-0123456789abcdef", SignatureID: "openai-python", Category: inventory.SignalPackageDependency,
			Vendor: "openai", Product: "openai", Confidence: .95, State: inventory.AIStateNew,
			Detector: "package_manifest",
		}},
	}
	components := []inventory.AIDiscoveryV8ComponentObservation{{
		ComponentID: "ai-fedcba9876543210", ComponentType: inventory.SignalPackageDependency,
		HasLifecycleChange: true,
		Metrics: telemetry.AIComponentConfidenceAttrs{
			Ecosystem: "pypi", Name: "openai", Framework: "OpenAI SDK",
			IdentityScore: .95, IdentityBand: "very_high", PresenceScore: .8, PresenceBand: "high",
			InstallCount: 1, WorkspaceCount: 1, DetectorCount: 1, PolicyVersion: 1,
		},
	}}
	err := adapter.EmitReport(t.Context(), report, components)
	var bounded *sidecarObservabilityError
	if !asSidecarObservabilityError(err, &bounded) || bounded.Code() != sidecarObservabilityEmitFailed {
		t.Fatalf("EmitReport error=%v want bounded aggregate metric failure", err)
	}

	rows := readStoredContinuousDiscoveryV8(t, fixture.path)
	if len(rows) != 3 {
		t.Fatalf("canonical log rows=%d want summary + signal + confidence: %#v", len(rows), rows)
	}
	want := []string{"ai.discovery.completed", "ai_component.confidence.changed", "ai_component.discovered"}
	for index, row := range rows {
		if row.eventName != want[index] || row.body == nil {
			t.Fatalf("row[%d]=%+v want=%s", index, row, want[index])
		}
	}

	calls := runtime.snapshot()
	wantCalls := map[observability.EventName]int{
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoveryRuns):             1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoveryDuration):         1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoveryActiveSignals):    1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoveryFilesScanned):     1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoveryDedupeSuppressed): 1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoverySignals):          1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIDiscoveryNewSignals):       2,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIComponentsObservations):    1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIComponentsInstalls):        1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIComponentsWorkspaces):      1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIConfidenceIdentityScore):   1,
		observability.EventName(observability.TelemetryInstrumentDefenseClawAIConfidencePresenceScore):   1,
	}
	gotCalls := make(map[observability.EventName]int, len(wantCalls))
	for _, family := range calls {
		gotCalls[family]++
	}
	if len(calls) != 13 || len(gotCalls) != len(wantCalls) {
		t.Fatalf("metric families/calls=%d/%v want exact registered set %v", len(calls), gotCalls, wantCalls)
	}
	for family, count := range wantCalls {
		if gotCalls[family] != count {
			t.Fatalf("metric %s calls=%d want=%d; all=%v", family, gotCalls[family], count, calls)
		}
	}
}

func asSidecarObservabilityError(err error, target **sidecarObservabilityError) bool {
	value, ok := err.(*sidecarObservabilityError)
	if ok {
		*target = value
	}
	return ok
}
