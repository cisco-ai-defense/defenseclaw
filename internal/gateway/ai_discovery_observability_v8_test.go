// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"database/sql"
	"encoding/json"
	"strings"
	"sync"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
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

func TestContinuousAIDiscoveryV8EmitsBoundedLocalModelProvenance(t *testing.T) {
	quantized := true
	distilled := false
	capture := &endpointInventoryCapture{}
	adapter := &aiDiscoveryV8Adapter{runtime: capture}
	report := inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{
			ScanID: "scan-model-provenance", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: 5, ActiveSignals: 5, NewSignals: 5,
		},
		Signals: []inventory.AISignal{
			{
				SignalID: "model-rich", SignatureID: "local-model", Category: inventory.SignalLocalModel,
				Vendor: "Local", Product: "Local Model Artifact", Confidence: .95, State: inventory.AIStateNew,
				Detector: "model_file",
				Model: &inventory.LocalModelInfo{
					ID: "private-installed-model", Status: "installed",
					Provenance: &inventory.LocalModelProvenance{
						Publisher: "Alibaba Cloud", CountryCode: "CN", RootModel: "Qwen/Qwen3-8B",
						BaseModels: []string{"Qwen/Qwen3-8B", "Qwen/Qwen3-4B"},
						Quantized:  &quantized, Quantization: "Q4_K_M", Distilled: &distilled,
						Derivation: "quantized", Source: "catalog_exact", Confidence: "high",
					},
				},
			},
			{
				SignalID: "model-family-private", SignatureID: "local-model", Category: inventory.SignalLocalModel,
				Vendor: "Local", Product: "Local Model Artifact", Confidence: .85, State: inventory.AIStateNew,
				Detector: "model_file",
				Model: &inventory.LocalModelInfo{
					ID: "customer-secret-llama.gguf", Status: "installed",
					Provenance: &inventory.LocalModelProvenance{
						Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/customer-secret-llama",
						BaseModels: []string{"checkpoints/customer-secret-parent"}, Quantized: &quantized,
						Derivation: "quantized", Source: "catalog_family", Confidence: "medium",
					},
				},
			},
			{
				SignalID: "model-hub-public", SignatureID: "local-model", Category: inventory.SignalLocalModel,
				Vendor: "Local", Product: "Local Model Artifact", Confidence: .9, State: inventory.AIStateNew,
				Detector: "model_file",
				Model: &inventory.LocalModelInfo{
					ID: "renamed-public-model", Status: "installed",
					Provenance: &inventory.LocalModelProvenance{
						Publisher: "Alibaba Cloud", CountryCode: "CN", RootModel: "Qwen/Qwen3-4B",
						BaseModels: []string{"Qwen/Qwen3-4B"}, Source: "huggingface_hub", Confidence: "high",
					},
				},
			},
			{
				SignalID: "model-unknown-flags", SignatureID: "local-model", Category: inventory.SignalLocalModel,
				Vendor: "Local", Product: "Local Model Artifact", Confidence: .8, State: inventory.AIStateNew,
				Detector: "model_file",
				Model: &inventory.LocalModelInfo{
					ID: "another-private-model", Status: "installed",
					Provenance: &inventory.LocalModelProvenance{
						RootModel:  "meta-llama/customer-secret-model",
						BaseModels: []string{"checkpoints/customer-secret-parent"},
						Source:     "model_id", Confidence: "low",
					},
				},
			},
			{
				SignalID: "non-model", SignatureID: "package", Category: inventory.SignalPackageDependency,
				Vendor: "Example", Product: "example", Confidence: .9, State: inventory.AIStateNew,
				Detector: "package_manifest",
				// A malformed internal signal must not move model data across the
				// category boundary even though external reports reject this shape.
				Model: &inventory.LocalModelInfo{
					ID: "must-not-escape", Status: "installed",
					Provenance: &inventory.LocalModelProvenance{
						Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/private",
						Source: "catalog_family", Confidence: "medium",
					},
				},
			},
		},
	}
	if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
		t.Fatal(err)
	}

	provenanceFields := []string{
		observability.TelemetryAttributeDefenseClawAIModelProvenancePublisher,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceCountryCode,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantized,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantization,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceDistilled,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceDerivation,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceSource,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceConfidence,
	}
	recordsByID := make(map[string]observability.Record)
	for _, record := range capture.snapshot() {
		if record.EventName() != "ai_component.discovered" {
			continue
		}
		body := canonicalBody(t, record)
		if id, ok := body[observability.TelemetryAttributeDefenseClawAIComponentID].(string); ok {
			recordsByID[id] = record
		}
	}
	if len(recordsByID) != 5 {
		t.Fatalf("model/non-model discovery records=%d want=5", len(recordsByID))
	}

	rich := recordsByID["model-rich"]
	richBody := canonicalBody(t, rich)
	for field, want := range map[string]any{
		observability.TelemetryAttributeDefenseClawAIModelProvenancePublisher:    "Alibaba Cloud",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceCountryCode:  "CN",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel:    "Qwen/Qwen3-8B",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantized:    true,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantization: "Q4_K_M",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceDistilled:    false,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceDerivation:   "quantized",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceSource:       "catalog_exact",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceConfidence:   "high",
	} {
		if got := richBody[field]; got != want {
			t.Errorf("rich provenance %s=%T(%v) want %T(%v)", field, got, got, want, want)
		}
	}
	baseModels, ok := richBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels].([]any)
	if !ok || len(baseModels) != 2 || baseModels[0] != "Qwen/Qwen3-8B" || baseModels[1] != "Qwen/Qwen3-4B" {
		t.Errorf("rich provenance base models=%T(%v)", richBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels], richBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels])
	}
	encodedRich, err := json.Marshal(richBody)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedRich), "private-installed-model") {
		t.Fatalf("installed model ID escaped canonical log: %s", encodedRich)
	}
	classes := rich.FieldClasses()
	if classes["/"+observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel] != observability.FieldClassContent ||
		classes["/"+observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels+"/0"] != observability.FieldClassContent ||
		classes["/"+observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantization] != observability.FieldClassContent ||
		classes["/"+observability.TelemetryAttributeDefenseClawAIModelProvenancePublisher] != observability.FieldClassMetadata ||
		classes["/"+observability.TelemetryAttributeDefenseClawAIModelProvenanceCountryCode] != observability.FieldClassMetadata {
		t.Fatalf("model provenance field classes=%#v", classes)
	}
	engine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x51}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileContent)
	if !ok {
		t.Fatal("content profile is unavailable")
	}
	projection, _, err := engine.Project(rich, profile)
	if err != nil {
		t.Fatal(err)
	}
	projectedBody, err := projection.Payload().Object()
	if err != nil {
		t.Fatal(err)
	}
	if got := projectedBody[observability.TelemetryAttributeDefenseClawAIModelProvenancePublisher]; got != "Alibaba Cloud" {
		t.Errorf("content projection publisher=%T(%v) want preserved metadata", got, got)
	}
	if got := projectedBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceCountryCode]; got != "CN" {
		t.Errorf("content projection country=%T(%v) want preserved metadata", got, got)
	}
	projectedRoot, present := projectedBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel]
	projectedRootText, typed := projectedRoot.(string)
	if !present || !typed || projectedRootText == "" || projectedRootText == "Qwen/Qwen3-8B" {
		t.Errorf("content projection root=%T(%v) want present nonempty redaction token", projectedRoot, projectedRoot)
	}
	projectedQuantization, present := projectedBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantization]
	projectedQuantizationText, typed := projectedQuantization.(string)
	if !present || !typed || projectedQuantizationText == "" || projectedQuantizationText == "Q4_K_M" {
		t.Errorf("content projection quantization=%T(%v) want present nonempty redaction token", projectedQuantization, projectedQuantization)
	}
	projectedBaseModels, ok := projectedBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels].([]any)
	if !ok || len(projectedBaseModels) != 2 || projectedBaseModels[0] == "Qwen/Qwen3-8B" || projectedBaseModels[1] == "Qwen/Qwen3-4B" {
		t.Errorf("content projection base models=%T(%v) want redacted items", projectedBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels], projectedBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels])
	}

	unknownBody := canonicalBody(t, recordsByID["model-unknown-flags"])
	for _, field := range []string{
		observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantized,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceDistilled,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceDerivation,
	} {
		if _, present := unknownBody[field]; present {
			t.Errorf("unknown tri-state field %s was fabricated: %#v", field, unknownBody[field])
		}
	}
	encodedUnknown, err := json.Marshal(unknownBody)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedUnknown), "customer-secret") || strings.Contains(string(encodedUnknown), "checkpoints/") {
		t.Fatalf("unreviewed lineage names escaped canonical log: %s", encodedUnknown)
	}

	familyBody := canonicalBody(t, recordsByID["model-family-private"])
	for field, want := range map[string]any{
		observability.TelemetryAttributeDefenseClawAIModelProvenancePublisher:   "Meta",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceCountryCode: "US",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceQuantized:   true,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceDerivation:  "quantized",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceSource:      "catalog_family",
		observability.TelemetryAttributeDefenseClawAIModelProvenanceConfidence:  "medium",
	} {
		if got := familyBody[field]; got != want {
			t.Errorf("family provenance %s=%T(%v) want %T(%v)", field, got, got, want, want)
		}
	}
	for _, field := range []string{
		observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel,
		observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels,
	} {
		if _, present := familyBody[field]; present {
			t.Errorf("family-derived lineage name %s escaped: %#v", field, familyBody[field])
		}
	}
	encodedFamily, err := json.Marshal(familyBody)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedFamily), "customer-secret") || strings.Contains(string(encodedFamily), "checkpoints/") {
		t.Fatalf("family-derived private names escaped canonical log: %s", encodedFamily)
	}

	hubBody := canonicalBody(t, recordsByID["model-hub-public"])
	if got := hubBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel]; got != "Qwen/Qwen3-4B" {
		t.Errorf("Hub root=%T(%v) want public lineage", got, got)
	}
	hubBaseModels, ok := hubBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels].([]any)
	if !ok || len(hubBaseModels) != 1 || hubBaseModels[0] != "Qwen/Qwen3-4B" {
		t.Errorf("Hub base models=%T(%v)", hubBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels], hubBody[observability.TelemetryAttributeDefenseClawAIModelProvenanceBaseModels])
	}

	nonModelBody := canonicalBody(t, recordsByID["non-model"])
	for _, field := range provenanceFields {
		if _, present := nonModelBody[field]; present {
			t.Errorf("non-model record carried %s=%#v", field, nonModelBody[field])
		}
	}
	encodedNonModel, err := json.Marshal(nonModelBody)
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encodedNonModel), "must-not-escape") || strings.Contains(string(encodedNonModel), "meta-llama/private") {
		t.Fatalf("non-model payload leaked model identity: %s", encodedNonModel)
	}
}

func TestContinuousAIDiscoveryV8RejectsOversizeModelProvenanceAncestry(t *testing.T) {
	for _, tc := range []struct {
		name       string
		baseModels []string
	}{
		{name: "item", baseModels: []string{strings.Repeat("a", 513)}},
		{name: "count", baseModels: []string{"a", "b", "c", "d", "e", "f", "g", "h", "i"}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			capture := &endpointInventoryCapture{}
			adapter := &aiDiscoveryV8Adapter{runtime: capture}
			report := inventory.AIDiscoveryReport{
				Summary: inventory.AIDiscoverySummary{
					ScanID: "scan-model-boundary", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
					TotalSignals: 1, ActiveSignals: 1, NewSignals: 1,
				},
				Signals: []inventory.AISignal{{
					SignalID: "model-boundary", SignatureID: "local-model", Category: inventory.SignalLocalModel,
					Vendor: "Local", Product: "Local Model Artifact", Confidence: .9, State: inventory.AIStateNew,
					Detector: "model_file",
					Model: &inventory.LocalModelInfo{ID: "private-boundary", Status: "installed", Provenance: &inventory.LocalModelProvenance{
						RootModel: "Qwen/Qwen3-8B", BaseModels: tc.baseModels,
						Source: "catalog_exact", Confidence: "high",
					}},
				}},
			}
			if err := adapter.EmitReport(t.Context(), report, nil); err == nil {
				t.Fatal("oversize provenance ancestry was accepted")
			}
			for _, record := range capture.snapshot() {
				if record.EventName() == "ai_component.discovered" {
					t.Fatal("invalid model provenance record was emitted")
				}
			}
		})
	}
}

func TestContinuousAIDiscoveryV8CarriesModelProvenanceAcrossLifecycleFamilies(t *testing.T) {
	withManagedEnterprise(t, true)
	capture := &endpointInventoryCapture{}
	adapter := &aiDiscoveryV8Adapter{runtime: capture}
	states := []struct {
		state     string
		eventName observability.EventName
	}{
		{inventory.AIStateNew, "ai_component.discovered"},
		{inventory.AIStateChanged, "ai_component.changed"},
		{inventory.AIStateSeen, "ai_component.observed"},
		{inventory.AIStateGone, "ai_component.removed"},
	}
	report := inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{
			ScanID: "scan-model-lifecycle", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: 4, ActiveSignals: 3, NewSignals: 1, ChangedSignals: 1, GoneSignals: 1,
		},
	}
	for _, item := range states {
		report.Signals = append(report.Signals, inventory.AISignal{
			SignalID: "model-" + item.state, SignatureID: "local-model", Category: inventory.SignalLocalModel,
			Vendor: "Local", Product: "Local Model Artifact", Confidence: .9, State: item.state,
			Detector: "model_file",
			Model: &inventory.LocalModelInfo{
				ID: "private-" + item.state, Status: "installed",
				Provenance: &inventory.LocalModelProvenance{
					Publisher: "Meta", CountryCode: "US", RootModel: "meta-llama/Llama-3.2-3B",
					Source: "catalog_exact", Confidence: "high",
				},
			},
		})
	}
	if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
		t.Fatal(err)
	}

	got := make(map[string]observability.EventName, len(states))
	for _, record := range capture.snapshot() {
		if record.EventName() == "ai.discovery.completed" {
			continue
		}
		body := canonicalBody(t, record)
		id, _ := body[observability.TelemetryAttributeDefenseClawAIComponentID].(string)
		got[id] = record.EventName()
		if publisher := body[observability.TelemetryAttributeDefenseClawAIModelProvenancePublisher]; publisher != "Meta" {
			t.Errorf("%s publisher=%T(%v) want Meta", record.EventName(), publisher, publisher)
		}
		if root := body[observability.TelemetryAttributeDefenseClawAIModelProvenanceRootModel]; root != "meta-llama/Llama-3.2-3B" {
			t.Errorf("%s root=%T(%v)", record.EventName(), root, root)
		}
	}
	for _, item := range states {
		if eventName := got["model-"+item.state]; eventName != item.eventName {
			t.Errorf("state %s event=%q want=%q", item.state, eventName, item.eventName)
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
