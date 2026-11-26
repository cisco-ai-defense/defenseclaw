// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/inventory"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
)

// Spec 016: only the Secure Client profile exports local model identity and
// the snapshot completeness fields. These tests pin both the Secure Client
// output and the byte-for-byte absence of the new fields in every other mode.

var localModelExportFields = []string{
	observability.TelemetryAttributeDefenseClawAIModelID,
	observability.TelemetryAttributeDefenseClawAIModelKey,
	observability.TelemetryAttributeDefenseClawAIModelProvider,
	observability.TelemetryAttributeDefenseClawAIModelStatus,
	observability.TelemetryAttributeDefenseClawAIModelFormat,
	observability.TelemetryAttributeDefenseClawAIModelSizeBytes,
	observability.TelemetryAttributeDefenseClawAIModelModality,
	observability.TelemetryAttributeDefenseClawAIModelOwnerApplication,
	observability.TelemetryAttributeDefenseClawAIModelRelevance,
}

var localModelSummaryFields = []string{
	observability.TelemetryAttributeDefenseClawAIDiscoverySnapshotPublished,
	observability.TelemetryAttributeDefenseClawAIDiscoveryLocalModelSignals,
}

func localModelExportReport(scanID string, state string) inventory.AIDiscoveryReport {
	newCount := 0
	if state == inventory.AIStateNew {
		newCount = 4
	}
	return inventory.AIDiscoveryReport{
		Summary: inventory.AIDiscoverySummary{
			ScanID: scanID, Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: 4, ActiveSignals: 4, NewSignals: newCount,
		},
		Signals: []inventory.AISignal{
			{
				// File-based Ollama manifest.
				SignalID: "model_file_ollama", Fingerprint: "fp-file", SignatureID: "local-model-artifact",
				Category: inventory.SignalLocalModel, Vendor: "Ollama", Product: "Ollama", Confidence: .98,
				State: state, Detector: "model_file", EvidenceHash: "ev-file",
				Model: &inventory.LocalModelInfo{
					ID: "llama3.2:3b", Status: "installed", Format: "ollama", Provider: "ollama",
					Modality: "generative", SizeBytes: 2019393189, OwnerApplication: "Ollama", Relevance: "primary",
				},
			},
			{
				// The same model reported loaded by the loopback /api/ps probe.
				SignalID: "model_api_ollama", Fingerprint: "fp-api", SignatureID: "ollama",
				Category: inventory.SignalLocalModel, Vendor: "Ollama", Product: "Ollama", Confidence: .99,
				State: state, Detector: "model_runtime", EvidenceHash: "ev-api",
				Model: &inventory.LocalModelInfo{ID: "llama3.2:3b", Status: "loaded", Format: "GGUF", Provider: "ollama"},
			},
			{
				// A model whose identity could not be resolved.
				SignalID: "model_file_noid", Fingerprint: "fp-noid", SignatureID: "local-model-artifact",
				Category: inventory.SignalLocalModel, Vendor: "Local", Product: "Local Model Artifact", Confidence: .9,
				State: state, Detector: "model_file", EvidenceHash: "ev-noid",
				Model: &inventory.LocalModelInfo{
					Status: "installed", Format: "pth", Provider: "filesystem", Modality: "bogus", Relevance: "embedded",
				},
			},
			{
				SignalID: "ai-skill-alpha", SignatureID: "skill", Category: inventory.SignalSkill,
				Vendor: "local", Product: "alpha", Confidence: .9, State: state,
				Detector: "skill_dir", EvidenceHash: "ev-skill",
				// A malformed internal signal must not move model data across the
				// category boundary.
				Model: &inventory.LocalModelInfo{ID: "must-not-escape", Status: "installed"},
			},
		},
	}
}

func localModelRecordsByComponent(t *testing.T, records []observability.Record) (map[string]map[string]any, map[string]any) {
	t.Helper()
	byID := map[string]map[string]any{}
	var summary map[string]any
	for _, record := range records {
		body := canonicalBody(t, record)
		if record.EventName() == "ai.discovery.completed" {
			summary = body
			continue
		}
		if id, ok := body[observability.TelemetryAttributeDefenseClawAIComponentID].(string); ok {
			byID[id] = body
		}
	}
	return byID, summary
}

func TestSecureClientExportsLocalModelIdentity(t *testing.T) {
	for _, state := range []string{inventory.AIStateNew, inventory.AIStateSeen} {
		t.Run(state, func(t *testing.T) {
			withManagedEnterprise(t, true)
			capture := &endpointInventoryCapture{}
			adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: managedPublishTestState(t), secureClient: true}
			if err := adapter.EmitReport(t.Context(), localModelExportReport("scan-sc-"+state, state), nil); err != nil {
				t.Fatal(err)
			}
			byID, summary := localModelRecordsByComponent(t, capture.snapshot())
			if len(byID) != 4 || summary == nil {
				t.Fatalf("records=%d summary=%v", len(byID), summary != nil)
			}
			wantKey := inventory.LocalModelKey("ollama", "llama3.2:3b")
			file := byID["model_file_ollama"]
			for field, want := range map[string]any{
				observability.TelemetryAttributeDefenseClawAIModelID:               "llama3.2:3b",
				observability.TelemetryAttributeDefenseClawAIModelKey:              wantKey,
				observability.TelemetryAttributeDefenseClawAIModelProvider:         "ollama",
				observability.TelemetryAttributeDefenseClawAIModelStatus:           "installed",
				observability.TelemetryAttributeDefenseClawAIModelFormat:           "ollama",
				observability.TelemetryAttributeDefenseClawAIModelModality:         "generative",
				observability.TelemetryAttributeDefenseClawAIModelOwnerApplication: "Ollama",
				observability.TelemetryAttributeDefenseClawAIModelRelevance:        "primary",
			} {
				if got := file[field]; got != want {
					t.Errorf("file %s=%T(%v) want %v", field, got, got, want)
				}
			}
			if got := numberValue(file[observability.TelemetryAttributeDefenseClawAIModelSizeBytes]); got != 2019393189 {
				t.Errorf("file size=%v want 2019393189", file[observability.TelemetryAttributeDefenseClawAIModelSizeBytes])
			}

			api := byID["model_api_ollama"]
			if api[observability.TelemetryAttributeDefenseClawAIModelKey] != wantKey {
				t.Errorf("api key=%v want the file key %v", api[observability.TelemetryAttributeDefenseClawAIModelKey], wantKey)
			}
			if api[observability.TelemetryAttributeDefenseClawAIModelStatus] != "loaded" ||
				api[observability.TelemetryAttributeDefenseClawAIModelFormat] != "gguf" {
				t.Errorf("api status/format=%v/%v", api[observability.TelemetryAttributeDefenseClawAIModelStatus], api[observability.TelemetryAttributeDefenseClawAIModelFormat])
			}

			noID := byID["model_file_noid"]
			if _, ok := noID[observability.TelemetryAttributeDefenseClawAIModelID]; ok {
				t.Errorf("model without an ID exported an id: %v", noID)
			}
			if _, ok := noID[observability.TelemetryAttributeDefenseClawAIModelKey]; ok {
				t.Errorf("model without an ID exported a key: %v", noID)
			}
			for field, want := range map[string]any{
				observability.TelemetryAttributeDefenseClawAIModelProvider:  "filesystem",
				observability.TelemetryAttributeDefenseClawAIModelFormat:    "pytorch",
				observability.TelemetryAttributeDefenseClawAIModelModality:  "unknown",
				observability.TelemetryAttributeDefenseClawAIModelRelevance: "embedded",
			} {
				if got := noID[field]; got != want {
					t.Errorf("no-id %s=%v want %v", field, got, want)
				}
			}

			skill := byID["ai-skill-alpha"]
			for _, field := range localModelExportFields {
				if _, ok := skill[field]; ok {
					t.Errorf("non-model record carries %s", field)
				}
			}

			if summary[observability.TelemetryAttributeDefenseClawAIDiscoverySnapshotPublished] != true {
				t.Errorf("snapshot_published=%v want true", summary[observability.TelemetryAttributeDefenseClawAIDiscoverySnapshotPublished])
			}
			if got := numberValue(summary[observability.TelemetryAttributeDefenseClawAIDiscoveryLocalModelSignals]); got != 3 {
				t.Errorf("local_model_signals=%v want 3", summary[observability.TelemetryAttributeDefenseClawAIDiscoveryLocalModelSignals])
			}
		})
	}
}

// TestSecureClientSuppressedSnapshotReportsZero: when the unchanged-inventory
// gate suppresses the snapshot, the summary says so and counts no records, so
// AI Defense never reconciles against it.
func TestSecureClientSuppressedSnapshotReportsZero(t *testing.T) {
	withManagedEnterprise(t, true)
	gate := managedPublishTestState(t)
	// Two full fanouts settle the gate (the endpoint hook stamps the bundle).
	for _, scanID := range []string{"scan-1", "scan-2"} {
		managedGateFanout(t, gate, managedGateReport(scanID, "alpha"))
	}
	capture := &endpointInventoryCapture{}
	adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: gate, secureClient: true}
	report := managedGateReport("scan-3", "alpha")
	report.Signals = append(report.Signals[:0:0], report.Signals...)
	if err := adapter.EmitReport(t.Context(), report, nil); err != nil {
		t.Fatal(err)
	}
	_, summary := localModelRecordsByComponent(t, capture.snapshot())
	if counts := managedGateScanCounts(capture.snapshot()); counts["ai_component.observed"] != 0 {
		t.Fatalf("steady state republished: %v", counts)
	}
	if summary[observability.TelemetryAttributeDefenseClawAIDiscoverySnapshotPublished] != false {
		t.Errorf("snapshot_published=%v want false", summary[observability.TelemetryAttributeDefenseClawAIDiscoverySnapshotPublished])
	}
	if got := numberValue(summary[observability.TelemetryAttributeDefenseClawAIDiscoveryLocalModelSignals]); got != 0 {
		t.Errorf("local_model_signals=%v want 0", got)
	}
}

// failingFirstEmitCapture fails the first record it is asked to emit and
// captures the rest, standing in for a managed destination that rejects one
// record of the snapshot.
type failingFirstEmitCapture struct {
	*endpointInventoryCapture
	calls int
}

func (capture *failingFirstEmitCapture) Emit(
	ctx context.Context,
	metadata router.Metadata,
	build observabilityruntime.EmitBuilder,
) (pipeline.LocalLogOutcome, error) {
	capture.calls++
	if capture.calls == 1 {
		return pipeline.LocalLogOutcome{}, errors.New("managed destination rejected the record")
	}
	return capture.endpointInventoryCapture.Emit(ctx, metadata, build)
}

// TestSecureClientRejectedRecordUnpublishesSnapshot: the Secure Client summary
// is emitted after the records and reflects their outcomes, so a scan in which
// one record was not sent never claims a complete, published snapshot.
func TestSecureClientRejectedRecordUnpublishesSnapshot(t *testing.T) {
	withManagedEnterprise(t, true)
	capture := &failingFirstEmitCapture{endpointInventoryCapture: &endpointInventoryCapture{}}
	adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: managedPublishTestState(t), secureClient: true}
	if err := adapter.EmitReport(t.Context(), localModelExportReport("scan-sc-reject", inventory.AIStateNew), nil); err == nil {
		t.Fatal("EmitReport returned nil after a record failed")
	}
	records := capture.snapshot()
	byID, summary := localModelRecordsByComponent(t, records)
	if summary == nil {
		t.Fatal("summary was not emitted after a failed record")
	}
	if _, ok := byID["model_file_ollama"]; ok {
		t.Fatal("the failed record was captured")
	}
	if records[len(records)-1].EventName() != "ai.discovery.completed" {
		t.Errorf("Secure Client summary is not the last record: %s", records[len(records)-1].EventName())
	}
	if summary[observability.TelemetryAttributeDefenseClawAIDiscoverySnapshotPublished] != false {
		t.Errorf("snapshot_published=%v want false", summary[observability.TelemetryAttributeDefenseClawAIDiscoverySnapshotPublished])
	}
	if got := numberValue(summary[observability.TelemetryAttributeDefenseClawAIDiscoveryLocalModelSignals]); got != 0 {
		t.Errorf("local_model_signals=%v want 0", got)
	}
}

// TestNonSecureClientModesExportNoLocalModelIdentity pins OSS per-user and
// standalone managed: none of the Spec 016 fields appear, and the installed
// model ID never reaches a record.
func TestNonSecureClientModesExportNoLocalModelIdentity(t *testing.T) {
	cases := []struct {
		name       string
		standalone bool
	}{
		{name: "oss"},
		{name: "standalone", standalone: true},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			withManagedEnterprise(t, false)
			previous := standaloneEnterpriseActive.Load()
			standaloneEnterpriseActive.Store(tc.standalone)
			t.Cleanup(func() { standaloneEnterpriseActive.Store(previous) })

			capture := &endpointInventoryCapture{}
			adapter := &aiDiscoveryV8Adapter{runtime: capture, publishGate: managedPublishTestState(t)}
			if err := adapter.EmitReport(t.Context(), localModelExportReport("scan-"+tc.name, inventory.AIStateNew), nil); err != nil {
				t.Fatal(err)
			}
			records := capture.snapshot()
			if len(records) == 0 {
				t.Fatal("no records emitted")
			}
			for _, record := range records {
				body := canonicalBody(t, record)
				for _, field := range append(append([]string{}, localModelExportFields...), localModelSummaryFields...) {
					if _, ok := body[field]; ok {
						t.Errorf("%s record carries %s in mode %s", record.EventName(), field, tc.name)
					}
				}
				encoded, err := json.Marshal(body)
				if err != nil {
					t.Fatal(err)
				}
				if strings.Contains(string(encoded), "llama3.2:3b") || strings.Contains(string(encoded), "must-not-escape") {
					t.Errorf("model ID escaped in mode %s: %s", tc.name, encoded)
				}
			}
		})
	}
}

func TestAIDiscoveryV8AdapterResolvesSecureClientFromConfig(t *testing.T) {
	if aiDiscoveryV8SecureClient(nil) {
		t.Fatal("nil config must not resolve to Secure Client")
	}
	if aiDiscoveryV8SecureClient(&config.Config{}) {
		t.Fatal("an OSS config must not resolve to Secure Client")
	}
	capture := &endpointInventoryCapture{}
	adapter, ok := newAIDiscoveryV8Adapter(capture, nil, true).(*aiDiscoveryV8Adapter)
	if !ok || !adapter.secureClient {
		t.Fatalf("constructor dropped the resolved profile: %#v", adapter)
	}
	adapter, ok = newAIDiscoveryV8Adapter(capture, nil, false).(*aiDiscoveryV8Adapter)
	if !ok || adapter.secureClient {
		t.Fatalf("constructor set Secure Client for a non Secure Client config: %#v", adapter)
	}
}

func numberValue(value any) int64 {
	switch v := value.(type) {
	case int64:
		return v
	case int:
		return int64(v)
	case float64:
		return int64(v)
	case json.Number:
		n, _ := v.Int64()
		return n
	default:
		return -1
	}
}
