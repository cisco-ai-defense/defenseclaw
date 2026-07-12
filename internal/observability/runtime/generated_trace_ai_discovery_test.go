// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package runtime

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func generatedAIDiscoveryInput(start, end time.Time) observability.SpanAIDiscoveryInput {
	return observability.SpanAIDiscoveryInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceSystem, Action: "ai_discovery", Phase: "scan",
			Correlation: observability.Correlation{RunID: "run-discovery-1"},
			Provenance:  observability.FamilyProvenanceInput{Producer: "inventory.ai_discovery"},
		},
		Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano: uint64(start.UnixNano()), EndTimeUnixNano: uint64(end.UnixNano()),
		Status:                                 observability.NewTraceStatusOK(),
		DefenseClawRunID:                       observability.Present("run-discovery-1"),
		DefenseClawAIDiscoveryScanID:           observability.Present("scan-1"),
		DefenseClawAIDiscoverySource:           observability.Present("scheduled"),
		DefenseClawAIDiscoveryPrivacyMode:      observability.Present("enhanced"),
		DefenseClawAIDiscoveryResult:           observability.Present("ok"),
		DefenseClawAIDiscoveryDurationMs:       observability.Present[int64](40),
		DefenseClawAIDiscoverySignalsTotal:     observability.Present[int64](3),
		DefenseClawAIDiscoveryActiveSignals:    observability.Present[int64](2),
		DefenseClawAIDiscoveryNewSignals:       observability.Present[int64](1),
		DefenseClawAIDiscoveryChangedSignals:   observability.Present[int64](1),
		DefenseClawAIDiscoveryGoneSignals:      observability.Present[int64](0),
		DefenseClawAIDiscoveryFilesScanned:     observability.Present[int64](5),
		DefenseClawAIDiscoveryDedupeSuppressed: observability.Present[int64](1),
		DefenseClawAIDiscoveryErrors:           observability.Present[int64](0),
		ConditionOperationTerminal:             true,
	}
}

func TestGeneratedAIDiscoveryTracePreservesScanDetectorTopologyAndFacts(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_on", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)

	start := time.Now().UTC().Add(-time.Second)
	rootInput := generatedAIDiscoveryInput(start, start.Add(40*time.Millisecond))
	ctx, root, err := runtime.StartAIDiscoveryTrace(t.Context(), rootInput)
	if err != nil || root == nil || ctx == nil || root.Generation() != 1 {
		t.Fatalf("start discovery trace=%v context=%v error=%v", root, ctx, err)
	}
	detectorInput := observability.SpanAIDiscoveryDetectorInput{
		Envelope: rootInput.Envelope, Outcome: observability.OutcomeCompleted, Kind: "INTERNAL",
		StartTimeUnixNano:                  uint64(start.Add(5 * time.Millisecond).UnixNano()),
		EndTimeUnixNano:                    uint64(start.Add(15 * time.Millisecond).UnixNano()),
		Status:                             observability.NewTraceStatusOK(),
		DefenseClawRunID:                   observability.Present("run-discovery-1"),
		DefenseClawAIDiscoveryScanID:       observability.Present("scan-1"),
		DefenseClawAIDiscoveryDetector:     "process",
		DefenseClawAIDiscoveryDurationMs:   observability.Present[int64](10),
		DefenseClawAIDiscoverySignalsTotal: observability.Present[int64](2),
		DefenseClawAIDiscoveryFilesScanned: observability.Present[int64](0),
		ConditionOperationTerminal:         true,
	}
	detector, err := root.StartDetector(detectorInput)
	if err != nil || detector == nil || detector.Generation() != 1 {
		t.Fatalf("start detector=%v error=%v", detector, err)
	}
	if err := detector.End(detectorInput); err != nil {
		t.Fatal(err)
	}
	if err := root.End(rootInput); err != nil {
		t.Fatal(err)
	}

	spans := pipelines.consumer(t, 1).snapshot()
	if len(spans) != 2 {
		t.Fatalf("canonical discovery spans=%d want detector + root", len(spans))
	}
	detectorSpan, rootSpan := spans[0], spans[1]
	if detectorSpan.Name() != "defenseclaw.ai.discovery.detector" ||
		rootSpan.Name() != "defenseclaw.ai.discovery" ||
		detectorSpan.Record().EventName() != observability.EventName(observability.TelemetryFamilyAIDiscoveryDetector) ||
		rootSpan.Record().EventName() != observability.EventName(observability.TelemetryFamilyAIDiscovery) {
		t.Fatalf("span identities detector=%q/%s root=%q/%s", detectorSpan.Name(), detectorSpan.Record().EventName(), rootSpan.Name(), rootSpan.Record().EventName())
	}
	parent, parentOK := detectorSpan.ParentSpanID()
	if !parentOK || parent != rootSpan.SpanID() || detectorSpan.TraceID() != rootSpan.TraceID() {
		t.Fatalf("discovery topology parent=%s/%t root=%s traces=%s/%s", parent, parentOK, rootSpan.SpanID(), detectorSpan.TraceID(), rootSpan.TraceID())
	}
	rootAttributes := generatedTraceRecordAttributes(t, rootSpan.Record())
	if rootAttributes["defenseclaw.ai.discovery.scan_id"] != "scan-1" ||
		rootAttributes["defenseclaw.ai.discovery.changed_signals"] != float64(1) ||
		rootAttributes["defenseclaw.ai.discovery.dedupe_suppressed"] != float64(1) ||
		rootAttributes["defenseclaw.config.generation"] != float64(1) {
		t.Fatalf("root discovery attributes=%v", rootAttributes)
	}
	detectorAttributes := generatedTraceRecordAttributes(t, detectorSpan.Record())
	if detectorAttributes["defenseclaw.ai.discovery.detector"] != "process" ||
		detectorAttributes["defenseclaw.ai.discovery.duration_ms"] != float64(10) ||
		detectorAttributes["defenseclaw.ai.discovery.signals_total"] != float64(2) {
		t.Fatalf("detector attributes=%v", detectorAttributes)
	}
}

func TestGeneratedAIDiscoveryTraceSamplingDropDoesNotConstructChildren(t *testing.T) {
	dependencies := newRuntimeTestDependencies(t)
	pipelines := &generatedTracePipelines{consumers: make(map[uint64]*generatedTraceConsumer)}
	plan := generatedTracePlan(t, dependencies, 90, "always_off", []observability.Bucket{"*"})
	runtime := newGeneratedTraceRuntime(t, dependencies, pipelines, plan)
	start := time.Now().UTC().Add(-time.Second)
	ctx, root, err := runtime.StartAIDiscoveryTrace(t.Context(), generatedAIDiscoveryInput(start, start.Add(time.Millisecond)))
	if err != nil || root != nil || ctx == nil {
		t.Fatalf("sampled discovery root=%v context=%v error=%v", root, ctx, err)
	}
	if spans := pipelines.consumer(t, 1).snapshot(); len(spans) != 0 {
		t.Fatalf("sampled discovery registered %d canonical spans", len(spans))
	}
}
