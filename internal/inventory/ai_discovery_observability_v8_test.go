// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"strings"
	"sync"
	"testing"
	"time"
)

type captureAIDiscoveryV8 struct {
	mu         sync.Mutex
	starts     []AIDiscoveryV8ScanStart
	reports    []AIDiscoveryReport
	components [][]AIDiscoveryV8ComponentObservation
	trace      *captureAIDiscoveryV8Trace
}

func (capture *captureAIDiscoveryV8) StartScan(
	ctx context.Context,
	start AIDiscoveryV8ScanStart,
) (context.Context, AIDiscoveryV8ScanTrace, error) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.starts = append(capture.starts, start)
	capture.trace = &captureAIDiscoveryV8Trace{}
	return context.WithValue(ctx, aiDiscoveryV8ContextKey{}, "v8"), capture.trace, nil
}

func (capture *captureAIDiscoveryV8) EmitReport(
	_ context.Context,
	report AIDiscoveryReport,
	components []AIDiscoveryV8ComponentObservation,
) error {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	capture.reports = append(capture.reports, cloneAIDiscoveryReport(report))
	capture.components = append(capture.components, append([]AIDiscoveryV8ComponentObservation(nil), components...))
	return nil
}

func (*captureAIDiscoveryV8) RecordSQLiteBusyMetric(context.Context, string) error { return nil }

type aiDiscoveryV8ContextKey struct{}

type captureAIDiscoveryV8Trace struct {
	mu        sync.Mutex
	starts    []AIDiscoveryV8DetectorStart
	results   []AIDiscoveryV8DetectorResult
	ended     []AIDiscoveryReport
	abortCall int
}

func (capture *captureAIDiscoveryV8Trace) StartDetector(start AIDiscoveryV8DetectorStart) (AIDiscoveryV8DetectorTrace, error) {
	capture.mu.Lock()
	capture.starts = append(capture.starts, start)
	capture.mu.Unlock()
	return &captureAIDiscoveryV8DetectorCapture{parent: capture}, nil
}

func (capture *captureAIDiscoveryV8Trace) End(report AIDiscoveryReport) error {
	capture.mu.Lock()
	capture.ended = append(capture.ended, cloneAIDiscoveryReport(report))
	capture.mu.Unlock()
	return nil
}

func (capture *captureAIDiscoveryV8Trace) Abort() {
	capture.mu.Lock()
	capture.abortCall++
	capture.mu.Unlock()
}

type captureAIDiscoveryV8DetectorCapture struct{ parent *captureAIDiscoveryV8Trace }

func (capture *captureAIDiscoveryV8DetectorCapture) End(result AIDiscoveryV8DetectorResult) error {
	capture.parent.mu.Lock()
	capture.parent.results = append(capture.parent.results, result)
	capture.parent.mu.Unlock()
	return nil
}

func (*captureAIDiscoveryV8DetectorCapture) Abort() {}

func TestAIDiscoveryV8AuthorityOwnsTraceAcrossEndAndDetach(t *testing.T) {
	service := &ContinuousDiscoveryService{}
	capture := &captureAIDiscoveryV8{}
	service.BindObservabilityV8(capture)
	start := time.Now().UTC().Add(-time.Second)
	ctx, observation := service.startScanObservation(t.Context(), AIDiscoveryV8ScanStart{
		ScanID: "scan-1", Source: "api", PrivacyMode: "enhanced", StartedAt: start,
	})
	if got := ctx.Value(aiDiscoveryV8ContextKey{}); got != "v8" || observation == nil {
		t.Fatalf("started context=%v observation=%+v", got, observation)
	}
	detector := observation.startDetector(ctx, service, AIDiscoveryV8DetectorStart{
		ScanID: "scan-1", Detector: "process", StartedAt: start.Add(time.Millisecond),
	})
	detector.end(AIDiscoveryV8DetectorResult{
		EndedAt: start.Add(2 * time.Millisecond), DurationMs: 1, SignalsTotal: 2,
	})
	report := AIDiscoveryReport{Summary: AIDiscoverySummary{ScanID: "scan-1", Result: "ok"}}
	observation.end(report)
	observation.abort()
	if len(capture.starts) != 1 || capture.trace == nil || len(capture.trace.starts) != 1 ||
		len(capture.trace.results) != 1 || len(capture.trace.ended) != 1 || capture.trace.abortCall != 1 {
		t.Fatalf("capture=%+v trace=%+v", capture, capture.trace)
	}

	service.BindObservabilityV8(nil)
	_, detached := service.startScanObservation(t.Context(), AIDiscoveryV8ScanStart{
		ScanID: "scan-2", Source: "scheduled", PrivacyMode: "enhanced", StartedAt: start,
	})
	if detached == nil || detached.generated != nil || len(capture.starts) != 1 {
		t.Fatalf("detached observation=%+v starts=%d", detached, len(capture.starts))
	}
}

func TestAIDiscoveryV8BindingOwnsInventorySQLiteContention(t *testing.T) {
	store := &InventoryStore{}
	service := &ContinuousDiscoveryService{invStore: store}
	capture := &captureAIDiscoveryV8{}
	service.BindObservabilityV8(capture)
	if store.sqliteBusyObservabilityV8() != capture {
		t.Fatal("inventory store did not receive the generated contention observer")
	}
	service.BindObservabilityV8(nil)
	if store.sqliteBusyObservabilityV8() != nil {
		t.Fatal("inventory store retained contention observer after detach")
	}
}

func TestAIDiscoveryV8FanoutUsesOneRollupAndDoesNotResurrectLegacyAfterDetach(t *testing.T) {
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatal(err)
	}
	service := &ContinuousDiscoveryService{
		confidenceParams: ConfidenceParams{Policy: policy},
	}
	capture := &captureAIDiscoveryV8{}
	service.BindObservabilityV8(capture)
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID: "scan-1", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: 1, ActiveSignals: 1, NewSignals: 1,
		},
		Signals: []AISignal{newComponentSignal(
			"signal-1", "pypi", "openai", "1.0.0", "workspace-1", AIStateNew, "OpenAI SDK",
		)},
	}
	service.fanoutReport(t.Context(), report)
	if len(capture.reports) != 1 || len(capture.components) != 1 || len(capture.components[0]) != 1 {
		t.Fatalf("reports=%d components=%v", len(capture.reports), capture.components)
	}
	component := capture.components[0][0]
	if component.ComponentID == "" || component.ComponentType == "" || !component.HasLifecycleChange ||
		component.Metrics.Ecosystem != "pypi" || component.Metrics.Name != "openai" {
		t.Fatalf("component=%+v", component)
	}

	service.BindObservabilityV8(nil)
	service.fanoutReport(t.Context(), report)
	if len(capture.reports) != 1 {
		t.Fatalf("detached v8 fanout resurrected an emitter: reports=%d", len(capture.reports))
	}
}

func TestAIDiscoveryV8ModelLifecycleUsesInstallationKeyedPseudonym(t *testing.T) {
	savedKey := currentPathHashKey()
	t.Cleanup(func() { SetPathHashKey(savedKey) })

	fingerprint := hashValue("local-model|lemonade|private-model|model_api")
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID: "scan-model", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
			TotalSignals: 1, ActiveSignals: 1, NewSignals: 1,
		},
		Signals: []AISignal{{
			Fingerprint: fingerprint,
			SignalID:    stableSignalID(fingerprint),
			Category:    SignalLocalModel,
			Detector:    "model_api",
			Vendor:      "AMD",
			Product:     "Lemonade",
			State:       AIStateNew,
			// Even a malformed/external model signal cannot inject its ID into
			// the component metric name label.
			Component: &AIComponent{Ecosystem: "model", Name: "private-model"},
			Model:     &LocalModelInfo{ID: "private-model", Status: "installed", Provider: "lemonade"},
		}},
	}

	service := &ContinuousDiscoveryService{}
	capture := &captureAIDiscoveryV8{}
	service.BindObservabilityV8(capture)

	SetPathHashKey([]byte("installation-a"))
	service.fanoutReport(t.Context(), report)
	service.fanoutReport(t.Context(), report)
	if len(capture.reports) != 2 || len(capture.reports[0].Signals) != 1 {
		t.Fatalf("reports=%d first=%+v", len(capture.reports), capture.reports)
	}
	firstID := capture.reports[0].Signals[0].SignalID
	if !strings.HasPrefix(firstID, "model_") || firstID == report.Signals[0].SignalID {
		t.Fatalf("model lifecycle id %q is not an installation-keyed pseudonym", firstID)
	}
	if secondID := capture.reports[1].Signals[0].SignalID; secondID != firstID {
		t.Fatalf("same installation key produced unstable IDs: %q != %q", secondID, firstID)
	}
	if len(capture.components) != 2 || len(capture.components[0]) != 0 {
		t.Fatalf("local model entered component metric labels: %+v", capture.components)
	}

	SetPathHashKey([]byte("installation-b"))
	service.fanoutReport(t.Context(), report)
	thirdID := capture.reports[2].Signals[0].SignalID
	if thirdID == firstID {
		t.Fatalf("different installation keys produced the same lifecycle id %q", thirdID)
	}
	SetPathHashKey(nil)
	service.fanoutReport(t.Context(), report)
	if unkeyedID := capture.reports[3].Signals[0].SignalID; unkeyedID != "" {
		t.Fatalf("unkeyed model lifecycle correlation was not omitted: %q", unkeyedID)
	}
	if report.Signals[0].SignalID != stableSignalID(fingerprint) {
		t.Fatalf("v8 projection mutated the local report: %+v", report.Signals[0])
	}
}

var _ AIDiscoveryObservabilityV8 = (*captureAIDiscoveryV8)(nil)

type droppedAIDiscoveryV8 struct{ reports int }

func (*droppedAIDiscoveryV8) StartScan(
	ctx context.Context,
	_ AIDiscoveryV8ScanStart,
) (context.Context, AIDiscoveryV8ScanTrace, error) {
	return ctx, nil, nil
}

func (observer *droppedAIDiscoveryV8) EmitReport(
	_ context.Context,
	_ AIDiscoveryReport,
	_ []AIDiscoveryV8ComponentObservation,
) error {
	observer.reports++
	return nil
}

func TestAIDiscoveryV8DroppedTraceAndReportStayOnCanonicalAdapter(t *testing.T) {
	observer := &droppedAIDiscoveryV8{}
	service := &ContinuousDiscoveryService{}
	service.BindObservabilityV8(observer)
	start := time.Now().UTC().Add(-time.Second)
	ctx, observation := service.startScanObservation(t.Context(), AIDiscoveryV8ScanStart{
		ScanID: "scan-drop", Source: "scheduled", PrivacyMode: "enhanced", StartedAt: start,
	})
	detector := observation.startDetector(ctx, service, AIDiscoveryV8DetectorStart{
		ScanID: "scan-drop", Detector: "process", StartedAt: start,
	})
	detector.end(AIDiscoveryV8DetectorResult{EndedAt: start.Add(time.Millisecond), DurationMs: 1})
	report := AIDiscoveryReport{Summary: AIDiscoverySummary{
		ScanID: "scan-drop", Source: "scheduled", PrivacyMode: "enhanced", Result: "ok",
	}}
	service.fanoutReport(ctx, report)
	observation.end(report)
	observation.abort()

	if observer.reports != 1 {
		t.Fatalf("canonical report calls=%d want one", observer.reports)
	}
}

var _ AIDiscoveryObservabilityV8 = (*droppedAIDiscoveryV8)(nil)
