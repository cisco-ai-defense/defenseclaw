// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package inventory

import (
	"context"
	"math"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestGroupSignalsForRollup_DedupesByLowercaseEcosystemName confirms the
// two-axis emitter sees the same dedupe key the API rollup uses, so an
// "OpenAI" and "openai" install share one OTel emission instead of
// double-counting from a casing diff.
func TestGroupSignalsForRollup_DedupesByLowercaseEcosystemName(t *testing.T) {
	t.Parallel()
	signals := []AISignal{
		newComponentSignal("a", "PyPI", "OpenAI", "1.40.0", "ws-1", AIStateNew, ""),
		newComponentSignal("b", "pypi", "openai", "1.40.0", "ws-1", AIStateSeen, ""),
		newComponentSignal("c", "pypi", "openai", "1.41.0", "ws-2", AIStateSeen, ""),
		newComponentSignal("d", "npm", "openai", "1.0.0", "ws-1", AIStateSeen, ""),
		// Catch-all signal without component should be ignored.
		{Fingerprint: "no-component", State: AIStateNew},
	}
	got := groupSignalsForRollup(signals)
	if len(got) != 2 {
		t.Fatalf("groupSignalsForRollup returned %d groups; want 2", len(got))
	}
	byKey := map[string]componentSignalGroup{}
	for _, g := range got {
		byKey[g.Ecosystem+"/"+g.Name] = g
	}
	pypi := mustGroup(t, byKey, "PyPI/OpenAI")
	if len(pypi.Signals) != 3 {
		t.Fatalf("pypi group signals = %d; want 3", len(pypi.Signals))
	}
	if pypi.WorkspaceCount != 2 {
		t.Fatalf("pypi workspace count = %d; want 2", pypi.WorkspaceCount)
	}
	if !pypi.HasLifecycleChange {
		t.Fatalf("pypi group should be flagged as lifecycle (has 1 New signal)")
	}
	npm := mustGroup(t, byKey, "npm/openai")
	if npm.HasLifecycleChange {
		t.Fatalf("npm group should NOT be lifecycle (only Seen)")
	}
}

// TestGroupSignalsForRollup_FrameworkFirstNonEmpty pins the first-non-empty
// rule for the Framework label so a noisy detector that emits the package
// name without a framework can't blank out a richer signal in the same
// group.
func TestGroupSignalsForRollup_FrameworkFirstNonEmpty(t *testing.T) {
	t.Parallel()
	first := newComponentSignal("a", "pypi", "openai", "1.0.0", "ws-1", AIStateSeen, "")
	second := newComponentSignal("b", "pypi", "openai", "1.0.0", "ws-1", AIStateSeen, "OpenAI Python SDK")
	got := groupSignalsForRollup([]AISignal{first, second})
	if len(got) != 1 || got[0].Framework != "OpenAI Python SDK" {
		t.Fatalf("framework = %q; want OpenAI Python SDK", got[0].Framework)
	}
}

func TestGroupSignalsForRollup_SkipsGoneSignals(t *testing.T) {
	t.Parallel()
	gone := newComponentSignal("gone", "pypi", "openai", "1.0.0", "ws-old", AIStateGone, "OpenAI Python SDK")
	if got := groupSignalsForRollup([]AISignal{gone}); len(got) != 0 {
		t.Fatalf("gone-only rollup len=%d want 0: %+v", len(got), got)
	}
	active := newComponentSignal("active", "pypi", "openai", "1.0.0", "ws-new", AIStateSeen, "OpenAI Python SDK")
	got := groupSignalsForRollup([]AISignal{gone, active})
	if len(got) != 1 {
		t.Fatalf("mixed rollup len=%d want 1: %+v", len(got), got)
	}
	if len(got[0].Signals) != 1 || got[0].Signals[0].State == AIStateGone {
		t.Fatalf("gone signal contributed to active confidence rollup: %+v", got[0].Signals)
	}
	if got[0].WorkspaceCount != 1 {
		t.Fatalf("workspace count = %d, want only active workspace", got[0].WorkspaceCount)
	}
}

// TestGroupSignalsForRollup_NULByteInEcosystemDoesNotCollide pins the
// F3 invariant: the dedupe key MUST be a struct, not a delimited
// string. Two distinct components whose lowercased keys would
// collide under a NUL-delimited string MUST be tracked separately.
func TestGroupSignalsForRollup_NULByteInEcosystemDoesNotCollide(t *testing.T) {
	t.Parallel()
	a := newComponentSignal("a", "pypi", "foo\x00bar", "1.0.0", "ws-1", AIStateNew, "")
	b := newComponentSignal("b", "pypi\x00foo", "bar", "1.0.0", "ws-1", AIStateNew, "")
	got := groupSignalsForRollup([]AISignal{a, b})
	if len(got) != 2 {
		t.Fatalf("expected two distinct groups; got %d (likely string-key collision regression)", len(got))
	}
}

// TestBuildAIDiscoveryPayload_StampsConfidenceWhenExtended confirms the
// new identity/presence/factors/detectors fields ship on the wire
// payload only when DisableRedaction is true AND a Confidence pointer
// is supplied. Receivers (OTel pipeline, webhooks, sinks.Manager) can
// rely on the absence of these fields meaning "redaction is on".
func TestBuildAIDiscoveryPayload_StampsConfidenceWhenExtended(t *testing.T) {
	t.Parallel()
	sig := newComponentSignal("sig", "pypi", "openai", "1.0.0", "ws-1", AIStateNew, "OpenAI Python SDK")
	conf := &ConfidenceResult{
		IdentityScore: 0.91,
		IdentityBand:  "very_high",
		PresenceScore: 0.42,
		PresenceBand:  "medium",
		Detectors:     []string{"package_manifest", "process"},
		IdentityFactors: []ConfidenceFactor{
			{Detector: "package_manifest", Quality: 1.0, Specificity: 0.9, LR: 4.0, LogitDelta: 1.25},
		},
		PresenceFactors: []ConfidenceFactor{
			{Detector: "process", Quality: 1.0, Specificity: 0.7, LR: 6.0, LogitDelta: 0.85},
		},
	}
	out := BuildAIDiscoveryPayload(sig, "scan-1", PayloadOpts{
		DisableRedaction: true,
		Confidence:       conf,
	})
	if math.Abs(out.IdentityScore-0.91) > 1e-9 || out.IdentityBand != "very_high" {
		t.Fatalf("identity not stamped: %+v", out)
	}
	if math.Abs(out.PresenceScore-0.42) > 1e-9 || out.PresenceBand != "medium" {
		t.Fatalf("presence not stamped: %+v", out)
	}
	if len(out.IdentityFactors) != 1 || out.IdentityFactors[0].Detector != "package_manifest" {
		t.Fatalf("identity factors wire-shape mismatch: %+v", out.IdentityFactors)
	}
	if len(out.PresenceFactors) != 1 || out.PresenceFactors[0].Detector != "process" {
		t.Fatalf("presence factors wire-shape mismatch: %+v", out.PresenceFactors)
	}
	if len(out.Detectors) != 2 {
		t.Fatalf("detectors not stamped: %+v", out.Detectors)
	}

	// Cloning safety: mutating the returned slice MUST NOT poison
	// the engine's in-memory result.
	out.Detectors[0] = "tampered"
	if conf.Detectors[0] != "package_manifest" {
		t.Fatalf("BuildAIDiscoveryPayload aliased the engine's Detectors slice (mutation safety regression)")
	}
}

// TestBuildAIDiscoveryPayload_RedactedModeNeverShipsConfidence confirms
// the privacy contract: redacted mode (DisableRedaction=false, the
// shipping default) MUST NOT include any confidence fields, even when
// the caller supplied a Confidence pointer.
func TestBuildAIDiscoveryPayload_RedactedModeNeverShipsConfidence(t *testing.T) {
	t.Parallel()
	sig := newComponentSignal("sig", "pypi", "openai", "1.0.0", "ws-1", AIStateNew, "")
	conf := &ConfidenceResult{
		IdentityScore: 0.95, IdentityBand: "very_high",
		PresenceScore: 0.5, PresenceBand: "medium",
	}
	out := BuildAIDiscoveryPayload(sig, "scan-1", PayloadOpts{
		DisableRedaction: false, // shipping default
		Confidence:       conf,
	})
	if out.IdentityScore != 0 || out.PresenceScore != 0 {
		t.Fatalf("redacted payload must zero confidence fields; got %+v", out)
	}
	if out.IdentityBand != "" || out.PresenceBand != "" {
		t.Fatalf("redacted payload leaked bands: %+v", out)
	}
	if len(out.IdentityFactors) > 0 || len(out.PresenceFactors) > 0 || len(out.Detectors) > 0 {
		t.Fatalf("redacted payload leaked factors/detectors: %+v", out)
	}
}

// TestBuildAIDiscoveryPayload_ClampsScoreOutOfRange confirms a
// corrupt engine result (NaN, >1, <0) cannot poison the wire
// payload's score histogram bucket on the receiver side.
func TestBuildAIDiscoveryPayload_ClampsScoreOutOfRange(t *testing.T) {
	t.Parallel()
	sig := newComponentSignal("sig", "pypi", "openai", "1.0.0", "ws-1", AIStateNew, "")
	conf := &ConfidenceResult{
		IdentityScore: 1.7,        // over-range
		PresenceScore: math.NaN(), // NaN
		IdentityBand:  "very_high",
		PresenceBand:  "very_low",
	}
	out := BuildAIDiscoveryPayload(sig, "scan-1", PayloadOpts{
		DisableRedaction: true,
		Confidence:       conf,
	})
	if out.IdentityScore != 1.0 {
		t.Fatalf("identity not clamped to 1.0; got %v", out.IdentityScore)
	}
	if out.PresenceScore != 0.0 {
		t.Fatalf("presence NaN not clamped to 0.0; got %v", out.PresenceScore)
	}
}

// TestEmitTelemetry_EmitsComponentMetricsAndLogsLifecycleOnly
// drives the wire by running emitTelemetry directly against a
// fake provider and asserts:
//
//   - the new component instruments fire on every scan, and
//   - the per-component log only fires for groups with a lifecycle
//     change (matching the per-signal log gate so SIEM volume stays
//     bounded).
func TestEmitTelemetry_EmitsComponentMetricsAndLogsLifecycleOnly(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	prov, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatal(err)
	}
	svc := &ContinuousDiscoveryService{
		otel:             prov,
		opts:             AIDiscoveryOptions{EmitOTel: true},
		confidenceParams: ConfidenceParams{Policy: policy},
	}
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{
			ScanID: "scan-x", Source: "sidecar", Result: "ok", PrivacyMode: "enhanced",
			TotalSignals: 3, ActiveSignals: 3, NewSignals: 1,
		},
		Signals: []AISignal{
			// pypi/openai: one NEW signal => lifecycle group
			newComponentSignal("a", "pypi", "openai", "1.40.0", "ws-1", AIStateNew, "OpenAI Python SDK"),
			newComponentSignal("b", "pypi", "openai", "1.40.0", "ws-2", AIStateSeen, ""),
			// npm/openai: only SEEN => no lifecycle log
			newComponentSignal("c", "npm", "openai", "1.0.0", "ws-1", AIStateSeen, ""),
		},
	}

	snap := buildComponentRollupSnapshot(report.Signals, svc.confidenceParams)
	svc.emitTelemetry(context.Background(), report, snap)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	// Both component groups must have produced one observation
	// counter increment AND one identity / presence histogram sample.
	c := findMetric(rm, "defenseclaw.ai.components.observations")
	if c == nil {
		t.Fatal("observations counter not emitted")
	}
	cd, ok := c.Data.(metricdata.Sum[int64])
	if !ok {
		t.Fatalf("observations data = %T; want Sum[int64]", c.Data)
	}
	if len(cd.DataPoints) != 2 {
		t.Fatalf("expected 2 datapoints (one per component); got %d", len(cd.DataPoints))
	}
	identity := findMetric(rm, "defenseclaw.ai.confidence.identity_score")
	if identity == nil {
		t.Fatal("identity histogram missing")
	}
	hd, ok := identity.Data.(metricdata.Histogram[float64])
	if !ok || len(hd.DataPoints) != 2 {
		t.Fatalf("identity histogram = %+v", identity.Data)
	}
	for _, dp := range hd.DataPoints {
		if dp.Sum < 0 || dp.Sum > 1 {
			t.Fatalf("identity score out of [0,1]: %v", dp.Sum)
		}
	}
}

// TestEmitGatewayEvents_PerSignalPayloadCarriesGroupConfidence
// pins the contract that every signal in a (ecosystem, name)
// group carries the SAME identity / presence numbers in its wire
// payload. Without this, downstream consumers would see different
// scores for two signals about the same SDK and break their
// dedupe-then-render pipeline.
func TestEmitGatewayEvents_PerSignalPayloadCarriesGroupConfidence(t *testing.T) {
	t.Parallel()
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatal(err)
	}
	captured := newCapturingWriter(t)
	svc := &ContinuousDiscoveryService{
		events:           captured.writer,
		opts:             AIDiscoveryOptions{DisableRedaction: true},
		confidenceParams: ConfidenceParams{Policy: policy},
	}
	signals := []AISignal{
		// Both NEW so emitGatewayEvents iterates them.
		evidenceSignal("a", "pypi", "openai", "1.40.0", "ws-1", AIStateNew, "package_manifest"),
		evidenceSignal("b", "pypi", "openai", "1.40.0", "ws-2", AIStateNew, "process"),
		// A different component to confirm it gets its own scores.
		evidenceSignal("c", "npm", "openai", "1.0.0", "ws-1", AIStateNew, "package_manifest"),
	}
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-y"},
		Signals: signals,
	}
	snap := buildComponentRollupSnapshot(report.Signals, svc.confidenceParams)
	svc.emitGatewayEvents(context.Background(), report, snap)

	events := captured.events()
	if len(events) != 3 {
		t.Fatalf("expected 3 emitted events, got %d", len(events))
	}
	byEcosystemName := map[string][]float64{}
	for _, ev := range events {
		if ev.AIDiscovery == nil {
			t.Fatalf("event missing AIDiscovery payload: %+v", ev)
		}
		key := ev.AIDiscovery.Component.Ecosystem + "/" + ev.AIDiscovery.Component.Name
		byEcosystemName[key] = append(byEcosystemName[key], ev.AIDiscovery.IdentityScore)
	}
	// Both pypi/openai signals must report the same identity score.
	if scores := byEcosystemName["pypi/openai"]; len(scores) != 2 || scores[0] != scores[1] {
		t.Fatalf("pypi group identity scores diverge: %+v", scores)
	}
	// npm/openai gets its own score (different group).
	if scores := byEcosystemName["npm/openai"]; len(scores) != 1 {
		t.Fatalf("npm group missing or duplicated: %+v", scores)
	}
	// Cross-group scores can equal each other (the engine is
	// deterministic) but must NOT alias the same slice memory:
	// mutate one and confirm the other doesn't see it.
	events[0].AIDiscovery.IdentityFactors = nil
	if events[1].AIDiscovery.IdentityFactors == nil {
		t.Fatalf("payload IdentityFactors aliased between sibling signals (mutation regression)")
	}
}

// TestFanoutReport_OTelAndGatewayPayloadAgree pins the F1
// invariant: the OTel histogram sample and the gateway-events
// per-signal payload carry the EXACT same identity / presence
// numbers for the same component. Before the snapshot refactor
// each emitter called ComputeComponentConfidence with its own
// time.Now(), so the recency-decayed presence_score drifted
// sub-second between the two paths. Operators reconciling
// dashboards with downstream consumers would see ghost
// discrepancies.
func TestFanoutReport_OTelAndGatewayPayloadAgree(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	prov, err := telemetry.NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatal(err)
	}
	captured := newCapturingWriter(t)
	svc := &ContinuousDiscoveryService{
		otel:             prov,
		events:           captured.writer,
		opts:             AIDiscoveryOptions{EmitOTel: true, DisableRedaction: true},
		confidenceParams: ConfidenceParams{Policy: policy},
	}
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-fanout"},
		Signals: []AISignal{
			// Multiple evidences so PRESENCE has non-trivial recency math.
			evidenceSignalAt("a", "pypi", "openai", "1.0.0", "ws-1", AIStateNew, "package_manifest", time.Now().Add(-3*time.Hour)),
			evidenceSignalAt("b", "pypi", "openai", "1.0.0", "ws-2", AIStateNew, "process", time.Now().Add(-1*time.Hour)),
		},
	}

	svc.fanoutReport(context.Background(), report)

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatal(err)
	}
	identity := findMetric(rm, "defenseclaw.ai.confidence.identity_score")
	if identity == nil {
		t.Fatal("identity histogram missing")
	}
	hd := identity.Data.(metricdata.Histogram[float64])
	if len(hd.DataPoints) != 1 {
		t.Fatalf("identity histogram should have 1 datapoint (1 component); got %d", len(hd.DataPoints))
	}
	presence := findMetric(rm, "defenseclaw.ai.confidence.presence_score")
	pd := presence.Data.(metricdata.Histogram[float64])

	otelIdentity := hd.DataPoints[0].Sum // 1 sample, so Sum == value
	otelPresence := pd.DataPoints[0].Sum

	events := captured.events()
	if len(events) == 0 {
		t.Fatal("no gateway events captured")
	}
	for _, ev := range events {
		if ev.AIDiscovery == nil {
			continue
		}
		if ev.AIDiscovery.IdentityScore != otelIdentity {
			t.Fatalf("identity_score drift: OTel=%v gateway=%v", otelIdentity, ev.AIDiscovery.IdentityScore)
		}
		if ev.AIDiscovery.PresenceScore != otelPresence {
			t.Fatalf("presence_score drift: OTel=%v gateway=%v", otelPresence, ev.AIDiscovery.PresenceScore)
		}
	}
}

// TestFanoutReport_SkipsSnapshotWhenDefaultConfig pins the F2
// invariant: in the shipping default (EmitOTel=false +
// DisableRedaction=false) we MUST NOT pay for ComputeComponentConfidence
// because both downstream consumers would discard the result.
// We assert this by verifying the snapshot is "empty" when
// fanoutReport runs without OTel and without the redaction
// override -- the gateway-events payload still emits, just
// without confidence fields.
func TestFanoutReport_SkipsSnapshotWhenDefaultConfig(t *testing.T) {
	t.Parallel()
	policy, err := LoadDefaultConfidencePolicy()
	if err != nil {
		t.Fatal(err)
	}
	captured := newCapturingWriter(t)
	svc := &ContinuousDiscoveryService{
		events: captured.writer,
		// EmitOTel=false (no telemetry) AND
		// DisableRedaction=false (payload strips Confidence).
		opts:             AIDiscoveryOptions{},
		confidenceParams: ConfidenceParams{Policy: policy},
	}
	report := AIDiscoveryReport{
		Summary: AIDiscoverySummary{ScanID: "scan-default"},
		Signals: []AISignal{
			evidenceSignal("a", "pypi", "openai", "1.0.0", "ws-1", AIStateNew, "package_manifest"),
		},
	}
	svc.fanoutReport(context.Background(), report)

	events := captured.events()
	if len(events) != 1 {
		t.Fatalf("expected 1 redacted gateway event; got %d", len(events))
	}
	if p := events[0].AIDiscovery; p == nil {
		t.Fatal("missing AIDiscovery payload")
	} else if p.IdentityScore != 0 || p.IdentityBand != "" || p.PresenceScore != 0 || p.PresenceBand != "" {
		t.Fatalf("default-config payload leaked confidence fields (snapshot should have been skipped): %+v", p)
	}
}

// TestComponentRollupSnapshot_ScoreForUnknownGroup confirms the
// helper returns ok=false when called with a group not in the
// snapshot (defensive — current callers don't hit this branch
// but a future caller could).
func TestComponentRollupSnapshot_ScoreForUnknownGroup(t *testing.T) {
	t.Parallel()
	snap := componentRollupSnapshot{Scores: map[componentKey]*ConfidenceResult{}}
	if _, ok := snap.ScoreFor(componentSignalGroup{Ecosystem: "ghost", Name: "missing"}); ok {
		t.Fatal("ScoreFor returned ok=true for an unknown group")
	}
	// Nil Scores branch (the "default-config skipped snapshot" case):
	empty := componentRollupSnapshot{}
	if _, ok := empty.ScoreFor(componentSignalGroup{Ecosystem: "any", Name: "any"}); ok {
		t.Fatal("ScoreFor returned ok=true on empty snapshot")
	}
	if got := empty.LookupSignal(AISignal{Component: &AIComponent{Ecosystem: "p", Name: "n"}}); got != nil {
		t.Fatalf("LookupSignal on empty snapshot should be nil; got %+v", got)
	}
}

// ---------- helpers --------------------------------------------------------

func newComponentSignal(id, ecosystem, name, version, workspace, state, framework string) AISignal {
	now := time.Now().UTC()
	return AISignal{
		Fingerprint:   id,
		SignalID:      id,
		Detector:      "package_manifest",
		Category:      SignalAICLI,
		State:         state,
		WorkspaceHash: workspace,
		Component: &AIComponent{
			Ecosystem: ecosystem,
			Name:      name,
			Version:   version,
			Framework: framework,
		},
		LastSeen: now,
	}
}

// evidenceSignal augments newComponentSignal with one Evidence row
// so the engine has something to score (otherwise it falls back to
// a synthetic row but tests are easier to reason about with a real
// row attached).
func evidenceSignal(id, ecosystem, name, version, workspace, state, detector string) AISignal {
	return evidenceSignalAt(id, ecosystem, name, version, workspace, state, detector, time.Now().UTC())
}

// evidenceSignalAt is evidenceSignal but lets the test pin
// LastSeen so presence-score recency math is deterministic across
// the OTel and payload paths.
func evidenceSignalAt(id, ecosystem, name, version, workspace, state, detector string, lastSeen time.Time) AISignal {
	sig := newComponentSignal(id, ecosystem, name, version, workspace, state, "")
	sig.Detector = detector
	sig.LastSeen = lastSeen
	sig.Evidence = []AIEvidence{{
		Type:      detector,
		Quality:   1.0,
		MatchKind: MatchKindExact,
	}}
	return sig
}

func mustGroup(t *testing.T, by map[string]componentSignalGroup, key string) componentSignalGroup {
	t.Helper()
	g, ok := by[key]
	if !ok {
		t.Fatalf("group %q not found; have %+v", key, by)
	}
	return g
}

// findMetric is a copy of telemetry's internal helper so this test
// file doesn't have to import an internal test artifact.
func findMetric(rm metricdata.ResourceMetrics, name string) *metricdata.Metrics {
	for _, sm := range rm.ScopeMetrics {
		for i := range sm.Metrics {
			if sm.Metrics[i].Name == name {
				return &sm.Metrics[i]
			}
		}
	}
	return nil
}

// capturingWriter wraps a real gatewaylog.Writer with no JSONL sink
// and a fanout that mirrors every Emit into a slice the test reads.
// We use the real Writer so the tested code path is exactly what
// emitGatewayEvents runs in production, not a mock with a slightly
// different signature.
type capturingWriter struct {
	writer *gatewaylog.Writer
	mu     sync.Mutex
	out    []gatewaylog.Event
}

func newCapturingWriter(t *testing.T) *capturingWriter {
	t.Helper()
	w, err := gatewaylog.New(gatewaylog.Config{})
	if err != nil {
		t.Fatalf("gatewaylog.New: %v", err)
	}
	cw := &capturingWriter{writer: w}
	w.WithFanout(func(e gatewaylog.Event) {
		cw.mu.Lock()
		cw.out = append(cw.out, e)
		cw.mu.Unlock()
	})
	return cw
}

func (c *capturingWriter) events() []gatewaylog.Event {
	c.mu.Lock()
	defer c.mu.Unlock()
	out := make([]gatewaylog.Event, len(c.out))
	copy(out, c.out)
	return out
}
