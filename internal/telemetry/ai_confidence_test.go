// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"math"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	otellog "go.opentelemetry.io/otel/log"
	sdklog "go.opentelemetry.io/otel/sdk/log"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
)

// TestRecordAIComponentConfidence_EmitsAllInstruments pins the
// metric names + units the dashboards subscribe to and confirms
// each call records exactly one data point. Adding new
// instruments to the engine is fine; renaming or removing one
// breaks downstream alerting and must trip this test.
func TestRecordAIComponentConfidence_EmitsAllInstruments(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordAIComponentConfidence(ctx, AIComponentConfidenceAttrs{
		Ecosystem:      "pypi",
		Name:           "openai",
		Framework:      "langchain",
		IdentityScore:  0.93,
		IdentityBand:   "very_high",
		PresenceScore:  0.62,
		PresenceBand:   "medium",
		InstallCount:   3,
		WorkspaceCount: 2,
		PolicyVersion:  1,
		DetectorCount:  4,
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}

	c := findCounter(rm, "defenseclaw.ai.components.observations")
	if c == nil {
		t.Fatal("observations counter missing")
	}
	if c.Unit != "{observation}" {
		t.Fatalf("observations unit = %q want {observation}", c.Unit)
	}
	cd, ok := c.Data.(metricdata.Sum[int64])
	if !ok || len(cd.DataPoints) != 1 || cd.DataPoints[0].Value != 1 {
		t.Fatalf("observations counter = %+v", c.Data)
	}
	mustHaveAttr(t, cd.DataPoints[0].Attributes, "ecosystem", "pypi")
	mustHaveAttr(t, cd.DataPoints[0].Attributes, "name", "openai")
	mustHaveAttr(t, cd.DataPoints[0].Attributes, "identity_band", "very_high")
	mustHaveAttr(t, cd.DataPoints[0].Attributes, "presence_band", "medium")

	installs := findGauge(rm, "defenseclaw.ai.components.installs")
	if installs == nil {
		t.Fatal("installs gauge missing")
	}
	gd, ok := installs.Data.(metricdata.Gauge[int64])
	if !ok || len(gd.DataPoints) != 1 || gd.DataPoints[0].Value != 3 {
		t.Fatalf("installs gauge = %+v", installs.Data)
	}

	workspaces := findGauge(rm, "defenseclaw.ai.components.workspaces")
	if workspaces == nil {
		t.Fatal("workspaces gauge missing")
	}
	wd, _ := workspaces.Data.(metricdata.Gauge[int64])
	if len(wd.DataPoints) != 1 || wd.DataPoints[0].Value != 2 {
		t.Fatalf("workspaces gauge = %+v", workspaces.Data)
	}

	identity := findHistogram(rm, "defenseclaw.ai.confidence.identity_score")
	if identity == nil {
		t.Fatal("identity histogram missing")
	}
	if identity.Unit != "1" {
		t.Fatalf("identity histogram unit = %q want 1", identity.Unit)
	}
	hd, ok := identity.Data.(metricdata.Histogram[float64])
	if !ok || len(hd.DataPoints) != 1 || hd.DataPoints[0].Count != 1 {
		t.Fatalf("identity histogram = %+v", identity.Data)
	}
	if math.Abs(hd.DataPoints[0].Sum-0.93) > 1e-9 {
		t.Fatalf("identity histogram sum = %v want 0.93", hd.DataPoints[0].Sum)
	}
	mustHaveAttr(t, hd.DataPoints[0].Attributes, "ecosystem", "pypi")
	mustHaveAttr(t, hd.DataPoints[0].Attributes, "framework", "langchain")

	presence := findHistogram(rm, "defenseclaw.ai.confidence.presence_score")
	if presence == nil {
		t.Fatal("presence histogram missing")
	}
	pd, _ := presence.Data.(metricdata.Histogram[float64])
	if math.Abs(pd.DataPoints[0].Sum-0.62) > 1e-9 {
		t.Fatalf("presence histogram sum = %v want 0.62", pd.DataPoints[0].Sum)
	}
}

// TestRecordAIComponentConfidence_NoOpWhenDisabled guards the
// nil-provider / disabled-provider branches so we never panic in a
// prod build that has the feature disabled.
func TestRecordAIComponentConfidence_NoOpWhenDisabled(t *testing.T) {
	t.Parallel()
	var p *Provider
	// Should not panic on a nil receiver.
	p.RecordAIComponentConfidence(context.Background(), AIComponentConfidenceAttrs{
		Ecosystem: "npm", Name: "openai",
	})
	p.EmitAIComponentConfidenceLog(context.Background(), AIComponentConfidenceAttrs{
		Ecosystem: "npm", Name: "openai",
	})
}

// TestRecordAIComponentConfidence_NormalizesLabels confirms blank
// ecosystem / name fall back to "unknown" so we never emit
// metrics with empty-string labels (which break a few popular
// Prom UIs).
func TestRecordAIComponentConfidence_NormalizesLabels(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordAIComponentConfidence(ctx, AIComponentConfidenceAttrs{
		IdentityScore: 0.5,
		PresenceScore: 0.5,
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	c := findCounter(rm, "defenseclaw.ai.components.observations")
	if c == nil {
		t.Fatal("observations counter missing")
	}
	cd := c.Data.(metricdata.Sum[int64])
	mustHaveAttr(t, cd.DataPoints[0].Attributes, "ecosystem", "unknown")
	mustHaveAttr(t, cd.DataPoints[0].Attributes, "name", "unknown")
	mustHaveAttr(t, cd.DataPoints[0].Attributes, "identity_band", "unknown")
}

// TestRecordAIComponentConfidence_ClampsScoreOutOfRange protects
// the histogram +Inf bucket from a corrupt engine output. The
// engine targets [0,1] but a future calibration bug shouldn't be
// allowed to skew dashboards.
func TestRecordAIComponentConfidence_ClampsScoreOutOfRange(t *testing.T) {
	t.Parallel()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatal(err)
	}
	ctx := context.Background()
	p.RecordAIComponentConfidence(ctx, AIComponentConfidenceAttrs{
		Ecosystem:     "pypi",
		Name:          "openai",
		IdentityScore: 1.7,
		PresenceScore: -0.4,
	})

	var rm metricdata.ResourceMetrics
	if err := reader.Collect(ctx, &rm); err != nil {
		t.Fatal(err)
	}
	identity := findHistogram(rm, "defenseclaw.ai.confidence.identity_score")
	hd := identity.Data.(metricdata.Histogram[float64])
	if hd.DataPoints[0].Sum != 1.0 {
		t.Fatalf("identity sum = %v want 1.0 (clamp)", hd.DataPoints[0].Sum)
	}
	presence := findHistogram(rm, "defenseclaw.ai.confidence.presence_score")
	pd := presence.Data.(metricdata.Histogram[float64])
	if pd.DataPoints[0].Sum != 0.0 {
		t.Fatalf("presence sum = %v want 0.0 (clamp)", pd.DataPoints[0].Sum)
	}
}

// TestClampUnitInterval covers the helper used by both metrics
// and wire payloads. NaN inputs must return 0 so the OTel
// histogram never sees a NaN sample.
func TestClampUnitInterval(t *testing.T) {
	t.Parallel()
	cases := []struct {
		in, want float64
	}{
		{-1.5, 0},
		{0, 0},
		{0.5, 0.5},
		{1, 1},
		{1.7, 1},
		{math.NaN(), 0},
	}
	for _, tc := range cases {
		got := clampUnitInterval(tc.in)
		if got != tc.want && !(math.IsNaN(tc.in) && got == 0) {
			t.Fatalf("clampUnitInterval(%v) = %v want %v", tc.in, got, tc.want)
		}
	}
}

// mustHaveAttr asserts the attribute set carries (key,value) and
// fails with the actual contents on mismatch. Keeps the per-test
// boilerplate minimal so adding new label assertions stays cheap.
func mustHaveAttr(t *testing.T, set attribute.Set, key, want string) {
	t.Helper()
	v, ok := set.Value(attribute.Key(key))
	if !ok {
		t.Fatalf("attribute %q missing; have %v", key, set.ToSlice())
	}
	if v.AsString() != want {
		t.Fatalf("attribute %q = %q want %q", key, v.AsString(), want)
	}
}

// TestEmitAIComponentConfidenceLog_INFOSeverityCarriesAllAttrs pins
// the INFO branch of the per-component log: every documented
// attribute key MUST be present and the body MUST identify the
// event domain so SIEM filters keep working.
func TestEmitAIComponentConfidenceLog_INFOSeverityCarriesAllAttrs(t *testing.T) {
	t.Parallel()
	p, exp := newProviderWithLogCapture(t)
	ctx := context.Background()
	p.EmitAIComponentConfidenceLog(ctx, AIComponentConfidenceAttrs{
		Ecosystem:      "pypi",
		Name:           "openai",
		Framework:      "langchain",
		IdentityScore:  0.75,
		IdentityBand:   "high",
		PresenceScore:  0.62, // > 0.2 so we stay on INFO
		PresenceBand:   "medium",
		InstallCount:   3,
		WorkspaceCount: 2,
		PolicyVersion:  4,
		DetectorCount:  5,
	})
	rec := requireOneAIConfidenceRecord(t, exp)
	if rec.Severity() != otellog.SeverityInfo {
		t.Fatalf("severity = %v; want INFO", rec.Severity())
	}
	if got := logAttrString(rec, "event.name"); got != "defenseclaw.ai.confidence.component" {
		t.Fatalf("event.name = %q", got)
	}
	if got := logAttrString(rec, "event.domain"); got != "defenseclaw.ai_visibility" {
		t.Fatalf("event.domain = %q", got)
	}
	if got := logAttrString(rec, "ai.component.ecosystem"); got != "pypi" {
		t.Fatalf("ecosystem = %q", got)
	}
	if got := logAttrString(rec, "ai.confidence.identity_band"); got != "high" {
		t.Fatalf("identity_band = %q", got)
	}
	if got := logAttrFloat64(rec, "ai.confidence.identity_score"); math.Abs(got-0.75) > 1e-9 {
		t.Fatalf("identity_score = %v", got)
	}
	if got := logAttrInt64(rec, "ai.component.install_count"); got != 3 {
		t.Fatalf("install_count = %d", got)
	}
	if got := logAttrInt64(rec, "ai.confidence.policy_version"); got != 4 {
		t.Fatalf("policy_version = %d", got)
	}
}

// TestEmitAIComponentConfidenceLog_WARNOnHighIdentityLowPresence
// pins the operator-alert branch: identity_score >= 0.7 AND
// presence_score <= 0.2 means "we're confident this SDK was here
// but it isn't running anymore". This is the signal SIEM rules
// fire on; flipping the threshold or losing it must trip this
// test.
func TestEmitAIComponentConfidenceLog_WARNOnHighIdentityLowPresence(t *testing.T) {
	t.Parallel()
	p, exp := newProviderWithLogCapture(t)
	ctx := context.Background()
	p.EmitAIComponentConfidenceLog(ctx, AIComponentConfidenceAttrs{
		Ecosystem:     "pypi",
		Name:          "openai",
		IdentityScore: 0.91,
		IdentityBand:  "very_high",
		PresenceScore: 0.05, // <= 0.2
		PresenceBand:  "very_low",
	})
	rec := requireOneAIConfidenceRecord(t, exp)
	if rec.Severity() != otellog.SeverityWarn {
		t.Fatalf("severity = %v; want WARN", rec.Severity())
	}
}

// TestEmitAIComponentConfidenceLog_INFOJustBelowWARNThreshold pins
// the OFF-by-one boundary so a small policy tweak doesn't flip a
// well-calibrated dashboard from INFO to WARN. presence == 0.21 is
// healthy enough to stay informational even with high identity.
func TestEmitAIComponentConfidenceLog_INFOJustBelowWARNThreshold(t *testing.T) {
	t.Parallel()
	p, exp := newProviderWithLogCapture(t)
	ctx := context.Background()
	p.EmitAIComponentConfidenceLog(ctx, AIComponentConfidenceAttrs{
		Ecosystem:     "pypi",
		Name:          "openai",
		IdentityScore: 0.91,
		PresenceScore: 0.21, // just over 0.2 threshold
	})
	rec := requireOneAIConfidenceRecord(t, exp)
	if rec.Severity() != otellog.SeverityInfo {
		t.Fatalf("severity = %v; want INFO at boundary (presence=0.21)", rec.Severity())
	}
}

// TestEmitAIComponentConfidenceLog_NormalizesAndClampsBeforeEmit
// confirms the same defenses the metric path applies are also
// applied to the log path: NaN scores become 0, blank labels fall
// back to "unknown". Without this a WARN-on-NaN bug would page
// the on-call.
func TestEmitAIComponentConfidenceLog_NormalizesAndClampsBeforeEmit(t *testing.T) {
	t.Parallel()
	p, exp := newProviderWithLogCapture(t)
	ctx := context.Background()
	p.EmitAIComponentConfidenceLog(ctx, AIComponentConfidenceAttrs{
		IdentityScore: math.NaN(),
		PresenceScore: 1.7,
	})
	rec := requireOneAIConfidenceRecord(t, exp)
	if got := logAttrFloat64(rec, "ai.confidence.identity_score"); got != 0 {
		t.Fatalf("identity_score = %v; want 0 (NaN clamped)", got)
	}
	if got := logAttrFloat64(rec, "ai.confidence.presence_score"); got != 1 {
		t.Fatalf("presence_score = %v; want 1 (over-range clamped)", got)
	}
	if got := logAttrString(rec, "ai.component.ecosystem"); got != "unknown" {
		t.Fatalf("ecosystem = %q; want unknown (label fallback)", got)
	}
}

// TestEmitAIComponentConfidenceLog_NoOpWhenLogsDisabled covers the
// fast-path where an operator has metrics on but logs off; the
// method must return without touching the (nil) logger.
func TestEmitAIComponentConfidenceLog_NoOpWhenLogsDisabled(t *testing.T) {
	t.Parallel()
	// Provider with no logger configured is the production
	// default before the OTel exporter starts. LogsEnabled()
	// returns false and Emit must short-circuit.
	p := &Provider{enabled: true}
	p.EmitAIComponentConfidenceLog(context.Background(), AIComponentConfidenceAttrs{
		Ecosystem: "pypi", Name: "openai",
	})
	// Reaching here without panic is the assertion.
}

// requireOneAIConfidenceRecord returns the single
// "defenseclaw.ai.confidence.component" log record from the
// capture, failing the test if zero or more than one matched.
func requireOneAIConfidenceRecord(t *testing.T, exp *capturedLogExporter) sdklog.Record {
	t.Helper()
	var matched []sdklog.Record
	for _, rec := range exp.snapshot() {
		if logAttrString(rec, "event.name") == "defenseclaw.ai.confidence.component" {
			matched = append(matched, rec)
		}
	}
	if len(matched) != 1 {
		t.Fatalf("expected 1 ai.confidence.component log; got %d", len(matched))
	}
	return matched[0]
}

func logAttrString(r sdklog.Record, key string) string {
	var out string
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		if kv.Key == key && kv.Value.Kind() == otellog.KindString {
			out = kv.Value.AsString()
			return false
		}
		return true
	})
	return out
}

func logAttrFloat64(r sdklog.Record, key string) float64 {
	var out float64
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		if kv.Key == key && kv.Value.Kind() == otellog.KindFloat64 {
			out = kv.Value.AsFloat64()
			return false
		}
		return true
	})
	return out
}

func logAttrInt64(r sdklog.Record, key string) int64 {
	var out int64
	r.WalkAttributes(func(kv otellog.KeyValue) bool {
		if kv.Key == key && kv.Value.Kind() == otellog.KindInt64 {
			out = kv.Value.AsInt64()
			return false
		}
		return true
	})
	return out
}
