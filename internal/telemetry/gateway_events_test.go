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
	"encoding/json"
	"strings"
	"testing"
	"time"

	"go.opentelemetry.io/otel/log"
	metricdata "go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdklog "go.opentelemetry.io/otel/sdk/log"

	sdkmetric "go.opentelemetry.io/otel/sdk/metric"

	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

// intAttrValue is the int64 counterpart to the helper in
// pii_redaction_test.go (attrValue covers strings only).
func intAttrValue(r sdklog.Record, key string) (int64, bool) {
	var (
		out   int64
		found bool
	)
	r.WalkAttributes(func(kv log.KeyValue) bool {
		if string(kv.Key) == key {
			if kv.Value.Kind() == log.KindInt64 {
				out = kv.Value.AsInt64()
				found = true
			}
			return false
		}
		return true
	})
	return out, found
}

func TestGatewaySeverityToOTel(t *testing.T) {
	cases := []struct {
		in      gatewaylog.Severity
		wantT   string
		wantNum int
	}{
		{gatewaylog.SeverityCritical, "CRITICAL", 21},
		{gatewaylog.SeverityHigh, "ERROR", 17},
		{gatewaylog.SeverityMedium, "WARN", 13},
		{gatewaylog.SeverityLow, "INFO2", 10},
		{gatewaylog.SeverityInfo, "INFO", 9},
		{gatewaylog.Severity(""), "INFO", 9},
		{gatewaylog.Severity("bogus"), "INFO", 9}, // fail-open on unknown
	}
	for _, tt := range cases {
		t.Run(string(tt.in), func(t *testing.T) {
			gotT, gotN := gatewaySeverityToOTel(tt.in)
			if gotT != tt.wantT || gotN != tt.wantNum {
				t.Fatalf("gatewaySeverityToOTel(%q)=(%s,%d) want (%s,%d)",
					tt.in, gotT, gotN, tt.wantT, tt.wantNum)
			}
		})
	}
}

func TestRenderGatewayBody_IsValidJSONWithPayload(t *testing.T) {
	e := gatewaylog.Event{
		EventType: gatewaylog.EventVerdict,
		Severity:  gatewaylog.SeverityHigh,
		Model:     "gpt-4",
		Verdict: &gatewaylog.VerdictPayload{
			Stage: gatewaylog.StageFinal, Action: "block",
			Reason: "pii-detected", LatencyMs: 42,
		},
	}
	body := renderGatewayBody(e)
	var parsed map[string]any
	if err := json.Unmarshal([]byte(body), &parsed); err != nil {
		t.Fatalf("body not JSON: %v (%s)", err, body)
	}
	if parsed["event_type"] != string(gatewaylog.EventVerdict) {
		t.Fatalf("event_type missing from body: %v", parsed)
	}
}

// TestEmitGatewayEvent_VerdictLogAttributes verifies every top-level
// envelope field + verdict-specific attribute lands on the OTel log
// record. This is the contract receivers (Splunk/Loki/Grafana)
// rely on for routing without parsing the body JSON.
func TestEmitGatewayEvent_VerdictLogAttributes(t *testing.T) {
	p, exp := newProviderWithLogCapture(t)

	e := gatewaylog.Event{
		Timestamp: time.Unix(1700000000, 0).UTC(),
		EventType: gatewaylog.EventVerdict,
		Severity:  gatewaylog.SeverityHigh,
		RunID:     "run-1", RequestID: "req-1", SessionID: "sess-1",
		Provider: "openai", Model: "gpt-4",
		Direction: gatewaylog.DirectionPrompt,
		Verdict: &gatewaylog.VerdictPayload{
			Stage: gatewaylog.StageFinal, Action: "block",
			Reason: "injection-high", LatencyMs: 125,
			Categories: []string{"prompt-injection", "pii"},
		},
	}
	p.EmitGatewayEvent(e)

	records := exp.snapshot()
	if len(records) != 1 {
		t.Fatalf("records=%d want 1", len(records))
	}
	rec := records[0]
	if got := rec.SeverityText(); got != "ERROR" {
		t.Fatalf("severity text=%q want ERROR (high → ERROR)", got)
	}
	if got := attrValue(rec, "defenseclaw.gateway.event_type"); got != "verdict" {
		t.Fatalf("event_type attr=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.run_id"); got != "run-1" {
		t.Fatalf("run_id attr=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.llm.model"); got != "gpt-4" {
		t.Fatalf("model attr=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.verdict.stage"); got != "final" {
		t.Fatalf("stage attr=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.verdict.action"); got != "block" {
		t.Fatalf("action attr=%q", got)
	}
	if got, ok := intAttrValue(rec, "defenseclaw.verdict.latency_ms"); !ok || got != 125 {
		t.Fatalf("latency_ms attr=%d ok=%v", got, ok)
	}
	if got := attrValue(rec, "defenseclaw.verdict.categories"); got != "prompt-injection,pii" {
		t.Fatalf("categories attr=%q", got)
	}
}

func TestEmitGatewayEvent_JudgeAttributes(t *testing.T) {
	p, exp := newProviderWithLogCapture(t)
	p.EmitGatewayEvent(gatewaylog.Event{
		Timestamp: time.Now(), EventType: gatewaylog.EventJudge,
		Severity: gatewaylog.SeverityMedium, Model: "gpt-4",
		Judge: &gatewaylog.JudgePayload{
			Kind: "injection", Action: "alert", LatencyMs: 280,
			InputBytes: 512, ParseError: "",
		},
	})
	rec := exp.snapshot()[0]
	if got := attrValue(rec, "defenseclaw.judge.kind"); got != "injection" {
		t.Fatalf("judge.kind=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.judge.action"); got != "alert" {
		t.Fatalf("judge.action=%q", got)
	}
	if got, _ := intAttrValue(rec, "defenseclaw.judge.latency_ms"); got != 280 {
		t.Fatalf("judge.latency_ms=%d", got)
	}
}

func TestEmitGatewayEvent_LifecycleAttributes(t *testing.T) {
	p, exp := newProviderWithLogCapture(t)
	p.EmitGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventLifecycle, Severity: gatewaylog.SeverityInfo,
		Lifecycle: &gatewaylog.LifecyclePayload{
			Subsystem: "gateway", Transition: "init",
		},
	})
	rec := exp.snapshot()[0]
	if got := attrValue(rec, "defenseclaw.lifecycle.subsystem"); got != "gateway" {
		t.Fatalf("lifecycle.subsystem=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.lifecycle.transition"); got != "init" {
		t.Fatalf("lifecycle.transition=%q", got)
	}
}

func TestEmitGatewayEvent_ErrorAttributesWithCause(t *testing.T) {
	p, exp := newProviderWithLogCapture(t)
	p.EmitGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventError, Severity: gatewaylog.SeverityHigh,
		Error: &gatewaylog.ErrorPayload{
			Subsystem: "guardrail", Code: "policy-compile-failed",
			Cause: "syntax error at line 12",
		},
	})
	rec := exp.snapshot()[0]
	if got := attrValue(rec, "defenseclaw.error.subsystem"); got != "guardrail" {
		t.Fatalf("error.subsystem=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.error.code"); got != "policy-compile-failed" {
		t.Fatalf("error.code=%q", got)
	}
	if got := attrValue(rec, "defenseclaw.error.cause"); !strings.Contains(got, "syntax error") {
		t.Fatalf("error.cause=%q", got)
	}
}

func TestEmitGatewayEvent_NilPayloadDoesNotPanic(t *testing.T) {
	// Contract: a verdict event with a nil Verdict payload is an
	// observability bug, but must not crash the sidecar. The envelope
	// still emits; typed attrs are simply absent.
	p, exp := newProviderWithLogCapture(t)
	p.EmitGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventVerdict, Severity: gatewaylog.SeverityInfo,
	})
	if got := len(exp.snapshot()); got != 1 {
		t.Fatalf("records=%d want 1 (envelope still emits on nil payload)", got)
	}
}

func TestRecordGatewayEvent_UpdatesMetrics(t *testing.T) {
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTest(reader)
	if err != nil {
		t.Fatalf("NewProviderForTest: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })

	// Two verdicts (one block, one allow), one judge invocation (alert),
	// one judge-error, one gateway error.
	p.RecordGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventVerdict, Severity: gatewaylog.SeverityHigh,
		Verdict: &gatewaylog.VerdictPayload{Stage: gatewaylog.StageFinal, Action: "block"},
	})
	p.RecordGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventVerdict, Severity: gatewaylog.SeverityInfo,
		Verdict: &gatewaylog.VerdictPayload{Stage: gatewaylog.StageFinal, Action: "allow"},
	})
	p.RecordGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventJudge, Severity: gatewaylog.SeverityMedium,
		Judge: &gatewaylog.JudgePayload{Kind: "pii", Action: "alert", LatencyMs: 75},
	})
	p.RecordGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventJudge, Severity: gatewaylog.SeverityHigh,
		Judge: &gatewaylog.JudgePayload{Kind: "injection", Action: "error", ParseError: "json"},
	})
	p.RecordGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventError, Severity: gatewaylog.SeverityHigh,
		Error: &gatewaylog.ErrorPayload{Subsystem: "router", Code: "timeout"},
	})

	// Force a collection so the async instruments emit.
	var rm metricdata.ResourceMetrics
	if err := reader.Collect(context.Background(), &rm); err != nil {
		t.Fatalf("Collect: %v", err)
	}

	counts := map[string]int64{}
	for _, sm := range rm.ScopeMetrics {
		for _, m := range sm.Metrics {
			switch data := m.Data.(type) {
			case metricdata.Sum[int64]:
				for _, dp := range data.DataPoints {
					counts[m.Name] += dp.Value
				}
			case metricdata.Histogram[float64]:
				counts[m.Name] += int64(data.DataPoints[0].Count)
			}
		}
	}

	// 2 verdicts total, 2 judge invocations, 1 judge error, 1 gateway error.
	expectations := map[string]int64{
		"defenseclaw.gateway.verdicts":        2,
		"defenseclaw.gateway.judge.invocations": 2,
		"defenseclaw.gateway.judge.errors":    1,
		"defenseclaw.gateway.errors":          1,
	}
	for name, want := range expectations {
		if got, ok := counts[name]; !ok || got != want {
			t.Errorf("metric %s=%d ok=%v want %d (all counts: %+v)",
				name, got, ok, want, counts)
		}
	}
	// judge.latency is a histogram — we expect at least one observation.
	if counts["defenseclaw.gateway.judge.latency"] == 0 {
		t.Errorf("judge.latency histogram never observed: %+v", counts)
	}
}

func TestRecordGatewayEvent_IsNoopWhenDisabled(t *testing.T) {
	// A zero-value Provider reports Enabled()=false — this is the path
	// exercised when telemetry is intentionally off (no sink, no
	// exporter). Recording must not panic or allocate metrics state.
	var p Provider
	p.RecordGatewayEvent(gatewaylog.Event{
		EventType: gatewaylog.EventVerdict,
		Verdict:   &gatewaylog.VerdictPayload{Stage: gatewaylog.StageFinal},
	})
}
