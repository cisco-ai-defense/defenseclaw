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
	"strings"
	"testing"

	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
)

func attrByKey(kv []attribute.KeyValue, key string) (attribute.Value, bool) {
	for _, a := range kv {
		if string(a.Key) == key {
			return a.Value, true
		}
	}
	return attribute.Value{}, false
}

func newTracingProvider(t *testing.T) (*Provider, *tracetest.InMemoryExporter) {
	t.Helper()
	exp := tracetest.NewInMemoryExporter()
	reader := sdkmetric.NewManualReader()
	p, err := NewProviderForTraceTest(reader, exp)
	if err != nil {
		t.Fatalf("NewProviderForTraceTest: %v", err)
	}
	t.Cleanup(func() { _ = p.Shutdown(context.Background()) })
	return p, exp
}

func TestStartGuardrailStageSpan_OpensSpanWithStageAttrs(t *testing.T) {
	p, exp := newTracingProvider(t)

	ctx, span := p.StartGuardrailStageSpan(context.Background(), "regex_judge", "prompt", "gpt-4")
	if span == nil {
		t.Fatal("span must not be nil when traces enabled")
	}
	if ctx == nil {
		t.Fatal("returned context is nil")
	}

	// End with a representative verdict — must attach the verdict attrs
	// and set status=Error when action==block.
	p.EndGuardrailStageSpan(span, "block", "HIGH", "prompt-injection matched", 120)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatalf("got %d spans want 1", len(spans))
	}
	s := spans[0]
	if want := "guardrail/regex_judge"; s.Name != want {
		t.Fatalf("name=%q want %q", s.Name, want)
	}

	// Stage / direction / model / action / severity / reason / latency.
	for _, pair := range [][2]string{
		{"defenseclaw.guardrail.stage", "regex_judge"},
		{"defenseclaw.guardrail.direction", "prompt"},
		{"defenseclaw.guardrail.model", "gpt-4"},
		{"defenseclaw.guardrail.action", "block"},
		{"defenseclaw.guardrail.severity", "HIGH"},
	} {
		v, ok := attrByKey(s.Attributes, pair[0])
		if !ok || v.AsString() != pair[1] {
			t.Errorf("attr %s=%v ok=%v want %q", pair[0], v.AsString(), ok, pair[1])
		}
	}
	if v, ok := attrByKey(s.Attributes, "defenseclaw.guardrail.latency_ms"); !ok || v.AsInt64() != 120 {
		t.Errorf("latency_ms=%d ok=%v", v.AsInt64(), ok)
	}

	// Block action → Error status so block-rate is queryable via span
	// status without custom filters.
	if s.Status.Code != codes.Error {
		t.Fatalf("status=%v want Error on block", s.Status.Code)
	}
}

func TestEndGuardrailStageSpan_TruncatesLongReason(t *testing.T) {
	p, exp := newTracingProvider(t)
	_, span := p.StartGuardrailStageSpan(context.Background(), "regex_only", "completion", "gpt-4")
	long := strings.Repeat("x", 1000)
	p.EndGuardrailStageSpan(span, "allow", "INFO", long, 5)

	spans := exp.GetSpans()
	if len(spans) != 1 {
		t.Fatal("no span")
	}
	reason, ok := attrByKey(spans[0].Attributes, "defenseclaw.guardrail.reason")
	if !ok {
		t.Fatal("reason attr missing")
	}
	if got := reason.AsString(); len(got) > 300 {
		t.Fatalf("reason not truncated: len=%d", len(got))
	}
}

func TestEndGuardrailStageSpan_AllowActionGetsOkStatus(t *testing.T) {
	p, exp := newTracingProvider(t)
	_, span := p.StartGuardrailStageSpan(context.Background(), "regex_only", "prompt", "gpt-4")
	p.EndGuardrailStageSpan(span, "allow", "INFO", "clean", 3)
	spans := exp.GetSpans()
	if spans[0].Status.Code != codes.Ok {
		t.Fatalf("status=%v want Ok on allow", spans[0].Status.Code)
	}
}

func TestStartGuardrailStageSpan_NilProviderSafe(t *testing.T) {
	// A Provider with no tracer must return (ctx, nil) rather than
	// panicking. End on nil must be a no-op per the OTel SDK contract.
	var p Provider
	ctx, span := p.StartGuardrailStageSpan(context.Background(), "regex_only", "prompt", "")
	if span != nil {
		t.Fatal("span must be nil when traces disabled")
	}
	if ctx == nil {
		t.Fatal("context must still be returned even when traces disabled")
	}
	// Must not panic.
	p.EndGuardrailStageSpan(span, "allow", "INFO", "", 0)
}
