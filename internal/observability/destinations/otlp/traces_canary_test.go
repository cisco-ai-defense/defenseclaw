// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/codes"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
)

func TestCompleteOTLPCanaryTraceRequiresExactGeneratedPair(t *testing.T) {
	t.Parallel()
	root, child := generatedOTLPCanaryPair(t)
	if got := completeOTLPCanaryTrace([]sdktrace.ReadOnlySpan{child.Snapshot(), root.Snapshot()}, "otlp-primary"); got != root.SpanContext.TraceID().String() {
		t.Fatalf("complete trace = %q", got)
	}
}

func TestCompleteOTLPCanaryTraceRejectsMalformedOrPartialPairs(t *testing.T) {
	t.Parallel()
	tests := map[string]func(*tracetest.SpanStub, *tracetest.SpanStub){
		"missing marker": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			child.Attributes = removeCanaryAttribute(child.Attributes, "defenseclaw.telemetry.canary")
		},
		"duplicate marker": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			child.Attributes = append(child.Attributes, attribute.Bool("defenseclaw.telemetry.canary", true))
		},
		"diagnostic family": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			replaceCanaryAttribute(child, attribute.String("defenseclaw.span.family", observability.TelemetryFamilyDiagnosticCanary))
			replaceCanaryAttribute(child, attribute.String("defenseclaw.bucket", string(observability.BucketDiagnostic)))
		},
		"wrong bucket": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			replaceCanaryAttribute(child, attribute.String("defenseclaw.bucket", string(observability.BucketAgentLifecycle)))
		},
		"wrong operation": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			replaceCanaryAttribute(child, attribute.String("gen_ai.operation.name", "text_completion"))
		},
		"wrong canary operation": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			replaceCanaryAttribute(child, attribute.String("defenseclaw.telemetry.canary.operation", "probe"))
		},
		"wrong destination": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			replaceCanaryAttribute(child, attribute.String("defenseclaw.telemetry.canary.destination", "other"))
		},
		"wrong outcome": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			replaceCanaryAttribute(child, attribute.String("defenseclaw.outcome", string(observability.OutcomeFailed)))
		},
		"generation mismatch": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			replaceCanaryAttribute(child, attribute.Int64("defenseclaw.config.generation", 9))
		},
		"wrong parent": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			child.Parent = trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: child.SpanContext.TraceID(), SpanID: trace.SpanID{0xff}, TraceFlags: trace.FlagsSampled,
				TraceState: child.SpanContext.TraceState(),
			})
		},
		"remote parent": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			parent := child.Parent
			child.Parent = trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: parent.TraceID(), SpanID: parent.SpanID(), TraceFlags: parent.TraceFlags(),
				TraceState: parent.TraceState(), Remote: true,
			})
		},
		"root has parent": func(root, _ *tracetest.SpanStub) { root.Parent = root.SpanContext },
		"different trace": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			child.SpanContext = trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: trace.TraceID{0xee}, SpanID: child.SpanContext.SpanID(), TraceFlags: trace.FlagsSampled,
			})
		},
		"unsampled": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			child.SpanContext = trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: child.SpanContext.TraceID(), SpanID: child.SpanContext.SpanID(),
			})
		},
		"tracestate mismatch": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			state, _ := trace.ParseTraceState("vendor=other")
			child.SpanContext = trace.NewSpanContext(trace.SpanContextConfig{
				TraceID: child.SpanContext.TraceID(), SpanID: child.SpanContext.SpanID(),
				TraceFlags: trace.FlagsSampled, TraceState: state,
			})
		},
		"resource mismatch": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			child.Resource = generatedCanaryResource(t, "other-team")
		},
		"scope mismatch": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) {
			child.InstrumentationScope.Version = "other"
		},
		"wrong name":   func(_ *tracetest.SpanStub, child *tracetest.SpanStub) { child.Name = "chat other" },
		"wrong kind":   func(_ *tracetest.SpanStub, child *tracetest.SpanStub) { child.SpanKind = trace.SpanKindInternal },
		"wrong status": func(_ *tracetest.SpanStub, child *tracetest.SpanStub) { child.Status.Code = codes.Error },
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			root, child := generatedOTLPCanaryPair(t)
			mutate(&root, &child)
			if got := completeOTLPCanaryTrace([]sdktrace.ReadOnlySpan{root.Snapshot(), child.Snapshot()}, "otlp-primary"); got != "" {
				t.Fatalf("malformed pair acknowledged as %q", got)
			}
		})
	}
	root, child := generatedOTLPCanaryPair(t)
	if got := completeOTLPCanaryTrace([]sdktrace.ReadOnlySpan{root.Snapshot()}, "otlp-primary"); got != "" {
		t.Fatalf("partial pair acknowledged as %q", got)
	}
	if got := completeOTLPCanaryTrace([]sdktrace.ReadOnlySpan{root.Snapshot(), child.Snapshot()}, "other"); got != "" {
		t.Fatalf("wrong exporter destination acknowledged as %q", got)
	}
}

func generatedOTLPCanaryPair(t *testing.T) (tracetest.SpanStub, tracetest.SpanStub) {
	t.Helper()
	traceID := trace.TraceID{1, 2, 3, 4}
	rootID, childID := trace.SpanID{1, 2, 3}, trace.SpanID{4, 5, 6}
	state, err := trace.ParseTraceState("dc=runtime-pipeline-test")
	if err != nil {
		t.Fatal(err)
	}
	rootContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: rootID, TraceFlags: trace.FlagsSampled, TraceState: state,
	})
	childContext := trace.NewSpanContext(trace.SpanContextConfig{
		TraceID: traceID, SpanID: childID, TraceFlags: trace.FlagsSampled, TraceState: state,
	})
	resource := generatedCanaryResource(t, "runtime-security")
	scope := instrumentation.Scope{
		Name: "defenseclaw.telemetry", Version: "v8-test", SchemaURL: "https://defenseclaw.io/schemas/telemetry/v8",
		Attributes: attribute.NewSet(
			attribute.String("defenseclaw.trace.schema_version", observability.RuntimeTraceSchemaVersion),
			attribute.String("defenseclaw.semantic_profile", observability.RuntimeSemanticProfileID),
		),
	}
	base := func(bucket, family, operation string) []attribute.KeyValue {
		return []attribute.KeyValue{
			attribute.String("defenseclaw.bucket", bucket),
			attribute.String("defenseclaw.span.family", family),
			attribute.Int64("defenseclaw.span.family_schema_version", 1),
			attribute.Int64("defenseclaw.config.generation", 8),
			attribute.String("defenseclaw.source", string(observability.SourceGateway)),
			attribute.String("defenseclaw.outcome", string(observability.OutcomeCompleted)),
			attribute.Bool("defenseclaw.telemetry.canary", true),
			attribute.String("defenseclaw.telemetry.canary.operation", "runtime-pipeline-test"),
			attribute.String("defenseclaw.telemetry.canary.destination", "otlp-primary"),
			attribute.String("gen_ai.operation.name", operation),
		}
	}
	now := time.Now()
	root := tracetest.SpanStub{
		Name: "invoke_agent diagnostic", SpanContext: rootContext, SpanKind: trace.SpanKindInternal,
		StartTime: now.Add(-time.Millisecond), EndTime: now, Status: sdktrace.Status{Code: codes.Ok},
		Attributes: base(string(observability.BucketAgentLifecycle), observability.TelemetryFamilyAgentInvoke, "invoke_agent"),
		Resource:   resource, InstrumentationScope: scope,
	}
	child := tracetest.SpanStub{
		Name: "chat gpt-4o-mini", SpanContext: childContext, Parent: rootContext, SpanKind: trace.SpanKindClient,
		StartTime: now.Add(-time.Millisecond), EndTime: now, Status: sdktrace.Status{Code: codes.Ok},
		Attributes: base(string(observability.BucketModelIO), observability.TelemetryFamilyModelChat, "chat"),
		Resource:   resource, InstrumentationScope: scope,
	}
	return root, child
}

func generatedCanaryResource(t *testing.T, team string) *resource.Resource {
	t.Helper()
	return resource.NewWithAttributes(
		"https://opentelemetry.io/schemas/1.42.0",
		attribute.String("service.name", "defenseclaw"),
		attribute.String("service.version", "v8-test"),
		attribute.String("service.namespace", "cisco.ai-defense"),
		attribute.String("service.instance.id", "instance-1"),
		attribute.String("deployment.environment.name", "test"),
		attribute.String("defenseclaw.instance.id", "instance-1"),
		attribute.String("defenseclaw.deployment.mode", "gateway"),
		attribute.String("team.owner", team),
	)
}

func removeCanaryAttribute(attributes []attribute.KeyValue, key string) []attribute.KeyValue {
	result := make([]attribute.KeyValue, 0, len(attributes))
	for _, item := range attributes {
		if string(item.Key) != key {
			result = append(result, item)
		}
	}
	return result
}

func replaceCanaryAttribute(span *tracetest.SpanStub, replacement attribute.KeyValue) {
	for index := range span.Attributes {
		if span.Attributes[index].Key == replacement.Key {
			span.Attributes[index] = replacement
			return
		}
	}
	span.Attributes = append(span.Attributes, replacement)
}
