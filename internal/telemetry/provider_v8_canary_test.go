// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package telemetry

import (
	"context"
	"encoding/json"
	"path/filepath"
	"sync"
	"testing"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
)

type generatedCanaryConsumer struct {
	mu      sync.Mutex
	spans   []V8CanonicalEndedSpan
	flushed bool
}

func (consumer *generatedCanaryConsumer) TryEnqueue(span V8CanonicalEndedSpan) V8CanonicalSpanEnqueueResult {
	consumer.mu.Lock()
	consumer.spans = append(consumer.spans, span)
	consumer.mu.Unlock()
	return V8CanonicalSpanEnqueueAccepted
}

func (consumer *generatedCanaryConsumer) ForceFlush(context.Context) error {
	consumer.mu.Lock()
	consumer.flushed = true
	consumer.mu.Unlock()
	return nil
}

func (*generatedCanaryConsumer) Shutdown(context.Context) error { return nil }

func (consumer *generatedCanaryConsumer) acknowledged(destination, traceID string) bool {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return consumer.flushed && destination == "otlp-all" && generatedCanaryPair(consumer.spans, traceID)
}

func (consumer *generatedCanaryConsumer) snapshot() []V8CanonicalEndedSpan {
	consumer.mu.Lock()
	defer consumer.mu.Unlock()
	return append([]V8CanonicalEndedSpan(nil), consumer.spans...)
}

func generatedCanaryPair(spans []V8CanonicalEndedSpan, traceID string) bool {
	if len(spans) != 2 {
		return false
	}
	var root, child *V8CanonicalEndedSpan
	for index := range spans {
		span := &spans[index]
		if span.TraceID().String() != traceID {
			return false
		}
		switch span.Record().EventName() {
		case observability.EventName(observability.TelemetryFamilyAgentInvoke):
			root = span
		case observability.EventName(observability.TelemetryFamilyModelChat):
			child = span
		default:
			return false
		}
	}
	if root == nil || child == nil || root.Record().Bucket() != observability.BucketAgentLifecycle ||
		child.Record().Bucket() != observability.BucketModelIO || root.Name() != "invoke_agent diagnostic" ||
		child.Name() != "chat gpt-4o-mini" {
		return false
	}
	if _, hasParent := root.ParentSpanID(); hasParent {
		return false
	}
	parent, hasParent := child.ParentSpanID()
	return hasParent && parent == root.SpanID()
}

func generatedCanaryPlan(t *testing.T) *config.ObservabilityV8Plan {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: "always_off"},
		Local: config.ObservabilityV8LocalSource{
			Path: filepath.Join(t.TempDir(), "audit.db"), JudgeBodiesPath: filepath.Join(t.TempDir(), "judge.db"),
		},
		Destinations: []config.ObservabilityV8DestinationSource{{
			Name: "otlp-all", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
			Send: &config.ObservabilityV8SendSource{
				Signals: []observability.Signal{observability.SignalTraces},
				Buckets: []observability.Bucket{"*"},
			},
		}},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func generatedCanaryManager(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
	consumer *generatedCanaryConsumer,
	samplingObserver func(SamplingDecisionDebug),
) *runtimegraph.Manager {
	t.Helper()
	factory := NewV8ProviderFactory(V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "canary-instance",
		SamplingObserver: samplingObserver,
		GenerationPipelines: func(
			context.Context, *config.ObservabilityV8Plan, uint64, V8MetricReaderSpec,
		) (V8GenerationPipelines, error) {
			return V8GenerationPipelines{
				SpanPipelines:      []V8GenerationSpanPipeline{{Destination: "otlp-all", Canonical: consumer}},
				CanaryAcknowledged: consumer.acknowledged,
			}, nil
		},
	})
	manager, err := runtimegraph.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false),
		[]runtimegraph.ComponentFactory{factory},
		runtimegraph.Options{
			DrainTimeout: time.Second, Clock: v8TestClock{}, Deadlines: v8TestDeadlines{}, Reporter: v8TestReporter{},
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	return manager
}

func TestEmitV8GeneratedCanaryBuildsExactContentFreePairAndAcknowledges(t *testing.T) {
	plan := generatedCanaryPlan(t)
	consumer := &generatedCanaryConsumer{}
	manager := generatedCanaryManager(t, plan, consumer, nil)
	provider, lease := providerFromGraph(t, manager)
	defer lease.Release()

	result, err := provider.EmitV8GeneratedCanary(t.Context(), lease, "otlp-all")
	if err != nil {
		t.Fatal(err)
	}
	if !result.Acknowledged || result.TraceID == "" || result.Destination != "otlp-all" || result.Generation != 1 {
		t.Fatalf("result=%+v", result)
	}
	spans := consumer.snapshot()
	if !generatedCanaryPair(spans, result.TraceID) {
		t.Fatalf("not an exact generated canary pair: %+v", spans)
	}
	resourceContext, ok := provider.V8ResourceContext()
	if !ok {
		t.Fatal("resource context unavailable")
	}
	for _, span := range spans {
		record := span.Record()
		body, present := record.Body()
		if !present {
			t.Fatal("canary record has no body")
		}
		object, objectErr := body.Object()
		if objectErr != nil {
			t.Fatal(objectErr)
		}
		attributes := object["attributes"].(map[string]any)
		if attributes[telemetryCanaryAttribute] != true ||
			attributes[v8CanaryOperationAttribute] != v8CanaryOperationValue ||
			attributes[telemetryCanaryDestinationAttribute] != "otlp-all" ||
			attributes["defenseclaw.telemetry.input.reported"] != false ||
			attributes["defenseclaw.telemetry.output.reported"] != false ||
			attributes["defenseclaw.content.input.state"] != "not_reported" ||
			attributes["defenseclaw.content.output.state"] != "not_reported" {
			t.Fatalf("invalid canary attributes=%v", attributes)
		}
		if _, exists := attributes["gen_ai.input.messages"]; exists {
			t.Fatal("canary synthesized input content")
		}
		if _, exists := attributes["gen_ai.output.messages"]; exists {
			t.Fatal("canary synthesized output content")
		}
		if object["flags"] != json.Number("257") || span.TraceFlags() != byte(trace.FlagsSampled) || span.OTLPFlags() != 0x101 {
			t.Fatalf("flags canonical/sdk/otlp=%v/%d/%x", object["flags"], span.TraceFlags(), span.OTLPFlags())
		}
		resourceObject := object["resource"].(map[string]any)
		resourceAttributes := resourceObject["attributes"].(map[string]any)
		for key, value := range resourceContext.Values() {
			if resourceAttributes[key] != value {
				t.Fatalf("resource[%s]=%v want %q", key, resourceAttributes[key], value)
			}
		}
	}
}

func TestEmitV8GeneratedCanaryRejectsNilAndReleasedLeaseBeforeConstruction(t *testing.T) {
	plan := generatedCanaryPlan(t)
	consumer := &generatedCanaryConsumer{}
	manager := generatedCanaryManager(t, plan, consumer, nil)
	provider, lease := providerFromGraph(t, manager)

	if result, err := provider.EmitV8GeneratedCanary(t.Context(), nil, "otlp-all"); err == nil || result.TraceID != "" {
		t.Fatalf("nil lease result/error=%+v/%v", result, err)
	}
	lease.Release()
	if result, err := provider.EmitV8GeneratedCanary(t.Context(), lease, "otlp-all"); err == nil || result.TraceID != "" {
		t.Fatalf("released lease result/error=%+v/%v", result, err)
	}
	if got := len(consumer.snapshot()); got != 0 {
		t.Fatalf("invalid lease constructed %d canonical spans", got)
	}
}
