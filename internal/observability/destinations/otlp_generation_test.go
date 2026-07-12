// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package destinations

import (
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"reflect"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	compatibility "github.com/defenseclaw/defenseclaw/internal/observability/compatibility/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/localobservability"
	otlpdestination "github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	collectormetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricpb "go.opentelemetry.io/proto/otlp/metrics/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/protobuf/proto"
)

type otlpGenerationCapture struct {
	mu      sync.Mutex
	traces  []*collectortracepb.ExportTraceServiceRequest
	metrics []*collectormetricpb.ExportMetricsServiceRequest
	headers []http.Header
	partial bool
}

func (capture *otlpGenerationCapture) handler(writer http.ResponseWriter, request *http.Request) {
	body, _ := io.ReadAll(request.Body)
	capture.mu.Lock()
	capture.headers = append(capture.headers, request.Header.Clone())
	partial := capture.partial
	switch request.URL.Path {
	case "/v1/traces":
		decoded := &collectortracepb.ExportTraceServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err == nil {
			capture.traces = append(capture.traces, decoded)
		}
		capture.mu.Unlock()
		if partial {
			response, _ := proto.Marshal(&collectortracepb.ExportTraceServiceResponse{
				PartialSuccess: &collectortracepb.ExportTracePartialSuccess{RejectedSpans: 1},
			})
			writer.Header().Set("Content-Type", "application/x-protobuf")
			_, _ = writer.Write(response)
			return
		}
	case "/v1/metrics":
		decoded := &collectormetricpb.ExportMetricsServiceRequest{}
		if err := proto.Unmarshal(body, decoded); err == nil {
			capture.metrics = append(capture.metrics, decoded)
		}
		capture.mu.Unlock()
	default:
		capture.mu.Unlock()
		writer.WriteHeader(http.StatusNotFound)
		return
	}
	writer.Header().Set("Content-Type", "application/x-protobuf")
	writer.WriteHeader(http.StatusOK)
}

func (capture *otlpGenerationCapture) snapshot() ([]*collectortracepb.ExportTraceServiceRequest, []*collectormetricpb.ExportMetricsServiceRequest, []http.Header) {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectortracepb.ExportTraceServiceRequest(nil), capture.traces...),
		append([]*collectormetricpb.ExportMetricsServiceRequest(nil), capture.metrics...),
		append([]http.Header(nil), capture.headers...)
}

func generationMetricSpec() telemetry.V8MetricReaderSpec {
	return telemetry.V8MetricReaderSpec{
		ExportInterval: time.Hour, ExportTimeout: time.Second,
		Temporality: metricdata.DeltaTemporality, CardinalityLimit: 2_048,
	}
}

func compileGenerationPlan(t *testing.T, destinations ...config.ObservabilityV8DestinationSource) *config.ObservabilityV8Plan {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{Destinations: destinations})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func compileGenerationRuntimePlan(
	t *testing.T,
	directory string,
	destinations ...config.ObservabilityV8DestinationSource,
) *config.ObservabilityV8Plan {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            filepath.Join(directory, "audit.db"),
			JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
		},
		Destinations: destinations,
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func traceSend(name, endpoint string, buckets []observability.Bucket) config.ObservabilityV8DestinationSource {
	return config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: endpoint,
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalTraces}, Buckets: buckets,
			RedactionProfile: "none",
		},
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		// Keep the generated root/child release canary in one batch under the
		// race detector. Tests that exercise split acknowledgement set the
		// maximum batch size to one explicitly.
		Batch: config.ObservabilityV8BatchSource{ScheduledDelayMS: 100},
	}
}

func metricSend(name, endpoint string, buckets []observability.Bucket) config.ObservabilityV8DestinationSource {
	return config.ObservabilityV8DestinationSource{
		Name: name, Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: endpoint,
		Send: &config.ObservabilityV8SendSource{
			Signals: []observability.Signal{observability.SignalMetrics}, Buckets: buckets,
		},
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	}
}

func generatedHookLatencyRecord(
	t *testing.T,
	provider *telemetry.Provider,
	id string,
	value float64,
) observability.Record {
	t.Helper()
	digest, generation, ok := provider.V8PlanBinding()
	if !ok || digest == "" || generation == 0 {
		t.Fatalf("provider binding digest=%q generation=%d ok=%v", digest, generation, ok)
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(500, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return id, nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: observability.SourceGateway,
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: "generation-test",
					ConfigGeneration: int64(generation), ConfigDigest: digest,
				},
			},
			Value: value, DefenseClawConnectorSource: observability.Present("codex"),
			DefenseClawMetricEventType: observability.Present("prompt"),
			DefenseClawMetricReason:    observability.Present("allow"),
			DefenseClawMetricResult:    observability.Present("ok"),
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func generatedModelChatRecord(t *testing.T, provider *telemetry.Provider) observability.Record {
	t.Helper()
	digest, generation, ok := provider.V8PlanBinding()
	if !ok || digest == "" || generation == 0 {
		t.Fatalf("provider binding digest=%q generation=%d ok=%v", digest, generation, ok)
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(600, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "generic-galileo-xor", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Correlation: observability.Correlation{
				RunID: "run-xor", TurnID: "turn-xor",
				TraceID: "1234567890abcdef1234567890abcdef", SpanID: "1234567890abcdef",
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "defenseclaw", BinaryVersion: "generation-test",
				ConfigGeneration: int64(generation), ConfigDigest: digest,
			},
		},
		Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: 1_783_278_200_000_000_000,
		EndTimeUnixNano:   1_783_278_200_100_000_000,
		TraceState:        observability.Present("dc=xor"), Flags: 0x101,
		Status:              observability.NewTraceStatusOK(),
		Resource:            observability.TraceResourceInput{SchemaURL: "https://opentelemetry.io/schemas/1.42.0"},
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-xor", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID:       "instance-xor",
		DefenseClawAgentReportedCostPresent: false,
		DefenseClawContentInputState:        "not_reported", DefenseClawTelemetryInputReported: false,
		DefenseClawContentOutputState: "not_reported", DefenseClawTelemetryOutputReported: false,
		GenAIOperationName: observability.Present("chat"), GenAIProviderName: observability.Present("openai"),
		GenAIRequestModel: "gpt-xor", DefenseClawTelemetryTokensReported: observability.Present(false),
		ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func drainGeneratedProvider(t *testing.T, lease *runtimegraph.Lease) {
	t.Helper()
	componentValue, componentOK := lease.Component(telemetry.V8ProviderComponentName)
	component, typed := componentValue.(*telemetry.V8ProviderComponent)
	if !componentOK || !typed {
		t.Fatal("generation provider component missing")
	}
	ctx, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := component.Drain(ctx); err != nil {
		t.Fatal(err)
	}
}

func TestMetricsOnlyLocalOTLPDestinationRetainsLocalIdentity(t *testing.T) {
	destination := metricSend(
		localobservability.DestinationName, "http://local-collector.example.test",
		[]observability.Bucket{observability.BucketAgentLifecycle},
	)
	plan := compileGenerationRuntimePlan(t, t.TempDir(), destination)
	compiled, ok := plan.RuntimeDestination(localobservability.DestinationName)
	if !ok || !effectiveDestinationSelectsSignal(compiled, observability.SignalMetrics) ||
		effectiveDestinationSelectsSignal(compiled, observability.SignalTraces) ||
		!isLocalObservabilityOTLP(compiled) {
		t.Fatalf("metrics-only local destination lost identity: %+v", compiled)
	}
}

func TestOTLPGenerationAssemblerUsesUnmaskedRuntimeTransportAndDefaultAllSignals(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewTLSServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	const caPath = "/trusted/generation-ca.pem"
	secrets := &secretResolver{values: map[string]string{"OTLP_AUTH": "Bearer resolved-secret"}, calls: map[string]int{}}
	loader := &caLoader{bundles: map[string][]byte{caPath: certificate}, errors: map[string]error{}, calls: map[string]int{}}
	factory := newTestFactory(t, io.Discard, secrets, loader, net.Dialer{}, nil)
	plan := compileGenerationPlan(t, config.ObservabilityV8DestinationSource{
		Name: "all-signals", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: server.URL,
		Headers: map[string]config.ObservabilityV8HeaderValue{
			"Authorization": config.ObservabilityV8EnvironmentHeader("OTLP_AUTH"),
			"X-Static":      config.ObservabilityV8StaticHeader("runtime-unmasked-value"),
		},
		TLS:           config.ObservabilityV8TLSSource{CACert: caPath},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
		Batch:         config.ObservabilityV8BatchSource{ScheduledDelayMS: 1},
	})
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 1, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 1 || len(pipelines.MetricReaders) != 1 || len(pipelines.MetricPipelines) != 1 || len(pipelines.HealthSources) != 2 ||
		pipelines.CanaryAcknowledged == nil || secrets.callCount("OTLP_AUTH") != 1 || loader.callCount(caPath) != 1 {
		t.Fatalf("pipelines=%d/%d secret=%d CA=%d", len(pipelines.SpanPipelines), len(pipelines.MetricReaders), secrets.callCount("OTLP_AUTH"), loader.callCount(caPath))
	}
	if pipelines.SpanPipelines[0].Destination != "all-signals" ||
		pipelines.SpanPipelines[0].Canonical == nil {
		t.Fatalf("OTLP trace pipeline is not canonical: %+v", pipelines.SpanPipelines[0])
	}

	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(pipelines.MetricReaders[0]))
	meter := meterProvider.Meter("test")
	counter, err := meter.Int64Counter("defenseclaw.scan.count")
	if err != nil {
		t.Fatal(err)
	}
	counter.Add(context.Background(), 1)
	if err := meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	traces, metrics, headers := capture.snapshot()
	if len(traces) != 0 || len(metrics) != 1 {
		t.Fatalf("requests traces=%d metrics=%d", len(traces), len(metrics))
	}
	for _, header := range headers {
		if header.Get("Authorization") != "Bearer resolved-secret" || header.Get("X-Static") != "runtime-unmasked-value" {
			t.Fatalf("masked or unresolved runtime headers: %+v", header)
		}
	}
	if err := pipelines.SpanPipelines[0].Canonical.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := meterProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOTLPGenerationAssemblerAppliesBucketRoutesAcrossMultipleDestinations(t *testing.T) {
	agentCapture, toolCapture, metricCapture := &otlpGenerationCapture{}, &otlpGenerationCapture{}, &otlpGenerationCapture{}
	agentServer := httptest.NewServer(http.HandlerFunc(agentCapture.handler))
	toolServer := httptest.NewServer(http.HandlerFunc(toolCapture.handler))
	metricServer := httptest.NewServer(http.HandlerFunc(metricCapture.handler))
	defer agentServer.Close()
	defer toolServer.Close()
	defer metricServer.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	plan := compileGenerationPlan(t,
		traceSend("agent-traces", agentServer.URL, []observability.Bucket{observability.BucketAgentLifecycle}),
		traceSend("tool-traces", toolServer.URL, []observability.Bucket{observability.BucketToolActivity}),
		metricSend("scan-metrics", metricServer.URL, []observability.Bucket{observability.BucketAssetScan}),
	)
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 7, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 2 || len(pipelines.MetricReaders) != 1 || len(pipelines.MetricPipelines) != 1 || len(pipelines.HealthSources) != 3 {
		t.Fatalf("pipelines = %d/%d", len(pipelines.SpanPipelines), len(pipelines.MetricReaders))
	}
	if pipelines.SpanPipelines[0].Destination != "agent-traces" ||
		pipelines.SpanPipelines[1].Destination != "tool-traces" {
		t.Fatalf("named OTLP pipeline order = %q/%q", pipelines.SpanPipelines[0].Destination, pipelines.SpanPipelines[1].Destination)
	}
	for _, pipeline := range pipelines.SpanPipelines {
		if pipeline.Canonical == nil {
			t.Fatalf("destination %s is not canonical: %+v", pipeline.Destination, pipeline)
		}
	}

	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(pipelines.MetricReaders[0]))
	meter := meterProvider.Meter("test")
	for _, name := range []string{"defenseclaw.scan.count", "defenseclaw.activity.total"} {
		counter, err := meter.Int64Counter(name)
		if err != nil {
			t.Fatal(err)
		}
		counter.Add(context.Background(), 1)
	}
	if err := meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}

	agentTraces, _, _ := agentCapture.snapshot()
	toolTraces, _, _ := toolCapture.snapshot()
	_, metricRequests, _ := metricCapture.snapshot()
	if len(agentTraces) != 0 || len(toolTraces) != 0 {
		t.Fatalf("unproduced trace routes agent=%d tool=%d", len(agentTraces), len(toolTraces))
	}
	if names := metricNames(metricRequests); len(names) != 1 || names[0] != "defenseclaw.scan.count" {
		t.Fatalf("metric route names=%v", names)
	}
	for _, pipeline := range pipelines.SpanPipelines {
		_ = pipeline.Canonical.Shutdown(context.Background())
	}
	_ = meterProvider.Shutdown(context.Background())
}

func TestOTLPGenerationAssemblerAppliesMetricEventNameFirstMatchRoutes(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	plan := compileGenerationPlan(t, config.ObservabilityV8DestinationSource{
		Name: "metric-event-route", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: server.URL,
		Routes: []config.ObservabilityV8RouteSource{
			{
				Name: "scan-count", Signals: []observability.Signal{observability.SignalMetrics},
				Selector: &config.ObservabilityV8SelectorSource{
					Buckets: []observability.Bucket{observability.BucketAssetScan},
					EventNames: []observability.EventName{
						"defenseclaw.scan.count",
					},
				},
				Action: config.ObservabilityV8RouteSend,
			},
			{
				Name: "drop-rest", Signals: []observability.Signal{observability.SignalMetrics},
				Selector: &config.ObservabilityV8SelectorSource{
					Buckets:    []observability.Bucket{"*"},
					EventNames: []observability.EventName{"*"},
				},
				Action: config.ObservabilityV8RouteDrop,
			},
		},
		TLS:           config.ObservabilityV8TLSSource{Insecure: true},
		NetworkSafety: config.ObservabilityV8NetworkSafetySource{AllowPrivateNetworks: true},
	})
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 8, generationMetricSpec())
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 0 || len(pipelines.MetricReaders) != 1 || len(pipelines.MetricPipelines) != 1 || len(pipelines.HealthSources) != 1 {
		t.Fatalf("pipelines=%d/%d", len(pipelines.SpanPipelines), len(pipelines.MetricReaders))
	}
	if pipelines.CanaryAcknowledged != nil {
		t.Fatal("metric-only pipeline exposed a trace acknowledgement callback")
	}
	if got := pipelines.MetricPipelines[0].SelectedFamilies; !reflect.DeepEqual(got, []observability.EventName{"defenseclaw.scan.count"}) {
		t.Fatalf("generated metric route selection=%v", got)
	}
	meterProvider := sdkmetric.NewMeterProvider(sdkmetric.WithReader(pipelines.MetricReaders[0]))
	meter := meterProvider.Meter("test")
	for _, name := range []string{"defenseclaw.scan.count", "defenseclaw.scan.errors"} {
		counter, counterErr := meter.Int64Counter(name)
		if counterErr != nil {
			t.Fatal(counterErr)
		}
		counter.Add(context.Background(), 1)
	}
	if err := meterProvider.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	_, requests, _ := capture.snapshot()
	if names := metricNames(requests); len(names) != 1 || names[0] != "defenseclaw.scan.count" {
		t.Fatalf("metric event-name route names=%v", names)
	}
	if err := meterProvider.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestGeneratedMetricOTLPSinksProjectGenericAndLocalLabelsWithExactResource(t *testing.T) {
	genericCapture, localCapture := &otlpGenerationCapture{}, &otlpGenerationCapture{}
	genericServer := httptest.NewServer(http.HandlerFunc(genericCapture.handler))
	localServer := httptest.NewServer(http.HandlerFunc(localCapture.handler))
	defer genericServer.Close()
	defer localServer.Close()
	plan := compileGenerationRuntimePlan(t, t.TempDir(),
		metricSend("generic-metrics", genericServer.URL, []observability.Bucket{observability.BucketAgentLifecycle}),
		metricSend(localobservability.DestinationName, localServer.URL, []observability.Bucket{observability.BucketAgentLifecycle}),
	)
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	manager := generationOTLPManager(t, factory, plan)
	provider, lease := compositeProviderFromManager(t, manager)
	digest, generation, ok := provider.V8PlanBinding()
	if !ok || digest == "" || generation != 1 {
		lease.Release()
		t.Fatalf("provider binding digest=%q generation=%d ok=%v", digest, generation, ok)
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(500, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "generated-metric-e2e", nil }),
	)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	record, err := builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: observability.SourceGateway,
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: "generation-test",
					ConfigGeneration: int64(generation), ConfigDigest: digest,
				},
			},
			Value: 17.5, DefenseClawConnectorSource: observability.Present("codex"),
			DefenseClawMetricEventType: observability.Present("prompt"),
			DefenseClawMetricReason:    observability.Present("allow"),
			DefenseClawMetricResult:    observability.Present("ok"),
		},
	)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	result, err := provider.RecordGeneratedMetric(t.Context(), record)
	if err != nil || result != (telemetry.V8MetricRecordResult{Matched: 2, Delivered: 2}) {
		lease.Release()
		t.Fatalf("record result=%+v err=%v", result, err)
	}
	componentValue, componentOK := lease.Component(telemetry.V8ProviderComponentName)
	component, typed := componentValue.(*telemetry.V8ProviderComponent)
	if !componentOK || !typed {
		lease.Release()
		t.Fatal("generation provider component missing")
	}
	flushContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	defer cancel()
	if err := component.Drain(flushContext); err != nil {
		lease.Release()
		t.Fatal(err)
	}
	lease.Release()

	_, genericRequests, _ := genericCapture.snapshot()
	_, localRequests, _ := localCapture.snapshot()
	generic := capturedHistogramMetric(t, genericRequests, "defenseclaw.connector.hook.latency")
	local := capturedHistogramMetric(t, localRequests, "defenseclaw.connector.hook.latency")
	wantBounds := []float64{1, 2, 5, 10, 25, 50, 100, 250, 500, 1000, 2500, 5000, 10000}
	for name, metric := range map[string]capturedHistogram{"generic": generic, "local": local} {
		if metric.unit != "ms" || metric.temporality != metricpb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA ||
			!reflect.DeepEqual(metric.bounds, wantBounds) || metric.resource["service.name"] != "defenseclaw" ||
			metric.resource["service.instance.id"] != "generation-test-instance" ||
			metric.resource["service.version"] != "generation-test" {
			t.Fatalf("%s metric contract=%+v", name, metric)
		}
	}
	wantGeneric := map[string]any{
		"defenseclaw.connector.source": "codex", "defenseclaw.metric.event_type": "prompt",
		"defenseclaw.metric.reason": "allow", "defenseclaw.metric.result": "ok",
	}
	wantLocal := map[string]any{
		"connector": "codex", "event_type": "prompt", "reason": "allow", "result": "ok",
	}
	if !reflect.DeepEqual(generic.attributes, wantGeneric) || !reflect.DeepEqual(local.attributes, wantLocal) {
		t.Fatalf("generic/local labels=%v/%v", generic.attributes, local.attributes)
	}
}

func TestGeneratedMetricOTLPSinkFailureDoesNotSuppressSiblingDestination(t *testing.T) {
	var failedCalls atomic.Int64
	failedServer := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		failedCalls.Add(1)
		writer.WriteHeader(http.StatusInternalServerError)
	}))
	goodCapture := &otlpGenerationCapture{}
	goodServer := httptest.NewServer(http.HandlerFunc(goodCapture.handler))
	defer failedServer.Close()
	defer goodServer.Close()
	failed := metricSend("failed-metrics", failedServer.URL, []observability.Bucket{observability.BucketAgentLifecycle})
	failed.TimeoutMS = 100
	good := metricSend("good-metrics", goodServer.URL, []observability.Bucket{observability.BucketAgentLifecycle})
	plan := compileGenerationRuntimePlan(t, t.TempDir(), failed, good)
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	manager := generationOTLPManager(t, factory, plan)
	provider, lease := compositeProviderFromManager(t, manager)
	digest, generation, ok := provider.V8PlanBinding()
	if !ok {
		lease.Release()
		t.Fatal("provider binding missing")
	}
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(501, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) { return "generated-metric-failure", nil }),
	)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	record, err := builder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: observability.FamilyEnvelopeInput{
				Source: observability.SourceGateway,
				Provenance: observability.FamilyProvenanceInput{
					Producer: "defenseclaw", BinaryVersion: "generation-test",
					ConfigGeneration: int64(generation), ConfigDigest: digest,
				},
			},
			Value: 5, DefenseClawConnectorSource: observability.Present("codex"),
			DefenseClawMetricEventType: observability.Present("prompt"),
			DefenseClawMetricReason:    observability.Present("allow"),
			DefenseClawMetricResult:    observability.Present("ok"),
		},
	)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	if result, recordErr := provider.RecordGeneratedMetric(t.Context(), record); recordErr != nil ||
		result != (telemetry.V8MetricRecordResult{Matched: 2, Delivered: 2}) {
		lease.Release()
		t.Fatalf("record result=%+v err=%v", result, recordErr)
	}
	componentValue, _ := lease.Component(telemetry.V8ProviderComponentName)
	component := componentValue.(*telemetry.V8ProviderComponent)
	flushContext, cancel := context.WithTimeout(t.Context(), 3*time.Second)
	defer cancel()
	if err := component.Drain(flushContext); err == nil {
		lease.Release()
		t.Fatal("failed destination flush unexpectedly succeeded")
	}
	lease.Release()
	_, requests, _ := goodCapture.snapshot()
	if failedCalls.Load() == 0 || len(requests) != 1 ||
		!reflect.DeepEqual(metricNames(requests), []string{"defenseclaw.connector.hook.latency"}) {
		t.Fatalf("failed calls=%d good metrics=%v", failedCalls.Load(), metricNames(requests))
	}
}

func TestGeneratedMetricOTLPSinkExportsEveryCatalogInstrumentShapeOverGRPC(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capture := &generationGRPCMetricCapture{}
	server := grpc.NewServer()
	collectormetricpb.RegisterMetricsServiceServer(server, capture)
	go func() { _ = server.Serve(listener) }()
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	destination := metricSend(
		"grpc-generated", listener.Addr().String(),
		[]observability.Bucket{
			observability.BucketComplianceActivity,
			observability.BucketAgentLifecycle,
			observability.BucketPlatformHealth,
		},
	)
	destination.Protocol = "grpc"
	plan := compileGenerationRuntimePlan(t, t.TempDir(), destination)
	families := []observability.EventName{
		"defenseclaw.activity.total",
		"defenseclaw.audit.sink.circuit.state",
		"defenseclaw.agent.discovery.installed",
		"defenseclaw.agent.last_seen",
		"defenseclaw.activity.diff_entries",
		"defenseclaw.agent.discovery.duration",
	}
	resource, projected := captureGeneratedMetricProjections(
		t, plan, destination.Name, families,
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) []observability.Record {
			records := make([]observability.Record, 0, len(families))
			appendRecord := func(record observability.Record, buildErr error) {
				if buildErr != nil {
					t.Fatal(buildErr)
				}
				records = append(records, record)
			}
			appendRecord(builder.BuildMetricDefenseClawActivityTotal(
				observability.MetricDefenseClawActivityTotalInput{Envelope: envelope, Value: 7},
			))
			appendRecord(builder.BuildMetricDefenseClawAuditSinkCircuitState(
				observability.MetricDefenseClawAuditSinkCircuitStateInput{Envelope: envelope, Value: -3},
			))
			appendRecord(builder.BuildMetricDefenseClawAgentDiscoveryInstalled(
				observability.MetricDefenseClawAgentDiscoveryInstalledInput{Envelope: envelope, Value: 11},
			))
			appendRecord(builder.BuildMetricDefenseClawAgentLastSeen(
				observability.MetricDefenseClawAgentLastSeenInput{Envelope: envelope, Value: 12.5},
			))
			appendRecord(builder.BuildMetricDefenseClawActivityDiffEntries(
				observability.MetricDefenseClawActivityDiffEntriesInput{Envelope: envelope, Value: 13},
			))
			appendRecord(builder.BuildMetricDefenseClawAgentDiscoveryDuration(
				observability.MetricDefenseClawAgentDiscoveryDurationInput{Envelope: envelope, Value: 14.5},
			))
			return records
		},
	)
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	sink := materializeGeneratedMetricSink(t, factory, plan, 1, resource)
	for _, metric := range projected {
		if err := sink.RecordMetric(t.Context(), metric); err != nil {
			t.Fatal(err)
		}
	}
	flushContext, cancel := context.WithTimeout(t.Context(), 5*time.Second)
	if err := sink.ForceFlush(flushContext); err != nil {
		cancel()
		t.Fatal(err)
	}
	cancel()
	if err := sink.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	descriptors, err := telemetry.V8MetricDescriptorCatalog()
	if err != nil {
		t.Fatal(err)
	}
	descriptorByName := make(map[string]telemetry.V8MetricDescriptor, len(descriptors))
	catalogShapes := make(map[string]struct{})
	for _, descriptor := range descriptors {
		descriptorByName[descriptor.Name] = descriptor
		catalogShapes[descriptor.InstrumentType+"/"+descriptor.ValueType] = struct{}{}
	}
	wantCatalogShapes := map[string]struct{}{
		"counter/int64": {}, "updowncounter/int64": {},
		"gauge/int64": {}, "gauge/double": {},
		"histogram/int64": {}, "histogram/double": {},
	}
	if !reflect.DeepEqual(catalogShapes, wantCatalogShapes) {
		t.Fatalf("generated metric catalog shapes=%v want=%v", catalogShapes, wantCatalogShapes)
	}
	wire := capturedMetricsByName(capture.snapshot())
	for _, test := range []struct {
		name           string
		instrumentType string
		valueType      string
		value          float64
	}{
		{name: "defenseclaw.activity.total", instrumentType: "counter", valueType: "int64", value: 7},
		{name: "defenseclaw.audit.sink.circuit.state", instrumentType: "updowncounter", valueType: "int64", value: -3},
		{name: "defenseclaw.agent.discovery.installed", instrumentType: "gauge", valueType: "int64", value: 11},
		{name: "defenseclaw.agent.last_seen", instrumentType: "gauge", valueType: "double", value: 12.5},
		{name: "defenseclaw.activity.diff_entries", instrumentType: "histogram", valueType: "int64", value: 13},
		{name: "defenseclaw.agent.discovery.duration", instrumentType: "histogram", valueType: "double", value: 14.5},
	} {
		t.Run(test.instrumentType+"_"+test.valueType, func(t *testing.T) {
			descriptor, ok := descriptorByName[test.name]
			if !ok || descriptor.InstrumentType != test.instrumentType || descriptor.ValueType != test.valueType {
				t.Fatalf("descriptor=%+v present=%v", descriptor, ok)
			}
			metric := wire[test.name]
			if metric == nil || metric.Unit != descriptor.Unit {
				t.Fatalf("wire metric=%+v unit=%q", metric, descriptor.Unit)
			}
			kind, value, delta, ok := capturedMetricShape(metric)
			if !ok || kind != test.instrumentType || value != test.value ||
				(test.instrumentType != "gauge" && !delta) {
				t.Fatalf("wire kind=%q value=%v delta=%v ok=%v", kind, value, delta, ok)
			}
		})
	}
}

func TestGeneratedMetricOTLPSinkShutdownTimeoutRetryAndIdempotence(t *testing.T) {
	started := make(chan struct{})
	release := make(chan struct{})
	var startedOnce, releaseOnce sync.Once
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		_, _ = io.Copy(io.Discard, request.Body)
		calls.Add(1)
		startedOnce.Do(func() { close(started) })
		<-release
		writer.Header().Set("Content-Type", "application/x-protobuf")
		writer.WriteHeader(http.StatusOK)
	}))
	t.Cleanup(func() {
		releaseOnce.Do(func() { close(release) })
		server.Close()
	})
	destination := metricSend(
		"shutdown-metrics", server.URL,
		[]observability.Bucket{observability.BucketAgentLifecycle},
	)
	plan := compileGenerationRuntimePlan(t, t.TempDir(), destination)
	resource, projected := captureGeneratedMetricProjections(
		t, plan, destination.Name,
		[]observability.EventName{"defenseclaw.connector.hook.latency"},
		func(builder *observability.FamilyBuilder, envelope observability.FamilyEnvelopeInput) []observability.Record {
			record, buildErr := builder.BuildMetricDefenseClawConnectorHookLatency(
				observability.MetricDefenseClawConnectorHookLatencyInput{Envelope: envelope, Value: 9.5},
			)
			if buildErr != nil {
				t.Fatal(buildErr)
			}
			return []observability.Record{record}
		},
	)
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	sink := materializeGeneratedMetricSink(t, factory, plan, 1, resource)
	if len(projected) != 1 {
		t.Fatalf("projected metrics=%d", len(projected))
	}
	if err := sink.RecordMetric(t.Context(), projected[0]); err != nil {
		t.Fatal(err)
	}

	firstContext, firstCancel := context.WithTimeout(t.Context(), 100*time.Millisecond)
	defer firstCancel()
	firstDone := make(chan error, 1)
	go func() { firstDone <- sink.Shutdown(firstContext) }()
	select {
	case <-started:
	case <-time.After(2 * time.Second):
		t.Fatal("shutdown did not begin its final export")
	}
	select {
	case firstErr := <-firstDone:
		if !otlpdestination.IsError(firstErr, otlpdestination.ErrorShutdown) ||
			!errors.Is(firstErr, context.DeadlineExceeded) {
			t.Fatalf("first shutdown error=%v", firstErr)
		}
	case <-time.After(time.Second):
		t.Fatal("caller timeout did not bound shutdown wait")
	}

	retryContext, retryCancel := context.WithTimeout(t.Context(), 2*time.Second)
	defer retryCancel()
	retryDone := make(chan error, 1)
	go func() { retryDone <- sink.Shutdown(retryContext) }()
	select {
	case retryErr := <-retryDone:
		t.Fatalf("retry returned before terminal exporter state: %v", retryErr)
	case <-time.After(25 * time.Millisecond):
	}
	releaseOnce.Do(func() { close(release) })
	select {
	case retryErr := <-retryDone:
		if retryErr != nil {
			t.Fatal(retryErr)
		}
	case <-time.After(time.Second):
		t.Fatal("retry did not observe terminal shutdown")
	}
	if err := sink.Shutdown(context.Background()); err != nil {
		t.Fatalf("idempotent shutdown error=%v", err)
	}
	if calls.Load() != 1 {
		t.Fatalf("shutdown export calls=%d want=1", calls.Load())
	}
}

func TestOTLPGenerationAssemblerAcceptsCentralRedactionAndAdvancedTraceRoutes(t *testing.T) {
	secrets := &secretResolver{values: map[string]string{"SECRET": "value"}, calls: map[string]int{}}
	tests := []struct {
		name        string
		destination config.ObservabilityV8DestinationSource
	}{
		{name: "redacted", destination: func() config.ObservabilityV8DestinationSource {
			value := traceSend("redacted", "https://8.8.8.8:4318", []observability.Bucket{observability.BucketAgentLifecycle})
			value.Send.RedactionProfile = "sensitive"
			value.TLS = config.ObservabilityV8TLSSource{}
			return value
		}()},
		{name: "advanced source selector", destination: config.ObservabilityV8DestinationSource{
			Name: "advanced", Kind: config.ObservabilityV8DestinationOTLP,
			Protocol: "http/protobuf", Endpoint: "https://8.8.8.8:4318",
			Routes: []config.ObservabilityV8RouteSource{{
				Name: "source", Signals: []observability.Signal{observability.SignalTraces},
				Selector:         &config.ObservabilityV8SelectorSource{Sources: []observability.Source{observability.SourceGateway}},
				RedactionProfile: "none",
			}},
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			factory := newTestFactory(t, io.Discard, secrets, nil, net.Dialer{}, nil)
			test.destination.Headers = map[string]config.ObservabilityV8HeaderValue{
				"Authorization": config.ObservabilityV8EnvironmentHeader("SECRET"),
			}
			plan := compileGenerationPlan(t, test.destination)
			pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, uint64(20+index), generationMetricSpec())
			if err != nil || len(pipelines.SpanPipelines) != 1 || len(pipelines.MetricReaders) != 0 || len(pipelines.HealthSources) != 1 ||
				pipelines.SpanPipelines[0].Canonical == nil {
				t.Fatalf("pipelines=%+v error=%v", pipelines, err)
			}
			cleanupOTLPGenerationPipelines(pipelines)
		})
	}
	if secrets.callCount("SECRET") != len(tests) {
		t.Fatalf("supported policies resolved secret %d times", secrets.callCount("SECRET"))
	}
}

func TestOTLPGenerationAssemblerPreparesCanonicalGalileoAndNeverRawLegacy(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	enableGalileoGeneration(t, factory)
	destination := traceSend("galileo", server.URL, []observability.Bucket{"*"})
	destination.Preset = "galileo"
	plan := compileGenerationPlan(t, destination)

	pipelines, err := factory.PrepareOTLPGenerationPipelines(
		context.Background(), plan, 21, generationMetricSpec(),
	)
	if err != nil {
		t.Fatal(err)
	}
	if len(pipelines.SpanPipelines) != 1 || len(pipelines.HealthSources) != 1 || pipelines.SpanPipelines[0].Destination != "galileo" ||
		pipelines.SpanPipelines[0].Canonical == nil ||
		pipelines.CanaryAcknowledged == nil {
		t.Fatalf("Galileo pipeline is not canonical XOR: %+v", pipelines)
	}
	// A zero handoff is intentionally invalid, but returning failed rather than
	// closed proves activation happened only after the generation was complete.
	if result := pipelines.SpanPipelines[0].Canonical.TryEnqueue(telemetry.V8CanonicalEndedSpan{}); result != telemetry.V8CanonicalSpanEnqueueFailed {
		t.Fatalf("activated canonical consumer result=%s", result)
	}
	if traces, _, _ := capture.snapshot(); len(traces) != 0 {
		t.Fatalf("invalid canonical handoff reached network: %d requests", len(traces))
	}
	if err := pipelines.SpanPipelines[0].Canonical.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if factory.OTLPGenerationAcknowledgedCanaryTrace(21, "galileo", "0102030405060708090a0b0c0d0e0f10") {
		t.Fatal("Galileo canary registry outlived canonical consumer")
	}
}

func TestOTLPGenerationAssemblerGenericGalileoCanonicalXORAndSiblingFanout(t *testing.T) {
	genericCapture, galileoCapture := &otlpGenerationCapture{}, &otlpGenerationCapture{}
	genericServer := httptest.NewServer(http.HandlerFunc(genericCapture.handler))
	galileoServer := httptest.NewServer(http.HandlerFunc(galileoCapture.handler))
	defer genericServer.Close()
	defer galileoServer.Close()
	genericDestination := traceSend("generic", genericServer.URL, []observability.Bucket{observability.BucketModelIO})
	galileoDestination := traceSend("galileo", galileoServer.URL, []observability.Bucket{observability.BucketModelIO})
	galileoDestination.Preset = "galileo"
	plan := compileGenerationRuntimePlan(t, t.TempDir(), genericDestination, galileoDestination)
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)

	prepared, err := factory.PrepareOTLPGenerationPipelines(
		context.Background(), plan, 1, generationMetricSpec(),
	)
	if err != nil || len(prepared.SpanPipelines) != 2 || len(prepared.HealthSources) != 2 {
		t.Fatalf("prepared pipelines=%+v error=%v", prepared, err)
	}
	for _, pipeline := range prepared.SpanPipelines {
		wrapper, ok := pipeline.Canonical.(*canaryRegisteredCanonicalConsumer)
		if !ok || wrapper == nil || wrapper.V8CanonicalSpanConsumer == nil {
			t.Fatalf("destination %q is not canonical: %+v", pipeline.Destination, pipeline)
		}
		switch pipeline.Destination {
		case "generic":
			if _, ok := wrapper.V8CanonicalSpanConsumer.(*otlpdestination.CanonicalTraceConsumer); !ok {
				t.Fatalf("generic destination consumer = %T", wrapper.V8CanonicalSpanConsumer)
			}
		case "galileo":
			if _, ok := wrapper.V8CanonicalSpanConsumer.(*galileo.CanonicalTraceConsumer); !ok {
				t.Fatalf("Galileo destination consumer = %T", wrapper.V8CanonicalSpanConsumer)
			}
		default:
			t.Fatalf("unexpected destination %q", pipeline.Destination)
		}
	}
	cleanupOTLPGenerationPipelines(prepared)

	manager := generationOTLPManager(t, factory, plan)
	provider, lease := compositeProviderFromManager(t, manager)
	result, err := provider.ImportV8CanonicalSpan(generatedModelChatRecord(t, provider))
	if err != nil || result.Matched != 2 || result.Delivered != 2 || result.Dropped != 0 ||
		result.Failed != 0 || result.Suppressed != 0 {
		t.Fatalf("canonical sibling fanout=%+v error=%v", result, err)
	}
	drainGeneratedProvider(t, lease)
	lease.Release()

	genericRequests, _, _ := genericCapture.snapshot()
	galileoRequests, _, _ := galileoCapture.snapshot()
	if len(genericRequests) != 1 || len(galileoRequests) != 1 ||
		len(traceRequestSpans(genericRequests[0])) != 1 || len(traceRequestSpans(galileoRequests[0])) != 1 {
		t.Fatalf("generic/Galileo request counts=%d/%d", len(genericRequests), len(galileoRequests))
	}
	genericSpan := traceRequestSpans(genericRequests[0])[0]
	galileoSpan := traceRequestSpans(galileoRequests[0])[0]
	for _, span := range []*tracepb.Span{genericSpan, galileoSpan} {
		if span.Name != "chat gpt-xor" ||
			protoAttribute(span.Attributes, "defenseclaw.span.family") != observability.TelemetryFamilyModelChat ||
			protoAttribute(span.Attributes, "defenseclaw.bucket") != string(observability.BucketModelIO) {
			t.Fatalf("canonical identity changed: %+v", span)
		}
	}
	if protoAttribute(genericSpan.Attributes, "openinference.span.kind") != "LLM" ||
		protoAttribute(galileoSpan.Attributes, "openinference.span.kind") != "LLM" {
		t.Fatalf("destination-private OpenInference kind generic=%+v Galileo=%+v", genericSpan, galileoSpan)
	}
	if genericSpan.TraceState != galileoSpan.TraceState || genericSpan.Flags != galileoSpan.Flags ||
		!reflect.DeepEqual(genericSpan.TraceId, galileoSpan.TraceId) ||
		!reflect.DeepEqual(genericSpan.SpanId, galileoSpan.SpanId) {
		t.Fatalf("generic/Galileo canonical topology diverged generic=%+v Galileo=%+v", genericSpan, galileoSpan)
	}
	genericScope := genericRequests[0].ResourceSpans[0].ScopeSpans[0].Scope
	galileoScope := galileoRequests[0].ResourceSpans[0].ScopeSpans[0].Scope
	if protoAttribute(genericScope.Attributes, "defenseclaw.galileo.compatibility_profile") != "" ||
		protoAttribute(galileoScope.Attributes, "defenseclaw.galileo.compatibility_profile") != compatibility.ProfileID {
		t.Fatalf("destination-private profile generic=%+v Galileo=%+v", genericScope, galileoScope)
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
}

func TestOTLPGenerationAssemblerUsesLocalCompatibilityProjectionInsteadOfGenericOTLP(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	destination := traceSend(localobservability.DestinationName, server.URL, generationCanaryBuckets())
	destination.Batch.MaxExportBatchSize = 2
	plan := compileGenerationRuntimePlan(t, t.TempDir(), destination)
	manager := generationOTLPManager(t, factory, plan)
	provider, lease := compositeProviderFromManager(t, manager)
	result, err := provider.EmitV8GeneratedCanary(t.Context(), lease, localobservability.DestinationName)
	lease.Release()
	if err != nil || !result.Acknowledged {
		t.Fatalf("local canary=%+v error=%v", result, err)
	}

	requests, _, _ := capture.snapshot()
	if len(requests) != 1 {
		t.Fatalf("local trace requests=%d want=1", len(requests))
	}
	spans := traceRequestSpans(requests[0])
	if len(spans) != 2 {
		t.Fatalf("local projected spans=%d want=2", len(spans))
	}
	foundAgentAlias := false
	for _, span := range spans {
		if value := protoAttribute(span.Attributes, "openinference.span.kind"); value != "" {
			t.Fatalf("local compatibility arm received generic OpenInference alias %q", value)
		}
		if protoAttribute(span.Attributes, "defenseclaw.span.family") != observability.TelemetryFamilyAgentInvoke {
			continue
		}
		foundAgentAlias = protoAttribute(span.Attributes, "defenseclaw.agent.type") == "diagnostic" &&
			protoAttribute(span.Attributes, "gen_ai.agent.type") == "diagnostic"
	}
	if !foundAgentAlias {
		t.Fatal("local compatibility projection omitted the Agent360 agent-type alias")
	}
}

func traceRequestSpans(request *collectortracepb.ExportTraceServiceRequest) []*tracepb.Span {
	result := make([]*tracepb.Span, 0)
	if request == nil {
		return result
	}
	for _, resource := range request.ResourceSpans {
		if resource == nil {
			continue
		}
		for _, scope := range resource.ScopeSpans {
			if scope != nil {
				result = append(result, scope.Spans...)
			}
		}
	}
	return result
}

func TestOTLPGenerationAssemblerRejectsGalileoWithoutCentralDependenciesBeforeSecrets(t *testing.T) {
	secrets := &secretResolver{values: map[string]string{"SECRET": "value"}, calls: map[string]int{}}
	factory := newTestFactory(t, io.Discard, secrets, nil, net.Dialer{}, nil)
	factory.redaction = nil
	destination := traceSend("galileo", "https://8.8.8.8:4318", []observability.Bucket{"*"})
	destination.Preset = "galileo"
	destination.TLS = config.ObservabilityV8TLSSource{}
	destination.Headers = map[string]config.ObservabilityV8HeaderValue{
		"Authorization": config.ObservabilityV8EnvironmentHeader("SECRET"),
	}
	plan := compileGenerationPlan(t, destination)
	pipelines, err := factory.PrepareOTLPGenerationPipelines(context.Background(), plan, 22, generationMetricSpec())
	if len(pipelines.SpanPipelines) != 0 || !IsError(err, ErrorInvalidDependencies) {
		t.Fatalf("pipelines=%+v error=%v", pipelines, err)
	}
	if secrets.callCount("SECRET") != 0 {
		t.Fatalf("missing Galileo dependencies resolved secret %d times", secrets.callCount("SECRET"))
	}
}

func enableGalileoGeneration(t *testing.T, factory *Factory) {
	t.Helper()
	engine, err := redaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	factory.redaction = engine
	factory.deliveryObserver = delivery.ObserverFunc(func(delivery.HealthTransition) {})
	factory.galileoObserver = galileo.CanonicalObserverFunc(func(galileo.CanonicalFailure) {})
}

func generationOTLPManager(
	t *testing.T,
	factory *Factory,
	plan *config.ObservabilityV8Plan,
) *runtimegraph.Manager {
	t.Helper()
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version:             "generation-test",
		Environment:         "test",
		ServiceInstanceID:   "generation-test-instance",
		GenerationPipelines: factory.OTLPGenerationPipelineFactory(),
	})
	manager, err := runtimegraph.New(
		t.Context(),
		runtimegraph.ConfigFromPlan(plan, false),
		[]runtimegraph.ComponentFactory{providerFactory},
		runtimegraph.DefaultOptions(compositePipelineReporter{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = manager.Close(context.Background()) })
	return manager
}

func TestOTLPGenerationCanaryTargetIsolationAcknowledgementAndSplitBatch(t *testing.T) {
	for _, test := range []struct {
		name      string
		batchSize int
		partial   bool
		wantAck   bool
		wantCalls int
	}{
		{name: "complete zero rejection", batchSize: 2, wantAck: true, wantCalls: 1},
		{name: "split batch is not exact trace", batchSize: 1, wantCalls: 2},
		{name: "partial rejection", batchSize: 2, partial: true, wantCalls: 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			targetCapture, otherCapture := &otlpGenerationCapture{partial: test.partial}, &otlpGenerationCapture{}
			localCapture, galileoCapture := &otlpGenerationCapture{}, &otlpGenerationCapture{}
			targetServer := httptest.NewServer(http.HandlerFunc(targetCapture.handler))
			otherServer := httptest.NewServer(http.HandlerFunc(otherCapture.handler))
			localServer := httptest.NewServer(http.HandlerFunc(localCapture.handler))
			galileoServer := httptest.NewServer(http.HandlerFunc(galileoCapture.handler))
			defer targetServer.Close()
			defer otherServer.Close()
			defer localServer.Close()
			defer galileoServer.Close()
			target := traceSend("target", targetServer.URL, generationCanaryBuckets())
			other := traceSend("other", otherServer.URL, generationCanaryBuckets())
			local := traceSend(localobservability.DestinationName, localServer.URL, generationCanaryBuckets())
			galileo := traceSend("galileo", galileoServer.URL, generationCanaryBuckets())
			galileo.Preset = "galileo"
			target.Batch.MaxExportBatchSize = test.batchSize
			other.Batch.MaxExportBatchSize = test.batchSize
			local.Batch.MaxExportBatchSize = test.batchSize
			galileo.Batch.MaxExportBatchSize = test.batchSize
			plan := compileGenerationRuntimePlan(t, t.TempDir(), target, other, local, galileo)
			factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
			manager := generationOTLPManager(t, factory, plan)
			provider, lease := compositeProviderFromManager(t, manager)
			result, emitErr := provider.EmitV8GeneratedCanary(t.Context(), lease, "target")
			lease.Release()
			if test.wantAck && emitErr != nil {
				t.Fatal(emitErr)
			}
			if !test.wantAck && emitErr == nil {
				t.Fatal("unacknowledged canary unexpectedly succeeded")
			}
			targetTraces, _, _ := targetCapture.snapshot()
			otherTraces, _, _ := otherCapture.snapshot()
			localTraces, _, _ := localCapture.snapshot()
			galileoTraces, _, _ := galileoCapture.snapshot()
			if len(targetTraces) != test.wantCalls || len(otherTraces) != 0 ||
				len(localTraces) != 0 || len(galileoTraces) != 0 {
				t.Fatalf("target/other/local/galileo calls=%d/%d/%d/%d",
					len(targetTraces), len(otherTraces), len(localTraces), len(galileoTraces))
			}
			if got := result.Acknowledged; got != test.wantAck {
				t.Fatalf("acknowledged=%t want=%t", got, test.wantAck)
			}
			if err := manager.Close(context.Background()); err != nil {
				t.Fatal(err)
			}
			if factory.OTLPGenerationAcknowledgedCanaryTrace(result.Generation, "target", result.TraceID) {
				t.Fatal("acknowledgement outlived generation processors")
			}
		})
	}
}

func TestOTLPGenerationAssemblerKeepsReloadGenerationsIsolated(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	firstDestination := traceSend("reload-traces", server.URL, generationCanaryBuckets())
	directory := t.TempDir()
	firstPlan := compileGenerationRuntimePlan(t, directory, firstDestination)
	manager := generationOTLPManager(t, factory, firstPlan)
	firstProvider, firstLease := compositeProviderFromManager(t, manager)
	firstCanary, err := firstProvider.EmitV8GeneratedCanary(t.Context(), firstLease, "reload-traces")
	firstLease.Release()
	if err != nil || !firstCanary.Acknowledged || firstCanary.Generation != 1 {
		t.Fatalf("first canary=%+v error=%v", firstCanary, err)
	}

	secondDestination := traceSend("reload-traces", server.URL, generationCanaryBuckets())
	secondDestination.Batch.ScheduledDelayMS = 200
	secondPlan := compileGenerationRuntimePlan(t, directory, secondDestination)
	result, reloadErr := manager.Reload(t.Context(), runtimegraph.ConfigFromPlan(secondPlan, false))
	if reloadErr != nil || result.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s error=%v", result.Status(), reloadErr)
	}
	if firstProvider.DestinationAcknowledgedCanaryTrace("reload-traces", firstCanary.TraceID) {
		t.Fatal("retired generation remained queryable")
	}

	secondProvider, secondLease := compositeProviderFromManager(t, manager)
	secondCanary, err := secondProvider.EmitV8GeneratedCanary(t.Context(), secondLease, "reload-traces")
	secondLease.Release()
	if err != nil || !secondCanary.Acknowledged || secondCanary.Generation != 2 {
		t.Fatalf("second canary=%+v error=%v", secondCanary, err)
	}
	if secondProvider.DestinationAcknowledgedCanaryTrace("reload-traces", firstCanary.TraceID) ||
		!secondProvider.DestinationAcknowledgedCanaryTrace("reload-traces", secondCanary.TraceID) {
		t.Fatal("acknowledgement leaked across generation boundary")
	}
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	if secondProvider.DestinationAcknowledgedCanaryTrace("reload-traces", secondCanary.TraceID) {
		t.Fatal("active generation remained queryable after shutdown")
	}

	traceRequests, _, _ := capture.snapshot()
	if len(traceRequests) != 2 {
		t.Fatalf("reload export requests=%d want=2", len(traceRequests))
	}
}

func TestGeneratedMetricOTLPSinksKeepReloadGenerationsAndEndpointsIsolated(t *testing.T) {
	firstCapture, secondCapture := &otlpGenerationCapture{}, &otlpGenerationCapture{}
	firstServer := httptest.NewServer(http.HandlerFunc(firstCapture.handler))
	secondServer := httptest.NewServer(http.HandlerFunc(secondCapture.handler))
	defer firstServer.Close()
	defer secondServer.Close()

	directory := t.TempDir()
	firstDestination := metricSend(
		"reload-metrics", firstServer.URL,
		[]observability.Bucket{observability.BucketAgentLifecycle},
	)
	firstPlan := compileGenerationRuntimePlan(t, directory, firstDestination)
	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	manager := generationOTLPManager(t, factory, firstPlan)
	firstProvider, firstLease := compositeProviderFromManager(t, manager)
	firstRecord := generatedHookLatencyRecord(t, firstProvider, "reload-metric-one", 11.5)
	if result, err := firstProvider.RecordGeneratedMetric(t.Context(), firstRecord); err != nil ||
		result != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
		firstLease.Release()
		t.Fatalf("first record result=%+v error=%v", result, err)
	}
	drainGeneratedProvider(t, firstLease)
	firstLease.Release()

	secondDestination := metricSend(
		"reload-metrics", secondServer.URL,
		[]observability.Bucket{observability.BucketAgentLifecycle},
	)
	secondPlan := compileGenerationRuntimePlan(t, directory, secondDestination)
	reload, err := manager.Reload(t.Context(), runtimegraph.ConfigFromPlan(secondPlan, false))
	if err != nil || reload.Status() != runtimegraph.ReloadApplied {
		t.Fatalf("reload=%s error=%v", reload.Status(), err)
	}
	if result, recordErr := firstProvider.RecordGeneratedMetric(t.Context(), firstRecord); recordErr == nil ||
		result != (telemetry.V8MetricRecordResult{}) {
		t.Fatalf("retired generation accepted record: result=%+v error=%v", result, recordErr)
	}

	secondProvider, secondLease := compositeProviderFromManager(t, manager)
	if _, generation, ok := secondProvider.V8PlanBinding(); !ok || generation != 2 {
		secondLease.Release()
		t.Fatalf("second provider generation=%d ok=%v", generation, ok)
	}
	if result, recordErr := secondProvider.RecordGeneratedMetric(t.Context(), firstRecord); recordErr == nil ||
		result != (telemetry.V8MetricRecordResult{}) {
		secondLease.Release()
		t.Fatalf("new generation accepted old record: result=%+v error=%v", result, recordErr)
	}
	secondRecord := generatedHookLatencyRecord(t, secondProvider, "reload-metric-two", 22.5)
	if result, recordErr := secondProvider.RecordGeneratedMetric(t.Context(), secondRecord); recordErr != nil ||
		result != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
		secondLease.Release()
		t.Fatalf("second record result=%+v error=%v", result, recordErr)
	}
	drainGeneratedProvider(t, secondLease)
	secondLease.Release()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	_, firstRequests, _ := firstCapture.snapshot()
	_, secondRequests, _ := secondCapture.snapshot()
	firstValues := capturedHistogramValues(firstRequests, "defenseclaw.connector.hook.latency")
	secondValues := capturedHistogramValues(secondRequests, "defenseclaw.connector.hook.latency")
	if !reflect.DeepEqual(firstValues, []float64{11.5}) || !reflect.DeepEqual(secondValues, []float64{22.5}) {
		t.Fatalf("cross-generation delivery first=%v second=%v", firstValues, secondValues)
	}
}

func TestOTLPGenerationAssemblerCleansPartialFailureWithoutAffectingActiveGeneration(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := httptest.NewTLSServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	certificate := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: server.Certificate().Raw})
	const validCA = "/trusted/valid-generation-ca.pem"
	const invalidCA = "/trusted/invalid-generation-ca.pem"
	loader := &caLoader{
		bundles: map[string][]byte{validCA: certificate, invalidCA: []byte("not a certificate")},
		errors:  map[string]error{}, calls: map[string]int{},
	}
	factory := newTestFactory(t, io.Discard, nil, loader, net.Dialer{}, nil)
	activePlan := compileGenerationRuntimePlan(t, t.TempDir(), secureTraceSend(
		"active-traces", server.URL, validCA, generationCanaryBuckets(),
	))
	manager := generationOTLPManager(t, factory, activePlan)

	failingPlan := compileGenerationPlan(t,
		secureTraceSend("a-prepared", server.URL, validCA, generationCanaryBuckets()),
		secureTraceSend("z-invalid-ca", server.URL, invalidCA, generationCanaryBuckets()),
	)
	failed, err := factory.PrepareOTLPGenerationPipelines(context.Background(), failingPlan, 52, generationMetricSpec())
	if err == nil || len(failed.SpanPipelines) != 0 || len(failed.MetricReaders) != 0 {
		t.Fatalf("failed pipelines=%d/%d error=%v", len(failed.SpanPipelines), len(failed.MetricReaders), err)
	}
	factory.canaryMu.RLock()
	_, failedGenerationPresent := factory.canary[52]
	_, activeGenerationPresent := factory.canary[1]
	factory.canaryMu.RUnlock()
	if failedGenerationPresent || !activeGenerationPresent {
		t.Fatalf("canary registries failed=%t active=%t", failedGenerationPresent, activeGenerationPresent)
	}
	if loader.callCount(invalidCA) != 1 {
		t.Fatalf("invalid CA resolutions=%d want=1", loader.callCount(invalidCA))
	}

	provider, lease := compositeProviderFromManager(t, manager)
	canary, emitErr := provider.EmitV8GeneratedCanary(t.Context(), lease, "active-traces")
	lease.Release()
	if emitErr != nil || !canary.Acknowledged || canary.Generation != 1 {
		t.Fatalf("later assembly failure disrupted active generation: canary=%+v error=%v", canary, emitErr)
	}
}

func TestOTLPGenerationCanaryRegistryReleasesAfterProcessorShutdownError(t *testing.T) {
	const generation = 71
	factory := &Factory{canary: make(map[uint64]*otlpGenerationCanaryRegistry)}
	registry := &otlpGenerationCanaryRegistry{processors: 1}
	factory.canary[generation] = registry
	inner := &shutdownErrorSpanProcessor{}
	processor := &canaryRegisteredSpanProcessor{
		SpanProcessor: inner,
		release:       func() { factory.releaseOTLPCanaryProcessor(generation, registry) },
	}
	if err := processor.Shutdown(context.Background()); err == nil {
		t.Fatal("shutdown error was suppressed")
	}
	factory.canaryMu.RLock()
	_, retained := factory.canary[generation]
	factory.canaryMu.RUnlock()
	if retained {
		t.Fatal("failed processor shutdown retained a stale generation registry")
	}
	if !inner.terminal {
		t.Fatal("shutdown error returned before the owned processor reached terminal state")
	}
	if err := processor.Shutdown(context.Background()); err != nil || inner.shutdowns != 1 {
		t.Fatalf("second shutdown error=%v inner calls=%d", err, inner.shutdowns)
	}
}

func TestOTLPGenerationCanaryOwnershipWaitsForTerminalCleanupAfterShutdownTimeout(t *testing.T) {
	const generation = 72
	factory := &Factory{canary: make(map[uint64]*otlpGenerationCanaryRegistry)}
	registry := &otlpGenerationCanaryRegistry{processors: 1}
	factory.canary[generation] = registry
	inner := &terminalTimeoutSpanProcessor{terminal: make(chan struct{})}
	processor := &canaryRegisteredSpanProcessor{
		SpanProcessor: inner,
		release:       func() { factory.releaseOTLPCanaryProcessor(generation, registry) },
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := processor.Shutdown(ctx); err == nil {
		t.Fatal("timed-out processor shutdown unexpectedly succeeded")
	}
	factory.canaryMu.RLock()
	_, retained := factory.canary[generation]
	factory.canaryMu.RUnlock()
	if !retained {
		t.Fatal("canary ownership released before worker/exporter terminal cleanup")
	}
	close(inner.terminal)
	deadline := time.Now().Add(time.Second)
	for time.Now().Before(deadline) {
		factory.canaryMu.RLock()
		_, retained = factory.canary[generation]
		factory.canaryMu.RUnlock()
		if !retained {
			break
		}
		time.Sleep(time.Millisecond)
	}
	if retained {
		t.Fatal("terminal cleanup did not release canary ownership")
	}
	if err := processor.Shutdown(context.Background()); err != nil || inner.shutdowns.Load() != 1 {
		t.Fatalf("second shutdown error/calls = %v/%d", err, inner.shutdowns.Load())
	}
}

type terminalTimeoutSpanProcessor struct {
	terminal  chan struct{}
	shutdowns atomic.Int64
}

func (*terminalTimeoutSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*terminalTimeoutSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (*terminalTimeoutSpanProcessor) ForceFlush(context.Context) error                { return nil }
func (processor *terminalTimeoutSpanProcessor) Shutdown(context.Context) error {
	processor.shutdowns.Add(1)
	return context.DeadlineExceeded
}
func (processor *terminalTimeoutSpanProcessor) TerminalDone() <-chan struct{} {
	return processor.terminal
}

type shutdownErrorSpanProcessor struct {
	shutdowns int
	terminal  bool
}

func (*shutdownErrorSpanProcessor) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*shutdownErrorSpanProcessor) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (*shutdownErrorSpanProcessor) ForceFlush(context.Context) error                { return nil }
func (processor *shutdownErrorSpanProcessor) Shutdown(context.Context) error {
	processor.shutdowns++
	processor.terminal = true
	return context.DeadlineExceeded
}

type cleanupDualSpanChild struct {
	shutdowns atomic.Int64
	panic     bool
}

func (*cleanupDualSpanChild) OnStart(context.Context, sdktrace.ReadWriteSpan) {}
func (*cleanupDualSpanChild) OnEnd(sdktrace.ReadOnlySpan)                     {}
func (*cleanupDualSpanChild) ForceFlush(context.Context) error                { return nil }
func (*cleanupDualSpanChild) TryEnqueue(telemetry.V8CanonicalEndedSpan) telemetry.V8CanonicalSpanEnqueueResult {
	return telemetry.V8CanonicalSpanEnqueueAccepted
}
func (child *cleanupDualSpanChild) Shutdown(context.Context) error {
	child.shutdowns.Add(1)
	if child.panic {
		panic("cleanup panic")
	}
	return nil
}

func TestCleanupOTLPGenerationPipelinesDedupesCanonicalAndContainsPanic(t *testing.T) {
	panicking := &cleanupDualSpanChild{panic: true}
	good := &cleanupDualSpanChild{}
	cleanupOTLPGenerationPipelines(telemetry.V8GenerationPipelines{SpanPipelines: []telemetry.V8GenerationSpanPipeline{
		{Destination: "bad", Canonical: panicking},
		{Destination: "bad-reused", Canonical: panicking},
		{Destination: "good", Canonical: good},
	}})
	if panicking.shutdowns.Load() != 1 || good.shutdowns.Load() != 1 {
		t.Fatalf("shutdowns = %d/%d", panicking.shutdowns.Load(), good.shutdowns.Load())
	}
}

func secureTraceSend(name, endpoint, caPath string, buckets []observability.Bucket) config.ObservabilityV8DestinationSource {
	destination := traceSend(name, endpoint, buckets)
	destination.TLS = config.ObservabilityV8TLSSource{CACert: caPath}
	return destination
}

func generationCanaryBuckets() []observability.Bucket {
	return []observability.Bucket{
		observability.BucketAgentLifecycle,
		observability.BucketModelIO,
	}
}

func traceNames(requests []*collectortracepb.ExportTraceServiceRequest) string {
	for _, request := range requests {
		for _, resource := range request.ResourceSpans {
			for _, scope := range resource.ScopeSpans {
				for _, span := range scope.Spans {
					return span.Name
				}
			}
		}
	}
	return ""
}

func metricNames(requests []*collectormetricpb.ExportMetricsServiceRequest) []string {
	result := make([]string, 0)
	for _, request := range requests {
		for _, resource := range request.ResourceMetrics {
			for _, scope := range resource.ScopeMetrics {
				for _, metric := range scope.Metrics {
					result = append(result, metric.Name)
				}
			}
		}
	}
	return result
}

type capturedHistogram struct {
	unit        string
	temporality metricpb.AggregationTemporality
	bounds      []float64
	attributes  map[string]any
	resource    map[string]any
}

func capturedHistogramMetric(
	t *testing.T,
	requests []*collectormetricpb.ExportMetricsServiceRequest,
	name string,
) capturedHistogram {
	t.Helper()
	for _, request := range requests {
		for _, resourceMetrics := range request.ResourceMetrics {
			resourceAttributes := capturedKeyValues(resourceMetrics.Resource.Attributes)
			for _, scope := range resourceMetrics.ScopeMetrics {
				for _, metric := range scope.Metrics {
					if metric.Name != name {
						continue
					}
					histogram := metric.GetHistogram()
					if histogram == nil || len(histogram.DataPoints) != 1 {
						t.Fatalf("metric %s data=%T points=%d", name, metric.Data, len(histogram.GetDataPoints()))
					}
					point := histogram.DataPoints[0]
					return capturedHistogram{
						unit: metric.Unit, temporality: histogram.AggregationTemporality,
						bounds:     append([]float64(nil), point.ExplicitBounds...),
						attributes: capturedKeyValues(point.Attributes), resource: resourceAttributes,
					}
				}
			}
		}
	}
	t.Fatalf("metric %q not captured", name)
	return capturedHistogram{}
}

func capturedKeyValues(values []*commonpb.KeyValue) map[string]any {
	result := make(map[string]any, len(values))
	for _, item := range values {
		if item == nil || item.Value == nil {
			continue
		}
		switch value := item.Value.Value.(type) {
		case *commonpb.AnyValue_StringValue:
			result[item.Key] = value.StringValue
		case *commonpb.AnyValue_IntValue:
			result[item.Key] = value.IntValue
		case *commonpb.AnyValue_BoolValue:
			result[item.Key] = value.BoolValue
		case *commonpb.AnyValue_DoubleValue:
			result[item.Key] = value.DoubleValue
		}
	}
	return result
}

func capturedHistogramValues(
	requests []*collectormetricpb.ExportMetricsServiceRequest,
	name string,
) []float64 {
	result := make([]float64, 0)
	for _, request := range requests {
		for _, resourceMetrics := range request.ResourceMetrics {
			for _, scope := range resourceMetrics.ScopeMetrics {
				for _, metric := range scope.Metrics {
					if metric.Name != name || metric.GetHistogram() == nil {
						continue
					}
					for _, point := range metric.GetHistogram().DataPoints {
						result = append(result, point.GetSum())
					}
				}
			}
		}
	}
	return result
}

type projectedMetricCaptureSink struct {
	mu      sync.Mutex
	metrics []telemetry.V8ProjectedMetric
}

func (sink *projectedMetricCaptureSink) RecordMetric(
	_ context.Context,
	metric telemetry.V8ProjectedMetric,
) error {
	sink.mu.Lock()
	sink.metrics = append(sink.metrics, metric)
	sink.mu.Unlock()
	return nil
}

func (*projectedMetricCaptureSink) ForceFlush(context.Context) error { return nil }
func (*projectedMetricCaptureSink) Shutdown(context.Context) error   { return nil }

func (sink *projectedMetricCaptureSink) snapshot() []telemetry.V8ProjectedMetric {
	sink.mu.Lock()
	defer sink.mu.Unlock()
	return append([]telemetry.V8ProjectedMetric(nil), sink.metrics...)
}

func captureGeneratedMetricProjections(
	t *testing.T,
	plan *config.ObservabilityV8Plan,
	destination string,
	families []observability.EventName,
	build func(*observability.FamilyBuilder, observability.FamilyEnvelopeInput) []observability.Record,
) (telemetry.V8ResourceContext, []telemetry.V8ProjectedMetric) {
	t.Helper()
	capture := &projectedMetricCaptureSink{}
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "generation-test", Environment: "test", ServiceInstanceID: "generation-test-instance",
		GenerationPipelines: func(
			context.Context,
			*config.ObservabilityV8Plan,
			uint64,
			telemetry.V8MetricReaderSpec,
		) (telemetry.V8GenerationPipelines, error) {
			return telemetry.V8GenerationPipelines{MetricPipelines: []telemetry.V8GenerationMetricPipeline{{
				Destination: destination, Projection: telemetry.V8MetricProjectionCanonical,
				SelectedFamilies: append([]observability.EventName(nil), families...), Sink: capture,
			}}}, nil
		},
	})
	manager, err := runtimegraph.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false),
		[]runtimegraph.ComponentFactory{providerFactory},
		runtimegraph.DefaultOptions(compositePipelineReporter{}),
	)
	if err != nil {
		t.Fatal(err)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = manager.Close(context.Background())
		}
	})
	provider, lease := compositeProviderFromManager(t, manager)
	digest, generation, ok := provider.V8PlanBinding()
	if !ok {
		lease.Release()
		t.Fatal("projection provider binding missing")
	}
	resource, ok := provider.V8ResourceContext()
	if !ok {
		lease.Release()
		t.Fatal("projection provider resource missing")
	}
	var occurrence atomic.Int64
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(600, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("projected-metric-%d", occurrence.Add(1)), nil
		}),
	)
	if err != nil {
		lease.Release()
		t.Fatal(err)
	}
	envelope := observability.FamilyEnvelopeInput{
		Source: observability.SourceGateway,
		Provenance: observability.FamilyProvenanceInput{
			Producer: "defenseclaw", BinaryVersion: "generation-test",
			ConfigGeneration: int64(generation), ConfigDigest: digest,
		},
	}
	for _, record := range build(builder, envelope) {
		result, recordErr := provider.RecordGeneratedMetric(t.Context(), record)
		if recordErr != nil || result != (telemetry.V8MetricRecordResult{Matched: 1, Delivered: 1}) {
			lease.Release()
			t.Fatalf("project metric %q result=%+v error=%v", record.EventName(), result, recordErr)
		}
	}
	lease.Release()
	if err := manager.Close(context.Background()); err != nil {
		t.Fatal(err)
	}
	closed = true
	return resource, capture.snapshot()
}

func materializeGeneratedMetricSink(
	t *testing.T,
	factory *Factory,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	resource telemetry.V8ResourceContext,
) telemetry.V8CanonicalMetricSink {
	t.Helper()
	pipelines, err := factory.PrepareOTLPGenerationPipelines(
		t.Context(), plan, generation, generationMetricSpec(),
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		for index := len(pipelines.MetricReaders) - 1; index >= 0; index-- {
			_ = pipelines.MetricReaders[index].Shutdown(context.Background())
		}
	})
	if len(pipelines.MetricPipelines) != 1 || pipelines.MetricPipelines[0].SinkFactory == nil {
		t.Fatalf("generated metric pipelines=%d", len(pipelines.MetricPipelines))
	}
	sink, err := pipelines.MetricPipelines[0].SinkFactory(t.Context(), resource)
	if err != nil || sink == nil {
		t.Fatalf("materialize generated metric sink=%T error=%v", sink, err)
	}
	return sink
}

type generationGRPCMetricCapture struct {
	collectormetricpb.UnimplementedMetricsServiceServer
	mu       sync.Mutex
	requests []*collectormetricpb.ExportMetricsServiceRequest
}

func (capture *generationGRPCMetricCapture) Export(
	_ context.Context,
	request *collectormetricpb.ExportMetricsServiceRequest,
) (*collectormetricpb.ExportMetricsServiceResponse, error) {
	capture.mu.Lock()
	capture.requests = append(
		capture.requests,
		proto.Clone(request).(*collectormetricpb.ExportMetricsServiceRequest),
	)
	capture.mu.Unlock()
	return &collectormetricpb.ExportMetricsServiceResponse{}, nil
}

func (capture *generationGRPCMetricCapture) snapshot() []*collectormetricpb.ExportMetricsServiceRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectormetricpb.ExportMetricsServiceRequest(nil), capture.requests...)
}

func capturedMetricsByName(
	requests []*collectormetricpb.ExportMetricsServiceRequest,
) map[string]*metricpb.Metric {
	result := make(map[string]*metricpb.Metric)
	for _, request := range requests {
		for _, resourceMetrics := range request.ResourceMetrics {
			for _, scope := range resourceMetrics.ScopeMetrics {
				for _, metric := range scope.Metrics {
					result[metric.Name] = metric
				}
			}
		}
	}
	return result
}

func capturedMetricShape(metric *metricpb.Metric) (string, float64, bool, bool) {
	if metric == nil {
		return "", 0, false, false
	}
	if sum := metric.GetSum(); sum != nil && len(sum.DataPoints) == 1 {
		value, ok := capturedNumberDataPoint(sum.DataPoints[0])
		kind := "updowncounter"
		if sum.IsMonotonic {
			kind = "counter"
		}
		return kind, value,
			sum.AggregationTemporality == metricpb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA, ok
	}
	if gauge := metric.GetGauge(); gauge != nil && len(gauge.DataPoints) == 1 {
		value, ok := capturedNumberDataPoint(gauge.DataPoints[0])
		return "gauge", value, false, ok
	}
	if histogram := metric.GetHistogram(); histogram != nil && len(histogram.DataPoints) == 1 {
		return "histogram", histogram.DataPoints[0].GetSum(),
			histogram.AggregationTemporality == metricpb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA, true
	}
	return "", 0, false, false
}

func capturedNumberDataPoint(point *metricpb.NumberDataPoint) (float64, bool) {
	if point == nil {
		return 0, false
	}
	switch value := point.Value.(type) {
	case *metricpb.NumberDataPoint_AsInt:
		return float64(value.AsInt), true
	case *metricpb.NumberDataPoint_AsDouble:
		return value.AsDouble, true
	default:
		return 0, false
	}
}
