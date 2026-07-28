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
	"errors"
	"io"
	"net"
	"net/http"
	"path/filepath"
	"strings"
	"sync"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/prometheus"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel"
)

type compositePipelineReporter struct{}

func (compositePipelineReporter) PlatformHealth(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

func (compositePipelineReporter) ComplianceActivity(*runtimegraph.Graph, runtimegraph.Report) error {
	return nil
}

type compositeListenerTracker struct {
	mu        sync.Mutex
	listeners []net.Listener
}

func (tracker *compositeListenerTracker) listen(
	ctx context.Context,
	network string,
	_ string,
) (net.Listener, error) {
	if err := ctx.Err(); err != nil {
		return nil, err
	}
	listener, err := (&net.ListenConfig{}).Listen(ctx, network, "127.0.0.1:0")
	if err != nil {
		return nil, err
	}
	tracker.mu.Lock()
	tracker.listeners = append(tracker.listeners, listener)
	tracker.mu.Unlock()
	return listener, nil
}

func (tracker *compositeListenerTracker) listener(t *testing.T, index int) net.Listener {
	t.Helper()
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	if index < 0 || index >= len(tracker.listeners) {
		t.Fatalf("listener %d absent from %d prepared generations", index, len(tracker.listeners))
	}
	return tracker.listeners[index]
}

func (tracker *compositeListenerTracker) count() int {
	tracker.mu.Lock()
	defer tracker.mu.Unlock()
	return len(tracker.listeners)
}

func compositePipelinePlan(
	t *testing.T,
	directory string,
	otlpEndpoint string,
) *config.ObservabilityV8Plan {
	t.Helper()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path:            filepath.Join(directory, "audit.db"),
			JudgeBodiesPath: filepath.Join(directory, "judge-bodies.db"),
		},
		Destinations: []config.ObservabilityV8DestinationSource{
			{
				Name: "otlp-all", Kind: config.ObservabilityV8DestinationOTLP,
				Protocol: "http/protobuf", Endpoint: otlpEndpoint,
				TLS: config.ObservabilityV8TLSSource{Insecure: true},
				NetworkSafety: config.ObservabilityV8NetworkSafetySource{
					AllowPrivateNetworks: true,
				},
				// Keep the release canary's generated root/child pair in one
				// request even under the race detector. A separate OTLP test
				// deliberately sets MaxExportBatchSize=1 and proves a truly split
				// pair is not acknowledged.
				Batch: config.ObservabilityV8BatchSource{ScheduledDelayMS: 100},
			},
			{
				Name: "prometheus", Kind: config.ObservabilityV8DestinationPrometheus,
				Listen: "127.0.0.1:9464", Path: "/metrics",
			},
		},
	})
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func compositeProviderFromManager(
	t *testing.T,
	manager *runtimegraph.Manager,
) (*telemetry.Provider, *runtimegraph.Lease) {
	t.Helper()
	lease, err := manager.Acquire(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	provider, ok := telemetry.V8ProviderFromLease(lease)
	if !ok {
		lease.Release()
		t.Fatal("active graph has no generation-owned telemetry provider")
	}
	return provider, lease
}

func scrapeCompositePrometheus(t *testing.T, listener net.Listener) string {
	t.Helper()
	client := &http.Client{Timeout: 3 * time.Second}
	response, err := client.Get("http://" + listener.Addr().String() + "/metrics")
	if err != nil {
		t.Fatal(err)
	}
	defer response.Body.Close()
	body, err := io.ReadAll(response.Body)
	if err != nil {
		t.Fatal(err)
	}
	if response.StatusCode != http.StatusOK {
		t.Fatalf("Prometheus status=%d body=%q", response.StatusCode, string(body))
	}
	return string(body)
}

func TestGenerationPipelineFactoryRuntimeGraphFanoutRestartRequiredAndGlobalIsolation(t *testing.T) {
	firstCapture := &otlpGenerationCapture{}
	firstServer := &http.Server{Handler: http.HandlerFunc(firstCapture.handler)}
	firstListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = firstServer.Serve(firstListener) }()
	defer func() { _ = firstServer.Close() }()

	secondCapture := &otlpGenerationCapture{}
	secondServer := &http.Server{Handler: http.HandlerFunc(secondCapture.handler)}
	secondListener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = secondServer.Serve(secondListener) }()
	defer func() { _ = secondServer.Close() }()

	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	listeners := &compositeListenerTracker{}
	traceGlobal := otel.GetTracerProvider()
	metricGlobal := otel.GetMeterProvider()
	directory := t.TempDir()
	firstPlan := compositePipelinePlan(t, directory, "http://"+firstListener.Addr().String())
	firstOTLP, ok := firstPlan.RuntimeDestination("otlp-all")
	if !ok || !firstOTLP.Capabilities.Supports(observability.SignalLogs) ||
		!firstOTLP.Capabilities.Supports(observability.SignalTraces) ||
		!firstOTLP.Capabilities.Supports(observability.SignalMetrics) ||
		len(firstOTLP.SelectedSignals) != 3 {
		t.Fatalf("default OTLP capabilities/signals=%+v/%v", firstOTLP.Capabilities, firstOTLP.SelectedSignals)
	}
	firstPrometheus, ok := firstPlan.RuntimeDestination("prometheus")
	if !ok || firstPrometheus.Capabilities.Supports(observability.SignalLogs) ||
		firstPrometheus.Capabilities.Supports(observability.SignalTraces) ||
		!firstPrometheus.Capabilities.Supports(observability.SignalMetrics) ||
		len(firstPrometheus.SelectedSignals) != 1 {
		t.Fatalf("Prometheus capabilities/signals=%+v/%v", firstPrometheus.Capabilities, firstPrometheus.SelectedSignals)
	}

	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "composite-test", Environment: "test", ServiceInstanceID: "composite-process",
		GenerationPipelines: factory.GenerationPipelineFactory(prometheus.Options{
			Listen: listeners.listen,
		}),
	})
	manager, graphErr := runtimegraph.New(
		t.Context(), runtimegraph.ConfigFromPlan(firstPlan, false),
		[]runtimegraph.ComponentFactory{providerFactory},
		runtimegraph.DefaultOptions(compositePipelineReporter{}),
	)
	if graphErr != nil {
		t.Fatal(graphErr)
	}
	closed := false
	t.Cleanup(func() {
		if !closed {
			_ = manager.Close(context.Background())
		}
	})
	if otel.GetTracerProvider() != traceGlobal || otel.GetMeterProvider() != metricGlobal {
		t.Fatal("generation pipeline construction mutated an OTel process global")
	}

	firstProvider, firstLease := compositeProviderFromManager(t, manager)
	firstDigest, firstGeneration, bound := firstProvider.V8PlanBinding()
	if !bound || firstDigest != firstPlan.Digest() || firstGeneration != 1 {
		t.Fatalf("first provider binding=%q/%d/%v", firstDigest, firstGeneration, bound)
	}
	metricBuilder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time { return time.Unix(100, 0).UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return "composite-generated-metric", nil
		}),
	)
	if err != nil {
		firstLease.Release()
		t.Fatal(err)
	}
	metricEnvelope := observability.FamilyEnvelopeInput{
		Source: "gateway", Provenance: observability.FamilyProvenanceInput{
			Producer: "defenseclaw", BinaryVersion: "8.0.0",
			ConfigGeneration: int64(firstGeneration), ConfigDigest: firstDigest,
		},
	}
	agentDiscoveryMetric, err := metricBuilder.BuildMetricDefenseClawAgentDiscoveryRuns(
		observability.MetricDefenseClawAgentDiscoveryRunsInput{
			Envelope: metricEnvelope, Value: 1,
			DefenseClawMetricCacheHit: observability.Present(false),
			DefenseClawMetricResult:   observability.Present("ok"),
			DefenseClawMetricSource:   observability.Present("cli"),
		},
	)
	if err != nil {
		firstLease.Release()
		t.Fatal(err)
	}
	if result, recordErr := firstProvider.RecordGeneratedMetric(t.Context(), agentDiscoveryMetric); recordErr != nil ||
		result != (telemetry.V8MetricRecordResult{Matched: 2, Delivered: 2}) {
		firstLease.Release()
		t.Fatalf("generated discovery result=%+v err=%v", result, recordErr)
	}
	generatedMetric, err := metricBuilder.BuildMetricDefenseClawConnectorHookLatency(
		observability.MetricDefenseClawConnectorHookLatencyInput{
			Envelope: metricEnvelope,
			Value:    7.5, DefenseClawConnectorSource: observability.Present("codex"),
		},
	)
	if err != nil {
		firstLease.Release()
		t.Fatal(err)
	}
	generatedResult, err := firstProvider.RecordGeneratedMetric(t.Context(), generatedMetric)
	if err != nil || generatedResult != (telemetry.V8MetricRecordResult{Matched: 2, Delivered: 2}) {
		firstLease.Release()
		t.Fatalf("generated bridge result=%+v err=%v", generatedResult, err)
	}
	firstCanary, err := firstProvider.EmitV8GeneratedCanary(t.Context(), firstLease, "otlp-all")
	firstLease.Release()
	if err != nil {
		t.Fatal(err)
	}
	traceID := firstCanary.TraceID
	if !firstCanary.Acknowledged || firstCanary.Generation != 1 {
		t.Fatalf("first canary=%+v", firstCanary)
	}
	if !firstProvider.DestinationAcknowledgedCanaryTrace("otlp-all", traceID) {
		t.Fatal("composite callback lost the OTLP canary acknowledgement bridge")
	}
	firstPromBody := scrapeCompositePrometheus(t, listeners.listener(t, 0))
	if !strings.Contains(firstPromBody, "defenseclaw_agent_discovery_runs_total") ||
		!strings.Contains(firstPromBody, "defenseclaw_connector_hook_latency_milliseconds_count") {
		t.Fatalf("Prometheus did not expose both generated records on its single reader:\n%s", firstPromBody)
	}
	firstTraces, _, _ := firstCapture.snapshot()
	if len(firstTraces) == 0 {
		t.Fatal("OTLP trace processor did not export the targeted canary")
	}

	firstGraph := manager.Active()
	if firstGraph == nil {
		t.Fatal("first active graph is nil")
	}
	if firstGraph.Generation() != 1 || firstGraph.Digest() != firstPlan.Digest() {
		t.Fatalf("first active graph=%p generation/digest=%d/%q", firstGraph, firstGraph.Generation(), firstGraph.Digest())
	}
	firstPrometheusAddress := listeners.listener(t, 0).Addr().String()
	secondPlan := compositePipelinePlan(t, directory, "http://"+secondListener.Addr().String())
	result, reloadErr := manager.Reload(t.Context(), runtimegraph.ConfigFromPlan(secondPlan, false))
	reloadField := ""
	if reloadErr != nil {
		reloadField = reloadErr.FieldPath()
	}
	if reloadErr == nil || reloadErr.Code() != runtimegraph.ErrorRestartRequired ||
		reloadErr.FieldPath() != "observability.destinations.prometheus.listen" ||
		result.Status() != runtimegraph.ReloadRejected || result.ActiveGraph() != firstGraph ||
		manager.Active() != firstGraph {
		t.Fatalf("reload=%s active=%p first=%p error=%v field=%q", result.Status(), result.ActiveGraph(), firstGraph, reloadErr, reloadField)
	}
	if listeners.count() != 1 {
		t.Fatalf("restart-required reload prepared %d Prometheus listeners, want the original listener only", listeners.count())
	}
	factory.canaryMu.RLock()
	_, preparedSecondGeneration := factory.canary[2]
	factory.canaryMu.RUnlock()
	if preparedSecondGeneration {
		t.Fatal("restart-required reload prepared an OTLP candidate generation")
	}
	secondTraces, secondMetrics, secondHeaders := secondCapture.snapshot()
	if len(secondTraces) != 0 || len(secondMetrics) != 0 || len(secondHeaders) != 0 {
		t.Fatalf("restart-required reload reached replacement OTLP endpoint: traces=%d metrics=%d requests=%d", len(secondTraces), len(secondMetrics), len(secondHeaders))
	}
	if !firstProvider.Enabled() || !firstProvider.DestinationAcknowledgedCanaryTrace("otlp-all", traceID) {
		t.Fatal("restart-required reload retired the active provider or lost its canary acknowledgement")
	}
	activeProvider, activeLease := compositeProviderFromManager(t, manager)
	if activeProvider != firstProvider {
		activeLease.Release()
		t.Fatal("restart-required reload replaced the generation-owned provider")
	}
	if result, recordErr := activeProvider.RecordGeneratedMetric(t.Context(), agentDiscoveryMetric); recordErr != nil ||
		result != (telemetry.V8MetricRecordResult{Matched: 2, Delivered: 2}) {
		activeLease.Release()
		t.Fatalf("active generated discovery result=%+v err=%v", result, recordErr)
	}
	activeCanary, err := activeProvider.EmitV8GeneratedCanary(t.Context(), activeLease, "otlp-all")
	activeLease.Release()
	if err != nil {
		t.Fatal(err)
	}
	if !activeCanary.Acknowledged || activeCanary.Generation != 1 ||
		!activeProvider.DestinationAcknowledgedCanaryTrace("otlp-all", activeCanary.TraceID) {
		t.Fatalf("active canary after rejected reload=%+v", activeCanary)
	}
	activePromBody := scrapeCompositePrometheus(t, listeners.listener(t, 0))
	if !strings.Contains(activePromBody, "defenseclaw_agent_discovery_runs_total") {
		t.Fatalf("rejected reload stopped the active Prometheus reader:\n%s", activePromBody)
	}

	if closeErr := manager.Close(t.Context()); closeErr != nil {
		t.Fatal(closeErr)
	}
	closed = true
	_, firstMetrics, _ := firstCapture.snapshot()
	if len(firstMetrics) == 0 || firstProvider.Enabled() ||
		firstProvider.DestinationAcknowledgedCanaryTrace("otlp-all", traceID) ||
		firstProvider.DestinationAcknowledgedCanaryTrace("otlp-all", activeCanary.TraceID) {
		t.Fatal("graph close did not flush and retire the original active generation")
	}
	if connection, dialErr := net.DialTimeout("tcp", firstPrometheusAddress, 250*time.Millisecond); dialErr == nil {
		_ = connection.Close()
		t.Fatal("graph close left the original Prometheus listener accepting connections")
	}
	secondTraces, secondMetrics, secondHeaders = secondCapture.snapshot()
	if len(secondTraces) != 0 || len(secondMetrics) != 0 || len(secondHeaders) != 0 {
		t.Fatalf("graph close reached replacement OTLP endpoint: traces=%d metrics=%d requests=%d", len(secondTraces), len(secondMetrics), len(secondHeaders))
	}
	if otel.GetTracerProvider() != traceGlobal || otel.GetMeterProvider() != metricGlobal {
		t.Fatal("generation pipeline lifecycle mutated an OTel process global")
	}
}

func TestGenerationPipelineFactoryPrometheusFailureRollsBackOTLP(t *testing.T) {
	capture := &otlpGenerationCapture{}
	server := &http.Server{Handler: http.HandlerFunc(capture.handler)}
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	go func() { _ = server.Serve(listener) }()
	defer func() { _ = server.Close() }()

	factory := newTestFactory(t, io.Discard, nil, nil, net.Dialer{}, nil)
	plan := compositePipelinePlan(t, t.TempDir(), "http://"+listener.Addr().String())
	traceGlobal := otel.GetTracerProvider()
	metricGlobal := otel.GetMeterProvider()
	provider, err := telemetry.NewProviderV8Inactive(
		t.Context(), plan, 91,
		telemetry.V8ProviderOptions{
			Version: "test", Environment: "test", ServiceInstanceID: "rollback-test",
			GenerationPipelines: factory.GenerationPipelineFactory(prometheus.Options{
				Listen: func(context.Context, string, string) (net.Listener, error) {
					return nil, errors.New("untrusted configured address")
				},
			}),
		},
	)
	if provider != nil || err == nil {
		t.Fatalf("provider/error=%v/%v, want rejected candidate", provider, err)
	}
	var providerError *telemetry.V8ProviderError
	if !errors.As(err, &providerError) || providerError.Code() != telemetry.V8ProviderErrorPipelineInitialization {
		t.Fatalf("provider error=%T/%v", err, err)
	}
	factory.canaryMu.RLock()
	_, leaked := factory.canary[91]
	factory.canaryMu.RUnlock()
	if leaked {
		t.Fatal("Prometheus failure leaked the prepared OTLP generation registry")
	}
	traces, metrics, _ := capture.snapshot()
	if len(traces) != 0 || len(metrics) != 0 {
		t.Fatalf("rejected candidate exported trace/metric requests=%d/%d", len(traces), len(metrics))
	}
	if otel.GetTracerProvider() != traceGlobal || otel.GetMeterProvider() != metricGlobal {
		t.Fatal("failed generation pipeline construction mutated an OTel process global")
	}
}
