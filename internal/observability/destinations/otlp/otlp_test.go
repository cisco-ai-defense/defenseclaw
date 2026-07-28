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
	"bytes"
	"context"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net"
	"net/http"
	"net/http/httptest"
	"runtime"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/netguard"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/sdk/instrumentation"
	sdkmetric "go.opentelemetry.io/otel/sdk/metric"
	"go.opentelemetry.io/otel/sdk/metric/metricdata"
	"go.opentelemetry.io/otel/sdk/resource"
	sdktrace "go.opentelemetry.io/otel/sdk/trace"
	"go.opentelemetry.io/otel/sdk/trace/tracetest"
	"go.opentelemetry.io/otel/trace"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricpb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/codes"
	"google.golang.org/grpc/metadata"
	"google.golang.org/grpc/status"
	"google.golang.org/protobuf/proto"
)

func testLogResourceSnapshot() LogResourceSnapshot {
	return LogResourceSnapshot{
		SchemaURL: "https://opentelemetry.io/schemas/1.42.0",
		Values: map[string]string{
			"service.name":        "defenseclaw",
			"service.instance.id": "otlp-test-instance",
		},
	}
}

func TestHTTPLogAdapterExportsOnlyProjectedBytesAtExactPathAndHeaders(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_ENDPOINT", "https://ambient.invalid.example")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "ambient-secret=must-not-appear")
	received := make(chan *collectorlogpb.ExportLogsServiceRequest, 4)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		if request.URL.Path != "/tenant/v1/logs" {
			t.Errorf("path = %q", request.URL.Path)
		}
		if got := request.Header.Get("X-Destination"); got != "local-test" {
			t.Errorf("destination header = %q", got)
		}
		if got := request.Header.Get("ambient-secret"); got != "" {
			t.Errorf("ambient header leaked: %q", got)
		}
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		var decoded collectorlogpb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &decoded); err != nil {
			t.Error(err)
			writer.WriteHeader(http.StatusBadRequest)
			return
		}
		received <- &decoded
		writer.Header().Set("Content-Type", "application/x-protobuf")
		encoded, _ := proto.Marshal(&collectorlogpb.ExportLogsServiceResponse{
			PartialSuccess: &collectorlogpb.ExportLogsPartialSuccess{},
		})
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()

	factory := prepareTestFactory(t, Config{
		Destination: "http-logs", Protocol: ProtocolHTTPProtobuf, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalLogs},
		SignalOverride: map[observability.Signal]SignalOverride{
			observability.SignalLogs: {Path: "/tenant/v1/logs"},
		},
		Headers:    map[string]string{"X-Destination": "local-test"},
		LoggerName: "defenseclaw.projected",
		Timeout:    time.Second,
		TLS:        TLSConfig{Insecure: true},
		NetworkSafety: NetworkSafety{
			AllowPrivateNetworks: true,
		},
	}, Dependencies{})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "http-logs", adapter)
	projected := `{"bucket":"model.io","timestamp":"2026-07-06T12:34:56.123456789Z","severity":"HIGH","log_level":"WARN","correlation":{"trace_id":"0123456789abcdef0123456789abcdef","span_id":"0123456789abcdef"},"body":{"message":"projected-only"}}`
	enqueueOTLP(t, dispatcher, "record-http", projected)
	drainOTLP(t, dispatcher)
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case request := <-received:
		record := request.ResourceLogs[0].ScopeLogs[0].LogRecords[0]
		if got := request.ResourceLogs[0].ScopeLogs[0].Scope.Name; got != "defenseclaw.projected" {
			t.Fatalf("scope = %q", got)
		}
		if got := record.Body.GetStringValue(); got != projected {
			t.Fatalf("body = %q, want exact projection", got)
		}
		if got := findProtoAttribute(record.Attributes, "defenseclaw.record.id"); got != "record-http" {
			t.Fatalf("record id = %q", got)
		}
		if got := fmt.Sprintf("%x", record.TraceId); got != "0123456789abcdef0123456789abcdef" {
			t.Fatalf("trace id = %q", got)
		}
		if got := fmt.Sprintf("%x", record.SpanId); got != "0123456789abcdef" {
			t.Fatalf("span id = %q", got)
		}
		if record.SeverityText != "WARN" || record.SeverityNumber != logspb.SeverityNumber_SEVERITY_NUMBER_WARN {
			t.Fatalf("severity = %q/%s", record.SeverityText, record.SeverityNumber)
		}
		wantTimestamp := uint64(time.Date(2026, 7, 6, 12, 34, 56, 123456789, time.UTC).UnixNano())
		if record.TimeUnixNano != wantTimestamp || record.ObservedTimeUnixNano != wantTimestamp {
			t.Fatalf("timestamps = %d/%d want %d", record.TimeUnixNano, record.ObservedTimeUnixNano, wantTimestamp)
		}
	case <-time.After(time.Second):
		t.Fatal("OTLP log request not received")
	}
}

func TestGRPCLogAdapterUsesGuardedConnectionAndProtobuf(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	capture := &grpcLogCapture{requests: make(chan *collectorlogpb.ExportLogsServiceRequest, 1), headers: make(chan metadata.MD, 1)}
	collectorlogpb.RegisterLogsServiceServer(server, capture)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	factory := prepareTestFactory(t, Config{
		Destination: "grpc-logs", Protocol: ProtocolGRPCProtobuf, Endpoint: listener.Addr().String(),
		Selected: []observability.Signal{observability.SignalLogs},
		Headers:  map[string]string{"Authorization": "Bearer exact"}, LoggerName: "grpc.scope",
		Timeout: time.Second, TLS: TLSConfig{Insecure: true},
		NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "grpc-logs", adapter)
	enqueueOTLP(t, dispatcher, "record-grpc", `{"message":"grpc"}`)
	drainOTLP(t, dispatcher)
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case request := <-capture.requests:
		if got := request.ResourceLogs[0].ScopeLogs[0].Scope.Name; got != "grpc.scope" {
			t.Fatalf("scope = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("gRPC request not received")
	}
	select {
	case headers := <-capture.headers:
		if got := headers.Get("authorization"); len(got) != 1 || got[0] != "Bearer exact" {
			t.Fatalf("authorization metadata = %v", got)
		}
	case <-time.After(time.Second):
		t.Fatal("gRPC metadata not received")
	}
}

func TestGRPCTraceAndMetricExporterWireShapes(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	traceCapture := &grpcTraceCapture{requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1)}
	metricCapture := &grpcMetricCapture{requests: make(chan *collectormetricpb.ExportMetricsServiceRequest, 1)}
	collectortracepb.RegisterTraceServiceServer(server, traceCapture)
	collectormetricpb.RegisterMetricsServiceServer(server, metricCapture)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	factory := prepareTestFactory(t, Config{
		Destination: "grpc-signals", Protocol: ProtocolGRPC, Endpoint: listener.Addr().String(),
		Selected: []observability.Signal{observability.SignalTraces, observability.SignalMetrics},
		Timeout:  time.Second, TLS: TLSConfig{Insecure: true},
		NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	spanExporter, err := factory.NewSpanExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	metricExporter, err := factory.NewMetricExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	traceResource, traceSource := testCompleteSignalResource()
	metricResource, metricSource := testCompleteSignalResource()
	traceSource["service.name"] = "mutated-after-resource-construction"
	delete(traceSource, "operator.profile")
	metricSource["unexpected.extra"] = "must-not-appear"
	if err := spanExporter.ExportSpans(
		context.Background(),
		[]sdktrace.ReadOnlySpan{testSpanWithResource("agent.grpc", traceResource)},
	); err != nil {
		t.Fatal(err)
	}
	if err := spanExporter.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := metricExporter.Export(
		context.Background(),
		testMetricDataWithResource("defenseclaw.grpc.metric", metricResource),
	); err != nil {
		t.Fatal(err)
	}
	if err := metricExporter.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := metricExporter.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case request := <-traceCapture.requests:
		if len(request.ResourceSpans) != 1 {
			t.Fatalf("resource spans = %d, want 1", len(request.ResourceSpans))
		}
		assertExactSignalResource(
			t, request.ResourceSpans[0].SchemaUrl, request.ResourceSpans[0].Resource,
		)
		if got := request.ResourceSpans[0].ScopeSpans[0].Spans[0].Name; got != "agent.grpc" {
			t.Fatalf("span name = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("gRPC trace request not received")
	}
	select {
	case request := <-metricCapture.requests:
		if len(request.ResourceMetrics) != 1 {
			t.Fatalf("resource metrics = %d, want 1", len(request.ResourceMetrics))
		}
		assertExactSignalResource(
			t, request.ResourceMetrics[0].SchemaUrl, request.ResourceMetrics[0].Resource,
		)
		if got := request.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Name; got != "defenseclaw.grpc.metric" {
			t.Fatalf("metric name = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("gRPC metric request not received")
	}
}

func TestHTTPTraceAndMetricExportersPreserveGeneralGraphAndIndependentShutdown(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_TRACES_ENDPOINT", "https://ambient.invalid.example/v1/traces")
	t.Setenv("OTEL_EXPORTER_OTLP_HEADERS", "ambient=must-not-appear")
	traces := make(chan *collectortracepb.ExportTraceServiceRequest, 1)
	metrics := make(chan *collectormetricpb.ExportMetricsServiceRequest, 1)
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		body, _ := io.ReadAll(request.Body)
		if request.Header.Get("ambient") != "" {
			t.Error("ambient OTLP header was inherited")
		}
		writer.Header().Set("Content-Type", "application/x-protobuf")
		switch request.URL.Path {
		case "/custom/traces":
			var decoded collectortracepb.ExportTraceServiceRequest
			if err := proto.Unmarshal(body, &decoded); err != nil {
				t.Error(err)
			}
			traces <- &decoded
			encoded, _ := proto.Marshal(&collectortracepb.ExportTraceServiceResponse{})
			_, _ = writer.Write(encoded)
		case "/custom/metrics":
			var decoded collectormetricpb.ExportMetricsServiceRequest
			if err := proto.Unmarshal(body, &decoded); err != nil {
				t.Error(err)
			}
			metrics <- &decoded
			encoded, _ := proto.Marshal(&collectormetricpb.ExportMetricsServiceResponse{})
			_, _ = writer.Write(encoded)
		default:
			writer.WriteHeader(http.StatusNotFound)
		}
	}))
	defer server.Close()

	factory := prepareTestFactory(t, Config{
		Destination: "general-otlp", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalTraces, observability.SignalMetrics},
		SignalOverride: map[observability.Signal]SignalOverride{
			observability.SignalTraces:  {Path: "/custom/traces"},
			observability.SignalMetrics: {Path: "/custom/metrics"},
		},
		Headers: map[string]string{"X-Exact": "yes"}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	spanExporter, err := factory.NewSpanExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	metricExporter, err := factory.NewMetricExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	traceResource, traceSource := testCompleteSignalResource()
	metricResource, metricSource := testCompleteSignalResource()
	traceSource["service.name"] = "mutated-after-resource-construction"
	delete(traceSource, "operator.profile")
	metricSource["unexpected.extra"] = "must-not-appear"
	span := testSpanWithResource("guardrail.native", traceResource)
	if err := spanExporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{span}); err != nil {
		t.Fatal(err)
	}
	if err := spanExporter.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	metricData := testMetricDataWithResource("defenseclaw.runtime.test", metricResource)
	if err := metricExporter.Export(context.Background(), metricData); err != nil {
		t.Fatalf("metric export after trace shutdown: %v", err)
	}
	if err := metricExporter.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := metricExporter.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case request := <-traces:
		if len(request.ResourceSpans) != 1 {
			t.Fatalf("resource spans = %d, want 1", len(request.ResourceSpans))
		}
		assertExactSignalResource(
			t, request.ResourceSpans[0].SchemaUrl, request.ResourceSpans[0].Resource,
		)
		if got := request.ResourceSpans[0].ScopeSpans[0].Spans[0].Name; got != "guardrail.native" {
			t.Fatalf("trace name = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("trace request not received")
	}
	select {
	case request := <-metrics:
		if len(request.ResourceMetrics) != 1 {
			t.Fatalf("resource metrics = %d, want 1", len(request.ResourceMetrics))
		}
		assertExactSignalResource(
			t, request.ResourceMetrics[0].SchemaUrl, request.ResourceMetrics[0].Resource,
		)
		if got := request.ResourceMetrics[0].ScopeMetrics[0].Metrics[0].Name; got != "defenseclaw.runtime.test" {
			t.Fatalf("metric name = %q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("metric request not received")
	}
}

func TestSDKManagedTraceAndMetricRetriesReuseExactRequestAndExposeCounts(t *testing.T) {
	for _, signal := range []observability.Signal{observability.SignalTraces, observability.SignalMetrics} {
		t.Run(string(signal), func(t *testing.T) {
			var mu sync.Mutex
			var requests [][]byte
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
				body, err := io.ReadAll(request.Body)
				if err != nil {
					t.Error(err)
				}
				mu.Lock()
				requests = append(requests, append([]byte(nil), body...))
				attempt := len(requests)
				mu.Unlock()
				if attempt == 1 {
					writer.WriteHeader(http.StatusServiceUnavailable)
					return
				}
				writer.Header().Set("Content-Type", "application/x-protobuf")
				writer.WriteHeader(http.StatusOK)
			}))
			defer server.Close()

			observer := &signalEventCapture{}
			factory := prepareTestFactory(t, Config{
				Destination: "retry-" + string(signal), Protocol: ProtocolHTTP, Endpoint: server.URL,
				Selected: []observability.Signal{signal}, Timeout: 2 * time.Second,
				TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
			}, Dependencies{Observer: observer})
			var counters ExportCounters
			switch signal {
			case observability.SignalTraces:
				exporter, err := factory.NewSpanExporter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{testSpan("retry.exact")}); err != nil {
					t.Fatal(err)
				}
				counters = exporter.Counters()
				_ = exporter.Shutdown(context.Background())
			case observability.SignalMetrics:
				exporter, err := factory.NewMetricExporter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := exporter.Export(context.Background(), testMetricData("retry.exact")); err != nil {
					t.Fatal(err)
				}
				counters = exporter.Counters()
				_ = exporter.Shutdown(context.Background())
			}

			mu.Lock()
			defer mu.Unlock()
			if len(requests) != 2 {
				t.Fatalf("request count = %d, want 2", len(requests))
			}
			if !bytes.Equal(requests[0], requests[1]) {
				t.Fatal("retry did not reuse the exact encoded request")
			}
			if counters.Retried != 1 || counters.Exported != 1 || counters.Failed != 0 {
				t.Fatalf("counters = %+v", counters)
			}
			if got := observer.count(signal, SignalOutcomeRetried); got != 1 {
				t.Fatalf("retry observation = %d", got)
			}
		})
	}
}

func TestSDKManagedTraceAndMetricAuthenticationFailuresAreTerminalAndVisible(t *testing.T) {
	for _, signal := range []observability.Signal{observability.SignalTraces, observability.SignalMetrics} {
		t.Run(string(signal), func(t *testing.T) {
			var calls atomic.Uint64
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				calls.Add(1)
				writer.WriteHeader(http.StatusUnauthorized)
			}))
			defer server.Close()
			observer := &signalEventCapture{}
			factory := prepareTestFactory(t, Config{
				Destination: "auth-" + string(signal), Protocol: ProtocolHTTP, Endpoint: server.URL,
				Selected: []observability.Signal{signal}, Timeout: time.Second,
				TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
			}, Dependencies{Observer: observer})
			var counters ExportCounters
			switch signal {
			case observability.SignalTraces:
				exporter, err := factory.NewSpanExporter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{testSpan("auth.terminal")}); !IsError(err, ErrorExport) {
					t.Fatalf("trace error = %v", err)
				}
				counters = exporter.Counters()
				_ = exporter.Shutdown(context.Background())
			case observability.SignalMetrics:
				exporter, err := factory.NewMetricExporter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				if err := exporter.Export(context.Background(), testMetricData("auth.terminal")); !IsError(err, ErrorExport) {
					t.Fatalf("metric error = %v", err)
				}
				counters = exporter.Counters()
				_ = exporter.Shutdown(context.Background())
			}
			if calls.Load() != 1 || counters.Retried != 0 || counters.Failed != 1 {
				t.Fatalf("calls=%d counters=%+v", calls.Load(), counters)
			}
			if got := observer.count(signal, SignalOutcomeExportFailed); got != 1 {
				t.Fatalf("failure observation = %d", got)
			}
		})
	}
}

func TestSDKManagedTraceRetryPermitsPostWriteAcknowledgementAmbiguity(t *testing.T) {
	var calls atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		attempt := calls.Add(1)
		_, _ = io.Copy(io.Discard, request.Body)
		if attempt == 1 {
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Error("response writer cannot hijack")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err != nil {
				t.Error(err)
				return
			}
			_ = connection.Close()
			return
		}
		writer.Header().Set("Content-Type", "application/x-protobuf")
		writer.WriteHeader(http.StatusOK)
	}))
	defer server.Close()
	factory := prepareTestFactory(t, Config{
		Destination: "ambiguous-trace", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalTraces}, Timeout: 2 * time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	exporter, err := factory.NewSpanExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{testSpan("ambiguous.retry")}); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 2 {
		t.Fatalf("calls = %d, want acknowledgement retry", calls.Load())
	}
	if got := exporter.Counters(); got.Retried != 1 || got.Exported != 1 {
		t.Fatalf("trace counters = %+v", got)
	}
	_ = exporter.Shutdown(context.Background())
}

func TestGuardedHTTPDialBlocksDNSRebindingBeforeConnection(t *testing.T) {
	resolver := &sequenceResolver{answers: [][]net.IPAddr{
		{{IP: net.ParseIP("8.8.8.8")}},
		{{IP: net.ParseIP("10.0.0.8")}},
	}}
	dialer := &recordingDialer{}
	factory := prepareTestFactory(t, Config{
		Destination: "rebind", Protocol: ProtocolHTTP, Endpoint: "http://collector.example.test:4318",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: 100 * time.Millisecond,
		TLS: TLSConfig{Insecure: true},
	}, Dependencies{Resolver: resolver, Dialer: dialer})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "rebind", adapter)
	enqueueOTLP(t, dispatcher, "rebind-record", `{"message":"blocked"}`)
	drainOTLP(t, dispatcher)
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != 0 || got.Delivered != 0 {
		t.Fatalf("counters = %+v", got)
	}
	if dialer.calls.Load() != 0 {
		t.Fatalf("underlying dialer called %d times", dialer.calls.Load())
	}
	if resolver.callCount() < 2 {
		t.Fatalf("resolver calls = %d, want activation + dial", resolver.callCount())
	}
	_ = adapter.Close(context.Background())
}

func TestTemporaryDNSFailureDefersToGuardedDialWithoutBlockingActivation(t *testing.T) {
	resolverFailure := errors.New("resolver backend unavailable")
	factory, err := Prepare(context.Background(), Config{
		Destination: "temporarily-unresolved", Protocol: ProtocolHTTP,
		Endpoint: "https://collector.example.test:4318",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: 100 * time.Millisecond,
		Batch: testBatch(),
	}, Dependencies{Resolver: staticResolver{err: resolverFailure}})
	if err != nil || factory == nil {
		t.Fatalf("temporary DNS failure blocked optional destination activation: factory=%v err=%v", factory, err)
	}
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil || adapter == nil {
		t.Fatalf("temporary DNS failure blocked adapter construction: adapter=%v err=%v", adapter, err)
	}
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatalf("close unresolved adapter: %v", err)
	}
}

func TestGuardedGRPCDialPreservesUnsafeRebindingClassification(t *testing.T) {
	resolver := &sequenceResolver{answers: [][]net.IPAddr{
		{{IP: net.ParseIP("8.8.8.8")}},
		{{IP: net.ParseIP("10.0.0.8")}},
	}}
	dialer := &recordingDialer{}
	factory := prepareTestFactory(t, Config{
		Destination: "grpc-rebind", Protocol: ProtocolGRPC, Endpoint: "collector.example.test:4317",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: 100 * time.Millisecond,
		TLS: TLSConfig{Insecure: true},
	}, Dependencies{Resolver: resolver, Dialer: dialer})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "grpc-rebind", adapter)
	enqueueOTLP(t, dispatcher, "grpc-rebind-record", `{"message":"blocked"}`)
	drainOTLP(t, dispatcher)
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != 0 || got.Delivered != 0 {
		t.Fatalf("gRPC unsafe counters = %+v", got)
	}
	if dialer.calls.Load() != 0 {
		t.Fatalf("underlying gRPC dialer called %d times", dialer.calls.Load())
	}
	_ = adapter.Close(context.Background())
}

func TestGuardedHTTPTraceAndMetricExportersPreserveUnsafeRebindingClassification(t *testing.T) {
	for _, signal := range []observability.Signal{observability.SignalTraces, observability.SignalMetrics} {
		t.Run(string(signal), func(t *testing.T) {
			resolver := &sequenceResolver{answers: [][]net.IPAddr{
				{{IP: net.ParseIP("8.8.8.8")}},
				{{IP: net.ParseIP("10.0.0.8")}},
			}}
			dialer := &recordingDialer{}
			factory := prepareTestFactory(t, Config{
				Destination: "http-rebind-" + string(signal), Protocol: ProtocolHTTP,
				Endpoint: "http://collector.example.test:4318", Selected: []observability.Signal{signal},
				Timeout: 100 * time.Millisecond, TLS: TLSConfig{Insecure: true},
			}, Dependencies{Resolver: resolver, Dialer: dialer})

			switch signal {
			case observability.SignalTraces:
				exporter, err := factory.NewSpanExporter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				err = exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{testSpan("unsafe.http.trace")})
				if !IsError(err, ErrorUnsafeEndpoint) {
					t.Fatalf("trace export error = %v", err)
				}
				_ = exporter.Shutdown(context.Background())
			case observability.SignalMetrics:
				exporter, err := factory.NewMetricExporter(context.Background())
				if err != nil {
					t.Fatal(err)
				}
				err = exporter.Export(context.Background(), testMetricData("unsafe.http.metric"))
				if !IsError(err, ErrorUnsafeEndpoint) {
					t.Fatalf("metric export error = %v", err)
				}
				_ = exporter.Shutdown(context.Background())
			}
			if dialer.calls.Load() != 0 {
				t.Fatalf("underlying dialer called %d times", dialer.calls.Load())
			}
			if resolver.callCount() < 2 {
				t.Fatalf("resolver calls = %d, want activation + dial", resolver.callCount())
			}
		})
	}
}

func TestGuardedGRPCTraceExporterMakesUnsafeDialTerminalBeforeSDKRetry(t *testing.T) {
	resolver := &sequenceResolver{answers: [][]net.IPAddr{
		{{IP: net.ParseIP("8.8.8.8")}},
		{{IP: net.ParseIP("10.0.0.8")}},
	}}
	dialer := &recordingDialer{}
	factory := prepareTestFactory(t, Config{
		Destination: "grpc-trace-rebind", Protocol: ProtocolGRPC,
		Endpoint: "collector.example.test:4317", Selected: []observability.Signal{observability.SignalTraces},
		Timeout: 250 * time.Millisecond, TLS: TLSConfig{Insecure: true},
	}, Dependencies{Resolver: resolver, Dialer: dialer})
	exporter, err := factory.NewSpanExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{testSpan("unsafe.grpc.trace")}); !IsError(err, ErrorUnsafeEndpoint) {
		t.Fatalf("trace export error = %v", err)
	}
	if got := exporter.Counters(); got.Retried != 0 || got.Failed != 1 {
		t.Fatalf("trace counters = %+v", got)
	}
	if dialer.calls.Load() != 0 {
		t.Fatalf("underlying dialer called %d times", dialer.calls.Load())
	}
	_ = exporter.Shutdown(context.Background())
}

func TestSDKManagedGRPCTraceRetryIsBoundedAndReusesExactSpans(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	server := grpc.NewServer()
	capture := &retryingGRPCTraceCapture{}
	collectortracepb.RegisterTraceServiceServer(server, capture)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})
	factory := prepareTestFactory(t, Config{
		Destination: "grpc-trace-retry", Protocol: ProtocolGRPC, Endpoint: listener.Addr().String(),
		Selected: []observability.Signal{observability.SignalTraces}, Timeout: 2 * time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	exporter, err := factory.NewSpanExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.ExportSpans(context.Background(), []sdktrace.ReadOnlySpan{testSpan("retry.grpc.exact")}); err != nil {
		t.Fatal(err)
	}
	requests := capture.snapshot()
	if len(requests) != 2 || !proto.Equal(requests[0], requests[1]) {
		t.Fatalf("gRPC request count/equality = %d/%t", len(requests), len(requests) == 2 && proto.Equal(requests[0], requests[1]))
	}
	if got := exporter.Counters(); got.Retried != 1 || got.Exported != 1 || got.Failed != 0 {
		t.Fatalf("trace counters = %+v", got)
	}
	_ = exporter.Shutdown(context.Background())
}

func TestDialOutcomeTrackerKeepsLatestUnsafeSequenceMonotonic(t *testing.T) {
	tracker := &dialOutcomeTracker{}
	baseline := tracker.snapshot()
	tracker.record(netguard.ErrV8AddressProhibited)
	unsafeSequence := tracker.snapshot()
	tracker.record(nil)
	if !tracker.unsafeSince(baseline) {
		t.Fatal("later successful dial erased an unsafe result")
	}
	if tracker.unsafeSince(unsafeSequence) {
		t.Fatal("unsafe result predates the supplied sequence")
	}

	concurrentBaseline := tracker.snapshot()
	var group sync.WaitGroup
	for index := 0; index < 64; index++ {
		group.Add(1)
		go func(index int) {
			defer group.Done()
			if index == 17 {
				tracker.record(netguard.ErrV8EndpointInvalid)
				return
			}
			tracker.record(nil)
		}(index)
	}
	group.Wait()
	if !tracker.unsafeSince(concurrentBaseline) {
		t.Fatal("concurrent successful dials erased the unsafe result")
	}
}

func TestHTTPRedirectIsBlockedWithoutContactingRedirectTarget(t *testing.T) {
	var targetCalls atomic.Int64
	target := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) {
		targetCalls.Add(1)
	}))
	defer target.Close()
	source := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		writer.Header().Set("Location", target.URL)
		writer.WriteHeader(http.StatusTemporaryRedirect)
	}))
	defer source.Close()
	factory := prepareTestFactory(t, Config{
		Destination: "redirect", Protocol: ProtocolHTTP, Endpoint: source.URL,
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "redirect", adapter)
	enqueueOTLP(t, dispatcher, "redirect-record", `{"message":"redirect"}`)
	drainOTLP(t, dispatcher)
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != 0 {
		t.Fatalf("redirect counters = %+v", got)
	}
	if targetCalls.Load() != 0 {
		t.Fatalf("redirect target contacted %d times", targetCalls.Load())
	}
	_ = adapter.Close(context.Background())
}

func TestHTTPSCustomCAAndContentFreeFailures(t *testing.T) {
	received := make(chan struct{}, 1)
	server := httptest.NewTLSServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		received <- struct{}{}
		encoded, _ := proto.Marshal(&collectorlogpb.ExportLogsServiceResponse{
			PartialSuccess: &collectorlogpb.ExportLogsPartialSuccess{},
		})
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()
	certificate := server.Certificate()
	if certificate == nil {
		t.Fatal("TLS server certificate missing")
	}
	certificatePEM := pem.EncodeToMemory(&pem.Block{Type: "CERTIFICATE", Bytes: certificate.Raw})
	caBundle := append([]byte(nil), certificatePEM...)
	factory := prepareTestFactory(t, Config{
		Destination: "tls-logs", Protocol: ProtocolHTTPProtobuf, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{CABundle: caBundle}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	// Prepare owns a detached copy and a parsed pool. Mutating caller memory must
	// not alter the activated runtime generation.
	for index := range caBundle {
		caBundle[index] = 0
	}
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "tls-logs", adapter)
	enqueueOTLP(t, dispatcher, "tls-record", `{"message":"tls"}`)
	drainOTLP(t, dispatcher)
	_ = adapter.Close(context.Background())
	select {
	case <-received:
	case <-time.After(time.Second):
		t.Fatal("TLS request not received")
	}

	secret := "customer-secret-endpoint"
	_, err = Prepare(context.Background(), Config{
		Destination: "secret", Protocol: ProtocolHTTP, Endpoint: "https://" + secret + ".example:4318",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		Batch: testBatch(),
	}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("10.0.0.1")}}}})
	if !IsError(err, ErrorUnsafeEndpoint) || strings.Contains(err.Error(), secret) {
		t.Fatalf("unsafe error = %q", err)
	}
	invalidCA := []byte("customer-secret-ca-content")
	_, err = Prepare(context.Background(), Config{
		Destination: "secret-ca", Protocol: ProtocolHTTP, Endpoint: "https://collector.example:4318",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS:   TLSConfig{CABundle: invalidCA},
		Batch: testBatch(),
	}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}})
	if !IsError(err, ErrorTLS) || strings.Contains(err.Error(), string(invalidCA)) {
		t.Fatalf("TLS error = %q", err)
	}
	exactMaxCA := make([]byte, maxCABundleBytes)
	copy(exactMaxCA, certificatePEM)
	for index := len(certificatePEM); index < len(exactMaxCA); index++ {
		exactMaxCA[index] = '\n'
	}
	_, err = Prepare(context.Background(), Config{
		Destination: "max-ca", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{CABundle: exactMaxCA}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		Batch: testBatch(),
	}, Dependencies{})
	if err != nil {
		t.Fatalf("exact maximum CA bundle rejected: %v", err)
	}
	_, err = Prepare(context.Background(), Config{
		Destination: "oversize-ca", Protocol: ProtocolHTTP, Endpoint: "https://collector.example:4318",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{CABundle: make([]byte, maxCABundleBytes+1)}, Batch: testBatch(),
	}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}})
	if !IsError(err, ErrorTLS) {
		t.Fatalf("oversize TLS error = %v", err)
	}
}

func TestProtocolValidationSignalOverridesAndPrepareStartsNoWorkers(t *testing.T) {
	before := runtime.NumGoroutine()
	for _, protocol := range []string{ProtocolGRPC, ProtocolGRPCProtobuf, ProtocolHTTP, ProtocolHTTPProtobuf} {
		endpoint := "https://collector.example.test:4318"
		factory, err := Prepare(context.Background(), Config{
			Destination: "protocol-test", Protocol: protocol, Endpoint: endpoint,
			Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
			Batch: testBatch(),
		}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}})
		if err != nil || factory == nil {
			t.Fatalf("protocol %q: factory=%v err=%v", protocol, factory, err)
		}
	}
	if after := runtime.NumGoroutine(); after > before+1 {
		t.Fatalf("Prepare started workers: before=%d after=%d", before, after)
	}
	_, err := Prepare(context.Background(), Config{
		Destination: "grpc-path", Protocol: ProtocolGRPC, Endpoint: "collector.example.test:4317",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		SignalOverride: map[observability.Signal]SignalOverride{observability.SignalLogs: {Path: "/custom"}},
		Batch:          testBatch(),
	}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}})
	if !IsError(err, ErrorInvalidConfig) {
		t.Fatalf("gRPC path override error = %v", err)
	}
	_, err = Prepare(context.Background(), Config{
		Destination: "duplicates", Protocol: ProtocolHTTP, Endpoint: "https://collector.example.test:4318",
		Selected: []observability.Signal{observability.SignalLogs, observability.SignalLogs}, Timeout: time.Second,
		Batch: testBatch(),
	}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}})
	if !IsError(err, ErrorInvalidConfig) {
		t.Fatalf("duplicate signal error = %v", err)
	}
	endpointFactory, err := Prepare(context.Background(), Config{
		Destination: "overrides", Protocol: ProtocolHTTP, Endpoint: "https://default.example.test:4318",
		Selected: []observability.Signal{observability.SignalTraces, observability.SignalMetrics}, Timeout: time.Second,
		SignalOverride: map[observability.Signal]SignalOverride{
			observability.SignalTraces:  {Endpoint: "https://traces.example.test:4318", Path: "/trace%2Ftenant"},
			observability.SignalMetrics: {Endpoint: "https://metrics.example.test:4318", Path: "/metric-tenant"},
		},
		Batch: testBatch(),
	}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}})
	if err != nil {
		t.Fatal(err)
	}
	if got := endpointFactory.signals[observability.SignalTraces]; got.url.Hostname() != "traces.example.test" || got.path != "/trace%2Ftenant" {
		t.Fatalf("trace override = host %q path %q", got.url.Hostname(), got.path)
	}
	if got := signalURL(endpointFactory.signals[observability.SignalTraces]); got != "https://traces.example.test:4318/trace%2Ftenant" {
		t.Fatalf("escaped trace URL = %q", got)
	}
	if got := endpointFactory.signals[observability.SignalMetrics]; got.url.Hostname() != "metrics.example.test" || got.path != "/metric-tenant" {
		t.Fatalf("metric override = host %q path %q", got.url.Hostname(), got.path)
	}
	_, err = Prepare(context.Background(), Config{
		Destination: "grpc-header", Protocol: ProtocolGRPC, Endpoint: "collector.example.test:4317",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		Headers: map[string]string{"Bad!Header": "value"},
		Batch:   testBatch(),
	}, Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}})
	if !IsError(err, ErrorInvalidConfig) {
		t.Fatalf("invalid gRPC header error = %v", err)
	}
}

func TestPrepareEnforcesHardCapacityMaxima(t *testing.T) {
	base := Config{
		Destination: "capacity", Protocol: ProtocolHTTP, Endpoint: "https://collector.example.test:4318",
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		Batch: BatchConfig{
			MaxQueueSize: maxQueueItems, MaxQueueBytes: maxQueueBytes,
			MaxExportBatchSize: maxBatchItems, MaxExportBatchBytes: maxBatchBytes,
			ScheduledDelay: time.Second, ExportInterval: time.Second,
		},
	}
	dependencies := Dependencies{Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}}}
	if _, err := Prepare(context.Background(), base, dependencies); err != nil {
		t.Fatalf("exact maxima rejected: %v", err)
	}

	tests := []struct {
		name   string
		mutate func(*BatchConfig)
	}{
		{name: "queue items", mutate: func(batch *BatchConfig) { batch.MaxQueueSize = maxQueueItems + 1 }},
		{name: "queue bytes", mutate: func(batch *BatchConfig) { batch.MaxQueueBytes = maxQueueBytes + 1 }},
		{name: "batch items", mutate: func(batch *BatchConfig) { batch.MaxExportBatchSize = maxBatchItems + 1 }},
		{name: "batch bytes", mutate: func(batch *BatchConfig) { batch.MaxExportBatchBytes = maxBatchBytes + 1 }},
		{name: "batch items exceed queue", mutate: func(batch *BatchConfig) {
			batch.MaxQueueSize = 1
			batch.MaxExportBatchSize = 2
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			config := base
			config.Destination = "capacity-" + strings.ReplaceAll(test.name, " ", "-")
			test.mutate(&config.Batch)
			if _, err := Prepare(context.Background(), config, dependencies); !IsError(err, ErrorInvalidConfig) {
				t.Fatalf("error = %v", err)
			}
		})
	}
}

func TestMetricSelectorsAreExplicitAndIgnoreAmbientPreference(t *testing.T) {
	t.Setenv("OTEL_EXPORTER_OTLP_METRICS_TEMPORALITY_PREFERENCE", "delta")
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	config := Config{
		Destination: "metric-default", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalMetrics}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}
	defaultFactory := prepareTestFactory(t, config, Dependencies{})
	defaultExporter, err := defaultFactory.NewMetricExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := defaultExporter.Temporality(sdkmetric.InstrumentKindCounter); got != metricdata.CumulativeTemporality {
		t.Fatalf("default temporality = %v, ambient env leaked", got)
	}
	_ = defaultExporter.Shutdown(context.Background())

	config.Destination = "metric-delta"
	deltaFactory := prepareTestFactory(t, config, Dependencies{
		TemporalitySelector: func(sdkmetric.InstrumentKind) metricdata.Temporality {
			return metricdata.DeltaTemporality
		},
	})
	deltaExporter, err := deltaFactory.NewMetricExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if got := deltaExporter.Temporality(sdkmetric.InstrumentKindCounter); got != metricdata.DeltaTemporality {
		t.Fatalf("explicit temporality = %v", got)
	}
	_ = deltaExporter.Shutdown(context.Background())
}

func TestMetricReaderHealthSourceIsGenerationBoundAndQueueFree(t *testing.T) {
	server := httptest.NewServer(http.NotFoundHandler())
	defer server.Close()
	batch := testBatch()
	batch.ExportInterval = time.Hour
	factory := prepareTestFactory(t, Config{
		Destination: "metric-health", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalMetrics}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		Batch: batch,
	}, Dependencies{})
	reader, err := factory.NewPeriodicMetricReader(t.Context())
	if err != nil {
		t.Fatal(err)
	}
	source, err := reader.DeliveryHealthSource(7)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := reader.DeliveryHealthSource(8); !IsError(err, ErrorInvalidConfig) {
		t.Fatalf("cross-generation source error=%v", err)
	}
	snapshot := source.DeliveryHealthSnapshot()
	if snapshot.Destination != "metric-health" || snapshot.Generation != 7 ||
		snapshot.Signal != string(observability.SignalMetrics) ||
		snapshot.State != delivery.HealthInitializing || snapshot.Queue != nil {
		t.Fatalf("metric reader health=%+v", snapshot)
	}
	if err := reader.Shutdown(t.Context()); err != nil {
		t.Fatal(err)
	}
	if stopped := source.DeliveryHealthSnapshot(); stopped.State != delivery.HealthStopped || stopped.Queue != nil {
		t.Fatalf("stopped metric reader health=%+v", stopped)
	}
}

func TestLogFailureClassificationAndMalformedProjection(t *testing.T) {
	tests := []struct {
		name       string
		statusCode int
		partial    bool
		retried    uint64
	}{
		{name: "authentication", statusCode: http.StatusUnauthorized},
		{name: "too-early", statusCode: http.StatusTooEarly, retried: 2},
		{name: "transient", statusCode: http.StatusTooManyRequests, retried: 2},
		{name: "partial-rejection", statusCode: http.StatusOK, partial: true},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				if test.partial {
					encoded, _ := proto.Marshal(&collectorlogpb.ExportLogsServiceResponse{
						PartialSuccess: &collectorlogpb.ExportLogsPartialSuccess{RejectedLogRecords: 1},
					})
					writer.WriteHeader(test.statusCode)
					_, _ = writer.Write(encoded)
					return
				}
				writer.WriteHeader(test.statusCode)
			}))
			defer server.Close()
			factory := prepareTestFactory(t, Config{
				Destination: "failure-" + test.name, Protocol: ProtocolHTTP,
				Endpoint: server.URL, Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
				TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
			}, Dependencies{})
			adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := newOTLPDispatcher(t, factory.config.Destination, adapter)
			enqueueOTLP(t, dispatcher, "failure-record", `{"message":"bounded"}`)
			drainOTLP(t, dispatcher)
			if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != test.retried || got.Delivered != 0 {
				t.Fatalf("counters = %+v", got)
			}
			_ = adapter.Close(context.Background())
		})
	}

	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(http.ResponseWriter, *http.Request) { calls.Add(1) }))
	defer server.Close()
	factory := prepareTestFactory(t, Config{
		Destination: "malformed", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "malformed", adapter)
	enqueueOTLP(t, dispatcher, "malformed-record", string([]byte{'{', '"', 'x', '"', ':', '"', 0xff, '"', '}'}))
	drainOTLP(t, dispatcher)
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Retried != 0 {
		t.Fatalf("malformed counters = %+v", got)
	}
	if calls.Load() != 0 {
		t.Fatalf("malformed projection sent %d requests", calls.Load())
	}
	_ = adapter.Close(context.Background())
}

func TestLogPartialSuccessReportsExactAcceptedAndRejectedCountsWithoutRetry(t *testing.T) {
	var calls atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, err := io.ReadAll(request.Body)
		if err != nil {
			t.Error(err)
		}
		var decoded collectorlogpb.ExportLogsServiceRequest
		if err := proto.Unmarshal(body, &decoded); err != nil {
			t.Error(err)
		}
		if got := len(decoded.ResourceLogs[0].ScopeLogs[0].LogRecords); got != 2 {
			t.Errorf("log record count = %d, want 2", got)
		}
		encoded, _ := proto.Marshal(&collectorlogpb.ExportLogsServiceResponse{
			PartialSuccess: &collectorlogpb.ExportLogsPartialSuccess{RejectedLogRecords: 1},
		})
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()

	observer := &signalEventCapture{}
	factory := prepareTestFactory(t, Config{
		Destination: "partial-exact", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{Observer: observer})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcherWithDelay(t, "partial-exact", adapter, time.Hour)
	enqueueOTLP(t, dispatcher, "partial-record-1", `{"message":"accepted"}`)
	enqueueOTLP(t, dispatcher, "partial-record-2", `{"message":"rejected"}`)
	drainOTLP(t, dispatcher)

	if calls.Load() != 1 {
		t.Fatalf("calls = %d, want one terminal request", calls.Load())
	}
	if got := adapter.Counters(); got.Accepted != 2 || got.Exported != 1 || got.RejectedPartial != 1 {
		t.Fatalf("adapter counters = %+v", got)
	}
	if got := observer.count(observability.SignalLogs, SignalOutcomeExported); got != 1 {
		t.Fatalf("exported observation = %d", got)
	}
	if got := observer.count(observability.SignalLogs, SignalOutcomePartialRejected); got != 1 {
		t.Fatalf("partial rejection observation = %d", got)
	}
	if got := dispatcher.Counters(); got.Retried != 0 || got.Rejected != 1 || got.Delivered != 1 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
	_ = adapter.Close(context.Background())
}

func TestMalformedNegativeLogPartialSuccessIsTerminalForHTTPAndGRPC(t *testing.T) {
	t.Run("HTTP", func(t *testing.T) {
		var calls atomic.Uint64
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			encoded, _ := proto.Marshal(&collectorlogpb.ExportLogsServiceResponse{
				PartialSuccess: &collectorlogpb.ExportLogsPartialSuccess{RejectedLogRecords: -1},
			})
			_, _ = writer.Write(encoded)
		}))
		defer server.Close()
		observer := &signalEventCapture{}
		factory := prepareTestFactory(t, Config{
			Destination: "negative-http-partial", Protocol: ProtocolHTTP, Endpoint: server.URL,
			Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
			TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		}, Dependencies{Observer: observer})
		adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		dispatcher := newOTLPDispatcher(t, "negative-http-partial", adapter)
		enqueueOTLP(t, dispatcher, "negative-http-record", `{"message":"malformed partial"}`)
		drainOTLP(t, dispatcher)
		assertMalformedPartialResult(t, calls.Load(), dispatcher.Counters(), adapter.Counters(), observer)
		_ = adapter.Close(context.Background())
	})

	t.Run("gRPC", func(t *testing.T) {
		listener, err := net.Listen("tcp", "127.0.0.1:0")
		if err != nil {
			t.Fatal(err)
		}
		server := grpc.NewServer()
		capture := &negativePartialGRPCLogServer{}
		collectorlogpb.RegisterLogsServiceServer(server, capture)
		go server.Serve(listener)
		t.Cleanup(func() {
			server.Stop()
			_ = listener.Close()
		})
		observer := &signalEventCapture{}
		factory := prepareTestFactory(t, Config{
			Destination: "negative-grpc-partial", Protocol: ProtocolGRPC, Endpoint: listener.Addr().String(),
			Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
			TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		}, Dependencies{Observer: observer})
		adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		dispatcher := newOTLPDispatcher(t, "negative-grpc-partial", adapter)
		enqueueOTLP(t, dispatcher, "negative-grpc-record", `{"message":"malformed partial"}`)
		drainOTLP(t, dispatcher)
		assertMalformedPartialResult(t, capture.calls.Load(), dispatcher.Counters(), adapter.Counters(), observer)
		_ = adapter.Close(context.Background())
	})
}

func TestLogPartialSuccessAboveBatchCountClampsToAllRejected(t *testing.T) {
	var calls atomic.Uint64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
		calls.Add(1)
		encoded, _ := proto.Marshal(&collectorlogpb.ExportLogsServiceResponse{
			PartialSuccess: &collectorlogpb.ExportLogsPartialSuccess{RejectedLogRecords: 99},
		})
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()
	factory := prepareTestFactory(t, Config{
		Destination: "over-count-partial", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcherWithDelay(t, "over-count-partial", adapter, time.Hour)
	enqueueOTLP(t, dispatcher, "over-count-record-1", `{"message":"one"}`)
	enqueueOTLP(t, dispatcher, "over-count-record-2", `{"message":"two"}`)
	drainOTLP(t, dispatcher)
	if calls.Load() != 1 {
		t.Fatalf("calls = %d", calls.Load())
	}
	if got := dispatcher.Counters(); got.Retried != 0 || got.Delivered != 0 || got.Rejected != 2 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
	if got := adapter.Counters(); got.Exported != 0 || got.RejectedPartial != 2 {
		t.Fatalf("adapter counters = %+v", got)
	}
	_ = adapter.Close(context.Background())
}

func assertMalformedPartialResult(
	t *testing.T,
	calls uint64,
	dispatcher delivery.Counters,
	adapter ExportCounters,
	observer *signalEventCapture,
) {
	t.Helper()
	if calls != 1 {
		t.Fatalf("calls = %d, want terminal single attempt", calls)
	}
	if dispatcher.Retried != 0 || dispatcher.Delivered != 0 || dispatcher.Rejected != 1 {
		t.Fatalf("dispatcher counters = %+v", dispatcher)
	}
	if adapter.Exported != 0 || adapter.RejectedPartial != 0 || adapter.Failed != 1 {
		t.Fatalf("adapter counters = %+v", adapter)
	}
	if got := observer.count(observability.SignalLogs, SignalOutcomeExportFailed); got != 1 {
		t.Fatalf("failure observation = %d", got)
	}
}

func TestHTTPLogAcknowledgementAndPostWriteFailureClassification(t *testing.T) {
	t.Run("pre-write connect failure", func(t *testing.T) {
		dialer := &recordingDialer{}
		factory := prepareTestFactory(t, Config{
			Destination: "pre-write", Protocol: ProtocolHTTP, Endpoint: "http://collector.example.test:4318",
			Selected: []observability.Signal{observability.SignalLogs}, Timeout: 100 * time.Millisecond,
			TLS: TLSConfig{Insecure: true},
		}, Dependencies{
			Resolver: staticResolver{answers: []net.IPAddr{{IP: net.ParseIP("8.8.8.8")}}},
			Dialer:   dialer,
		})
		adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		dispatcher := newOTLPDispatcher(t, "pre-write", adapter)
		enqueueOTLP(t, dispatcher, "pre-write-record", `{"message":"retry"}`)
		drainOTLP(t, dispatcher)
		if got := dispatcher.Counters(); got.Retried != 2 || got.Rejected != 1 {
			t.Fatalf("pre-write counters = %+v", got)
		}
		if calls := dialer.calls.Load(); calls < 1 || calls > 3 {
			t.Fatalf("pre-write dial calls = %d, want within bounded delivery attempts", calls)
		}
		_ = adapter.Close(context.Background())
	})

	t.Run("empty success is the zero protobuf response", func(t *testing.T) {
		var calls atomic.Int64
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			calls.Add(1)
			writer.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		factory := prepareTestFactory(t, Config{
			Destination: "missing-ack", Protocol: ProtocolHTTP, Endpoint: server.URL,
			Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
			TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		}, Dependencies{})
		adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		dispatcher := newOTLPDispatcher(t, "missing-ack", adapter)
		enqueueOTLP(t, dispatcher, "missing-ack-record", `{"message":"ambiguous"}`)
		drainOTLP(t, dispatcher)
		if got := dispatcher.Counters(); got.Retried != 0 || got.Rejected != 0 || got.Delivered != 1 {
			t.Fatalf("empty success counters = %+v", got)
		}
		if calls.Load() != 1 {
			t.Fatalf("empty success calls = %d", calls.Load())
		}
		_ = adapter.Close(context.Background())
	})

	for name, responseBody := range map[string][]byte{
		"malformed acknowledgement": []byte("not-protobuf"),
		"oversized acknowledgement": make([]byte, maxLogResponseBodyBytes+1),
	} {
		t.Run(name, func(t *testing.T) {
			server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
				_, _ = writer.Write(responseBody)
			}))
			defer server.Close()
			factory := prepareTestFactory(t, Config{
				Destination: "bad-ack", Protocol: ProtocolHTTP, Endpoint: server.URL,
				Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
				TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
			}, Dependencies{})
			adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
			if err != nil {
				t.Fatal(err)
			}
			dispatcher := newOTLPDispatcher(t, "bad-ack", adapter)
			enqueueOTLP(t, dispatcher, "bad-ack-record", `{"message":"ambiguous"}`)
			drainOTLP(t, dispatcher)
			if got := dispatcher.Counters(); got.Retried != 2 || got.Rejected != 1 {
				t.Fatalf("bad ack counters = %+v", got)
			}
			_ = adapter.Close(context.Background())
		})
	}

	t.Run("truncated response body", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, _ *http.Request) {
			writer.Header().Set("Content-Length", "5")
			writer.WriteHeader(http.StatusOK)
		}))
		defer server.Close()
		factory := prepareTestFactory(t, Config{
			Destination: "truncated-ack", Protocol: ProtocolHTTP, Endpoint: server.URL,
			Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
			TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		}, Dependencies{})
		adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		dispatcher := newOTLPDispatcher(t, "truncated-ack", adapter)
		enqueueOTLP(t, dispatcher, "truncated-ack-record", `{"message":"ambiguous"}`)
		drainOTLP(t, dispatcher)
		if got := dispatcher.Counters(); got.Retried != 2 || got.Rejected != 1 {
			t.Fatalf("truncated response counters = %+v", got)
		}
		_ = adapter.Close(context.Background())
	})

	t.Run("post write disconnect", func(t *testing.T) {
		server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
			_, _ = io.Copy(io.Discard, request.Body)
			hijacker, ok := writer.(http.Hijacker)
			if !ok {
				t.Error("response writer cannot hijack")
				return
			}
			connection, _, err := hijacker.Hijack()
			if err == nil {
				_ = connection.Close()
			}
		}))
		defer server.Close()
		factory := prepareTestFactory(t, Config{
			Destination: "post-write", Protocol: ProtocolHTTP, Endpoint: server.URL,
			Selected: []observability.Signal{observability.SignalLogs}, Timeout: time.Second,
			TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		}, Dependencies{})
		adapter, err := factory.NewLogAdapter(context.Background(), testLogResourceSnapshot())
		if err != nil {
			t.Fatal(err)
		}
		dispatcher := newOTLPDispatcher(t, "post-write", adapter)
		enqueueOTLP(t, dispatcher, "post-write-record", `{"message":"ambiguous"}`)
		drainOTLP(t, dispatcher)
		if got := dispatcher.Counters(); got.Retried != 2 || got.Rejected != 1 {
			t.Fatalf("post-write counters = %+v", got)
		}
		_ = adapter.Close(context.Background())
	})
}

func TestBoundedSpanProcessorEnforcesQueueAndBatchBytes(t *testing.T) {
	span := testSpan("bounded.span")
	bound, ok := conservativeSpanBytes(span)
	if !ok {
		t.Fatal("span bound failed")
	}
	inner := &capturingSpanExporter{}
	exporter := &SpanExporter{
		inner: inner, maxBytes: bound,
		config: signalConfig{observer: SignalObserverFunc(func(SignalEvent) {})},
	}
	processor := newBoundedSpanProcessor(exporter, BatchConfig{
		MaxQueueSize: 2, MaxQueueBytes: 2 * bound,
		MaxExportBatchSize: 2, MaxExportBatchBytes: bound,
		ScheduledDelay: time.Hour,
	})
	processor.OnEnd(span)
	processor.OnEnd(span)
	processor.OnEnd(span)
	if err := processor.ForceFlush(context.Background()); err != nil {
		t.Fatal(err)
	}
	if err := processor.Shutdown(context.Background()); err != nil {
		t.Fatal(err)
	}
	if got := inner.batchSizes(); len(got) != 2 || got[0] != 1 || got[1] != 1 {
		t.Fatalf("span batches = %v, want [1 1]", got)
	}
	if got := processor.Counters(); got.DroppedQueueFull != 1 || got.Exported != 2 {
		t.Fatalf("span counters = %+v", got)
	}
}

func TestBoundedSpanProcessorShutdownAfterFlushTimeoutStillTerminatesWorkerAndExporter(t *testing.T) {
	inner := &capturingSpanExporter{}
	exporter := &SpanExporter{
		inner:  inner,
		config: signalConfig{timeout: time.Second, observer: SignalObserverFunc(func(SignalEvent) {})},
	}
	processor := newBoundedSpanProcessor(exporter, BatchConfig{
		MaxQueueSize: 1, MaxQueueBytes: 1024, MaxExportBatchSize: 1,
		MaxExportBatchBytes: 1024, ScheduledDelay: time.Hour,
	})
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	if err := processor.Shutdown(ctx); err == nil {
		t.Fatal("canceled shutdown unexpectedly succeeded")
	}
	select {
	case <-processor.done:
	case <-time.After(time.Second):
		t.Fatal("flush timeout stranded the span worker")
	}
	deadline := time.Now().Add(time.Second)
	for inner.shutdowns.Load() == 0 && time.Now().Before(deadline) {
		time.Sleep(time.Millisecond)
	}
	if inner.shutdowns.Load() != 1 {
		t.Fatalf("inner exporter shutdowns = %d", inner.shutdowns.Load())
	}
	exporter.mu.RLock()
	closed := exporter.closed
	exporter.mu.RUnlock()
	if !closed {
		t.Fatal("flush timeout left the span exporter open")
	}
}

func TestBoundedSpanProcessorPanickingExporterShutdownStillClosesTerminal(t *testing.T) {
	inner := &capturingSpanExporter{panicShutdown: true}
	exporter := &SpanExporter{
		inner:  inner,
		config: signalConfig{timeout: time.Second, observer: SignalObserverFunc(func(SignalEvent) {})},
	}
	processor := newBoundedSpanProcessor(exporter, BatchConfig{
		MaxQueueSize: 1, MaxQueueBytes: 1024, MaxExportBatchSize: 1,
		MaxExportBatchBytes: 1024, ScheduledDelay: time.Hour,
	})
	if err := processor.Shutdown(context.Background()); err == nil {
		t.Fatal("panicking exporter shutdown was not converted to a bounded error")
	}
	select {
	case <-processor.TerminalDone():
	default:
		t.Fatal("panicking exporter stranded terminal completion")
	}
	if inner.shutdowns.Load() != 1 {
		t.Fatalf("inner exporter shutdowns = %d", inner.shutdowns.Load())
	}
}

func TestMetricExporterPreflightRejectsAboveEncodedByteCeiling(t *testing.T) {
	metrics := testMetricData("defenseclaw.metric.boundary")
	bound, ok := conservativeMetricBytes(metrics)
	if !ok || bound <= 1 {
		t.Fatalf("metric bound = %d, %t", bound, ok)
	}
	var calls atomic.Int64
	var wireBytes atomic.Int64
	server := httptest.NewServer(http.HandlerFunc(func(writer http.ResponseWriter, request *http.Request) {
		calls.Add(1)
		body, _ := io.ReadAll(request.Body)
		wireBytes.Store(int64(len(body)))
		encoded, _ := proto.Marshal(&collectormetricpb.ExportMetricsServiceResponse{})
		_, _ = writer.Write(encoded)
	}))
	defer server.Close()
	config := Config{
		Destination: "metric-bound-low", Protocol: ProtocolHTTP, Endpoint: server.URL,
		Selected: []observability.Signal{observability.SignalMetrics}, Timeout: time.Second,
		TLS: TLSConfig{Insecure: true}, NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
		Batch: testBatch(),
	}
	config.Batch.MaxExportBatchBytes = bound - 1
	factory, err := Prepare(context.Background(), config, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	exporter, err := factory.NewMetricExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Export(context.Background(), metrics); !IsError(err, ErrorExport) {
		t.Fatalf("oversize export error = %v", err)
	}
	if calls.Load() != 0 || exporter.Counters().RejectedOversize != 1 {
		t.Fatalf("oversize calls=%d counters=%+v", calls.Load(), exporter.Counters())
	}
	if health := exporter.deliveryHealthSnapshot(); health.State != delivery.HealthFailing ||
		health.Reason != string(delivery.HealthReasonDeliveryFailed) || health.LastFailure.IsZero() {
		t.Fatalf("oversize metric health=%+v", health)
	}
	_ = exporter.Shutdown(context.Background())

	config.Destination = "metric-bound-ok"
	config.Batch.MaxExportBatchBytes = bound
	factory, err = Prepare(context.Background(), config, Dependencies{})
	if err != nil {
		t.Fatal(err)
	}
	exporter, err = factory.NewMetricExporter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	if err := exporter.Export(context.Background(), metrics); err != nil {
		t.Fatal(err)
	}
	if calls.Load() != 1 || exporter.Counters().Exported != 1 {
		t.Fatalf("boundary calls=%d counters=%+v", calls.Load(), exporter.Counters())
	}
	if health := exporter.deliveryHealthSnapshot(); health.State != delivery.HealthHealthy ||
		health.Reason != string(delivery.HealthReasonRecovered) || health.LastSuccess.IsZero() {
		t.Fatalf("successful metric health=%+v", health)
	}
	if wireBytes.Load() <= 0 || wireBytes.Load() > int64(bound) {
		t.Fatalf("metric wire bytes = %d, conservative bound = %d", wireBytes.Load(), bound)
	}
	_ = exporter.Shutdown(context.Background())
}

func TestLogEncodedSizeAndMalformedProjection(t *testing.T) {
	adapter := &LogAdapter{}
	if size, ok := adapter.EncodedSize([]int{10, 20}); !ok || size != logRequestBaseBytes+30+2*logRecordWrapperBytes {
		t.Fatalf("EncodedSize = (%d,%t)", size, ok)
	}
	if _, ok := adapter.EncodedSize([]int{-1}); ok {
		t.Fatal("negative size accepted")
	}
	if _, ok := adapter.EncodedSize([]int{maxInt}); ok {
		t.Fatal("overflow size accepted")
	}
}

type grpcLogCapture struct {
	collectorlogpb.UnimplementedLogsServiceServer
	requests chan *collectorlogpb.ExportLogsServiceRequest
	headers  chan metadata.MD
}

type negativePartialGRPCLogServer struct {
	collectorlogpb.UnimplementedLogsServiceServer
	calls atomic.Uint64
}

func (server *negativePartialGRPCLogServer) Export(context.Context, *collectorlogpb.ExportLogsServiceRequest) (*collectorlogpb.ExportLogsServiceResponse, error) {
	server.calls.Add(1)
	return &collectorlogpb.ExportLogsServiceResponse{
		PartialSuccess: &collectorlogpb.ExportLogsPartialSuccess{RejectedLogRecords: -1},
	}, nil
}

type capturingSpanExporter struct {
	mu            sync.Mutex
	batches       []int
	shutdowns     atomic.Int64
	panicShutdown bool
}

type signalEventCapture struct {
	mu     sync.Mutex
	events []SignalEvent
}

func (capture *signalEventCapture) ObserveOTLPSignal(event SignalEvent) {
	capture.mu.Lock()
	capture.events = append(capture.events, event)
	capture.mu.Unlock()
}

func (capture *signalEventCapture) count(signal observability.Signal, outcome SignalOutcome) uint64 {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	var count uint64
	for _, event := range capture.events {
		if event.Signal == signal && event.Outcome == outcome {
			count += event.Count
		}
	}
	return count
}

func (exporter *capturingSpanExporter) ExportSpans(_ context.Context, spans []sdktrace.ReadOnlySpan) error {
	exporter.mu.Lock()
	exporter.batches = append(exporter.batches, len(spans))
	exporter.mu.Unlock()
	return nil
}

func (exporter *capturingSpanExporter) Shutdown(context.Context) error {
	exporter.shutdowns.Add(1)
	if exporter.panicShutdown {
		panic("exporter shutdown panic")
	}
	return nil
}

func (exporter *capturingSpanExporter) batchSizes() []int {
	exporter.mu.Lock()
	defer exporter.mu.Unlock()
	return append([]int(nil), exporter.batches...)
}

func (capture *grpcLogCapture) Export(ctx context.Context, request *collectorlogpb.ExportLogsServiceRequest) (*collectorlogpb.ExportLogsServiceResponse, error) {
	headers, _ := metadata.FromIncomingContext(ctx)
	capture.headers <- headers
	capture.requests <- request
	return &collectorlogpb.ExportLogsServiceResponse{}, nil
}

type grpcTraceCapture struct {
	collectortracepb.UnimplementedTraceServiceServer
	requests chan *collectortracepb.ExportTraceServiceRequest
}

type retryingGRPCTraceCapture struct {
	collectortracepb.UnimplementedTraceServiceServer
	mu       sync.Mutex
	requests []*collectortracepb.ExportTraceServiceRequest
}

func (capture *retryingGRPCTraceCapture) Export(_ context.Context, request *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	capture.mu.Lock()
	capture.requests = append(capture.requests, proto.Clone(request).(*collectortracepb.ExportTraceServiceRequest))
	attempt := len(capture.requests)
	capture.mu.Unlock()
	if attempt == 1 {
		return nil, status.Error(codes.Unavailable, "retryable test failure")
	}
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

func (capture *retryingGRPCTraceCapture) snapshot() []*collectortracepb.ExportTraceServiceRequest {
	capture.mu.Lock()
	defer capture.mu.Unlock()
	return append([]*collectortracepb.ExportTraceServiceRequest(nil), capture.requests...)
}

func (capture *grpcTraceCapture) Export(_ context.Context, request *collectortracepb.ExportTraceServiceRequest) (*collectortracepb.ExportTraceServiceResponse, error) {
	capture.requests <- request
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

type grpcMetricCapture struct {
	collectormetricpb.UnimplementedMetricsServiceServer
	requests chan *collectormetricpb.ExportMetricsServiceRequest
}

func (capture *grpcMetricCapture) Export(_ context.Context, request *collectormetricpb.ExportMetricsServiceRequest) (*collectormetricpb.ExportMetricsServiceResponse, error) {
	capture.requests <- request
	return &collectormetricpb.ExportMetricsServiceResponse{}, nil
}

type staticResolver struct {
	answers []net.IPAddr
	err     error
}

func (resolver staticResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	return append([]net.IPAddr(nil), resolver.answers...), resolver.err
}

type sequenceResolver struct {
	mu      sync.Mutex
	answers [][]net.IPAddr
	calls   int
}

func (resolver *sequenceResolver) LookupIPAddr(context.Context, string) ([]net.IPAddr, error) {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	index := resolver.calls
	resolver.calls++
	if index >= len(resolver.answers) {
		index = len(resolver.answers) - 1
	}
	return append([]net.IPAddr(nil), resolver.answers[index]...), nil
}

func (resolver *sequenceResolver) callCount() int {
	resolver.mu.Lock()
	defer resolver.mu.Unlock()
	return resolver.calls
}

type recordingDialer struct{ calls atomic.Int64 }

func (dialer *recordingDialer) DialContext(context.Context, string, string) (net.Conn, error) {
	dialer.calls.Add(1)
	return nil, errors.New("dialer detail must not escape")
}

func prepareTestFactory(t *testing.T, config Config, dependencies Dependencies) *Factory {
	t.Helper()
	if config.Batch.MaxQueueSize == 0 {
		config.Batch = testBatch()
	}
	factory, err := Prepare(context.Background(), config, dependencies)
	if err != nil {
		t.Fatal(err)
	}
	return factory
}

func testBatch() BatchConfig {
	return BatchConfig{
		MaxQueueSize: 64, MaxQueueBytes: 64 * 1024 * 1024,
		MaxExportBatchSize: 16, MaxExportBatchBytes: 8 * 1024 * 1024,
		ScheduledDelay: time.Millisecond, ExportInterval: time.Second,
	}
}

func newOTLPDispatcher(t *testing.T, name string, adapter delivery.Adapter) *delivery.Dispatcher {
	return newOTLPDispatcherWithDelay(t, name, adapter, time.Millisecond)
}

func newOTLPDispatcherWithDelay(t *testing.T, name string, adapter delivery.Adapter, delay time.Duration) *delivery.Dispatcher {
	t.Helper()
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: name, Enabled: true,
		MaxQueueItems: 16, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: 4, MaxBatchBytes: 8 * 1024 * 1024,
		ScheduledDelay: delay, AttemptTimeout: time.Second,
		Retry: delivery.RetryPolicy{
			MaxAttempts: 3, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond,
			Jitter: func(delay time.Duration, _ int) time.Duration { return delay },
		},
	}, adapter)
	if err != nil {
		t.Fatal(err)
	}
	dispatcher.Activate()
	return dispatcher
}

func enqueueOTLP(t *testing.T, dispatcher *delivery.Dispatcher, id, body string) {
	t.Helper()
	payload, err := delivery.NewPayload([]byte(body), delivery.RoutingIdentity{
		RecordID: id, Bucket: "model.io", Signal: "logs", EventName: "model.response",
	})
	if err != nil {
		t.Fatal(err)
	}
	if result := dispatcher.Enqueue(payload); !result.Accepted() {
		t.Fatalf("enqueue = %+v", result)
	}
}

func drainOTLP(t *testing.T, dispatcher *delivery.Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
	defer cancel()
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func findProtoAttribute(attributes []*commonpb.KeyValue, key string) string {
	for _, attribute := range attributes {
		if attribute != nil && attribute.Key == key && attribute.Value != nil {
			return attribute.Value.GetStringValue()
		}
	}
	return ""
}

const testCompleteSignalResourceSchemaURL = "https://opentelemetry.io/schemas/1.42.0"

func testCompleteSignalResourceValues() map[string]string {
	return map[string]string{
		"service.name":                "defenseclaw",
		"service.version":             "8.0.0-test",
		"service.namespace":           "defenseclaw",
		"service.instance.id":         "otlp-test-instance",
		"deployment.environment.name": "test",
		"host.name":                   "otlp-test-host",
		"host.arch":                   "amd64",
		"os.type":                     "linux",
		"tenant.id":                   "tenant-test",
		"workspace.id":                "workspace-test",
		"defenseclaw.deployment.mode": "unmanaged",
		"defenseclaw.claw.mode":       "multi",
		"defenseclaw.instance.id":     "defenseclaw-test-instance",
		"defenseclaw.device.public_key_fingerprint": "sha256:test-device-fingerprint",
		"operator.profile":                          "soc",
		"deployment.environment":                    "test",
		"deployment.mode":                           "unmanaged",
		"defenseclaw.device.id":                     "sha256:test-device-fingerprint",
	}
}

func testCompleteSignalResource() (*resource.Resource, map[string]string) {
	values := testCompleteSignalResourceValues()
	attrs := make([]attribute.KeyValue, 0, len(values))
	for key, value := range values {
		attrs = append(attrs, attribute.String(key, value))
	}
	return resource.NewWithAttributes(testCompleteSignalResourceSchemaURL, attrs...), values
}

func assertExactSignalResource(
	t *testing.T,
	schemaURL string,
	got *resourcepb.Resource,
) {
	t.Helper()
	want := testCompleteSignalResourceValues()
	if schemaURL != testCompleteSignalResourceSchemaURL {
		t.Fatalf("resource schema URL = %q, want %q", schemaURL, testCompleteSignalResourceSchemaURL)
	}
	if got == nil || got.DroppedAttributesCount != 0 || len(got.Attributes) != len(want) {
		count := -1
		dropped := uint32(0)
		if got != nil {
			count = len(got.Attributes)
			dropped = got.DroppedAttributesCount
		}
		t.Fatalf("resource attributes/dropped = %d/%d, want %d/0", count, dropped, len(want))
	}
	seen := make(map[string]struct{}, len(got.Attributes))
	for _, item := range got.Attributes {
		if item == nil || item.Value == nil {
			t.Fatal("resource contains nil attribute")
		}
		if _, duplicate := seen[item.Key]; duplicate {
			t.Fatalf("resource contains duplicate attribute %q", item.Key)
		}
		seen[item.Key] = struct{}{}
		stringValue, ok := item.Value.Value.(*commonpb.AnyValue_StringValue)
		if !ok {
			t.Fatalf("resource attribute %q has non-string wire type %T", item.Key, item.Value.Value)
		}
		expected, known := want[item.Key]
		if !known || stringValue.StringValue != expected {
			t.Fatalf("resource attribute %q = %q known=%t, want %q", item.Key, stringValue.StringValue, known, expected)
		}
	}
	for key := range want {
		if _, present := seen[key]; !present {
			t.Fatalf("resource is missing attribute %q", key)
		}
	}
	for alias, canonical := range map[string]string{
		"deployment.environment": "deployment.environment.name",
		"deployment.mode":        "defenseclaw.deployment.mode",
		"defenseclaw.device.id":  "defenseclaw.device.public_key_fingerprint",
	} {
		if want[alias] != want[canonical] {
			t.Fatalf("resource alias %q does not mirror %q", alias, canonical)
		}
	}
}

func testSpan(name string) sdktrace.ReadOnlySpan {
	return testSpanWithResource(
		name,
		resource.NewSchemaless(attribute.String("service.name", "defenseclaw")),
	)
}

func testSpanWithResource(name string, signalResource *resource.Resource) sdktrace.ReadOnlySpan {
	return tracetest.SpanStub{
		Name: name, SpanContext: trace.NewSpanContext(trace.SpanContextConfig{
			TraceID: trace.TraceID{1}, SpanID: trace.SpanID{2}, TraceFlags: trace.FlagsSampled,
		}),
		StartTime: time.Now().Add(-time.Millisecond), EndTime: time.Now(),
		Attributes:           []attribute.KeyValue{attribute.String("defenseclaw.bucket", "guardrail.evaluation")},
		Resource:             signalResource,
		InstrumentationScope: instrumentation.Scope{Name: "defenseclaw", Version: "test"},
	}.Snapshot()
}

func testMetricData(name string) *metricdata.ResourceMetrics {
	return testMetricDataWithResource(
		name,
		resource.NewSchemaless(attribute.String("service.name", "defenseclaw")),
	)
}

func testMetricDataWithResource(name string, signalResource *resource.Resource) *metricdata.ResourceMetrics {
	return &metricdata.ResourceMetrics{
		Resource: signalResource,
		ScopeMetrics: []metricdata.ScopeMetrics{{
			Scope: instrumentation.Scope{Name: "defenseclaw"},
			Metrics: []metricdata.Metrics{{
				Name: name,
				Data: metricdata.Gauge[int64]{DataPoints: []metricdata.DataPoint[int64]{{Value: 1, Time: time.Now()}}},
			}},
		}},
	}
}
