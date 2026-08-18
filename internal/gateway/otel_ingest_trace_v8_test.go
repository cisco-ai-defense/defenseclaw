// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net/http"
	"net/http/httptest"
	"path/filepath"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/pipeline"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	"github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/observability/runtimegraph"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
	"go.opentelemetry.io/otel/codes"
	collectorlogspb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	collectormetricspb "go.opentelemetry.io/proto/otlp/collector/metrics/v1"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

type otlpTracePipelines struct {
	mu       sync.Mutex
	captures map[uint64]*proxyCanonicalCapture
	engine   *observabilityredaction.Engine
}

type otlpRoutedTraceCapture struct {
	capture    *proxyCanonicalCapture
	projection *pipeline.TraceProjectionPipeline
}

func (capture *otlpRoutedTraceCapture) TryEnqueue(
	span telemetry.V8CanonicalEndedSpan,
) telemetry.V8CanonicalSpanEnqueueResult {
	if capture == nil || capture.capture == nil || capture.projection == nil {
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	outcome, err := capture.projection.Process(span.Record())
	if err != nil || len(outcome.OptionalFailures()) != 0 {
		return telemetry.V8CanonicalSpanEnqueueFailed
	}
	for _, work := range outcome.OptionalWork() {
		if work.Delivery().DestinationName == "capture" {
			return capture.capture.TryEnqueue(span)
		}
	}
	// A first-match route intentionally dropped or did not select this span.
	// The canonical handoff was still consumed successfully.
	return telemetry.V8CanonicalSpanEnqueueAccepted
}

func (capture *otlpRoutedTraceCapture) ForceFlush(ctx context.Context) error {
	if capture == nil || capture.capture == nil {
		return nil
	}
	return capture.capture.ForceFlush(ctx)
}

func (capture *otlpRoutedTraceCapture) Shutdown(ctx context.Context) error {
	if capture == nil || capture.capture == nil {
		return nil
	}
	return capture.capture.Shutdown(ctx)
}

func (pipelines *otlpTracePipelines) build(
	_ context.Context,
	plan *config.ObservabilityV8Plan,
	generation uint64,
	_ telemetry.V8MetricReaderSpec,
) (telemetry.V8GenerationPipelines, error) {
	evaluator, err := router.New(plan)
	if err != nil {
		return telemetry.V8GenerationPipelines{}, err
	}
	projection, err := pipeline.NewTraceProjectionPipeline(plan, evaluator, pipelines.engine)
	if err != nil {
		return telemetry.V8GenerationPipelines{}, err
	}
	capture := &proxyCanonicalCapture{}
	pipelines.mu.Lock()
	pipelines.captures[generation] = capture
	pipelines.mu.Unlock()
	return telemetry.V8GenerationPipelines{SpanPipelines: []telemetry.V8GenerationSpanPipeline{{
		Destination: "capture", Canonical: &otlpRoutedTraceCapture{capture: capture, projection: projection},
	}}}, nil
}

func (pipelines *otlpTracePipelines) capture(t *testing.T, generation uint64) *proxyCanonicalCapture {
	t.Helper()
	pipelines.mu.Lock()
	defer pipelines.mu.Unlock()
	capture := pipelines.captures[generation]
	if capture == nil {
		t.Fatalf("trace capture generation %d missing", generation)
	}
	return capture
}

func (pipelines *otlpTracePipelines) snapshot(generation uint64) []telemetry.V8CanonicalEndedSpan {
	pipelines.mu.Lock()
	capture := pipelines.captures[generation]
	pipelines.mu.Unlock()
	if capture == nil {
		return nil
	}
	return capture.snapshot()
}

type otlpTraceFixture struct {
	runtime   *observabilityruntime.Runtime
	path      string
	judgePath string
	pipelines *otlpTracePipelines
}

func compileOTLPTracePlan(
	t *testing.T,
	path, judgePath, sampler string,
	collectTraces bool,
	retentionDays int,
	eventNames []observability.EventName,
) *config.ObservabilityV8Plan {
	t.Helper()
	collectLogs, collectMetrics := true, false
	source := &config.ObservabilityV8Source{
		Local: config.ObservabilityV8LocalSource{
			Path: path, JudgeBodiesPath: judgePath, RetentionDays: &retentionDays,
		},
		Defaults: config.ObservabilityV8BucketPolicySource{Collect: config.ObservabilityV8CollectSource{
			Logs: &collectLogs, Traces: &collectTraces, Metrics: &collectMetrics,
		}},
		TracePolicy: config.ObservabilityV8TracePolicySource{Sampler: sampler},
	}
	destination := config.ObservabilityV8DestinationSource{
		Name: "capture", Kind: config.ObservabilityV8DestinationOTLP,
		Protocol: "http/protobuf", Endpoint: "https://otel.example.test",
	}
	if eventNames == nil {
		destination.Send = &config.ObservabilityV8SendSource{
			Signals:          []observability.Signal{observability.SignalTraces},
			Buckets:          []observability.Bucket{"*"},
			RedactionProfile: "none",
		}
	} else {
		selector := &config.ObservabilityV8SelectorSource{
			Buckets:    []observability.Bucket{"*"},
			EventNames: append([]observability.EventName(nil), eventNames...),
		}
		destination.Routes = []config.ObservabilityV8RouteSource{{
			Name: "selected-telemetry-spans", Signals: []observability.Signal{observability.SignalTraces},
			Selector: selector, RedactionProfile: "none",
		}}
	}
	source.Destinations = []config.ObservabilityV8DestinationSource{destination}
	plan, err := config.CompileObservabilityV8(source)
	if err != nil {
		t.Fatal(err)
	}
	return plan
}

func newOTLPTraceFixture(
	t *testing.T,
	sampler string,
	collectTraces bool,
	eventNames []observability.EventName,
) otlpTraceFixture {
	t.Helper()
	previousInstanceID := gatewaylog.SidecarInstanceID()
	if previousInstanceID == "" {
		gatewaylog.SetSidecarInstanceID("otlp-trace-test")
		t.Cleanup(func() { gatewaylog.SetSidecarInstanceID(previousInstanceID) })
	}
	directory := t.TempDir()
	path := filepath.Join(directory, "audit.db")
	judgePath := filepath.Join(directory, "judge-bodies.db")
	store, err := audit.NewStore(path)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = store.Close() })
	if err := store.Init(); err != nil {
		t.Fatal(err)
	}
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	var sequence atomic.Uint64
	builder, err := observability.NewRecordBuilder(
		observability.ClockFunc(func() time.Time { return time.Now().UTC() }),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			return fmt.Sprintf("otlp-trace-failure-%d", sequence.Add(1)), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	reaper, err := audit.NewRetentionReaper(store, nil, 0, audit.RetentionOptions{})
	if err != nil {
		t.Fatal(err)
	}
	retention, err := observabilityruntime.NewRetentionController(reaper, observabilityruntime.RetentionControllerOptions{})
	if err != nil {
		t.Fatal(err)
	}
	pipelines := &otlpTracePipelines{
		captures: make(map[uint64]*proxyCanonicalCapture), engine: engine,
	}
	plan := compileOTLPTracePlan(t, path, judgePath, sampler, collectTraces, 0, eventNames)
	providerFactory := telemetry.NewV8ProviderFactory(telemetry.V8ProviderOptions{
		Version: "8.0.0", Environment: "test", ServiceInstanceID: "otlp-trace-test",
		DefenseClawInstanceID: "otlp-trace-test", GenerationPipelines: pipelines.build,
	})
	runtime, err := observabilityruntime.New(
		t.Context(), runtimegraph.ConfigFromPlan(plan, false), observabilityruntime.Options{
			Store: store, Engine: engine, RecordBuilder: builder,
			Reporter: &discardSidecarGraphReporter{}, RetentionController: retention,
			TelemetryProviderFactory: providerFactory,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), 5*time.Second)
		defer cancel()
		if closeErr := runtime.Close(ctx); closeErr != nil {
			t.Errorf("close OTLP trace runtime: %v", closeErr)
		}
	})
	return otlpTraceFixture{runtime: runtime, path: path, judgePath: judgePath, pipelines: pipelines}
}

func TestOTLPInboundJSONProtobufParity(t *testing.T) {
	parityCases := []struct {
		name    string
		signal  otelIngestSignal
		message proto.Message
	}{
		{
			name: "logs", signal: otelSignalLogs,
			message: &collectorlogspb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
				ScopeLogs: []*logspb.ScopeLogs{{LogRecords: []*logspb.LogRecord{{
					TimeUnixNano: 1, Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: "parity"}},
				}}}},
			}}},
		},
		{
			name: "traces", signal: otelSignalTraces,
			message: &collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
				ScopeSpans: []*tracepb.ScopeSpans{{Spans: []*tracepb.Span{{
					TraceId: []byte{1, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 0, 1},
					SpanId:  []byte{1, 0, 0, 0, 0, 0, 0, 1}, StartTimeUnixNano: 1, EndTimeUnixNano: 2,
				}}}},
			}}},
		},
		{
			name: "metrics", signal: otelSignalMetrics,
			message: &collectormetricspb.ExportMetricsServiceRequest{ResourceMetrics: []*metricspb.ResourceMetrics{{
				ScopeMetrics: []*metricspb.ScopeMetrics{{Metrics: []*metricspb.Metric{{
					Name: "parity.metric", Unit: "1",
					Data: &metricspb.Metric_Gauge{Gauge: &metricspb.Gauge{DataPoints: []*metricspb.NumberDataPoint{{
						TimeUnixNano: 1, Value: &metricspb.NumberDataPoint_AsInt{AsInt: 1},
					}}}},
				}}}},
			}}},
		},
	}
	for _, test := range parityCases {
		t.Run(test.name+"-typed-parity", func(t *testing.T) {
			jsonBody, err := protojson.Marshal(test.message)
			if err != nil {
				t.Fatal(err)
			}
			protobufBody, err := proto.Marshal(test.message)
			if err != nil {
				t.Fatal(err)
			}
			normalizedJSON, jsonFormat, err := normalizeOTLPIngestBody(jsonBody, test.signal, "application/json")
			if err != nil {
				t.Fatal(err)
			}
			normalizedProtobuf, protobufFormat, err := normalizeOTLPIngestBody(protobufBody, test.signal, "application/x-protobuf")
			if err != nil {
				t.Fatal(err)
			}
			if jsonFormat != "json" || protobufFormat != "protobuf" || !bytes.Equal(normalizedJSON, normalizedProtobuf) {
				t.Fatalf("%s JSON/protobuf normalized mismatch\njson=%s\nprotobuf=%s",
					test.name, normalizedJSON, normalizedProtobuf)
			}
		})
	}

	protobufBody, err := proto.Marshal(&collectorlogspb.ExportLogsServiceRequest{
		ResourceLogs: []*logspb.ResourceLogs{{ScopeLogs: []*logspb.ScopeLogs{{
			LogRecords: []*logspb.LogRecord{{Body: &commonpb.AnyValue{
				Value: &commonpb.AnyValue_StringValue{StringValue: "protobuf-secret-value"},
			}}},
		}}}},
	})
	if err != nil {
		t.Fatal(err)
	}
	for _, test := range []struct {
		name        string
		contentType string
		body        []byte
		secret      string
		format      string
	}{
		{
			name: "json", contentType: "application/json", format: "json",
			body:   []byte(`{"resourceLogs":[{"scopeLogs":[{"logRecords":[{"body":{"stringValue":"json-secret-value"},"attributes":[{"key":"session.id","value":{"stringValue":"session-001"}}]}]}]}]}`),
			secret: "json-secret-value",
		},
		{name: "protobuf", contentType: "application/x-protobuf", body: protobufBody, secret: "protobuf-secret-value", format: "protobuf"},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOTLPTraceFixture(t, "always_on", true, nil)
			api := &APIServer{}
			api.bindOTLPObservabilityRuntime(fixture.runtime)
			request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			request.Header.Set(otelSourceHeader, "codex")
			response := httptest.NewRecorder()

			api.handleOTLPLogs(response, request)

			if response.Code != http.StatusOK || response.Body.String() != "{}" {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
			spans := fixture.pipelines.capture(t, 1).snapshot()
			receive, normalize := otlpTracePair(t, spans)
			parent, ok := normalize.ParentSpanID()
			if receive.Name() != "POST telemetry" || normalize.Name() != "telemetry.normalize logs" ||
				!ok || parent != receive.SpanID() || receive.StatusCode() != codes.Error || normalize.StatusCode() != codes.Error {
				t.Fatalf("trace hierarchy receive=%s normalize=%s parent=%s/%t", receive.Name(), normalize.Name(), parent, ok)
			}
			for _, span := range []telemetry.V8CanonicalEndedSpan{receive, normalize} {
				encoded, marshalErr := json.Marshal(span.Record())
				if marshalErr != nil {
					t.Fatal(marshalErr)
				}
				if bytes.Contains(encoded, []byte(test.secret)) {
					t.Fatalf("span retained raw payload: %s", encoded)
				}
				attributes := proxyCanonicalAttributes(t, span.Record())
				if attributes["defenseclaw.telemetry.payload_format"] != test.format ||
					fmt.Sprint(attributes["defenseclaw.telemetry.record_count"]) != "1" {
					t.Fatalf("span attributes=%v", attributes)
				}
			}
			events := readStoredOTLPV8Events(t, fixture.path)
			seen := map[string]bool{}
			for _, event := range events {
				seen[event.eventName] = true
				if strings.Contains(event.payload, test.secret) {
					t.Fatalf("durable accounting retained raw payload: %#v", event)
				}
			}
			if len(events) != 2 || !seen["telemetry.batch.normalized"] || !seen["telemetry.records.dropped"] {
				t.Fatalf("durable partial accounting=%#v", events)
			}
		})
	}
}

func TestOTLPIngestGeneratedTraceRejectsMalformedAndOversizeContentFree(t *testing.T) {
	for _, test := range []struct {
		name, contentType string
		body              []byte
		secret            string
	}{
		{
			name: "malformed JSON", contentType: "application/json",
			body:   []byte(`{"resourceLogs":[],"raw-secret-field":"must-not-survive"}`),
			secret: "must-not-survive",
		},
		{
			name: "malformed protobuf", contentType: "application/x-protobuf",
			body: append([]byte("protobuf-secret-value"), 0xff), secret: "protobuf-secret-value",
		},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOTLPTraceFixture(t, "always_on", true, nil)
			api := &APIServer{}
			api.bindOTLPObservabilityRuntime(fixture.runtime)
			request := httptest.NewRequest(http.MethodPost, "/v1/logs", bytes.NewReader(test.body))
			request.Header.Set("Content-Type", test.contentType)
			response := httptest.NewRecorder()
			api.handleOTLPLogs(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
			receive, normalize := otlpTracePair(t, fixture.pipelines.capture(t, 1).snapshot())
			for _, span := range []telemetry.V8CanonicalEndedSpan{receive, normalize} {
				if span.StatusCode() != codes.Error || span.StatusDescription() != "" {
					t.Fatalf("rejected status=%s description=%q", span.StatusCode(), span.StatusDescription())
				}
				encoded, err := json.Marshal(span.Record())
				if err != nil {
					t.Fatal(err)
				}
				if bytes.Contains(encoded, []byte(test.secret)) || bytes.Contains(encoded, []byte("raw-secret-field")) {
					t.Fatalf("rejected trace leaked raw input: %s", encoded)
				}
			}
			events := readStoredOTLPV8Events(t, fixture.path)
			if len(events) != 1 || events[0].eventName != "telemetry.batch.rejected" || events[0].mandatory != 1 {
				t.Fatalf("rejection floor=%#v", events)
			}
		})
	}

	t.Run("oversize has receive only", func(t *testing.T) {
		fixture := newOTLPTraceFixture(t, "always_on", true, nil)
		api := &APIServer{}
		api.bindOTLPObservabilityRuntime(fixture.runtime)
		request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(
			`{"resourceLogs":[],"secret":"oversize-secret"}`,
		))
		request.Body = http.MaxBytesReader(httptest.NewRecorder(), request.Body, 8)
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		api.handleOTLPLogs(response, request)
		if response.Code != http.StatusRequestEntityTooLarge {
			t.Fatalf("response=%d %q", response.Code, response.Body.String())
		}
		spans := fixture.pipelines.capture(t, 1).snapshot()
		if len(spans) != 1 || spans[0].Record().EventName() != observability.EventName(observability.TelemetryFamilyTelemetryReceive) ||
			spans[0].StatusCode() != codes.Error {
			t.Fatalf("oversize spans=%v", spans)
		}
		encoded, err := json.Marshal(spans[0].Record())
		if err != nil {
			t.Fatal(err)
		}
		if bytes.Contains(encoded, []byte("oversize-secret")) {
			t.Fatalf("oversize trace leaked body: %s", encoded)
		}
	})
}

func TestOTLPIngestGeneratedTraceSamplingCollectionRoutingAndLoopSafety(t *testing.T) {
	for _, test := range []struct {
		name          string
		sampler       string
		collectTraces bool
	}{
		{name: "zero sampling", sampler: "always_off", collectTraces: true},
		{name: "trace collection disabled", sampler: "always_on", collectTraces: false},
	} {
		t.Run(test.name, func(t *testing.T) {
			fixture := newOTLPTraceFixture(t, test.sampler, test.collectTraces, nil)
			api := &APIServer{}
			api.bindOTLPObservabilityRuntime(fixture.runtime)
			request := httptest.NewRequest(http.MethodPost, "/v1/traces", strings.NewReader(`{"resourceSpans":[]}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			api.handleOTLPTraces(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
			if spans := fixture.pipelines.snapshot(1); len(spans) != 0 {
				t.Fatalf("disabled trace path emitted %d spans", len(spans))
			}
			events := readStoredOTLPV8Events(t, fixture.path)
			if len(events) != 1 || events[0].eventName != "telemetry.batch.normalized" {
				t.Fatalf("durable accepted event=%#v", events)
			}
		})
	}

	t.Run("event route selects normalize only", func(t *testing.T) {
		fixture := newOTLPTraceFixture(t, "always_on", true, []observability.EventName{
			observability.EventName(observability.TelemetryFamilyTelemetryNormalize),
		})
		api := &APIServer{}
		api.bindOTLPObservabilityRuntime(fixture.runtime)
		request := httptest.NewRequest(http.MethodPost, "/v1/metrics", strings.NewReader(`{"resourceMetrics":[]}`))
		request.Header.Set("Content-Type", "application/json")
		response := httptest.NewRecorder()
		api.handleOTLPMetrics(response, request)
		spans := fixture.pipelines.capture(t, 1).snapshot()
		if len(spans) != 1 || spans[0].Record().EventName() != observability.EventName(observability.TelemetryFamilyTelemetryNormalize) {
			t.Fatalf("routed spans=%v", spans)
		}
	})

	t.Run("self export produces no recursive records", func(t *testing.T) {
		fixture := newOTLPTraceFixture(t, "always_on", true, nil)
		api := &APIServer{}
		api.bindOTLPObservabilityRuntime(fixture.runtime)
		classifier := mustOTLPInboundClassifierV8(t)
		match, ok := classifier.catalog.Match("otlp.native.span.v8.span.telemetry.receive")
		if !ok {
			t.Fatal("native telemetry.receive match missing")
		}
		leaf, source := inboundFixtureLeafForMatch(t, match)
		forwardKey := classifier.catalog.WireContract().ForwardInstanceKey
		leaf.span.Attributes = replaceInboundFixtureAttribute(
			leaf.span.Attributes, forwardKey, otlpClassifierStringAttribute(forwardKey, gatewaylog.SidecarInstanceID()),
		)
		leaf.leafAttributes = newOTLPTypedAttributeIndex(leaf.span.Attributes)
		body, err := proto.Marshal(&collectortracepb.ExportTraceServiceRequest{ResourceSpans: []*tracepb.ResourceSpans{{
			Resource:  &resourcepb.Resource{Attributes: inboundFixtureResourceAttributes(&leaf)},
			SchemaUrl: leaf.resource.schemaURL,
			ScopeSpans: []*tracepb.ScopeSpans{{
				Scope:     &commonpb.InstrumentationScope{Name: leaf.scope.name, Version: leaf.scope.version},
				SchemaUrl: leaf.scope.schemaURL, Spans: []*tracepb.Span{leaf.span},
			}},
		}}})
		if err != nil {
			t.Fatal(err)
		}
		request := httptest.NewRequest(http.MethodPost, "/v1/traces", bytes.NewReader(body))
		request.Header.Set("Content-Type", "application/x-protobuf")
		request.Header.Set(otelSourceHeader, source)
		response := httptest.NewRecorder()
		api.handleOTLPTraces(response, request)
		if spans := fixture.pipelines.capture(t, 1).snapshot(); len(spans) != 0 {
			t.Fatalf("self export emitted recursive spans=%d", len(spans))
		}
		if events := readStoredOTLPV8Events(t, fixture.path); len(events) != 0 {
			t.Fatalf("self export emitted recursive logs=%#v", events)
		}
	})
}

func TestOTLPIngestGeneratedTraceAuthenticationAndReload(t *testing.T) {
	t.Run("authentication floor has no unauthenticated trace", func(t *testing.T) {
		fixture := newOTLPTraceFixture(t, "always_on", true, nil)
		api := &APIServer{scannerCfg: &config.Config{}}
		api.scannerCfg.Gateway.Token = "configured-token"
		api.bindOTLPObservabilityRuntime(fixture.runtime)
		handler := api.tokenAuth(http.HandlerFunc(api.handleOTLPLogs))
		request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{"resourceLogs":[]}`))
		response := httptest.NewRecorder()
		handler.ServeHTTP(response, request)
		if response.Code != http.StatusUnauthorized {
			t.Fatalf("response=%d %q", response.Code, response.Body.String())
		}
		if spans := fixture.pipelines.capture(t, 1).snapshot(); len(spans) != 0 {
			t.Fatalf("unauthenticated request emitted spans=%d", len(spans))
		}
		events := readStoredOTLPV8Events(t, fixture.path)
		if len(events) != 1 || events[0].eventName != "telemetry.authentication.failed" || events[0].mandatory != 1 {
			t.Fatalf("authentication floor=%#v", events)
		}
	})

	t.Run("reload keeps generations disjoint", func(t *testing.T) {
		fixture := newOTLPTraceFixture(t, "always_on", true, nil)
		api := &APIServer{}
		api.bindOTLPObservabilityRuntime(fixture.runtime)
		emit := func() {
			request := httptest.NewRequest(http.MethodPost, "/v1/logs", strings.NewReader(`{"resourceLogs":[]}`))
			request.Header.Set("Content-Type", "application/json")
			response := httptest.NewRecorder()
			api.handleOTLPLogs(response, request)
			if response.Code != http.StatusOK {
				t.Fatalf("response=%d %q", response.Code, response.Body.String())
			}
		}
		emit()
		updated := compileOTLPTracePlan(t, fixture.path, fixture.judgePath, "always_on", true, 1, nil)
		reload, reloadErr := fixture.runtime.Reload(t.Context(), runtimegraph.ConfigFromPlan(updated, false))
		if reloadErr != nil || reload.Status() != runtimegraph.ReloadApplied {
			t.Fatalf("reload=%s err=%v", reload.Status(), reloadErr)
		}
		emit()
		for generation := uint64(1); generation <= 2; generation++ {
			spans := fixture.pipelines.capture(t, generation).snapshot()
			if len(spans) != 2 {
				t.Fatalf("generation %d spans=%d", generation, len(spans))
			}
			for _, span := range spans {
				if span.Record().Provenance().ConfigGeneration != int64(generation) {
					t.Fatalf("generation %d received provenance %+v", generation, span.Record().Provenance())
				}
			}
		}
	})
}

func otlpTracePair(
	t *testing.T,
	spans []telemetry.V8CanonicalEndedSpan,
) (telemetry.V8CanonicalEndedSpan, telemetry.V8CanonicalEndedSpan) {
	t.Helper()
	if len(spans) != 2 {
		t.Fatalf("spans=%d want receive+normalize", len(spans))
	}
	var receive, normalize telemetry.V8CanonicalEndedSpan
	for _, span := range spans {
		switch span.Record().EventName() {
		case observability.EventName(observability.TelemetryFamilyTelemetryReceive):
			receive = span
		case observability.EventName(observability.TelemetryFamilyTelemetryNormalize):
			normalize = span
		}
	}
	if receive.Name() == "" || normalize.Name() == "" {
		t.Fatalf("missing pair receive=%s normalize=%s", receive.Name(), normalize.Name())
	}
	return receive, normalize
}
