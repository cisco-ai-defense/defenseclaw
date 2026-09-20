// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package galileo

import (
	"bytes"
	"context"
	"encoding/json"
	"fmt"
	"net"
	"net/http"
	"net/http/httptest"
	"reflect"
	"sort"
	"strconv"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	compatibility "github.com/defenseclaw/defenseclaw/internal/observability/compatibility/galileo"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

const (
	testTraceID = "0102030405060708090a0b0c0d0e0f10"
	testRawPII  = "fixture@example.test"
)

type traceCapture struct {
	requests     chan *collectortracepb.ExportTraceServiceRequest
	response     func() *collectortracepb.ExportTraceServiceResponse
	jsonResponse bool
	calls        atomic.Int64
}

func (capture *traceCapture) handler(response http.ResponseWriter, request *http.Request) {
	capture.calls.Add(1)
	if request.Method != http.MethodPost || request.URL.Path != "/otel/traces" ||
		request.Header.Get("Galileo-API-Key") != "unit-test-key" ||
		request.Header.Get("project") != "defenseclaw" || request.Header.Get("logstream") != "tests" {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	body := http.MaxBytesReader(response, request.Body, 8*1024*1024)
	defer body.Close()
	encoded := new(bytes.Buffer)
	_, _ = encoded.ReadFrom(body)
	var payload collectortracepb.ExportTraceServiceRequest
	if proto.Unmarshal(encoded.Bytes(), &payload) != nil {
		response.WriteHeader(http.StatusBadRequest)
		return
	}
	select {
	case capture.requests <- &payload:
	default:
	}
	result := &collectortracepb.ExportTraceServiceResponse{}
	if capture.response != nil {
		result = capture.response()
	}
	encodedResponse, err := proto.Marshal(result)
	if err != nil {
		response.WriteHeader(http.StatusInternalServerError)
		return
	}
	contentType := "application/x-protobuf"
	if capture.jsonResponse {
		encodedResponse, err = protojson.Marshal(result)
		if err != nil {
			response.WriteHeader(http.StatusInternalServerError)
			return
		}
		contentType = "application/json; charset=utf-8"
	}
	response.Header().Set("Content-Type", contentType)
	response.WriteHeader(http.StatusOK)
	_, _ = response.Write(encodedResponse)
}

func TestAdapterAcceptsGalileoJSONEmptySuccessAndAcknowledgesExactCanary(t *testing.T) {
	t.Parallel()
	capture := &traceCapture{
		requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1),
		// Galileo Cloud acknowledges an accepted protobuf request with the JSON
		// zero response `{}` rather than a protobuf-encoded empty message.
		jsonResponse: true,
	}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()

	observer := &canaryObserver{}
	adapter := newTestAdapter(t, server.URL+"/otel/traces", observer)
	dispatcher := newTestDispatcher(t, adapter, 2)
	for _, result := range []compatibility.Result{
		makeResult(t, testTraceID, "1112131415161718", "invoke_agent", true, true),
		makeResult(t, testTraceID, "2122232425262728", "chat", true, true),
	} {
		payload, err := NewPayload(result, "")
		if err != nil {
			t.Fatal(err)
		}
		if !dispatcher.Enqueue(payload).Accepted() {
			t.Fatal("enqueue rejected")
		}
	}
	_ = waitRequest(t, capture.requests)
	closeDispatcher(t, dispatcher)

	if capture.calls.Load() != 1 {
		t.Fatalf("requests = %d, JSON success was retried", capture.calls.Load())
	}
	if got := dispatcher.Counters(); got.Delivered != 2 || got.Rejected != 0 || got.Retried != 0 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
	if got := adapter.Counters(); got.Accepted != 2 || got.Exported != 2 || got.RejectedPartial != 0 || got.Failed != 0 {
		t.Fatalf("adapter counters = %+v", got)
	}
	if got := observer.snapshot(); !reflect.DeepEqual(got, []otlp.CanaryAcknowledgement{{
		Destination: "galileo", TraceID: testTraceID,
	}}) {
		t.Fatalf("canary acknowledgements = %+v", got)
	}
}

func TestAdapterGalileoJSONPartialSuccessRejectsExactlyAndNeverAcknowledgesCanary(t *testing.T) {
	t.Parallel()
	capture := &traceCapture{
		requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1),
		response: func() *collectortracepb.ExportTraceServiceResponse {
			return &collectortracepb.ExportTraceServiceResponse{PartialSuccess: &collectortracepb.ExportTracePartialSuccess{
				RejectedSpans: 1, ErrorMessage: "must never enter health or errors",
			}}
		},
		jsonResponse: true,
	}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()

	observer := &canaryObserver{}
	adapter := newTestAdapter(t, server.URL+"/otel/traces", observer)
	dispatcher := newTestDispatcher(t, adapter, 2)
	for _, result := range []compatibility.Result{
		makeResult(t, testTraceID, "1112131415161718", "invoke_agent", true, true),
		makeResult(t, testTraceID, "2122232425262728", "chat", true, true),
	} {
		payload, err := NewPayload(result, "")
		if err != nil {
			t.Fatal(err)
		}
		if !dispatcher.Enqueue(payload).Accepted() {
			t.Fatal("enqueue rejected")
		}
	}
	_ = waitRequest(t, capture.requests)
	closeDispatcher(t, dispatcher)

	if capture.calls.Load() != 1 {
		t.Fatalf("requests = %d, JSON partial success was retried", capture.calls.Load())
	}
	if got := dispatcher.Counters(); got.Delivered != 1 || got.Rejected != 1 || got.Retried != 0 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
	if got := adapter.Counters(); got.Exported != 1 || got.RejectedPartial != 1 || got.Failed != 0 {
		t.Fatalf("adapter counters = %+v", got)
	}
	if got := observer.snapshot(); len(got) != 0 {
		t.Fatalf("JSON partial response acknowledged canary: %+v", got)
	}
}

type canaryObserver struct {
	mu     sync.Mutex
	events []otlp.CanaryAcknowledgement
}

func (observer *canaryObserver) ObserveOTLPCanaryAcknowledgement(event otlp.CanaryAcknowledgement) {
	observer.mu.Lock()
	observer.events = append(observer.events, event)
	observer.mu.Unlock()
}

func (observer *canaryObserver) snapshot() []otlp.CanaryAcknowledgement {
	observer.mu.Lock()
	defer observer.mu.Unlock()
	return append([]otlp.CanaryAcknowledgement(nil), observer.events...)
}

func TestAdapterExportsRichRedactedCanaryAndAcknowledgesExactTrace(t *testing.T) {
	t.Parallel()
	capture := &traceCapture{requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1)}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()

	observer := &canaryObserver{}
	adapter := newTestAdapter(t, server.URL+"/otel/traces", observer)
	dispatcher := newTestDispatcher(t, adapter, 2)

	agent := makeResult(t, testTraceID, "1112131415161718", "invoke_agent", true, true)
	model := makeResult(t, testTraceID, "2122232425262728", "chat", true, true)
	for _, result := range []compatibility.Result{agent, model} {
		payload, err := NewPayload(result, "")
		if err != nil {
			t.Fatalf("NewPayload: %v", err)
		}
		if enqueue := dispatcher.Enqueue(payload); !enqueue.Accepted() {
			t.Fatalf("enqueue = %+v", enqueue)
		}
	}
	request := waitRequest(t, capture.requests)
	closeDispatcher(t, dispatcher)

	spans := requestSpans(request)
	if len(spans) != 2 {
		t.Fatalf("spans = %d, want 2", len(spans))
	}
	for _, resourceSpans := range request.ResourceSpans {
		for _, scopeSpans := range resourceSpans.ScopeSpans {
			if scopeSpans.Scope == nil || scopeSpans.Scope.DroppedAttributesCount != 4 {
				t.Fatalf("scope dropped count = %+v", scopeSpans.Scope)
			}
		}
	}
	operations := make(map[string]bool)
	var agentSpan, modelSpan *tracepb.Span
	for _, span := range spans {
		if got := span.TraceId; !bytes.Equal(got, mustHex(t, testTraceID)) {
			t.Fatalf("trace ID = %x", got)
		}
		attrs := protoAttributes(span.Attributes)
		operation := attrs["gen_ai.operation.name"].GetStringValue()
		operations[operation] = true
		if operation == "invoke_agent" {
			agentSpan = span
		} else if operation == "chat" {
			modelSpan = span
		}
		if span.Flags != 0x101 || span.TraceState != "dc=runtime-pipeline-test" {
			t.Errorf("trace metadata = flags:%#x state:%q", span.Flags, span.TraceState)
		}
		for _, key := range []string{
			"defenseclaw.agent.root.id", "defenseclaw.agent.parent.id",
			"defenseclaw.agent.lifecycle.id", "defenseclaw.agent.execution.id",
			"defenseclaw.turn.id",
		} {
			if attrs[key].GetStringValue() == "" {
				t.Errorf("rich lifecycle attribute %q missing", key)
			}
		}
		if len(span.Events) != 1 || len(span.Links) != 1 || span.Status == nil || span.Status.Code != tracepb.Status_STATUS_CODE_OK {
			t.Errorf("rich span shape lost events/links/status: %+v", span)
		}
		if span.Events[0].DroppedAttributesCount != 2 || span.Links[0].DroppedAttributesCount != 3 ||
			span.Links[0].TraceState != "dc=linked" {
			t.Errorf("event/link metadata = dropped:%d/%d state:%q",
				span.Events[0].DroppedAttributesCount, span.Links[0].DroppedAttributesCount,
				span.Links[0].TraceState)
		}
	}
	if !operations["invoke_agent"] || !operations["chat"] {
		t.Fatalf("operations = %v", operations)
	}
	if agentSpan == nil || modelSpan == nil || len(agentSpan.ParentSpanId) != 0 ||
		!bytes.Equal(modelSpan.ParentSpanId, agentSpan.SpanId) {
		t.Fatalf("generated canary parent graph = agent:%+v model:%+v", agentSpan, modelSpan)
	}
	encoded, _ := proto.Marshal(request)
	if bytes.Contains(encoded, []byte(testRawPII)) {
		t.Fatal("OTLP request recovered raw PII after central redaction")
	}
	for _, resource := range request.ResourceSpans {
		attrs := protoAttributes(resource.Resource.Attributes)
		if attrs["service.name"].GetStringValue() != "defenseclaw" ||
			attrs["service.instance.id"].GetStringValue() == "" || len(resource.ScopeSpans) != 1 ||
			resource.ScopeSpans[0].Scope.Name != "defenseclaw.telemetry" ||
			resource.ScopeSpans[0].SchemaUrl == "" {
			t.Fatalf("resource/scope lost: %+v", resource)
		}
		for key, want := range map[string]string{
			"team.owner": "runtime-security", "region.site": "east-lab",
			"deployment.environment": "test", "deployment.mode": "gateway",
			"defenseclaw.device.id": "device-fingerprint",
		} {
			if got := attrs[key].GetStringValue(); got != want {
				t.Errorf("resource %q = %q, want %q", key, got, want)
			}
		}
		if resource.Resource.DroppedAttributesCount != 0 {
			t.Errorf("resource dropped attributes = %d, want 0", resource.Resource.DroppedAttributesCount)
		}
	}
	if got := observer.snapshot(); !reflect.DeepEqual(got, []otlp.CanaryAcknowledgement{{
		Destination: "galileo", TraceID: testTraceID,
	}}) {
		t.Fatalf("canary acknowledgements = %+v", got)
	}
	if got := adapter.Counters(); got.Accepted != 2 || got.Exported != 2 || got.RejectedPartial != 0 || got.Failed != 0 {
		t.Fatalf("adapter counters = %+v", got)
	}
}

func TestAdapterPartialSuccessIsExactTerminalAndNeverAcknowledgesCanary(t *testing.T) {
	t.Parallel()
	capture := &traceCapture{
		requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1),
		response: func() *collectortracepb.ExportTraceServiceResponse {
			return &collectortracepb.ExportTraceServiceResponse{PartialSuccess: &collectortracepb.ExportTracePartialSuccess{
				RejectedSpans: 1, ErrorMessage: "must never enter health or errors",
			}}
		},
	}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	observer := &canaryObserver{}
	adapter := newTestAdapter(t, server.URL+"/otel/traces", observer)
	dispatcher := newTestDispatcher(t, adapter, 2)
	for _, result := range []compatibility.Result{
		makeResult(t, testTraceID, "1112131415161718", "invoke_agent", true, true),
		makeResult(t, testTraceID, "2122232425262728", "chat", true, true),
	} {
		payload, err := NewPayload(result, "")
		if err != nil {
			t.Fatal(err)
		}
		if !dispatcher.Enqueue(payload).Accepted() {
			t.Fatal("enqueue rejected")
		}
	}
	_ = waitRequest(t, capture.requests)
	closeDispatcher(t, dispatcher)
	if capture.calls.Load() != 1 {
		t.Fatalf("requests = %d, partial success was retried", capture.calls.Load())
	}
	if got := dispatcher.Counters(); got.Delivered != 1 || got.Rejected != 1 || got.Retried != 0 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
	if got := adapter.Counters(); got.Exported != 1 || got.RejectedPartial != 1 {
		t.Fatalf("adapter counters = %+v", got)
	}
	if got := observer.snapshot(); len(got) != 0 {
		t.Fatalf("partial response acknowledged canary: %+v", got)
	}
}

func TestProjectedCanaryAcknowledgementRejectsMalformedOrPartialPairs(t *testing.T) {
	t.Parallel()
	if spans := projectedCanaryPair(t); !completeProjectedCanaryTrace(spans) {
		t.Fatal("valid projected generated pair was not acknowledged")
	}
	tests := map[string]func([]projectedCanarySpan){
		"wrong parent": func(spans []projectedCanarySpan) {
			spans[1].span.ParentSpanId = mustHex(t, "3132333435363738")
		},
		"different trace": func(spans []projectedCanarySpan) {
			spans[1].span.TraceId = mustHex(t, "11111111111111111111111111111111")
		},
		"same span id": func(spans []projectedCanarySpan) {
			spans[1].span.SpanId = append([]byte(nil), spans[0].span.SpanId...)
		},
		"wrong full flags": func(spans []projectedCanarySpan) {
			spans[1].span.Flags = 0x100
		},
		"tracestate mismatch": func(spans []projectedCanarySpan) {
			spans[1].span.TraceState = "vendor=other"
		},
		"generation mismatch": func(spans []projectedCanarySpan) {
			spans[1].wire.Provenance["config_generation"] = json.Number("9")
		},
		"resource mismatch": func(spans []projectedCanarySpan) {
			attrs := protoAttributes(spans[1].resource.Attributes)
			attrs["team.owner"].Value = &commonpb.AnyValue_StringValue{StringValue: "other-team"}
		},
		"resource dropped fields": func(spans []projectedCanarySpan) {
			spans[0].resource.DroppedAttributesCount = 1
		},
		"resource schema mismatch": func(spans []projectedCanarySpan) {
			spans[1].resourceSchema = "https://example.test/other"
		},
		"scope mismatch": func(spans []projectedCanarySpan) {
			spans[1].scope.Version = "other"
		},
		"wrong root name": func(spans []projectedCanarySpan) {
			spans[0].span.Name = "invoke_agent other"
		},
		"wrong child kind": func(spans []projectedCanarySpan) {
			spans[1].span.Kind = tracepb.Span_SPAN_KIND_INTERNAL
		},
		"wrong status": func(spans []projectedCanarySpan) {
			spans[1].span.Status.Code = tracepb.Status_STATUS_CODE_ERROR
		},
		"wrong outcome": func(spans []projectedCanarySpan) {
			spans[1].wire.Body.Attributes["defenseclaw.outcome"] = string(observability.OutcomeFailed)
		},
		"diagnostic family": func(spans []projectedCanarySpan) {
			spans[1].wire.Family = observability.TelemetryFamilyDiagnosticCanary
		},
	}
	for name, mutate := range tests {
		name, mutate := name, mutate
		t.Run(name, func(t *testing.T) {
			t.Parallel()
			spans := projectedCanaryPair(t)
			mutate(spans)
			if completeProjectedCanaryTrace(spans) {
				t.Fatal("malformed projected pair was acknowledged")
			}
		})
	}
	if spans := projectedCanaryPair(t); completeProjectedCanaryTrace(spans[:1]) {
		t.Fatal("partial projected pair was acknowledged")
	}
}

func TestAdapterMalformedNegativePartialIsTerminalAndContentFree(t *testing.T) {
	t.Parallel()
	capture := &traceCapture{
		requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1),
		response: func() *collectortracepb.ExportTraceServiceResponse {
			return &collectortracepb.ExportTraceServiceResponse{PartialSuccess: &collectortracepb.ExportTracePartialSuccess{
				RejectedSpans: -1, ErrorMessage: testRawPII,
			}}
		},
	}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/otel/traces", &canaryObserver{})
	dispatcher := newTestDispatcher(t, adapter, 1)
	payload, err := NewPayload(makeResult(t, testTraceID, "292a2b2c2d2e2f30", "chat", false, true), "")
	if err != nil {
		t.Fatal(err)
	}
	if !dispatcher.Enqueue(payload).Accepted() {
		t.Fatal("enqueue rejected")
	}
	_ = waitRequest(t, capture.requests)
	closeDispatcher(t, dispatcher)
	if capture.calls.Load() != 1 {
		t.Fatalf("requests = %d, malformed partial was retried", capture.calls.Load())
	}
	if got := dispatcher.Counters(); got.Delivered != 0 || got.Rejected != 1 || got.Retried != 0 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
	if got := adapter.Counters(); got.Failed != 1 || got.Exported != 0 || got.RejectedPartial != 0 {
		t.Fatalf("adapter counters = %+v", got)
	}
}

func TestAdapterRejectsMixedRawBatchBeforeNetworkAndNeverLeaksRawBytes(t *testing.T) {
	t.Parallel()
	capture := &traceCapture{requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1)}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/otel/traces", &canaryObserver{})
	dispatcher := newTestDispatcher(t, adapter, 2)
	validResult := makeResult(t, testTraceID, "3132333435363738", "chat", false, true)
	validPayload, err := NewPayload(validResult, "")
	if err != nil {
		t.Fatal(err)
	}
	rawPayload, err := delivery.NewPayload([]byte(`{"compatibility_profile":"raw","secret":"RAW-LEAK-CANARY"}`), delivery.RoutingIdentity{
		RecordID: "raw-record", Bucket: string(observability.BucketModelIO),
		Signal: string(observability.SignalTraces), EventName: "span.model.chat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dispatcher.Enqueue(validPayload).Accepted() || !dispatcher.Enqueue(rawPayload).Accepted() {
		t.Fatal("setup enqueue rejected")
	}
	closeDispatcher(t, dispatcher)
	if capture.calls.Load() != 0 {
		t.Fatalf("mixed/raw batch made %d network requests", capture.calls.Load())
	}
	if got := dispatcher.Counters(); got.Delivered != 0 || got.Rejected != 2 || got.Retried != 0 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
}

func TestAdapterRejectsForgedFutureEnvelopeVersionsBeforeNetwork(t *testing.T) {
	t.Parallel()
	for _, test := range []struct {
		name  string
		field string
		value int
	}{
		{name: "record schema", field: "schema_version", value: observability.CurrentRecordSchemaVersion + 1},
		{name: "bucket catalog", field: "bucket_catalog_version", value: observability.CurrentBucketCatalogVersion + 1},
	} {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			capture := &traceCapture{requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1)}
			server := httptest.NewServer(http.HandlerFunc(capture.handler))
			defer server.Close()
			adapter := newTestAdapter(t, server.URL+"/otel/traces", &canaryObserver{})
			dispatcher := newTestDispatcher(t, adapter, 1)
			const spanID = "5152535455565758"
			result := makeResult(t, testTraceID, spanID, "chat", false, true)
			encoded, err := result.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			var forged map[string]any
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.UseNumber()
			if err := decoder.Decode(&forged); err != nil {
				t.Fatal(err)
			}
			forged[test.field] = test.value
			encoded, err = json.Marshal(forged)
			if err != nil {
				t.Fatal(err)
			}
			payload, err := delivery.NewPayload(encoded, delivery.RoutingIdentity{
				RecordID: "galileo-" + spanID, Bucket: string(observability.BucketModelIO),
				Signal: string(observability.SignalTraces), EventName: "span.model.chat",
			})
			if err != nil {
				t.Fatal(err)
			}
			if !dispatcher.Enqueue(payload).Accepted() {
				t.Fatal("setup enqueue rejected")
			}
			closeDispatcher(t, dispatcher)
			if capture.calls.Load() != 0 {
				t.Fatalf("future-version projection made %d network requests", capture.calls.Load())
			}
			if got := dispatcher.Counters(); got.Rejected != 1 || got.Delivered != 0 || got.Retried != 0 {
				t.Fatalf("dispatcher counters = %+v", got)
			}
		})
	}
}

func TestAdapterRejectsMissingOrMismatchedCanonicalEndedIdentityBeforeNetwork(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name   string
		mutate func(*testing.T, map[string]any)
	}{
		{name: "missing bucket", mutate: func(t *testing.T, wire map[string]any) { delete(projectedAttributes(t, wire), "defenseclaw.bucket") }},
		{name: "mismatched family", mutate: func(t *testing.T, wire map[string]any) {
			projectedAttributes(t, wire)["defenseclaw.span.family"] = "span.tool.execute"
		}},
		{name: "zero family version", mutate: func(t *testing.T, wire map[string]any) {
			projectedAttributes(t, wire)["defenseclaw.span.family_schema_version"] = 0
		}},
		{name: "mismatched source", mutate: func(t *testing.T, wire map[string]any) {
			projectedAttributes(t, wire)["defenseclaw.source"] = "connector"
		}},
		{name: "mismatched generation", mutate: func(t *testing.T, wire map[string]any) {
			projectedAttributes(t, wire)["defenseclaw.config.generation"] = 9
		}},
		{name: "non-ended outcome", mutate: func(t *testing.T, wire map[string]any) {
			projectedAttributes(t, wire)["defenseclaw.outcome"] = string(observability.OutcomeAttempted)
			wire["outcome"] = string(observability.OutcomeAttempted)
		}},
		{name: "missing trace schema", mutate: func(t *testing.T, wire map[string]any) {
			delete(projectedScopeAttributes(t, wire), "defenseclaw.trace.schema_version")
		}},
		{name: "mismatched trace schema", mutate: func(t *testing.T, wire map[string]any) {
			projectedScopeAttributes(t, wire)["defenseclaw.trace.schema_version"] = "defenseclaw-trace-v2"
		}},
		{name: "missing semantic profile", mutate: func(t *testing.T, wire map[string]any) {
			delete(projectedScopeAttributes(t, wire), "defenseclaw.semantic_profile")
		}},
		{name: "mismatched semantic profile", mutate: func(t *testing.T, wire map[string]any) {
			projectedScopeAttributes(t, wire)["defenseclaw.semantic_profile"] = "defenseclaw-genai-rich-v2"
		}},
		{name: "mismatched Galileo profile", mutate: func(t *testing.T, wire map[string]any) {
			projectedScopeAttributes(t, wire)["defenseclaw.galileo.compatibility_profile"] = "galileo-rich-v3"
		}},
		{name: "non string Galileo profile", mutate: func(t *testing.T, wire map[string]any) {
			projectedScopeAttributes(t, wire)["defenseclaw.galileo.compatibility_profile"] = json.Number("2")
		}},
		{name: "non string resource attribute", mutate: func(t *testing.T, wire map[string]any) {
			projectedResourceAttributes(t, wire)["custom.count"] = json.Number("3")
		}},
		{name: "invalid resource dropped count", mutate: func(t *testing.T, wire map[string]any) {
			projectedResourceObject(t, wire)["dropped_attributes_count"] = json.Number("-1")
		}},
		{name: "invalid link trace state", mutate: func(t *testing.T, wire map[string]any) {
			body := wire["body"].(map[string]any)
			links := body["links"].([]any)
			links[0].(map[string]any)["trace_state"] = "duplicate=value,duplicate=other"
		}},
	}
	for index, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			spanID := fmt.Sprintf("%016x", uint64(0x6162636465666700)+uint64(index))
			result := makeResult(t, testTraceID, spanID, "chat", false, true)
			encoded, err := result.Bytes()
			if err != nil {
				t.Fatal(err)
			}
			var forged map[string]any
			decoder := json.NewDecoder(bytes.NewReader(encoded))
			decoder.UseNumber()
			if err := decoder.Decode(&forged); err != nil {
				t.Fatal(err)
			}
			test.mutate(t, forged)
			assertForgedProjectionRejectedBeforeNetwork(t, forged, "galileo-"+spanID)
		})
	}
}

func TestProjectedResourceCompatibilityAliasesRemainPolicyControlled(t *testing.T) {
	t.Parallel()
	const spanID = "7172737475767778"
	result := makeResult(t, testTraceID, spanID, "chat", false, true)
	encoded, err := result.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	resourceAttributes := projectedResourceAttributes(t, wire)
	for _, key := range []string{"deployment.environment", "deployment.mode", "defenseclaw.device.id"} {
		delete(resourceAttributes, key)
	}
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	projected, ok := decodeProjection(encoded)
	if !ok {
		t.Fatal("valid alias-free projection rejected")
	}
	resource, _, _, _, _, ok := projected.otlp("galileo")
	if !ok {
		t.Fatal("valid alias-free resource rejected")
	}
	attributes := protoAttributes(resource.Attributes)
	for _, key := range []string{"deployment.environment", "deployment.mode", "defenseclaw.device.id"} {
		if _, present := attributes[key]; present {
			t.Errorf("disabled compatibility alias %q was reconstructed", key)
		}
	}
	if got := attributes["team.owner"].GetStringValue(); got != "runtime-security" {
		t.Fatalf("custom resource attribute = %q", got)
	}
}

func TestGeneratedCanonicalScopeReceivesDestinationOwnedGalileoProfile(t *testing.T) {
	t.Parallel()
	result := makeResult(t, testTraceID, "797a7b7c7d7e7f80", "chat", false, true)
	encoded, err := result.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	var wire map[string]any
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	if err := decoder.Decode(&wire); err != nil {
		t.Fatal(err)
	}
	delete(projectedScopeAttributes(t, wire), "defenseclaw.galileo.compatibility_profile")
	encoded, err = json.Marshal(wire)
	if err != nil {
		t.Fatal(err)
	}
	projected, ok := decodeProjection(encoded)
	if !ok {
		t.Fatal("generated canonical projection without destination profile rejected")
	}
	_, _, scope, _, _, ok := projected.otlp("galileo")
	if !ok {
		t.Fatal("destination-owned Galileo profile was not applied")
	}
	attributes := protoAttributes(scope.Attributes)
	if got := attributes["defenseclaw.galileo.compatibility_profile"].GetStringValue(); got != compatibility.ProfileID {
		t.Fatalf("Galileo scope profile = %q, want %q", got, compatibility.ProfileID)
	}
}

func TestPayloadFailsClosedUntilGeneratedP5TraceStructureExists(t *testing.T) {
	t.Parallel()
	result := makeResult(t, testTraceID, "4142434445464748", "chat", false, false)
	if !result.Eligible() {
		t.Fatalf("compatibility eligibility unexpectedly changed: %s", result.Reason())
	}
	if _, err := NewPayload(result, ""); !IsError(err, ErrorInvalidProjection) {
		t.Fatalf("missing generated P5 resource/scope/timing accepted: %v", err)
	}
}

func TestGalileoPresetOwnsOneSecondV8DefaultWithoutChangingGeneralOTLP(t *testing.T) {
	t.Parallel()
	plan, err := config.CompileObservabilityV8(&config.ObservabilityV8Source{Destinations: []config.ObservabilityV8DestinationSource{
		{Name: "galileo", Kind: config.ObservabilityV8DestinationOTLP, Preset: "galileo", Endpoint: "https://api.galileo.ai/otel/traces"},
		{Name: "general", Kind: config.ObservabilityV8DestinationOTLP, Endpoint: "https://otel.example.test"},
	}})
	if err != nil {
		t.Fatal(err)
	}
	galileo, _ := plan.Destination("galileo")
	general, _ := plan.Destination("general")
	if galileo.Transport.Batch == nil || galileo.Transport.Batch.ScheduledDelayMS != 1_000 ||
		galileo.Transport.Protocol != otlp.ProtocolHTTPProtobuf || galileo.PresetProfile != compatibility.ProfileID {
		t.Fatalf("Galileo v8 preset = %+v", galileo)
	}
	if general.Transport.Batch == nil || general.Transport.Batch.ScheduledDelayMS != 5_000 ||
		general.Transport.Protocol != otlp.ProtocolGRPC {
		t.Fatalf("general OTLP defaults changed = %+v", general)
	}
}

func newTestAdapter(t *testing.T, endpoint string, observer otlp.CanaryAcknowledgementObserver) *Adapter {
	t.Helper()
	factory, err := otlp.Prepare(context.Background(), otlp.Config{
		Destination: "galileo", Protocol: otlp.ProtocolHTTPProtobuf, Endpoint: endpoint,
		Selected: []observability.Signal{observability.SignalTraces},
		Headers: map[string]string{
			"Galileo-API-Key": "unit-test-key", "project": "defenseclaw", "logstream": "tests",
		},
		Timeout: 2 * time.Second, TLS: otlp.TLSConfig{Insecure: true},
		NetworkSafety: otlp.NetworkSafety{AllowPrivateNetworks: true},
		Batch: otlp.BatchConfig{
			MaxQueueSize: 8, MaxQueueBytes: 8 * 1024 * 1024,
			MaxExportBatchSize: 8, MaxExportBatchBytes: 8 * 1024 * 1024,
			ScheduledDelay: time.Second,
		},
	}, otlp.Dependencies{
		Resolver: net.DefaultResolver, Dialer: &net.Dialer{Timeout: time.Second}, CanaryObserver: observer,
	})
	if err != nil {
		t.Fatalf("prepare OTLP: %v", err)
	}
	adapter, err := NewAdapter(context.Background(), factory)
	if err != nil {
		t.Fatalf("NewAdapter: %v", err)
	}
	t.Cleanup(func() {
		ctx, cancel := context.WithTimeout(context.Background(), time.Second)
		defer cancel()
		_ = adapter.Close(ctx)
	})
	return adapter
}

func newTestDispatcher(t *testing.T, adapter *Adapter, batchSize int) *delivery.Dispatcher {
	t.Helper()
	dispatcher, err := delivery.NewDispatcher(delivery.Config{
		Destination: "galileo", Enabled: true,
		MaxQueueItems: 8, MaxQueueBytes: 8 * 1024 * 1024,
		MaxBatchItems: batchSize, MaxBatchBytes: 8 * 1024 * 1024,
		ScheduledDelay: 100 * time.Millisecond, AttemptTimeout: 2 * time.Second,
		Retry: delivery.RetryPolicy{MaxAttempts: 2, InitialBackoff: time.Millisecond, MaxBackoff: time.Millisecond},
	}, adapter)
	if err != nil {
		t.Fatalf("NewDispatcher: %v", err)
	}
	dispatcher.Activate()
	return dispatcher
}

func closeDispatcher(t *testing.T, dispatcher *delivery.Dispatcher) {
	t.Helper()
	ctx, cancel := context.WithTimeout(context.Background(), 3*time.Second)
	defer cancel()
	if err := dispatcher.StopIntake(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Drain(ctx); err != nil {
		t.Fatal(err)
	}
	if err := dispatcher.Close(ctx); err != nil {
		t.Fatal(err)
	}
}

func waitRequest(t *testing.T, requests <-chan *collectortracepb.ExportTraceServiceRequest) *collectortracepb.ExportTraceServiceRequest {
	t.Helper()
	select {
	case request := <-requests:
		return request
	case <-time.After(3 * time.Second):
		t.Fatal("timed out waiting for Galileo OTLP request")
		return nil
	}
}

func assertForgedProjectionRejectedBeforeNetwork(t *testing.T, forged map[string]any, recordID string) {
	t.Helper()
	capture := &traceCapture{requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1)}
	server := httptest.NewServer(http.HandlerFunc(capture.handler))
	defer server.Close()
	adapter := newTestAdapter(t, server.URL+"/otel/traces", &canaryObserver{})
	dispatcher := newTestDispatcher(t, adapter, 1)
	encoded, err := json.Marshal(forged)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := delivery.NewPayload(encoded, delivery.RoutingIdentity{
		RecordID: recordID, Bucket: string(observability.BucketModelIO),
		Signal: string(observability.SignalTraces), EventName: "span.model.chat",
	})
	if err != nil {
		t.Fatal(err)
	}
	if !dispatcher.Enqueue(payload).Accepted() {
		t.Fatal("setup enqueue rejected")
	}
	closeDispatcher(t, dispatcher)
	if capture.calls.Load() != 0 {
		t.Fatalf("forged projection made %d network requests", capture.calls.Load())
	}
	if got := dispatcher.Counters(); got.Rejected != 1 || got.Delivered != 0 || got.Retried != 0 {
		t.Fatalf("dispatcher counters = %+v", got)
	}
}

func projectedAttributes(t *testing.T, wire map[string]any) map[string]any {
	t.Helper()
	body, ok := wire["body"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing body")
	}
	attributes, ok := body["attributes"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing attributes")
	}
	return attributes
}

func projectedResourceObject(t *testing.T, wire map[string]any) map[string]any {
	t.Helper()
	body, ok := wire["body"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing body")
	}
	resource, ok := body["resource"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing resource")
	}
	return resource
}

func projectedResourceAttributes(t *testing.T, wire map[string]any) map[string]any {
	t.Helper()
	attributes, ok := projectedResourceObject(t, wire)["attributes"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing resource attributes")
	}
	return attributes
}

func projectedScopeAttributes(t *testing.T, wire map[string]any) map[string]any {
	t.Helper()
	body, ok := wire["body"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing body")
	}
	scope, ok := body["scope"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing scope")
	}
	attributes, ok := scope["attributes"].(map[string]any)
	if !ok {
		t.Fatal("test projection missing scope attributes")
	}
	return attributes
}

func requestSpans(request *collectortracepb.ExportTraceServiceRequest) []*tracepb.Span {
	var spans []*tracepb.Span
	for _, resource := range request.ResourceSpans {
		for _, scope := range resource.ScopeSpans {
			spans = append(spans, scope.Spans...)
		}
	}
	return spans
}

func protoAttributes(attributes []*commonpb.KeyValue) map[string]*commonpb.AnyValue {
	output := make(map[string]*commonpb.AnyValue, len(attributes))
	for _, item := range attributes {
		if item != nil {
			output[item.Key] = item.Value
		}
	}
	return output
}

func projectedCanaryPair(t *testing.T) []projectedCanarySpan {
	t.Helper()
	results := []compatibility.Result{
		makeResult(t, testTraceID, "1112131415161718", "invoke_agent", true, true),
		makeResult(t, testTraceID, "2122232425262728", "chat", true, true),
	}
	spans := make([]projectedCanarySpan, 0, len(results))
	for _, result := range results {
		encoded, err := result.Bytes()
		if err != nil {
			t.Fatal(err)
		}
		wire, ok := decodeProjection(encoded)
		if !ok {
			t.Fatal("decode projected canary")
		}
		resource, span, scope, resourceSchema, scopeSchema, ok := wire.otlp("galileo")
		if !ok {
			t.Fatal("convert projected canary to OTLP")
		}
		spans = append(spans, projectedCanarySpan{
			wire: wire, resource: resource, resourceSchema: resourceSchema,
			scope: scope, scopeSchema: scopeSchema, span: span,
		})
	}
	return spans
}

func makeResult(
	t *testing.T,
	traceID, spanID, operation string,
	canary, transportReady bool,
) compatibility.Result {
	t.Helper()
	kind := "CLIENT"
	bucket := observability.BucketModelIO
	family := observability.EventName("span.model.chat")
	name := "chat fixture"
	attributes := map[string]any{
		"gen_ai.operation.name": operation, "gen_ai.provider.name": "openai",
		"gen_ai.input.messages":     message("user", "contact "+testRawPII),
		"gen_ai.output.messages":    message("assistant", "done"),
		"defenseclaw.agent.root.id": "root-agent", "defenseclaw.agent.parent.id": "parent-agent",
		"defenseclaw.agent.lifecycle.id": "lifecycle", "defenseclaw.agent.execution.id": "execution",
		"defenseclaw.turn.id": "turn",
	}
	if operation == "invoke_agent" {
		kind, bucket, family, name = "INTERNAL", observability.BucketAgentLifecycle, "span.agent.invoke", "invoke_agent reviewer"
		attributes["gen_ai.agent.name"] = "reviewer"
	}
	if canary {
		attributes[canaryMarker] = true
		attributes[canaryOperation] = canaryOperationTag
		attributes[canaryDestination] = "galileo"
		if operation == "invoke_agent" {
			name = "invoke_agent diagnostic"
		} else {
			name = "chat gpt-4o-mini"
		}
	}
	attributes["defenseclaw.bucket"] = string(bucket)
	attributes["defenseclaw.span.family"] = string(family)
	attributes["defenseclaw.span.family_schema_version"] = 1
	attributes["defenseclaw.source"] = string(observability.SourceGateway)
	attributes["defenseclaw.config.generation"] = 8
	attributes["defenseclaw.outcome"] = string(observability.OutcomeCompleted)
	body := map[string]any{
		"kind":       kind,
		"attributes": attributes,
		"events": []any{map[string]any{
			"name": "guardrail.decision", "time_unix_nano": uint64(1_000_000_005),
			"dropped_attributes_count": uint32(2),
			"attributes": map[string]any{
				"defenseclaw.evaluation.id":      "evaluation",
				"defenseclaw.guardrail.decision": "allow",
				"defenseclaw.security.severity":  "LOW",
			},
		}},
		"links": []any{map[string]any{
			"trace_id": "11111111111111111111111111111111", "span_id": "2222222222222222",
			"trace_state":              "dc=linked",
			"dropped_attributes_count": uint32(3),
			"attributes":               map[string]any{"defenseclaw.link.relation": "correlates_with"},
		}},
		"status": map[string]any{"code": 1},
	}
	if transportReady {
		body["start_time_unix_nano"] = uint64(1_000_000_000)
		body["end_time_unix_nano"] = uint64(1_100_000_000)
		body["flags"] = uint32(0x101)
		body["trace_state"] = "dc=runtime-pipeline-test"
		if canary && operation == "chat" {
			body["parent_span_id"] = "1112131415161718"
		}
		resourceDropped := uint32(7)
		if canary {
			resourceDropped = 0
		}
		body["resource"] = map[string]any{
			"schema_url": "https://opentelemetry.io/schemas/1.42.0", "dropped_attributes_count": resourceDropped,
			"attributes": map[string]any{
				"service.name": "defenseclaw", "service.version": "v8-test", "service.namespace": "defenseclaw",
				"service.instance.id": "instance", "deployment.environment.name": "test",
				"defenseclaw.instance.id": "defenseclaw-instance", "host.arch": "amd64",
				"team.owner": "runtime-security", "region.site": "east-lab",
				"defenseclaw.deployment.mode":               "gateway",
				"defenseclaw.device.public_key_fingerprint": "device-fingerprint",
				"deployment.environment":                    "test", "deployment.mode": "gateway",
				"defenseclaw.device.id": "device-fingerprint",
			}}
		body["scope"] = map[string]any{
			"name": "defenseclaw.telemetry", "version": "v8-test",
			"schema_url":               "https://defenseclaw.example/schemas/trace/v1",
			"dropped_attributes_count": uint32(4),
			"attributes": map[string]any{
				"defenseclaw.trace.schema_version":          "defenseclaw-trace-v1",
				"defenseclaw.semantic_profile":              "defenseclaw-genai-rich-v1",
				"defenseclaw.galileo.compatibility_profile": compatibility.ProfileID,
				"arbitrary.scope.secret":                    testRawPII,
			},
		}
	}
	record, err := observability.NewRecord(observability.RecordInput{
		Timestamp: time.Date(2026, 7, 3, 12, 0, 0, 0, time.UTC),
		RecordID:  "galileo-" + spanID,
		Identity:  observability.EventIdentity{Bucket: bucket, Signal: observability.SignalTraces, Name: family},
		SpanName:  name, Source: observability.SourceGateway,
		Outcome:     observability.OutcomeCompleted,
		Correlation: observability.Correlation{TraceID: traceID, SpanID: spanID, RunID: "run", SessionID: "session", TurnID: "turn"},
		Provenance: observability.Provenance{
			Producer: "gateway.trace", BinaryVersion: "v8-test", RegistrySchemaVersion: 1, ConfigGeneration: 8,
		},
		Body: body, FieldClasses: testFieldClasses(body),
	})
	if err != nil {
		t.Fatal(err)
	}
	engine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileSensitive)
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	result := compatibility.Project(projection, compatibility.Limits{})
	if !result.Eligible() {
		t.Fatalf("Galileo projection = %s missing=%v", result.Reason(), result.MissingFields())
	}
	return result
}

func message(role, content string) string {
	encoded, _ := json.Marshal([]map[string]string{{"role": role, "content": content}})
	return string(encoded)
}

func testFieldClasses(body map[string]any) map[string]observability.FieldClass {
	classes := make(map[string]observability.FieldClass)
	var visit func(any, string, string)
	visit = func(value any, pointer, key string) {
		switch typed := value.(type) {
		case map[string]any:
			keys := make([]string, 0, len(typed))
			for child := range typed {
				keys = append(keys, child)
			}
			sort.Strings(keys)
			for _, child := range keys {
				visit(typed[child], pointer+"/"+pointerToken(child), child)
			}
		case []any:
			for index, child := range typed {
				visit(child, pointer+"/"+strconv.Itoa(index), key)
			}
		default:
			class := observability.FieldClassMetadata
			lower := strings.ToLower(key)
			if strings.Contains(lower, "message") || strings.Contains(lower, "content") ||
				strings.Contains(lower, "argument") || strings.Contains(lower, "result") {
				class = observability.FieldClassContent
			}
			classes[pointer] = class
		}
	}
	visit(body, "", "")
	return classes
}

func pointerToken(input string) string {
	return strings.ReplaceAll(strings.ReplaceAll(input, "~", "~0"), "/", "~1")
}

func mustHex(t *testing.T, value string) []byte {
	t.Helper()
	decoded, ok := decodeID(value, len(value)/2)
	if !ok {
		t.Fatal("invalid test ID")
	}
	return decoded
}
