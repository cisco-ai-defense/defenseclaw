// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"bytes"
	"context"
	"fmt"
	"net"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/grpc"
	"google.golang.org/grpc/metadata"
)

func TestCanonicalTraceProjectionPreservesDirectOTLPContract(t *testing.T) {
	record := canonicalProjectionModelRecord(t)
	engine, err := observabilityredaction.NewEngine(bytes.Repeat([]byte{0x42}, 32))
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	if !ok {
		t.Fatal("missing none profile")
	}
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	identity := delivery.RoutingIdentity{
		RecordID: record.RecordID(), Bucket: string(record.Bucket()), Signal: string(record.Signal()),
		EventName: string(record.EventName()), OriginDestination: "upstream-collector",
	}
	payload, err := newCanonicalTracePayload(projection, identity)
	if err != nil {
		t.Fatal(err)
	}
	wire, ok := decodeCanonicalTraceProjection(payload.Bytes())
	if !ok {
		t.Fatal("projected canonical trace did not decode")
	}
	converted, ok := wire.otlp()
	if !ok {
		t.Fatal("projected canonical trace did not convert")
	}
	span := converted.span
	if got := fmt.Sprintf("%x", span.TraceId); got != record.Correlation().TraceID {
		t.Fatalf("trace id=%s", got)
	}
	if got := fmt.Sprintf("%x", span.SpanId); got != record.Correlation().SpanID {
		t.Fatalf("span id=%s", got)
	}
	if got := fmt.Sprintf("%x", span.ParentSpanId); got != "1111111111111111" {
		t.Fatalf("parent id=%s", got)
	}
	if span.Name != "chat gpt-test" || span.Kind != tracepb.Span_SPAN_KIND_CLIENT ||
		span.StartTimeUnixNano != 1_783_278_000_000_000_000 ||
		span.EndTimeUnixNano != 1_783_278_000_100_000_000 || span.Flags != 0x101 ||
		span.TraceState != "dc=canonical-otlp" || span.Status.Code != tracepb.Status_STATUS_CODE_OK {
		t.Fatalf("span contract mismatch: %+v", span)
	}
	if span.DroppedAttributesCount != 3 || span.DroppedEventsCount != 4 || span.DroppedLinksCount != 5 ||
		len(span.Events) != 1 || len(span.Links) != 1 {
		t.Fatalf("dropped/event/link contract mismatch: %+v", span)
	}
	if span.Events[0].DroppedAttributesCount != 6 || span.Events[0].Name != "model.retry" ||
		span.Links[0].DroppedAttributesCount != 7 || span.Links[0].TraceState != "dc=linked" {
		t.Fatalf("nested trace contract mismatch: event=%+v link=%+v", span.Events[0], span.Links[0])
	}
	attributes := keyValuesByName(span.Attributes)
	assertAnyValueArm(t, attributes["defenseclaw.model.retry_count"], "int", int64(0))
	assertAnyValueArm(t, attributes["gen_ai.request.temperature"], "double", float64(0))
	assertAnyValueArm(t, attributes["defenseclaw.model.streaming"], "bool", true)
	if _, ok := attributes["gen_ai.input.messages"].Value.(*commonpb.AnyValue_ArrayValue); !ok {
		t.Fatalf("structured input arm=%T", attributes["gen_ai.input.messages"].Value)
	}
	if got := attributes["openinference.span.kind"].GetStringValue(); got != "LLM" {
		t.Fatalf("OpenInference span kind=%q", got)
	}
	if got := attributes["input.mime_type"].GetStringValue(); got != "application/json" {
		t.Fatalf("OpenInference input MIME=%q", got)
	}
	if got := attributes["input.value"].GetStringValue(); !strings.Contains(got, "hello") {
		t.Fatalf("OpenInference input alias=%q", got)
	}
	resource := converted.resource
	if resource.SchemaUrl != "https://opentelemetry.io/schemas/1.42.0" ||
		resource.Resource.DroppedAttributesCount != 8 || len(resource.ScopeSpans) != 1 ||
		resource.ScopeSpans[0].SchemaUrl != "https://defenseclaw.io/schemas/telemetry/v8" ||
		resource.ScopeSpans[0].Scope.DroppedAttributesCount != 9 {
		t.Fatalf("resource/scope contract mismatch: %+v", resource)
	}
	if got := keyValuesByName(resource.Resource.Attributes)["operator.profile"].GetStringValue(); got != "soc" {
		t.Fatalf("custom resource attribute=%q", got)
	}
}

func TestCanonicalProjectedTraceAdapterDeliversCompleteGRPCShapeAndHeaders(t *testing.T) {
	listener, err := net.Listen("tcp", "127.0.0.1:0")
	if err != nil {
		t.Fatal(err)
	}
	capture := &canonicalGRPCCapture{
		requests: make(chan *collectortracepb.ExportTraceServiceRequest, 1),
		headers:  make(chan metadata.MD, 1),
	}
	server := grpc.NewServer()
	collectortracepb.RegisterTraceServiceServer(server, capture)
	go server.Serve(listener)
	t.Cleanup(func() {
		server.Stop()
		_ = listener.Close()
	})

	factory := prepareTestFactory(t, Config{
		Destination: "canonical-grpc", Protocol: ProtocolGRPC, Endpoint: listener.Addr().String(),
		Selected: []observability.Signal{observability.SignalTraces},
		Headers:  map[string]string{"Authorization": "Bearer projected"},
		Timeout:  time.Second, TLS: TLSConfig{Insecure: true},
		NetworkSafety: NetworkSafety{AllowPrivateNetworks: true},
	}, Dependencies{})
	adapter, err := factory.NewCanonicalTraceAdapter(context.Background())
	if err != nil {
		t.Fatal(err)
	}
	record := canonicalProjectionModelRecord(t)
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := newCanonicalTracePayload(projection, delivery.RoutingIdentity{
		RecordID: record.RecordID(), Bucket: string(record.Bucket()), Signal: string(record.Signal()),
		EventName: string(record.EventName()), OriginDestination: "inbound-upstream",
	})
	if err != nil {
		t.Fatal(err)
	}
	dispatcher := newOTLPDispatcher(t, "canonical-grpc", adapter)
	if result := dispatcher.Enqueue(payload); !result.Accepted() {
		t.Fatalf("canonical enqueue=%+v", result)
	}
	drainOTLP(t, dispatcher)
	if err := adapter.Close(context.Background()); err != nil {
		t.Fatal(err)
	}

	select {
	case request := <-capture.requests:
		if len(request.ResourceSpans) != 1 || len(request.ResourceSpans[0].ScopeSpans) != 1 ||
			len(request.ResourceSpans[0].ScopeSpans[0].Spans) != 1 {
			t.Fatalf("canonical gRPC shape=%+v", request)
		}
		resource := request.ResourceSpans[0]
		span := resource.ScopeSpans[0].Spans[0]
		if span.Name != "chat gpt-test" || len(span.Events) != 1 || len(span.Links) != 1 ||
			span.DroppedAttributesCount != 3 || span.Flags != 0x101 {
			t.Fatalf("canonical gRPC span=%+v", span)
		}
		if got := keyValuesByName(resource.Resource.Attributes)["operator.profile"].GetStringValue(); got != "soc" {
			t.Fatalf("canonical gRPC custom resource=%q", got)
		}
	case <-time.After(time.Second):
		t.Fatal("canonical gRPC request not received")
	}
	select {
	case headers := <-capture.headers:
		if values := headers.Get("authorization"); len(values) != 1 || values[0] != "Bearer projected" {
			t.Fatalf("canonical gRPC headers=%v", values)
		}
	case <-time.After(time.Second):
		t.Fatal("canonical gRPC metadata not received")
	}
}

type canonicalGRPCCapture struct {
	collectortracepb.UnimplementedTraceServiceServer
	requests chan *collectortracepb.ExportTraceServiceRequest
	headers  chan metadata.MD
}

func (capture *canonicalGRPCCapture) Export(
	ctx context.Context,
	request *collectortracepb.ExportTraceServiceRequest,
) (*collectortracepb.ExportTraceServiceResponse, error) {
	headers, _ := metadata.FromIncomingContext(ctx)
	capture.headers <- headers
	capture.requests <- request
	return &collectortracepb.ExportTraceServiceResponse{}, nil
}

func TestCanonicalTraceProjectionRejectsIdentityAndTypeForgery(t *testing.T) {
	record := canonicalProjectionModelRecord(t)
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, _ := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileNone)
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	identity := delivery.RoutingIdentity{
		RecordID: record.RecordID(), Bucket: string(record.Bucket()), Signal: string(record.Signal()),
		EventName: string(record.EventName()),
	}
	identity.Bucket = string(observability.BucketToolActivity)
	if _, err := newCanonicalTracePayload(projection, identity); err == nil {
		t.Fatal("mismatched delivery identity accepted")
	}
	encoded, err := projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte(`"defenseclaw.model.streaming":true`), []byte(`"defenseclaw.model.streaming":"true"`), 1)
	wire, ok := decodeCanonicalTraceProjection(encoded)
	if !ok {
		t.Fatal("test mutation damaged envelope")
	}
	if _, ok := wire.otlp(); ok {
		t.Fatal("wrong typed attribute reached OTLP")
	}
	encoded, err = projection.Bytes()
	if err != nil {
		t.Fatal(err)
	}
	encoded = bytes.Replace(encoded, []byte(`"kind":"CLIENT"`), []byte(`"kind":"INTERNAL"`), 1)
	wire, ok = decodeCanonicalTraceProjection(encoded)
	if !ok {
		t.Fatal("span-kind mutation damaged envelope")
	}
	if _, ok := wire.otlp(); ok {
		t.Fatal("OpenInference-incompatible span kind reached OTLP")
	}
}

func TestCanonicalTraceProjectionPreservesStrictRedactionArrayPositions(t *testing.T) {
	record := canonicalProjectionModelRecord(t)
	engine, err := observabilityredaction.NewEngine(nil)
	if err != nil {
		t.Fatal(err)
	}
	profile, ok := observabilityredaction.BuiltInProfile(observabilityredaction.ProfileStrict)
	if !ok {
		t.Fatal("missing strict profile")
	}
	projection, _, err := engine.Project(record, profile)
	if err != nil {
		t.Fatal(err)
	}
	payload, err := newCanonicalTracePayload(projection, delivery.RoutingIdentity{
		RecordID: record.RecordID(), Bucket: string(record.Bucket()), Signal: string(record.Signal()),
		EventName: string(record.EventName()),
	})
	if err != nil {
		t.Fatal(err)
	}
	wire, ok := decodeCanonicalTraceProjection(payload.Bytes())
	if !ok {
		t.Fatal("strict-redacted canonical trace did not decode")
	}
	converted, ok := wire.otlp()
	if !ok {
		t.Fatal("strict-redacted structured trace was dropped")
	}
	attributes := keyValuesByName(converted.span.Attributes)
	messages, ok := attributes["gen_ai.input.messages"].Value.(*commonpb.AnyValue_ArrayValue)
	if !ok || !containsEmptyAnyValue(messages.ArrayValue) {
		t.Fatalf("redaction array placeholder was not preserved: %#v", attributes["gen_ai.input.messages"])
	}
	if value := attributes["input.value"].GetStringValue(); value == "" || strings.Contains(value, "hello") {
		t.Fatalf("OpenInference alias bypassed strict redaction: %q", value)
	}
}

func containsEmptyAnyValue(array *commonpb.ArrayValue) bool {
	if array == nil {
		return false
	}
	for _, value := range array.Values {
		if value == nil || value.Value == nil {
			return true
		}
		switch typed := value.Value.(type) {
		case *commonpb.AnyValue_ArrayValue:
			if containsEmptyAnyValue(typed.ArrayValue) {
				return true
			}
		case *commonpb.AnyValue_KvlistValue:
			for _, item := range typed.KvlistValue.Values {
				if item != nil && containsEmptyAnyValue(&commonpb.ArrayValue{Values: []*commonpb.AnyValue{item.Value}}) {
					return true
				}
			}
		}
	}
	return false
}

func canonicalProjectionModelRecord(t *testing.T) observability.Record {
	return canonicalProjectionModelRecordForPlan(
		t,
		"0123456789abcdef0123456789abcdef0123456789abcdef0123456789abcdef",
		8,
	)
}

func canonicalProjectionModelRecordForPlan(t *testing.T, digest string, generation int64) observability.Record {
	t.Helper()
	sequence := 0
	builder, err := observability.NewFamilyBuilder(
		observability.ClockFunc(func() time.Time {
			return time.Date(2026, time.July, 5, 20, 0, 0, 0, time.UTC)
		}),
		observability.OccurrenceIDGeneratorFunc(func() (string, error) {
			sequence++
			return fmt.Sprintf("canonical-otlp-%d", sequence), nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	event, err := observability.NewSpanModelChatModelRetryEvent(observability.SpanModelChatModelRetryEventInput{
		TimeUnixNano: 1_783_278_000_050_000_000, DroppedAttributesCount: observability.Present[uint32](6),
		DefenseClawModelAttempt: observability.Present[int64](2), DefenseClawModelRetryCount: observability.Present[int64](1),
		ErrorType: observability.Present("rate_limited"),
	})
	if err != nil {
		t.Fatal(err)
	}
	link, err := observability.NewSpanModelChatDerivedFromLink(observability.SpanModelChatDerivedFromLinkInput{
		TraceID: "22222222222222222222222222222222", SpanID: "3333333333333333",
		TraceState: observability.Present("dc=linked"), DroppedAttributesCount: observability.Present[uint32](7),
	})
	if err != nil {
		t.Fatal(err)
	}
	inputMessages := observability.TelemetryStructuredGenAIInputMessages{Items: []observability.TelemetryStructuredGenAIChatMessage{{
		Role: "user", Parts: observability.TelemetryStructuredGenAIMessageParts{Items: []observability.TelemetryStructuredGenAIMessagePart{
			observability.TelemetryStructuredArmGenAIMessagePartText{Value: observability.TelemetryStructuredGenAITextPart{Content: "hello"}},
		}},
	}}}
	customResource, err := observability.NewTelemetryCustomResourceAttributes(
		map[string]string{"operator.profile": "soc"},
		false,
	)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildSpanModelChat(observability.SpanModelChatInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway,
			Correlation: observability.Correlation{
				TraceID: "0123456789abcdef0123456789abcdef", SpanID: "0123456789abcdef",
			},
			Provenance: observability.FamilyProvenanceInput{
				Producer: "gateway.test", BinaryVersion: "8.0.0", ConfigGeneration: generation,
				ConfigDigest: digest,
			},
		},
		Outcome: observability.OutcomeCompleted, Kind: "CLIENT",
		StartTimeUnixNano: 1_783_278_000_000_000_000, EndTimeUnixNano: 1_783_278_000_100_000_000,
		ParentSpanID: observability.Present("1111111111111111"), TraceState: observability.Present("dc=canonical-otlp"),
		Flags: 0x101, Status: observability.NewTraceStatusOK(),
		Resource: observability.WithTelemetryCustomResourceAttributes(observability.TraceResourceInput{
			SchemaURL: "https://opentelemetry.io/schemas/1.42.0", DroppedAttributesCount: observability.Present[uint32](8),
		}, customResource),
		Scope:                  observability.TraceScopeInput{DroppedAttributesCount: observability.Present[uint32](9)},
		DroppedAttributesCount: observability.Present[uint32](3), Events: []observability.TraceEventInput{event},
		DroppedEventsCount: observability.Present[uint32](4), Links: []observability.TraceLinkInput{link},
		DroppedLinksCount:   observability.Present[uint32](5),
		ResourceServiceName: "defenseclaw", ResourceServiceNamespace: "cisco.ai-defense",
		ResourceServiceInstanceID: "instance-1", ResourceDeploymentEnvironmentName: "test",
		ResourceDefenseClawInstanceID: "instance-1", GenAIOperationName: observability.Present("chat"),
		GenAIProviderName: observability.Present("openai"), GenAIRequestModel: "gpt-test",
		GenAIRequestTemperature: observability.Present(float64(0)), DefenseClawModelRetryCount: observability.Present[int64](0),
		DefenseClawModelStreaming: observability.Present(true), GenAIInputMessages: observability.Present(inputMessages),
		DefenseClawTelemetryInputReported: true, DefenseClawContentInputState: "preserved",
		DefenseClawContentInputOriginalBytes: observability.Present[int64](5), DefenseClawTelemetryOutputReported: false,
		DefenseClawContentOutputState: "not_reported", DefenseClawTelemetryTokensReported: observability.Present(false),
		ConditionOperationTerminal: true,
	})
	if err != nil {
		t.Fatal(err)
	}
	return record
}

func assertAnyValueArm(t *testing.T, value *commonpb.AnyValue, arm string, expected any) {
	t.Helper()
	if value == nil {
		t.Fatalf("missing %s AnyValue", arm)
	}
	switch arm {
	case "int":
		actual, ok := value.Value.(*commonpb.AnyValue_IntValue)
		if !ok || actual.IntValue != expected.(int64) {
			t.Fatalf("int arm=%T value=%v", value.Value, value)
		}
	case "double":
		actual, ok := value.Value.(*commonpb.AnyValue_DoubleValue)
		if !ok || actual.DoubleValue != expected.(float64) {
			t.Fatalf("double arm=%T value=%v", value.Value, value)
		}
	case "bool":
		actual, ok := value.Value.(*commonpb.AnyValue_BoolValue)
		if !ok || actual.BoolValue != expected.(bool) {
			t.Fatalf("bool arm=%T value=%v", value.Value, value)
		}
	}
}
