// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package localobservability

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/destinations/otlp"
	"go.opentelemetry.io/otel/trace"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

const (
	canaryMarker       = "defenseclaw.telemetry.canary"
	canaryOperation    = "defenseclaw.telemetry.canary.operation"
	canaryDestination  = "defenseclaw.telemetry.canary.destination"
	canaryOperationTag = "runtime-pipeline-test"
)

// NewPayload is the sole queue payload boundary. It accepts only the generated
// local compatibility result and validates that it can form a complete OTLP
// span before retaining immutable bytes.
func NewPayload(result Result, originDestination string) (delivery.Payload, bool) {
	encoded, ok := result.Bytes()
	if !ok {
		return delivery.Payload{}, false
	}
	wire, ok := decodeWire(encoded, true)
	if !ok {
		return delivery.Payload{}, false
	}
	target := stringMap(wire.Body.Attributes, canaryDestination)
	if _, _, _, _, _, ok := wire.otlp(target); !ok {
		return delivery.Payload{}, false
	}
	payload, err := delivery.NewPayload(encoded, delivery.RoutingIdentity{
		RecordID: wire.RecordID, Bucket: wire.Bucket, Signal: wire.Signal,
		EventName: wire.Family, OriginDestination: originDestination,
	})
	return payload, err == nil
}

// RequestBuilder converts only local-observability-v1 payloads into OTLP. It
// never accepts a canonical record or SDK ReadOnlySpan.
type RequestBuilder struct{}

var _ otlp.ProjectedTraceRequestBuilder = RequestBuilder{}

func (RequestBuilder) BuildProjectedTraceRequest(
	destination string,
	batch delivery.Batch,
) (otlp.ProjectedTraceRequest, bool) {
	if !observability.IsStableToken(destination) || batch.Destination() != destination || batch.Len() <= 0 {
		return otlp.ProjectedTraceRequest{}, false
	}
	resources := make([]*tracepb.ResourceSpans, 0, batch.Len())
	canaryByTrace := make(map[string][]localCanarySpan)
	traceCounts := make(map[string]int)
	for _, item := range batch.Items() {
		wire, ok := decodeWire(item.Bytes(), true)
		if !ok || wire.RecordID != item.RecordID() || wire.Bucket != item.Identity().Bucket ||
			wire.Signal != item.Identity().Signal || wire.Family != item.Identity().EventName {
			return otlp.ProjectedTraceRequest{}, false
		}
		resource, span, scope, resourceSchema, scopeSchema, ok := wire.otlp(destination)
		if !ok {
			return otlp.ProjectedTraceRequest{}, false
		}
		resources = append(resources, &tracepb.ResourceSpans{
			Resource: resource, SchemaUrl: resourceSchema,
			ScopeSpans: []*tracepb.ScopeSpans{{
				Scope: scope, SchemaUrl: scopeSchema, Spans: []*tracepb.Span{span},
			}},
		})
		traceID := stringMap(wire.Correlation, "trace_id")
		traceCounts[traceID]++
		if present, valid := generatedCanary(wire, destination); present {
			if !valid {
				return otlp.ProjectedTraceRequest{}, false
			}
			canaryByTrace[traceID] = append(canaryByTrace[traceID], localCanarySpan{
				wire: wire, resource: resource, scope: scope, resourceSchema: resourceSchema,
				scopeSchema: scopeSchema, span: span,
			})
		}
	}
	acknowledged := make([]string, 0, len(canaryByTrace))
	for traceID, spans := range canaryByTrace {
		if traceCounts[traceID] == 2 && completeCanary(spans) {
			acknowledged = append(acknowledged, traceID)
		}
	}
	sort.Strings(acknowledged)
	return otlp.ProjectedTraceRequest{
		Request:        &collectortracepb.ExportTraceServiceRequest{ResourceSpans: resources},
		CanaryTraceIDs: acknowledged,
	}, true
}

type localCanarySpan struct {
	wire           projectedWire
	resource       *resourcepb.Resource
	resourceSchema string
	scope          *commonpb.InstrumentationScope
	scopeSchema    string
	span           *tracepb.Span
}

func completeCanary(spans []localCanarySpan) bool {
	if len(spans) != 2 {
		return false
	}
	var root, child *localCanarySpan
	for index := range spans {
		candidate := &spans[index]
		switch candidate.wire.Family {
		case observability.TelemetryFamilyAgentInvoke:
			root = candidate
		case observability.TelemetryFamilyModelChat:
			child = candidate
		default:
			return false
		}
	}
	return root != nil && child != nil && root.span != nil && child.span != nil &&
		root.span.Name == "invoke_agent diagnostic" && child.span.Name == "chat gpt-4o-mini" &&
		root.span.Kind == tracepb.Span_SPAN_KIND_INTERNAL && child.span.Kind == tracepb.Span_SPAN_KIND_CLIENT &&
		root.span.Status != nil && child.span.Status != nil &&
		root.span.Status.Code == tracepb.Status_STATUS_CODE_OK && child.span.Status.Code == tracepb.Status_STATUS_CODE_OK &&
		len(root.span.ParentSpanId) == 0 && bytes.Equal(child.span.ParentSpanId, root.span.SpanId) &&
		bytes.Equal(root.span.TraceId, child.span.TraceId) && !bytes.Equal(root.span.SpanId, child.span.SpanId) &&
		root.span.Flags == 0x101 && child.span.Flags == 0x101 && root.span.TraceState == child.span.TraceState &&
		integerMap(root.wire.Provenance, "config_generation") == integerMap(child.wire.Provenance, "config_generation") &&
		root.resourceSchema == child.resourceSchema && root.scopeSchema == child.scopeSchema &&
		proto.Equal(root.resource, child.resource) && proto.Equal(root.scope, child.scope) &&
		root.resource != nil && root.resource.DroppedAttributesCount == 0 &&
		stringMap(root.wire.Body.Attributes, "defenseclaw.outcome") == string(observability.OutcomeCompleted) &&
		stringMap(child.wire.Body.Attributes, "defenseclaw.outcome") == string(observability.OutcomeCompleted)
}

func (wire projectedWire) otlp(destination string) (
	*resourcepb.Resource, *tracepb.Span, *commonpb.InstrumentationScope, string, string, bool,
) {
	traceID, ok := decodeID(stringMap(wire.Correlation, "trace_id"), 16)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	spanID, ok := decodeID(stringMap(wire.Correlation, "span_id"), 8)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	var parent []byte
	if wire.Body.ParentSpanID != "" {
		parent, ok = decodeID(wire.Body.ParentSpanID, 8)
		if !ok {
			return nil, nil, nil, "", "", false
		}
	}
	start, ok := unsigned(wire.Body.StartTimeUnixNano, 64)
	if !ok || start == 0 {
		return nil, nil, nil, "", "", false
	}
	end, ok := unsigned(wire.Body.EndTimeUnixNano, 64)
	if !ok || end < start {
		return nil, nil, nil, "", "", false
	}
	kind, ok := spanKind(wire.Body.Kind)
	if !ok || !canonicalEndedIdentity(wire) {
		return nil, nil, nil, "", "", false
	}
	if present, valid := generatedCanary(wire, destination); present && !valid {
		return nil, nil, nil, "", "", false
	}
	flags, ok := unsigned(wire.Body.Flags, 32)
	if !ok || wire.Body.Flags == "" || flags&^uint64(0x3ff) != 0 {
		return nil, nil, nil, "", "", false
	}
	if wire.Body.TraceState != "" {
		state, err := trace.ParseTraceState(wire.Body.TraceState)
		if err != nil || state.String() != wire.Body.TraceState {
			return nil, nil, nil, "", "", false
		}
	}
	spanAttributes, ok := spanAttributes(observability.EventName(wire.Family), wire.Body.Attributes)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	resourceAttributes, ok := requiredResourceAttributes(observability.EventName(wire.Family), wire.Body.Resource.Attributes)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	resourceDropped, ok := unsigned(wire.Body.Resource.DroppedAttributesCount, 32)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	scope, ok := requiredScope(observability.EventName(wire.Family), wire.Body.Scope)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	spanStatus, ok := status(wire.Body.Status)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	spanEvents, ok := events(observability.EventName(wire.Family), wire.Body.Events)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	spanLinks, ok := links(observability.EventName(wire.Family), wire.Body.Links)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	droppedAttributes, ok := unsigned(wire.Body.DroppedAttributesCount, 32)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	droppedEvents, ok := unsigned(wire.Body.DroppedEventsCount, 32)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	droppedLinks, ok := unsigned(wire.Body.DroppedLinksCount, 32)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	return &resourcepb.Resource{
			Attributes: resourceAttributes, DroppedAttributesCount: uint32(resourceDropped),
		}, &tracepb.Span{
			TraceId: traceID, SpanId: spanID, ParentSpanId: parent, Name: wire.SpanName,
			Kind: kind, StartTimeUnixNano: start, EndTimeUnixNano: end,
			TraceState: wire.Body.TraceState, Flags: uint32(flags), Attributes: spanAttributes,
			DroppedAttributesCount: uint32(droppedAttributes), Events: spanEvents,
			DroppedEventsCount: uint32(droppedEvents), Links: spanLinks,
			DroppedLinksCount: uint32(droppedLinks), Status: spanStatus,
		}, scope, wire.Body.Resource.SchemaURL, wire.Body.Scope.SchemaURL, true
}

func canonicalEndedIdentity(wire projectedWire) bool {
	if stringMap(wire.Body.Attributes, "defenseclaw.bucket") != wire.Bucket ||
		stringMap(wire.Body.Attributes, "defenseclaw.span.family") != wire.Family ||
		stringMap(wire.Body.Attributes, "defenseclaw.source") != wire.Source {
		return false
	}
	familyVersion, ok := unsignedNumber(wire.Body.Attributes["defenseclaw.span.family_schema_version"], 32)
	if !ok || familyVersion == 0 {
		return false
	}
	generation, ok := unsignedNumber(wire.Body.Attributes["defenseclaw.config.generation"], 63)
	if !ok || generation != uint64(integerMap(wire.Provenance, "config_generation")) {
		return false
	}
	outcome := observability.Outcome(stringMap(wire.Body.Attributes, "defenseclaw.outcome"))
	return outcome != observability.OutcomeAttempted && observability.IsOutcome(outcome) && string(outcome) == wire.Outcome
}

func generatedCanary(wire projectedWire, destination string) (present, valid bool) {
	marker, markerPresent := wire.Body.Attributes[canaryMarker]
	operation, operationPresent := wire.Body.Attributes[canaryOperation]
	target, targetPresent := wire.Body.Attributes[canaryDestination]
	present = markerPresent || operationPresent || targetPresent
	if !present {
		return false, true
	}
	expectedOperation, expectedBucket := "", ""
	switch wire.Family {
	case observability.TelemetryFamilyAgentInvoke:
		expectedOperation, expectedBucket = "invoke_agent", string(observability.BucketAgentLifecycle)
	case observability.TelemetryFamilyModelChat:
		expectedOperation, expectedBucket = "chat", string(observability.BucketModelIO)
	default:
		return true, false
	}
	markerValue, markerOK := marker.(bool)
	operationValue, operationOK := operation.(string)
	targetValue, targetOK := target.(string)
	return true, markerOK && markerValue && operationOK && operationValue == canaryOperationTag &&
		targetOK && targetValue == destination && observability.IsStableToken(targetValue) &&
		stringMap(wire.Body.Attributes, "gen_ai.operation.name") == expectedOperation && wire.Bucket == expectedBucket
}

func requiredResourceAttributes(family observability.EventName, input map[string]any) ([]*commonpb.KeyValue, bool) {
	if observability.ValidateTelemetryResourceAttributes(input) != nil {
		return nil, false
	}
	return keyValues(input, func(key string) (observability.OTLPValueKind, bool) {
		if kind, registered := observability.TraceOTLPResourceAttributeKind(family, key); registered {
			return kind, true
		}
		return observability.OTLPValueString, true
	})
}

func requiredScope(family observability.EventName, input projectedScope) (*commonpb.InstrumentationScope, bool) {
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Version) == "" ||
		strings.TrimSpace(input.SchemaURL) == "" ||
		stringMap(input.Attributes, "defenseclaw.trace.schema_version") != observability.RuntimeTraceSchemaVersion ||
		stringMap(input.Attributes, "defenseclaw.semantic_profile") != observability.RuntimeSemanticProfileID {
		return nil, false
	}
	values, ok := keyValues(input.Attributes, func(key string) (observability.OTLPValueKind, bool) {
		return observability.TraceOTLPScopeAttributeKind(family, key)
	})
	if !ok {
		return nil, false
	}
	dropped, ok := unsigned(input.DroppedAttributesCount, 32)
	if !ok {
		return nil, false
	}
	return &commonpb.InstrumentationScope{
		Name: input.Name, Version: input.Version, Attributes: values,
		DroppedAttributesCount: uint32(dropped),
	}, true
}

type valueKindResolver func(string) (observability.OTLPValueKind, bool)

func spanAttributes(family observability.EventName, input map[string]any) ([]*commonpb.KeyValue, bool) {
	return keyValues(input, func(key string) (observability.OTLPValueKind, bool) {
		if kind, ok := observability.TraceOTLPAttributeKind(family, key); ok {
			return kind, true
		}
		switch key {
		case "connector", "gen_ai.agent.type", "defenseclaw.raw_action", "defenseclaw.decision":
			return observability.OTLPValueString, true
		case "defenseclaw.would_block":
			return observability.OTLPValueBoolean, true
		default:
			return observability.OTLPValueInvalid, false
		}
	})
}

func keyValues(input map[string]any, resolve valueKindResolver) ([]*commonpb.KeyValue, bool) {
	keys := make([]string, 0, len(input))
	for key := range input {
		if key == "" || !utf8.ValidString(key) {
			return nil, false
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make([]*commonpb.KeyValue, 0, len(keys))
	for _, key := range keys {
		kind, ok := resolve(key)
		if !ok {
			return nil, false
		}
		value, ok := canonicalValue(input[key], kind)
		if !ok {
			return nil, false
		}
		output = append(output, &commonpb.KeyValue{Key: key, Value: value})
	}
	return output, true
}

func canonicalValue(input any, kind observability.OTLPValueKind) (*commonpb.AnyValue, bool) {
	switch kind {
	case observability.OTLPValueString:
		value, ok := input.(string)
		if !ok || !utf8.ValidString(value) {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}, true
	case observability.OTLPValueBoolean:
		value, ok := input.(bool)
		if !ok {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: value}}, true
	case observability.OTLPValueInt64:
		value, ok := input.(json.Number)
		if !ok {
			return nil, false
		}
		integer, err := value.Int64()
		if err != nil {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: integer}}, true
	case observability.OTLPValueUint32:
		value, ok := input.(json.Number)
		if !ok {
			return nil, false
		}
		integer, err := strconv.ParseUint(value.String(), 10, 32)
		if err != nil {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(integer)}}, true
	case observability.OTLPValueUint64:
		value, ok := input.(json.Number)
		if !ok {
			return nil, false
		}
		integer, err := strconv.ParseUint(value.String(), 10, 64)
		if err != nil || integer > math.MaxInt64 {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(integer)}}, true
	case observability.OTLPValueDouble:
		value, ok := input.(json.Number)
		if !ok {
			return nil, false
		}
		floating, err := strconv.ParseFloat(value.String(), 64)
		if err != nil || math.IsInf(floating, 0) || math.IsNaN(floating) {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: floating}}, true
	case observability.OTLPValueStringArray:
		values, ok := input.([]any)
		if !ok {
			return nil, false
		}
		output := make([]*commonpb.AnyValue, 0, len(values))
		for _, item := range values {
			text, ok := item.(string)
			if !ok || !utf8.ValidString(text) {
				return nil, false
			}
			output = append(output, &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: text}})
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: output}}}, true
	case observability.OTLPValueStructured:
		return structuredValue(input)
	default:
		return nil, false
	}
}

func structuredValue(input any) (*commonpb.AnyValue, bool) {
	switch value := input.(type) {
	case string:
		if !utf8.ValidString(value) {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: value}}, true
	case bool:
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: value}}, true
	case json.Number:
		if integer, err := value.Int64(); err == nil {
			return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: integer}}, true
		}
		floating, err := strconv.ParseFloat(value.String(), 64)
		if err != nil || math.IsInf(floating, 0) || math.IsNaN(floating) {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: floating}}, true
	case []any:
		values := make([]*commonpb.AnyValue, 0, len(value))
		for _, item := range value {
			converted, ok := structuredValue(item)
			if !ok {
				return nil, false
			}
			values = append(values, converted)
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: values}}}, true
	case map[string]any:
		keys := make([]string, 0, len(value))
		for key := range value {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		values := make([]*commonpb.KeyValue, 0, len(keys))
		for _, key := range keys {
			converted, ok := structuredValue(value[key])
			if key == "" || !ok {
				return nil, false
			}
			values = append(values, &commonpb.KeyValue{Key: key, Value: converted})
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: values}}}, true
	default:
		return nil, false
	}
}

func events(family observability.EventName, input []projectedEvent) ([]*tracepb.Span_Event, bool) {
	output := make([]*tracepb.Span_Event, 0, len(input))
	for _, event := range input {
		timestamp, ok := unsigned(event.TimeUnixNano, 64)
		if !ok || event.Name == "" {
			return nil, false
		}
		values, ok := keyValues(event.Attributes, func(key string) (observability.OTLPValueKind, bool) {
			return observability.TraceOTLPEventAttributeKind(family, event.Name, key)
		})
		if !ok {
			return nil, false
		}
		dropped, ok := unsigned(event.DroppedAttributesCount, 32)
		if !ok {
			return nil, false
		}
		output = append(output, &tracepb.Span_Event{
			TimeUnixNano: timestamp, Name: event.Name, Attributes: values,
			DroppedAttributesCount: uint32(dropped),
		})
	}
	return output, true
}

func links(family observability.EventName, input []projectedLink) ([]*tracepb.Span_Link, bool) {
	output := make([]*tracepb.Span_Link, 0, len(input))
	for _, link := range input {
		traceID, ok := decodeID(link.TraceID, 16)
		if !ok {
			return nil, false
		}
		spanID, ok := decodeID(link.SpanID, 8)
		if !ok {
			return nil, false
		}
		values, ok := keyValues(link.Attributes, func(key string) (observability.OTLPValueKind, bool) {
			return observability.TraceOTLPLinkAttributeKind(family, key)
		})
		if !ok {
			return nil, false
		}
		dropped, ok := unsigned(link.DroppedAttributesCount, 32)
		if !ok {
			return nil, false
		}
		output = append(output, &tracepb.Span_Link{
			TraceId: traceID, SpanId: spanID, TraceState: link.TraceState,
			Attributes: values, DroppedAttributesCount: uint32(dropped),
		})
	}
	return output, true
}

func status(input projectedStatus) (*tracepb.Status, bool) {
	var code tracepb.Status_StatusCode
	switch value := input.Code.(type) {
	case json.Number:
		parsed, err := strconv.ParseInt(value.String(), 10, 32)
		if err != nil || parsed < 0 || parsed > 2 {
			return nil, false
		}
		code = tracepb.Status_StatusCode(parsed)
	case string:
		switch strings.ToUpper(value) {
		case "UNSET":
			code = tracepb.Status_STATUS_CODE_UNSET
		case "OK":
			code = tracepb.Status_STATUS_CODE_OK
		case "ERROR":
			code = tracepb.Status_STATUS_CODE_ERROR
		default:
			return nil, false
		}
	default:
		return nil, false
	}
	message := input.Description
	if message == "" {
		message = input.Message
	}
	return &tracepb.Status{Code: code, Message: message}, true
}

func spanKind(input string) (tracepb.Span_SpanKind, bool) {
	switch strings.ToUpper(input) {
	case "INTERNAL":
		return tracepb.Span_SPAN_KIND_INTERNAL, true
	case "SERVER":
		return tracepb.Span_SPAN_KIND_SERVER, true
	case "CLIENT":
		return tracepb.Span_SPAN_KIND_CLIENT, true
	case "PRODUCER":
		return tracepb.Span_SPAN_KIND_PRODUCER, true
	case "CONSUMER":
		return tracepb.Span_SPAN_KIND_CONSUMER, true
	default:
		return tracepb.Span_SPAN_KIND_UNSPECIFIED, false
	}
}

func decodeID(value string, length int) ([]byte, bool) {
	if len(value) != length*2 {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != length {
		return nil, false
	}
	allZero := true
	for _, item := range decoded {
		allZero = allZero && item == 0
	}
	return decoded, !allZero
}

func unsigned(value json.Number, bits int) (uint64, bool) {
	if value == "" {
		return 0, true
	}
	if parsed, err := strconv.ParseUint(value.String(), 10, bits); err == nil {
		return parsed, true
	}
	rational, ok := new(big.Rat).SetString(value.String())
	if !ok || !rational.IsInt() || rational.Sign() < 0 || rational.Num().BitLen() > bits {
		return 0, false
	}
	return rational.Num().Uint64(), true
}

func unsignedNumber(value any, bits int) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	return unsigned(number, bits)
}

func stringMap(input map[string]any, key string) string {
	value, _ := input[key].(string)
	return strings.TrimSpace(value)
}

func integerMap(input map[string]any, key string) int64 { return integerValue(input[key]) }
