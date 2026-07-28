// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package galileo owns the Galileo-specific OTLP delivery boundary. It accepts
// only immutable galileo-rich-v2 results produced from a central redaction
// Projection; SDK spans and canonical records are intentionally not accepted.
//
// Production activation is owned by the generation assembler after every
// destination has prepared successfully. This package must never be wired by
// adapting raw SDK ReadOnlySpan values as a shortcut.
package galileo

import (
	"bytes"
	"context"
	"encoding/hex"
	"encoding/json"
	"errors"
	"io"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	compatibility "github.com/defenseclaw/defenseclaw/internal/observability/compatibility/galileo"
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
	canaryOperationTag = "runtime-pipeline-test"
	canaryDestination  = "defenseclaw.telemetry.canary.destination"
	// P5 registry generation replaces these narrow local pins with generated
	// constants from the immutable semantic-profile tuple.
	traceSchemaProfileID = observability.RuntimeTraceSchemaVersion
	semanticProfileID    = observability.RuntimeSemanticProfileID
)

type ErrorCode string

const (
	ErrorInvalidProjection ErrorCode = "invalid_projection"
	ErrorInvalidTransport  ErrorCode = "invalid_transport"
)

// Error is a content-free preparation failure. It never retains projected
// values, endpoints, headers, backend responses, or decoder diagnostics.
type Error struct{ code ErrorCode }

func (err *Error) Error() string {
	if err == nil {
		return "Galileo destination preparation failed"
	}
	return "Galileo destination preparation failed: " + string(err.code)
}

func (err *Error) Code() ErrorCode {
	if err == nil {
		return ""
	}
	return err.code
}

func IsError(err error, code ErrorCode) bool {
	var target *Error
	return errors.As(err, &target) && target.code == code
}

// Adapter delegates guarded HTTP/protobuf transport to the common OTLP layer
// while retaining Galileo's closed compatibility decoder.
type Adapter struct{ inner *otlp.ProjectedTraceAdapter }

// NewAdapter claims the prepared trace transport. The supplied factory must be
// configured for the Galileo preset's traces-only HTTP/protobuf contract.
func NewAdapter(ctx context.Context, factory *otlp.Factory) (*Adapter, error) {
	if ctx == nil || factory == nil {
		return nil, &Error{code: ErrorInvalidTransport}
	}
	inner, err := factory.NewProjectedTraceAdapter(ctx, projectedBuilder{})
	if err != nil {
		return nil, &Error{code: ErrorInvalidTransport}
	}
	return &Adapter{inner: inner}, nil
}

// NewPayload snapshots an eligible galileo-rich-v2 result for the common
// dispatcher. This is the only supported payload-construction path: callers
// cannot provide a canonical record or an SDK span.
func NewPayload(result compatibility.Result, originDestination string) (delivery.Payload, error) {
	encoded, err := result.Bytes()
	if err != nil {
		return delivery.Payload{}, &Error{code: ErrorInvalidProjection}
	}
	wire, ok := decodeProjection(encoded)
	if !ok || wire.Profile != compatibility.ProfileID || wire.Shape != result.Shape() {
		return delivery.Payload{}, &Error{code: ErrorInvalidProjection}
	}
	target := ""
	if value, ok := wire.Body.Attributes[canaryDestination].(string); ok {
		target = value
	}
	if _, _, _, _, _, ok := wire.otlp(target); !ok {
		return delivery.Payload{}, &Error{code: ErrorInvalidProjection}
	}
	payload, err := delivery.NewPayload(encoded, delivery.RoutingIdentity{
		RecordID: wire.RecordID, Bucket: wire.Bucket, Signal: wire.Signal,
		EventName: wire.Family, OriginDestination: originDestination,
	})
	if err != nil {
		return delivery.Payload{}, &Error{code: ErrorInvalidProjection}
	}
	return payload, nil
}

func (adapter *Adapter) EncodedSize(projectedSizes []int) (int, bool) {
	if adapter == nil || adapter.inner == nil {
		return 0, false
	}
	return adapter.inner.EncodedSize(projectedSizes)
}

func (adapter *Adapter) Deliver(ctx context.Context, batch delivery.Batch) delivery.DeliveryResult {
	if adapter == nil || adapter.inner == nil {
		return delivery.DeliveryResult{Outcome: delivery.OutcomePermanentPayload}
	}
	return adapter.inner.Deliver(ctx, batch)
}

func (adapter *Adapter) Close(ctx context.Context) error {
	if adapter == nil || adapter.inner == nil {
		return nil
	}
	return adapter.inner.Close(ctx)
}

func (adapter *Adapter) Counters() otlp.ExportCounters {
	if adapter == nil || adapter.inner == nil {
		return otlp.ExportCounters{}
	}
	return adapter.inner.Counters()
}

type projectedBuilder struct{}

func (projectedBuilder) BuildProjectedTraceRequest(
	destination string,
	batch delivery.Batch,
) (otlp.ProjectedTraceRequest, bool) {
	if !observability.IsStableToken(destination) || batch.Destination() != destination || batch.Len() <= 0 {
		return otlp.ProjectedTraceRequest{}, false
	}
	resources := make([]*tracepb.ResourceSpans, 0, batch.Len())
	canarySpans := make(map[string][]projectedCanarySpan)
	traceSpanCount := make(map[string]int)
	for _, item := range batch.Items() {
		wire, ok := decodeProjection(item.Bytes())
		if !ok || wire.Profile != compatibility.ProfileID || wire.Signal != string(observability.SignalTraces) ||
			wire.RecordID != item.RecordID() || wire.Bucket != item.Identity().Bucket ||
			wire.Family != item.Identity().EventName {
			return otlp.ProjectedTraceRequest{}, false
		}
		resource, span, scope, resourceSchema, scopeSchema, ok := wire.otlp(destination)
		if !ok {
			return otlp.ProjectedTraceRequest{}, false
		}
		resources = append(resources, &tracepb.ResourceSpans{
			Resource: resource, SchemaUrl: resourceSchema,
			ScopeSpans: []*tracepb.ScopeSpans{{Scope: scope, SchemaUrl: scopeSchema, Spans: []*tracepb.Span{span}}},
		})
		traceID := stringMap(wire.Correlation, "trace_id")
		traceSpanCount[traceID]++
		if present, valid := generatedCanaryWire(wire, destination); present {
			if !valid {
				return otlp.ProjectedTraceRequest{}, false
			}
			canarySpans[traceID] = append(canarySpans[traceID], projectedCanarySpan{
				wire: wire, resource: resource, resourceSchema: resourceSchema,
				scope: scope, scopeSchema: scopeSchema, span: span,
			})
		}
	}
	acknowledged := make([]string, 0, len(canarySpans))
	for traceID, spans := range canarySpans {
		if traceSpanCount[traceID] == 2 && completeProjectedCanaryTrace(spans) {
			acknowledged = append(acknowledged, traceID)
		}
	}
	sort.Strings(acknowledged)
	return otlp.ProjectedTraceRequest{
		Request:        &collectortracepb.ExportTraceServiceRequest{ResourceSpans: resources},
		CanaryTraceIDs: acknowledged,
	}, true
}

type projectedCanarySpan struct {
	wire           projectedWire
	resource       *resourcepb.Resource
	resourceSchema string
	scope          *commonpb.InstrumentationScope
	scopeSchema    string
	span           *tracepb.Span
}

func completeProjectedCanaryTrace(spans []projectedCanarySpan) bool {
	if len(spans) != 2 {
		return false
	}
	var root, child *projectedCanarySpan
	for index := range spans {
		candidate := &spans[index]
		switch candidate.wire.Family {
		case observability.TelemetryFamilyAgentInvoke:
			if root != nil {
				return false
			}
			root = candidate
		case observability.TelemetryFamilyModelChat:
			if child != nil {
				return false
			}
			child = candidate
		default:
			return false
		}
	}
	if root == nil || child == nil || root.span == nil || child.span == nil ||
		root.span.Name != "invoke_agent diagnostic" || child.span.Name != "chat gpt-4o-mini" ||
		root.span.Kind != tracepb.Span_SPAN_KIND_INTERNAL || child.span.Kind != tracepb.Span_SPAN_KIND_CLIENT ||
		root.span.Status == nil || root.span.Status.Code != tracepb.Status_STATUS_CODE_OK ||
		child.span.Status == nil || child.span.Status.Code != tracepb.Status_STATUS_CODE_OK ||
		len(root.span.ParentSpanId) != 0 || !bytes.Equal(child.span.ParentSpanId, root.span.SpanId) ||
		!bytes.Equal(root.span.TraceId, child.span.TraceId) || bytes.Equal(root.span.SpanId, child.span.SpanId) ||
		root.span.Flags != 0x101 || child.span.Flags != 0x101 ||
		root.span.TraceState != child.span.TraceState ||
		integerMap(root.wire.Provenance, "config_generation") != integerMap(child.wire.Provenance, "config_generation") ||
		root.resourceSchema != child.resourceSchema || root.scopeSchema != child.scopeSchema ||
		!proto.Equal(root.resource, child.resource) || !proto.Equal(root.scope, child.scope) ||
		root.resource == nil || root.resource.DroppedAttributesCount != 0 {
		return false
	}
	return stringMap(root.wire.Body.Attributes, "defenseclaw.outcome") == string(observability.OutcomeCompleted) &&
		stringMap(child.wire.Body.Attributes, "defenseclaw.outcome") == string(observability.OutcomeCompleted)
}

type projectedWire struct {
	Profile              string              `json:"compatibility_profile"`
	Shape                compatibility.Shape `json:"compatibility_shape"`
	SchemaVersion        int                 `json:"schema_version"`
	BucketCatalogVersion int                 `json:"bucket_catalog_version"`
	Timestamp            any                 `json:"timestamp"`
	ObservedAt           any                 `json:"observed_at,omitempty"`
	RecordID             string              `json:"record_id"`
	Bucket               string              `json:"bucket"`
	Signal               string              `json:"signal"`
	Family               string              `json:"event_name"`
	SpanName             string              `json:"span_name"`
	Source               string              `json:"source"`
	Connector            string              `json:"connector,omitempty"`
	Action               string              `json:"action,omitempty"`
	Phase                string              `json:"phase,omitempty"`
	Outcome              string              `json:"outcome,omitempty"`
	Correlation          map[string]any      `json:"correlation"`
	Provenance           map[string]any      `json:"provenance"`
	Projection           projectedMetadata   `json:"projection"`
	Body                 projectedBody       `json:"body"`
}

type projectedMetadata struct {
	RedactionProfile       string `json:"redaction_profile"`
	DetectorCatalogVersion int    `json:"detector_catalog_version"`
	State                  string `json:"state"`
	TransformedFields      int    `json:"transformed_fields"`
	RemovedFields          int    `json:"removed_fields"`
	OversizeFields         int    `json:"oversize_fields"`
	FailureCount           int    `json:"failure_count"`
	FailuresTruncated      bool   `json:"failures_truncated"`
}

type projectedBody struct {
	Kind                   string            `json:"kind"`
	ParentSpanID           string            `json:"parent_span_id,omitempty"`
	TraceState             string            `json:"trace_state,omitempty"`
	Flags                  json.Number       `json:"flags"`
	StartTimeUnixNano      json.Number       `json:"start_time_unix_nano"`
	EndTimeUnixNano        json.Number       `json:"end_time_unix_nano"`
	DroppedAttributesCount json.Number       `json:"dropped_attributes_count,omitempty"`
	DroppedEventsCount     json.Number       `json:"dropped_events_count,omitempty"`
	DroppedLinksCount      json.Number       `json:"dropped_links_count,omitempty"`
	Attributes             map[string]any    `json:"attributes"`
	Events                 []projectedEvent  `json:"events,omitempty"`
	Links                  []projectedLink   `json:"links,omitempty"`
	Status                 projectedStatus   `json:"status"`
	Resource               projectedResource `json:"resource"`
	Scope                  projectedScope    `json:"scope"`
}

type projectedResource struct {
	Attributes             map[string]any `json:"attributes"`
	SchemaURL              string         `json:"schema_url,omitempty"`
	DroppedAttributesCount json.Number    `json:"dropped_attributes_count,omitempty"`
}

type projectedScope struct {
	Name                   string         `json:"name"`
	Version                string         `json:"version"`
	SchemaURL              string         `json:"schema_url"`
	Attributes             map[string]any `json:"attributes,omitempty"`
	DroppedAttributesCount json.Number    `json:"dropped_attributes_count,omitempty"`
}

type projectedEvent struct {
	Name                   string         `json:"name"`
	TimeUnixNano           json.Number    `json:"time_unix_nano"`
	Attributes             map[string]any `json:"attributes,omitempty"`
	DroppedAttributesCount json.Number    `json:"dropped_attributes_count,omitempty"`
}

type projectedLink struct {
	TraceID                string         `json:"trace_id"`
	SpanID                 string         `json:"span_id"`
	TraceState             string         `json:"trace_state,omitempty"`
	Attributes             map[string]any `json:"attributes,omitempty"`
	DroppedAttributesCount json.Number    `json:"dropped_attributes_count,omitempty"`
}

type projectedStatus struct {
	Code        any    `json:"code"`
	Message     string `json:"message,omitempty"`
	Description string `json:"description,omitempty"`
}

func decodeProjection(encoded []byte) (projectedWire, bool) {
	if len(encoded) == 0 || len(encoded) > delivery.MaxPayloadBytes || !utf8.Valid(encoded) {
		return projectedWire{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var wire projectedWire
	if err := decoder.Decode(&wire); err != nil {
		return projectedWire{}, false
	}
	var trailing any
	if err := decoder.Decode(&trailing); err != io.EOF {
		return projectedWire{}, false
	}
	if wire.Profile != compatibility.ProfileID || !validShape(wire.Shape) ||
		wire.SchemaVersion != observability.CurrentRecordSchemaVersion ||
		wire.BucketCatalogVersion != observability.CurrentBucketCatalogVersion ||
		wire.RecordID == "" || wire.Signal != string(observability.SignalTraces) ||
		!observability.IsRegisteredEventIdentity(observability.EventIdentity{
			Bucket: observability.Bucket(wire.Bucket), Signal: observability.SignalTraces,
			Name: observability.EventName(wire.Family),
		}) || wire.SpanName == "" || wire.Source == "" ||
		wire.Projection.RedactionProfile == "" || wire.Projection.State == "" ||
		wire.Timestamp == nil || wire.Projection.DetectorCatalogVersion <= 0 ||
		stringMap(wire.Provenance, "binary_version") == "" ||
		integerMap(wire.Provenance, "registry_schema_version") <= 0 ||
		integerMap(wire.Provenance, "config_generation") < 0 {
		return projectedWire{}, false
	}
	return wire, true
}

func validShape(shape compatibility.Shape) bool {
	switch shape {
	case compatibility.ShapeAgent, compatibility.ShapeLLM, compatibility.ShapeTool,
		compatibility.ShapeRetriever, compatibility.ShapeWorkflow:
		return true
	default:
		return false
	}
}

func (wire projectedWire) otlp(destination string) (
	*resourcepb.Resource,
	*tracepb.Span,
	*commonpb.InstrumentationScope,
	string,
	string,
	bool,
) {
	traceIDText := stringMap(wire.Correlation, "trace_id")
	spanIDText := stringMap(wire.Correlation, "span_id")
	traceID, ok := decodeID(traceIDText, 16)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	spanID, ok := decodeID(spanIDText, 8)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	parentSpanID := []byte(nil)
	if wire.Body.ParentSpanID != "" {
		parentSpanID, ok = decodeID(wire.Body.ParentSpanID, 8)
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
	if !ok {
		return nil, nil, nil, "", "", false
	}
	attributes, ok := attributes(wire.Body.Attributes)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	if !canonicalEndedIdentity(wire) {
		return nil, nil, nil, "", "", false
	}
	if present, valid := generatedCanaryWire(wire, destination); present && !valid {
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
	resourceAttributes, ok := requiredResourceAttributes(wire.Body.Resource.Attributes)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	resourceDroppedAttributes, ok := unsigned(wire.Body.Resource.DroppedAttributesCount, 32)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	scope, ok := requiredScope(wire.Body.Scope)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	status, ok := status(wire.Body.Status)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	events, ok := events(wire.Body.Events)
	if !ok {
		return nil, nil, nil, "", "", false
	}
	links, ok := links(wire.Body.Links)
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
	span := &tracepb.Span{
		TraceId: traceID, SpanId: spanID, ParentSpanId: parentSpanID,
		Name: wire.SpanName, Kind: kind, StartTimeUnixNano: start, EndTimeUnixNano: end,
		TraceState: wire.Body.TraceState, Flags: uint32(flags),
		Attributes: attributes, DroppedAttributesCount: uint32(droppedAttributes),
		Events: events, DroppedEventsCount: uint32(droppedEvents),
		Links: links, DroppedLinksCount: uint32(droppedLinks), Status: status,
	}
	return &resourcepb.Resource{
			Attributes: resourceAttributes, DroppedAttributesCount: uint32(resourceDroppedAttributes),
		}, span, scope,
		wire.Body.Resource.SchemaURL, wire.Body.Scope.SchemaURL, true
}

func requiredResourceAttributes(input map[string]any) ([]*commonpb.KeyValue, bool) {
	if observability.ValidateTelemetryResourceAttributes(input) != nil {
		return nil, false
	}
	keys := make([]string, 0, len(input))
	for key, raw := range input {
		value, ok := raw.(string)
		if key == "" || !utf8.ValidString(key) || !ok || !utf8.ValidString(value) {
			return nil, false
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	output := make([]*commonpb.KeyValue, 0, len(keys))
	for _, key := range keys {
		output = append(output, &commonpb.KeyValue{
			Key: key,
			Value: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{
				StringValue: input[key].(string),
			}},
		})
	}
	return output, true
}

func requiredScope(input projectedScope) (*commonpb.InstrumentationScope, bool) {
	if strings.TrimSpace(input.Name) == "" || strings.TrimSpace(input.Version) == "" ||
		strings.TrimSpace(input.SchemaURL) == "" {
		return nil, false
	}
	if stringMap(input.Attributes, "defenseclaw.trace.schema_version") != traceSchemaProfileID ||
		stringMap(input.Attributes, "defenseclaw.semantic_profile") != semanticProfileID {
		return nil, false
	}
	// Generated canonical spans carry only the pinned DefenseClaw trace and
	// semantic profiles. The Galileo compatibility profile belongs to this
	// destination-owned projection, so inject it when absent and reject only an
	// explicitly conflicting value. This keeps producer schemas destination-
	// neutral without weakening the projected OTLP scope contract.
	if rawProfile, present := input.Attributes["defenseclaw.galileo.compatibility_profile"]; present {
		profile, valid := rawProfile.(string)
		if !valid || profile != compatibility.ProfileID {
			return nil, false
		}
	}
	projected := make(map[string]any, len(input.Attributes)+1)
	for key, value := range input.Attributes {
		projected[key] = value
	}
	projected["defenseclaw.galileo.compatibility_profile"] = compatibility.ProfileID
	attributes, ok := attributes(projected)
	if !ok {
		return nil, false
	}
	dropped, ok := unsigned(input.DroppedAttributesCount, 32)
	if !ok {
		return nil, false
	}
	return &commonpb.InstrumentationScope{
		Name: input.Name, Version: input.Version, Attributes: attributes,
		DroppedAttributesCount: uint32(dropped),
	}, true
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
	return outcome != observability.OutcomeAttempted && observability.IsOutcome(outcome) &&
		string(outcome) == wire.Outcome
}

func generatedCanaryWire(wire projectedWire, destination string) (present, valid bool) {
	markerRaw, markerPresent := wire.Body.Attributes[canaryMarker]
	operationRaw, operationPresent := wire.Body.Attributes[canaryOperation]
	targetRaw, targetPresent := wire.Body.Attributes[canaryDestination]
	present = markerPresent || operationPresent || targetPresent
	if !present {
		return false, true
	}
	marker, markerOK := markerRaw.(bool)
	operation, operationOK := operationRaw.(string)
	target, targetOK := targetRaw.(string)
	genAIOperation, genAIOperationOK := wire.Body.Attributes["gen_ai.operation.name"].(string)
	expectedOperation := ""
	expectedBucket := ""
	switch wire.Family {
	case observability.TelemetryFamilyAgentInvoke:
		expectedOperation, expectedBucket = "invoke_agent", string(observability.BucketAgentLifecycle)
	case observability.TelemetryFamilyModelChat:
		expectedOperation, expectedBucket = "chat", string(observability.BucketModelIO)
	default:
		return true, false
	}
	return true, markerOK && marker && operationOK && operation == canaryOperationTag &&
		targetOK && target == destination && observability.IsStableToken(target) &&
		genAIOperationOK && genAIOperation == expectedOperation && wire.Bucket == expectedBucket
}

func attributes(input map[string]any) ([]*commonpb.KeyValue, bool) {
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
		value, ok := anyValue(input[key])
		if !ok {
			return nil, false
		}
		output = append(output, &commonpb.KeyValue{Key: key, Value: value})
	}
	return output, true
}

func anyValue(input any) (*commonpb.AnyValue, bool) {
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
			converted, ok := anyValue(item)
			if !ok {
				return nil, false
			}
			values = append(values, converted)
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: values}}}, true
	case map[string]any:
		values, ok := attributes(value)
		if !ok {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: values}}}, true
	default:
		return nil, false
	}
}

func events(input []projectedEvent) ([]*tracepb.Span_Event, bool) {
	output := make([]*tracepb.Span_Event, 0, len(input))
	for _, event := range input {
		timestamp, ok := unsigned(event.TimeUnixNano, 64)
		if !ok || event.Name == "" {
			return nil, false
		}
		attributes, ok := attributes(event.Attributes)
		if !ok {
			return nil, false
		}
		dropped, ok := unsigned(event.DroppedAttributesCount, 32)
		if !ok {
			return nil, false
		}
		output = append(output, &tracepb.Span_Event{
			TimeUnixNano: timestamp, Name: event.Name, Attributes: attributes,
			DroppedAttributesCount: uint32(dropped),
		})
	}
	return output, true
}

func links(input []projectedLink) ([]*tracepb.Span_Link, bool) {
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
		if link.TraceState != "" {
			state, err := trace.ParseTraceState(link.TraceState)
			if err != nil || state.String() != link.TraceState {
				return nil, false
			}
		}
		attributes, ok := attributes(link.Attributes)
		if !ok {
			return nil, false
		}
		dropped, ok := unsigned(link.DroppedAttributesCount, 32)
		if !ok {
			return nil, false
		}
		output = append(output, &tracepb.Span_Link{
			TraceId: traceID, SpanId: spanID, TraceState: link.TraceState, Attributes: attributes,
			DroppedAttributesCount: uint32(dropped),
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

func decodeID(value string, bytes int) ([]byte, bool) {
	if len(value) != bytes*2 {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != bytes {
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

func integerMap(input map[string]any, key string) int64 {
	value, ok := input[key].(json.Number)
	if !ok {
		return -1
	}
	parsed, err := value.Int64()
	if err != nil {
		return -1
	}
	return parsed
}
