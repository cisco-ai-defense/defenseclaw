// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"bytes"
	"encoding/hex"
	"encoding/json"
	"math"
	"math/big"
	"sort"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/openinference"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
	collectortracepb "go.opentelemetry.io/proto/otlp/collector/trace/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	tracepb "go.opentelemetry.io/proto/otlp/trace/v1"
	"google.golang.org/protobuf/proto"
)

const canonicalTraceRepresentationID = "defenseclaw-otlp-v1"

// canonicalTraceProjectedBuilder implements the generated defenseclaw-otlp-v1
// direct-span representation. Its input is already destination-routed and
// redacted immutable bytes; it has no path back to a canonical producer record.
type canonicalTraceProjectedBuilder struct{}

func (canonicalTraceProjectedBuilder) BuildProjectedTraceRequest(
	destination string,
	batch delivery.Batch,
) (ProjectedTraceRequest, bool) {
	if !observability.IsStableToken(destination) || batch.Destination() != destination || batch.Len() == 0 {
		return ProjectedTraceRequest{}, false
	}
	resources := make([]*tracepb.ResourceSpans, 0, batch.Len())
	traceCounts := make(map[string]int)
	canaries := make(map[string][]canonicalProjectedSpan)
	for _, item := range batch.Items() {
		wire, ok := decodeCanonicalTraceProjection(item.Bytes())
		if !ok || wire.recordID != item.RecordID() || wire.bucket != item.Identity().Bucket ||
			string(wire.family) != item.Identity().EventName || item.Identity().Signal != string(observability.SignalTraces) {
			return ProjectedTraceRequest{}, false
		}
		converted, ok := wire.otlp()
		if !ok {
			return ProjectedTraceRequest{}, false
		}
		resources = append(resources, converted.resource)
		traceID := hex.EncodeToString(converted.span.TraceId)
		traceCounts[traceID]++
		if marked, valid := converted.canary(destination); marked {
			if !valid {
				return ProjectedTraceRequest{}, false
			}
			canaries[traceID] = append(canaries[traceID], converted)
		}
	}
	acknowledged := make([]string, 0, len(canaries))
	for traceID, spans := range canaries {
		if traceCounts[traceID] == 2 && completeCanonicalProjectedCanary(spans) {
			acknowledged = append(acknowledged, traceID)
		}
	}
	sort.Strings(acknowledged)
	return ProjectedTraceRequest{
		Request:        &collectortracepb.ExportTraceServiceRequest{ResourceSpans: resources},
		CanaryTraceIDs: acknowledged,
	}, true
}

func newCanonicalTracePayload(
	projection redaction.Projection,
	identity delivery.RoutingIdentity,
) (delivery.Payload, error) {
	encoded, err := projection.Bytes()
	if err != nil {
		return delivery.Payload{}, newError(ErrorInvalidConfig, nil)
	}
	wire, ok := decodeCanonicalTraceProjection(encoded)
	if !ok || wire.recordID != identity.RecordID || wire.bucket != identity.Bucket ||
		string(wire.family) != identity.EventName || identity.Signal != string(observability.SignalTraces) {
		return delivery.Payload{}, newError(ErrorInvalidConfig, nil)
	}
	payload, err := delivery.NewPayload(encoded, identity)
	if err != nil {
		return delivery.Payload{}, newError(ErrorInvalidConfig, nil)
	}
	return payload, nil
}

type canonicalTraceWire struct {
	recordID    string
	bucket      string
	family      observability.EventName
	spanName    string
	traceID     []byte
	spanID      []byte
	correlation map[string]any
	body        map[string]any
	projection  map[string]any
}

func decodeCanonicalTraceProjection(encoded []byte) (canonicalTraceWire, bool) {
	if len(encoded) == 0 || len(encoded) > redaction.MaxProjectedRecordBytes {
		return canonicalTraceWire{}, false
	}
	decoder := json.NewDecoder(bytes.NewReader(encoded))
	decoder.UseNumber()
	var root map[string]any
	if err := decoder.Decode(&root); err != nil || decoder.More() {
		return canonicalTraceWire{}, false
	}
	var trailing any
	if decoder.Decode(&trailing) == nil {
		return canonicalTraceWire{}, false
	}
	if text(root, "signal") != string(observability.SignalTraces) {
		return canonicalTraceWire{}, false
	}
	recordID, bucket, familyText, spanName := text(root, "record_id"), text(root, "bucket"), text(root, "event_name"), text(root, "span_name")
	family := observability.EventName(familyText)
	correlation, correlationOK := object(root, "correlation")
	body, bodyOK := object(root, "body")
	projection, projectionOK := object(root, "projection")
	traceID, traceOK := exactHex(text(correlation, "trace_id"), 16)
	spanID, spanOK := exactHex(text(correlation, "span_id"), 8)
	if recordID == "" || bucket == "" || spanName == "" || !bodyOK || !correlationOK || !projectionOK ||
		!traceOK || !spanOK || family.Validate() != nil ||
		!validProjectionMetadata(projection) {
		return canonicalTraceWire{}, false
	}
	return canonicalTraceWire{
		recordID: recordID, bucket: bucket, family: family, spanName: spanName,
		traceID: traceID, spanID: spanID, correlation: correlation, body: body, projection: projection,
	}, true
}

func validProjectionMetadata(projection map[string]any) bool {
	profile, state := text(projection, "redaction_profile"), text(projection, "state")
	if !observability.IsStableToken(profile) {
		return false
	}
	switch state {
	case "raw", "inspected", "transformed":
		return true
	default:
		return false
	}
}

type canonicalProjectedSpan struct {
	family   observability.EventName
	spanName string
	resource *tracepb.ResourceSpans
	span     *tracepb.Span
}

func (wire canonicalTraceWire) otlp() (canonicalProjectedSpan, bool) {
	attributes, ok := object(wire.body, "attributes")
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	attributes, ok = withCanonicalCorrelationAttributes(attributes, wire.correlation)
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	spanKindText := text(wire.body, "kind")
	compatibility := openinference.Project(
		observability.Bucket(wire.bucket), wire.family, spanKindText, attributes,
	)
	switch compatibility.Reason() {
	case openinference.ReasonEligible:
		aliases, available := compatibility.Attributes()
		if !available {
			return canonicalProjectedSpan{}, false
		}
		projected := make(map[string]any, len(attributes)+len(aliases))
		for key, value := range attributes {
			projected[key] = value
		}
		for key, value := range aliases {
			if _, conflict := projected[key]; conflict {
				return canonicalProjectedSpan{}, false
			}
			projected[key] = value
		}
		attributes = projected
	case openinference.ReasonUnsupported:
		// Generic OTLP still carries registered canonical spans that are not
		// members of the optional OpenInference compatibility profile.
	default:
		return canonicalProjectedSpan{}, false
	}
	spanAttributes, ok := canonicalKeyValues(attributes, func(key string) (observability.OTLPValueKind, bool) {
		if isCanonicalCorrelationAttribute(key) {
			return observability.OTLPValueString, true
		}
		if openinference.IsProjectionAttribute(key) {
			return observability.OTLPValueString, true
		}
		return observability.TraceOTLPAttributeKind(wire.family, key)
	})
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	resourceObject, resourceOK := object(wire.body, "resource")
	scopeObject, scopeOK := object(wire.body, "scope")
	statusObject, statusOK := object(wire.body, "status")
	if !resourceOK || !scopeOK || !statusOK {
		return canonicalProjectedSpan{}, false
	}
	resourceAttributes, ok := canonicalResourceKeyValues(wire.family, resourceObject)
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	scopeAttributes, ok := canonicalScopeKeyValues(wire.family, scopeObject)
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	kind, ok := canonicalSpanKind(spanKindText)
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	start, startOK := uint64Value(wire.body["start_time_unix_nano"])
	end, endOK := uint64Value(wire.body["end_time_unix_nano"])
	flags, flagsOK := uint32Value(wire.body["flags"])
	if !startOK || !endOK || start == 0 || end < start || !flagsOK {
		return canonicalProjectedSpan{}, false
	}
	parent := []byte(nil)
	if rawParent, present := wire.body["parent_span_id"]; present {
		parentText, typeOK := rawParent.(string)
		var parentOK bool
		parent, parentOK = exactHex(parentText, 8)
		if !typeOK || !parentOK {
			return canonicalProjectedSpan{}, false
		}
	}
	status, ok := canonicalStatus(statusObject)
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	events, ok := canonicalEvents(wire.family, wire.body["events"])
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	links, ok := canonicalLinks(wire.family, wire.body["links"])
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	droppedAttributes, ok := optionalUint32(wire.body, "dropped_attributes_count")
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	droppedEvents, ok := optionalUint32(wire.body, "dropped_events_count")
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	droppedLinks, ok := optionalUint32(wire.body, "dropped_links_count")
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	resourceDropped, ok := optionalUint32(resourceObject, "dropped_attributes_count")
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	scopeDropped, ok := optionalUint32(scopeObject, "dropped_attributes_count")
	if !ok {
		return canonicalProjectedSpan{}, false
	}
	span := &tracepb.Span{
		TraceId: wire.traceID, SpanId: wire.spanID, ParentSpanId: parent,
		Name: wire.spanName, Kind: kind, StartTimeUnixNano: start, EndTimeUnixNano: end,
		Attributes: spanAttributes, DroppedAttributesCount: droppedAttributes,
		Events: events, DroppedEventsCount: droppedEvents, Links: links,
		DroppedLinksCount: droppedLinks, Status: status, Flags: flags,
	}
	if traceState, present := wire.body["trace_state"]; present {
		state, typeOK := traceState.(string)
		if !typeOK || strings.TrimSpace(state) != state || len(state) > 512 {
			return canonicalProjectedSpan{}, false
		}
		span.TraceState = state
	}
	resource := &tracepb.ResourceSpans{
		Resource:  &resourcepb.Resource{Attributes: resourceAttributes, DroppedAttributesCount: resourceDropped},
		SchemaUrl: text(resourceObject, "schema_url"),
		ScopeSpans: []*tracepb.ScopeSpans{{
			Scope: &commonpb.InstrumentationScope{
				Name: text(scopeObject, "name"), Version: text(scopeObject, "version"),
				Attributes: scopeAttributes, DroppedAttributesCount: scopeDropped,
			},
			SchemaUrl: text(scopeObject, "schema_url"), Spans: []*tracepb.Span{span},
		}},
	}
	if resource.SchemaUrl == "" || resource.ScopeSpans[0].SchemaUrl == "" ||
		resource.ScopeSpans[0].Scope.Name == "" || resource.ScopeSpans[0].Scope.Version == "" {
		return canonicalProjectedSpan{}, false
	}
	return canonicalProjectedSpan{family: wire.family, spanName: wire.spanName, resource: resource, span: span}, true
}

func canonicalResourceKeyValues(family observability.EventName, resource map[string]any) ([]*commonpb.KeyValue, bool) {
	attributes, ok := object(resource, "attributes")
	if !ok || observability.ValidateTelemetryResourceAttributes(attributes) != nil {
		return nil, false
	}
	return canonicalKeyValues(attributes, func(key string) (observability.OTLPValueKind, bool) {
		if kind, registered := observability.TraceOTLPResourceAttributeKind(family, key); registered {
			return kind, true
		}
		// The generated resource extension contract validates custom members
		// before canonical construction; every custom value is a string.
		return observability.OTLPValueString, true
	})
}

func canonicalScopeKeyValues(family observability.EventName, scope map[string]any) ([]*commonpb.KeyValue, bool) {
	attributes, ok := object(scope, "attributes")
	if !ok {
		return nil, false
	}
	return canonicalKeyValues(attributes, func(key string) (observability.OTLPValueKind, bool) {
		return observability.TraceOTLPScopeAttributeKind(family, key)
	})
}

type canonicalKindResolver func(string) (observability.OTLPValueKind, bool)

func canonicalKeyValues(object map[string]any, resolve canonicalKindResolver) ([]*commonpb.KeyValue, bool) {
	keys := make([]string, 0, len(object))
	for key := range object {
		keys = append(keys, key)
	}
	sort.Strings(keys)
	result := make([]*commonpb.KeyValue, 0, len(keys))
	for _, key := range keys {
		kind, ok := resolve(key)
		if !ok {
			return nil, false
		}
		value, ok := canonicalAnyValue(object[key], kind)
		if !ok {
			return nil, false
		}
		result = append(result, &commonpb.KeyValue{Key: key, Value: value})
	}
	return result, true
}

func canonicalAnyValue(value any, kind observability.OTLPValueKind) (*commonpb.AnyValue, bool) {
	switch kind {
	case observability.OTLPValueString:
		text, ok := value.(string)
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: text}}, ok
	case observability.OTLPValueBoolean:
		boolean, ok := value.(bool)
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_BoolValue{BoolValue: boolean}}, ok
	case observability.OTLPValueInt64:
		integer, ok := int64Value(value)
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: integer}}, ok
	case observability.OTLPValueUint32:
		integer, ok := uint32Value(value)
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(integer)}}, ok
	case observability.OTLPValueUint64:
		integer, ok := uint64Value(value)
		if !ok || integer > math.MaxInt64 {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_IntValue{IntValue: int64(integer)}}, true
	case observability.OTLPValueDouble:
		floating, ok := float64Value(value)
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_DoubleValue{DoubleValue: floating}}, ok
	case observability.OTLPValueStringArray:
		items, ok := value.([]any)
		if !ok {
			return nil, false
		}
		values := make([]*commonpb.AnyValue, 0, len(items))
		for _, item := range items {
			converted, valid := canonicalAnyValue(item, observability.OTLPValueString)
			if !valid {
				return nil, false
			}
			values = append(values, converted)
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: values}}}, true
	case observability.OTLPValueStructured:
		return canonicalStructuredAnyValue(value)
	default:
		return nil, false
	}
}

func canonicalStructuredAnyValue(value any) (*commonpb.AnyValue, bool) {
	switch typed := value.(type) {
	case nil:
		// Central redaction deliberately preserves array positions with null
		// placeholders. OTLP AnyValue has no explicit null arm; an empty
		// AnyValue is its lossless positional representation and prevents one
		// removed nested value from dropping the complete trace.
		return &commonpb.AnyValue{}, true
	case string:
		return canonicalAnyValue(typed, observability.OTLPValueString)
	case bool:
		return canonicalAnyValue(typed, observability.OTLPValueBoolean)
	case json.Number:
		if integer, ok := int64Value(typed); ok {
			return canonicalAnyValue(integer, observability.OTLPValueInt64)
		}
		return canonicalAnyValue(typed, observability.OTLPValueDouble)
	case []any:
		values := make([]*commonpb.AnyValue, 0, len(typed))
		for _, item := range typed {
			converted, ok := canonicalStructuredAnyValue(item)
			if !ok {
				return nil, false
			}
			values = append(values, converted)
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_ArrayValue{ArrayValue: &commonpb.ArrayValue{Values: values}}}, true
	case map[string]any:
		values, ok := canonicalKeyValues(typed, func(string) (observability.OTLPValueKind, bool) {
			return observability.OTLPValueStructured, true
		})
		if !ok {
			return nil, false
		}
		return &commonpb.AnyValue{Value: &commonpb.AnyValue_KvlistValue{KvlistValue: &commonpb.KeyValueList{Values: values}}}, true
	default:
		return nil, false
	}
}

func canonicalEvents(family observability.EventName, raw any) ([]*tracepb.Span_Event, bool) {
	if raw == nil {
		return nil, true
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	result := make([]*tracepb.Span_Event, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		name := text(object, "name")
		attributes, attributesOK := objectValue(object["attributes"])
		timestamp, timestampOK := uint64Value(object["time_unix_nano"])
		dropped, droppedOK := optionalUint32(object, "dropped_attributes_count")
		if name == "" || !attributesOK || !timestampOK || timestamp == 0 || !droppedOK {
			return nil, false
		}
		converted, ok := canonicalKeyValues(attributes, func(key string) (observability.OTLPValueKind, bool) {
			return observability.TraceOTLPEventAttributeKind(family, name, key)
		})
		if !ok {
			return nil, false
		}
		result = append(result, &tracepb.Span_Event{
			Name: name, TimeUnixNano: timestamp, Attributes: converted, DroppedAttributesCount: dropped,
		})
	}
	return result, true
}

func canonicalLinks(family observability.EventName, raw any) ([]*tracepb.Span_Link, bool) {
	if raw == nil {
		return nil, true
	}
	items, ok := raw.([]any)
	if !ok {
		return nil, false
	}
	result := make([]*tracepb.Span_Link, 0, len(items))
	for _, item := range items {
		object, ok := item.(map[string]any)
		if !ok {
			return nil, false
		}
		traceID, traceOK := exactHex(text(object, "trace_id"), 16)
		spanID, spanOK := exactHex(text(object, "span_id"), 8)
		attributes, attributesOK := objectValue(object["attributes"])
		dropped, droppedOK := optionalUint32(object, "dropped_attributes_count")
		if !traceOK || !spanOK || !attributesOK || !droppedOK {
			return nil, false
		}
		converted, ok := canonicalKeyValues(attributes, func(key string) (observability.OTLPValueKind, bool) {
			return observability.TraceOTLPLinkAttributeKind(family, key)
		})
		if !ok {
			return nil, false
		}
		link := &tracepb.Span_Link{
			TraceId: traceID, SpanId: spanID, Attributes: converted, DroppedAttributesCount: dropped,
		}
		if state, present := object["trace_state"]; present {
			text, typeOK := state.(string)
			if !typeOK || strings.TrimSpace(text) != text || len(text) > 512 {
				return nil, false
			}
			link.TraceState = text
		}
		if flags, present := object["flags"]; present {
			parsed, valid := uint32Value(flags)
			if !valid {
				return nil, false
			}
			link.Flags = parsed
		}
		result = append(result, link)
	}
	return result, true
}

func canonicalStatus(object map[string]any) (*tracepb.Status, bool) {
	status := &tracepb.Status{}
	switch text(object, "code") {
	case "UNSET":
		status.Code = tracepb.Status_STATUS_CODE_UNSET
	case "OK":
		status.Code = tracepb.Status_STATUS_CODE_OK
	case "ERROR":
		status.Code = tracepb.Status_STATUS_CODE_ERROR
	default:
		return nil, false
	}
	if description, present := object["description"]; present {
		value, ok := description.(string)
		if !ok || status.Code != tracepb.Status_STATUS_CODE_ERROR {
			return nil, false
		}
		status.Message = value
	}
	return status, true
}

func canonicalSpanKind(value string) (tracepb.Span_SpanKind, bool) {
	switch value {
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

func (span canonicalProjectedSpan) canary(destination string) (bool, bool) {
	attributes := keyValuesByName(span.span.Attributes)
	marker, marked := anyBool(attributes["defenseclaw.telemetry.canary"])
	if !marked || !marker {
		return false, !marked
	}
	family, familyOK := anyString(attributes["defenseclaw.span.family"])
	target, targetOK := anyString(attributes["defenseclaw.telemetry.canary.destination"])
	operation, operationOK := anyString(attributes["defenseclaw.telemetry.canary.operation"])
	genAIOperation, genAIOperationOK := anyString(attributes["gen_ai.operation.name"])
	bucket, bucketOK := anyString(attributes["defenseclaw.bucket"])
	outcome, outcomeOK := anyString(attributes["defenseclaw.outcome"])
	expectedBucket, expectedOperation := "", ""
	switch family {
	case observability.TelemetryFamilyAgentInvoke:
		expectedBucket, expectedOperation = string(observability.BucketAgentLifecycle), "invoke_agent"
	case observability.TelemetryFamilyModelChat:
		expectedBucket, expectedOperation = string(observability.BucketModelIO), "chat"
	default:
		return true, false
	}
	valid := familyOK && family == string(span.family) && targetOK && target == destination &&
		operationOK && operation == "runtime-pipeline-test" && genAIOperationOK && genAIOperation == expectedOperation &&
		bucketOK && bucket == expectedBucket && outcomeOK && outcome == string(observability.OutcomeCompleted) &&
		span.span.Status != nil && span.span.Status.Code == tracepb.Status_STATUS_CODE_OK
	return true, valid
}

func completeCanonicalProjectedCanary(spans []canonicalProjectedSpan) bool {
	if len(spans) != 2 {
		return false
	}
	var root, child *canonicalProjectedSpan
	for index := range spans {
		switch spans[index].family {
		case observability.EventName(observability.TelemetryFamilyAgentInvoke):
			root = &spans[index]
		case observability.EventName(observability.TelemetryFamilyModelChat):
			child = &spans[index]
		}
	}
	if root == nil || child == nil || root.spanName != "invoke_agent diagnostic" ||
		child.spanName != "chat gpt-4o-mini" || root.span.Kind != tracepb.Span_SPAN_KIND_INTERNAL ||
		child.span.Kind != tracepb.Span_SPAN_KIND_CLIENT || len(root.span.ParentSpanId) != 0 ||
		!bytes.Equal(child.span.ParentSpanId, root.span.SpanId) || !bytes.Equal(root.span.TraceId, child.span.TraceId) ||
		root.span.Flags&1 == 0 || child.span.Flags&1 == 0 || root.span.TraceState != child.span.TraceState ||
		root.resource.SchemaUrl != child.resource.SchemaUrl || len(root.resource.ScopeSpans) != 1 ||
		len(child.resource.ScopeSpans) != 1 || !proto.Equal(root.resource.Resource, child.resource.Resource) ||
		!proto.Equal(root.resource.ScopeSpans[0].Scope, child.resource.ScopeSpans[0].Scope) ||
		root.resource.ScopeSpans[0].SchemaUrl != child.resource.ScopeSpans[0].SchemaUrl {
		return false
	}
	return true
}

func keyValuesByName(values []*commonpb.KeyValue) map[string]*commonpb.AnyValue {
	result := make(map[string]*commonpb.AnyValue, len(values))
	for _, item := range values {
		if item != nil {
			result[item.Key] = item.Value
		}
	}
	return result
}

func anyString(value *commonpb.AnyValue) (string, bool) {
	if value == nil {
		return "", false
	}
	text, ok := value.Value.(*commonpb.AnyValue_StringValue)
	if !ok {
		return "", false
	}
	return text.StringValue, true
}

func anyBool(value *commonpb.AnyValue) (bool, bool) {
	if value == nil {
		return false, false
	}
	boolean, ok := value.Value.(*commonpb.AnyValue_BoolValue)
	if !ok {
		return false, false
	}
	return boolean.BoolValue, true
}

func object(parent map[string]any, key string) (map[string]any, bool) {
	return objectValue(parent[key])
}

func objectValue(value any) (map[string]any, bool) {
	object, ok := value.(map[string]any)
	return object, ok
}

func text(parent map[string]any, key string) string {
	value, _ := parent[key].(string)
	return value
}

func exactHex(value string, size int) ([]byte, bool) {
	if len(value) != size*2 || strings.ToLower(value) != value {
		return nil, false
	}
	decoded, err := hex.DecodeString(value)
	if err != nil || len(decoded) != size {
		return nil, false
	}
	zero := true
	for _, item := range decoded {
		zero = zero && item == 0
	}
	return decoded, !zero
}

func optionalUint32(parent map[string]any, key string) (uint32, bool) {
	value, present := parent[key]
	if !present {
		return 0, true
	}
	return uint32Value(value)
}

func uint32Value(value any) (uint32, bool) {
	parsed, ok := uint64Value(value)
	return uint32(parsed), ok && parsed <= math.MaxUint32
}

func uint64Value(value any) (uint64, bool) {
	number, ok := value.(json.Number)
	if !ok {
		switch typed := value.(type) {
		case uint64:
			return typed, true
		case uint32:
			return uint64(typed), true
		case int64:
			return uint64(typed), typed >= 0
		case int:
			return uint64(typed), typed >= 0
		default:
			return 0, false
		}
	}
	parsed, _, err := big.ParseFloat(number.String(), 10, 256, big.ToNearestEven)
	if err != nil || parsed.Sign() < 0 {
		return 0, false
	}
	integer, accuracy := parsed.Int(nil)
	if accuracy != big.Exact || integer.Sign() < 0 || integer.BitLen() > 64 {
		return 0, false
	}
	return integer.Uint64(), true
}

func int64Value(value any) (int64, bool) {
	if typed, ok := value.(int64); ok {
		return typed, true
	}
	number, ok := value.(json.Number)
	if !ok {
		return 0, false
	}
	parsed, _, err := big.ParseFloat(number.String(), 10, 256, big.ToNearestEven)
	if err != nil {
		return 0, false
	}
	integer, accuracy := parsed.Int(nil)
	if accuracy != big.Exact || !integer.IsInt64() {
		return 0, false
	}
	return integer.Int64(), true
}

func float64Value(value any) (float64, bool) {
	switch typed := value.(type) {
	case float64:
		return typed, !math.IsNaN(typed) && !math.IsInf(typed, 0)
	case int64:
		return float64(typed), true
	case json.Number:
		parsed, err := strconv.ParseFloat(typed.String(), 64)
		return parsed, err == nil && !math.IsNaN(parsed) && !math.IsInf(parsed, 0)
	default:
		return 0, false
	}
}
