// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"bytes"
	"encoding/json"
	"errors"
	"io"
	"strconv"
	"time"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	metricspb "go.opentelemetry.io/proto/otlp/metrics/v1"
)

var errOTLPInboundClassifierV8 = errors.New("OTLP v8 inbound classifier rejected its input")

type otlpInboundIdentityState uint8

const (
	otlpInboundIdentityInvalid otlpInboundIdentityState = iota
	otlpInboundIdentityUnsupported
	otlpInboundIdentityMatched
	otlpInboundIdentityAmbiguous
	otlpInboundIdentityNativeMalformed
)

// otlpInboundLeafClassification is an I02-only result. The opaque generated
// handles may be consumed by later phases, but this type has no construction,
// collection, floor, persistence, or routing capability.
type otlpInboundLeafClassification struct {
	shape             observability.InboundShape
	identityState     otlpInboundIdentityState
	match             observability.InboundMatch
	matchCount        int
	echoRecognizer    observability.InboundEchoRecognizer
	echoRecognized    bool
	selfEchoCandidate bool
}

type otlpInboundClassifierV8 struct {
	catalog         observability.InboundCatalog
	localInstanceID string
}

func newOTLPInboundClassifierV8(localInstanceID string) (otlpInboundClassifierV8, error) {
	catalog, err := observability.LoadInboundCatalog()
	if err != nil {
		return otlpInboundClassifierV8{}, errOTLPInboundClassifierV8
	}
	return newOTLPInboundClassifierV8WithCatalog(catalog, localInstanceID)
}

func newOTLPInboundClassifierV8WithCatalog(
	catalog observability.InboundCatalog,
	localInstanceID string,
) (otlpInboundClassifierV8, error) {
	if localInstanceID == "" || !utf8.ValidString(localInstanceID) ||
		len(localInstanceID) > observability.MaxImportIdentifierBytes ||
		catalog.Policies().NativeMalformedExternalFallback != "forbidden" {
		return otlpInboundClassifierV8{}, errOTLPInboundClassifierV8
	}
	return otlpInboundClassifierV8{catalog: catalog, localInstanceID: localInstanceID}, nil
}

func (classifier otlpInboundClassifierV8) classify(
	leaf otlpDecodedLeaf,
	authenticatedSource string,
) (otlpInboundLeafClassification, error) {
	signal, ok := canonicalInboundLeafSignal(leaf)
	if !ok || !observability.IsStableToken(authenticatedSource) || authenticatedSource == "any_authenticated" ||
		classifier.localInstanceID == "" {
		return otlpInboundLeafClassification{}, errOTLPInboundClassifierV8
	}

	nativeCandidate := classifier.hasNativeMarker(leaf, signal)
	echo, echoRecognized := classifier.echoRecognizer(leaf, signal)
	nativeEchoShape := nativeCandidate && echoRecognized && classifier.validNativeEchoShape(leaf, signal)
	selfEchoCandidate := nativeEchoShape && classifier.forwardInstanceID(leaf, signal) == classifier.localInstanceID

	candidates := classifier.catalog.Matches(signal, authenticatedSource)
	matches := make([]observability.InboundMatch, 0, 1)
	for _, candidate := range candidates {
		if nativeCandidate != (candidate.Shape() == observability.InboundShapeNativeExact) {
			continue
		}
		if inboundMatchPredicates(candidate, leaf) {
			matches = append(matches, candidate)
		}
	}

	result := selectInboundIdentity(matches)
	result.echoRecognizer = echo
	result.echoRecognized = nativeEchoShape
	result.selfEchoCandidate = selfEchoCandidate
	if nativeCandidate {
		switch result.identityState {
		case otlpInboundIdentityMatched, otlpInboundIdentityAmbiguous:
			result.shape = observability.InboundShapeNativeExact
		case otlpInboundIdentityUnsupported:
			if nativeEchoShape {
				result.shape = observability.InboundShapeNativeExact
			} else {
				result.shape = observability.InboundShapeNativeMalformed
				result.identityState = otlpInboundIdentityNativeMalformed
			}
		}
	} else {
		result.shape = observability.InboundShapeExternal
	}
	return result, nil
}

func selectInboundIdentity(matches []observability.InboundMatch) otlpInboundLeafClassification {
	result := otlpInboundLeafClassification{matchCount: len(matches)}
	switch len(matches) {
	case 0:
		result.identityState = otlpInboundIdentityUnsupported
	case 1:
		result.identityState = otlpInboundIdentityMatched
		result.match = matches[0]
	default:
		result.identityState = otlpInboundIdentityAmbiguous
	}
	return result
}

func canonicalInboundLeafSignal(leaf otlpDecodedLeaf) (observability.Signal, bool) {
	switch leaf.signal {
	case otelSignalLogs:
		return observability.SignalLogs, leaf.logRecord != nil && leaf.span == nil && leaf.metric == nil &&
			leaf.numberPoint == nil && leaf.histogramPoint == nil && leaf.exponentialHistogram == nil && leaf.summaryPoint == nil
	case otelSignalTraces:
		return observability.SignalTraces, leaf.span != nil && leaf.logRecord == nil && leaf.metric == nil &&
			leaf.numberPoint == nil && leaf.histogramPoint == nil && leaf.exponentialHistogram == nil && leaf.summaryPoint == nil
	case otelSignalMetrics:
		if leaf.metric == nil || leaf.logRecord != nil || leaf.span != nil {
			return "", false
		}
		arms := 0
		for _, present := range []bool{
			leaf.numberPoint != nil,
			leaf.histogramPoint != nil,
			leaf.exponentialHistogram != nil,
			leaf.summaryPoint != nil,
		} {
			if present {
				arms++
			}
		}
		return observability.SignalMetrics, arms == 1 && validMetricLeafArm(leaf)
	default:
		return "", false
	}
}

func validMetricLeafArm(leaf otlpDecodedLeaf) bool {
	switch leaf.metricShape {
	case otlpTypedMetricGauge, otlpTypedMetricSum:
		return leaf.numberPoint != nil && (leaf.metricShape != otlpTypedMetricGauge || leaf.metric.GetGauge() != nil) &&
			(leaf.metricShape != otlpTypedMetricSum || leaf.metric.GetSum() != nil)
	case otlpTypedMetricHistogram:
		return leaf.histogramPoint != nil && leaf.metric.GetHistogram() != nil
	case otlpTypedMetricExponentialHistogram:
		return leaf.exponentialHistogram != nil && leaf.metric.GetExponentialHistogram() != nil
	case otlpTypedMetricSummary:
		return leaf.summaryPoint != nil && leaf.metric.GetSummary() != nil
	default:
		return false
	}
}

func (classifier otlpInboundClassifierV8) hasNativeMarker(
	leaf otlpDecodedLeaf,
	signal observability.Signal,
) bool {
	for _, marker := range classifier.catalog.NativeMarkers(signal) {
		switch marker.MarkerKind() {
		case observability.InboundMarkerReservedKeyPresence:
			if inboundAttributeState(leaf, marker.Location(), marker.Key()) != otlpTypedAttributeAbsent {
				return true
			}
		case observability.InboundMarkerExactStructuralValue:
			value, present := inboundStructuralString(leaf, marker.Location(), marker.Key())
			if present && inboundStringValueMatches(marker.Values(), value) {
				return true
			}
		case observability.InboundMarkerProjectedStructure:
			if projectedLogRecordStructure(leaf.logRecord.GetBody()) {
				return true
			}
		}
	}
	return false
}

func inboundMatchPredicates(match observability.InboundMatch, leaf otlpDecodedLeaf) bool {
	for _, predicate := range match.Predicates() {
		if !inboundPredicateMatches(leaf, predicate) {
			return false
		}
	}
	return true
}

func inboundPredicateMatches(leaf otlpDecodedLeaf, predicate observability.InboundPredicate) bool {
	switch predicate.Operator() {
	case observability.InboundPredicateProjectedRecordJSON:
		return validProjectedLogRecord(leaf)
	case observability.InboundPredicateValidEndedSpan:
		return validInboundEndedSpan(leaf)
	}

	if index, ok := inboundAttributeIndex(leaf, predicate.Location()); ok {
		value, state := index.lookup(predicate.Key())
		switch predicate.Operator() {
		case observability.InboundPredicateAbsent:
			return state == otlpTypedAttributeAbsent
		case observability.InboundPredicatePresent:
			return state == otlpTypedAttributeUnique && inboundAnyValueHasType(value, predicate.ValueType())
		case observability.InboundPredicateEquals, observability.InboundPredicateOneOf:
			return state == otlpTypedAttributeUnique && inboundAnyValueMatches(value, predicate.ValueType(), predicate.Values())
		case observability.InboundPredicateUint32Max:
			if state != otlpTypedAttributeUnique || predicate.ValueType() != observability.InboundValueInt64 {
				return false
			}
			typed, ok := value.GetValue().(*commonpb.AnyValue_IntValue)
			maximum, maximumOK := firstInboundInt64(predicate.Values())
			return ok && maximumOK && typed.IntValue >= 0 && typed.IntValue <= maximum
		default:
			return false
		}
	}

	value, present := inboundStructuralString(leaf, predicate.Location(), predicate.Key())
	switch predicate.Operator() {
	case observability.InboundPredicateAbsent:
		return !present
	case observability.InboundPredicatePresent:
		return present && predicate.ValueType() == observability.InboundValueString
	case observability.InboundPredicateEquals, observability.InboundPredicateOneOf:
		if !present || predicate.ValueType() != observability.InboundValueString {
			return false
		}
		if predicate.Location() == observability.InboundLocationMetricPoint && predicate.Key() == "$point_shape" {
			return inboundMetricShapeMatches(leaf, predicate.Values())
		}
		return inboundStringValueMatches(predicate.Values(), value)
	default:
		return false
	}
}

func inboundAttributeIndex(
	leaf otlpDecodedLeaf,
	location observability.InboundLocation,
) (otlpTypedAttributeIndex, bool) {
	switch location {
	case observability.InboundLocationResourceAttribute:
		return leaf.resource.attributes, true
	case observability.InboundLocationLeafAttribute:
		if leaf.signal == otelSignalLogs || leaf.signal == otelSignalTraces {
			return leaf.leafAttributes, true
		}
	case observability.InboundLocationMetricPointAttribute:
		if leaf.signal == otelSignalMetrics {
			return leaf.metricPointAttributes, true
		}
	}
	return otlpTypedAttributeIndex{}, false
}

func inboundAttributeState(
	leaf otlpDecodedLeaf,
	location observability.InboundLocation,
	key string,
) otlpTypedAttributeState {
	index, ok := inboundAttributeIndex(leaf, location)
	if !ok {
		return otlpTypedAttributeAbsent
	}
	_, state := index.lookup(key)
	return state
}

func inboundStructuralString(
	leaf otlpDecodedLeaf,
	location observability.InboundLocation,
	key string,
) (string, bool) {
	switch location {
	case observability.InboundLocationInstrumentName:
		if key == "$instrument_name" && leaf.metric != nil && leaf.metric.GetName() != "" {
			return leaf.metric.GetName(), true
		}
	case observability.InboundLocationMetricPoint:
		if key == "$point_shape" && leaf.metric != nil {
			if shape := primaryInboundMetricShape(leaf); shape != "" {
				return shape, true
			}
		}
	case observability.InboundLocationResourceSchemaURL:
		if key == "$resource_schema_url" && leaf.resource.schemaURL != "" {
			return leaf.resource.schemaURL, true
		}
	case observability.InboundLocationScopeName:
		if key == "$scope_name" && leaf.scope.name != "" {
			return leaf.scope.name, true
		}
	case observability.InboundLocationScopeSchemaURL:
		if key == "$scope_schema_url" && leaf.scope.schemaURL != "" {
			return leaf.scope.schemaURL, true
		}
	case observability.InboundLocationSpan:
		if key == "$span_name" && leaf.span != nil && leaf.span.GetName() != "" {
			return leaf.span.GetName(), true
		}
	}
	return "", false
}

func primaryInboundMetricShape(leaf otlpDecodedLeaf) string {
	switch leaf.metricShape {
	case otlpTypedMetricGauge:
		return "gauge"
	case otlpTypedMetricSum:
		return "sum"
	case otlpTypedMetricHistogram:
		return "histogram"
	case otlpTypedMetricExponentialHistogram:
		return "exponential_histogram"
	case otlpTypedMetricSummary:
		return "summary"
	default:
		return ""
	}
}

func inboundMetricShapeMatches(leaf otlpDecodedLeaf, expected []observability.InboundPredicateValue) bool {
	actual := []string{primaryInboundMetricShape(leaf)}
	if leaf.metricShape == otlpTypedMetricSum && leaf.metric != nil && leaf.metric.GetSum() != nil &&
		leaf.metric.GetSum().GetAggregationTemporality() == metricspb.AggregationTemporality_AGGREGATION_TEMPORALITY_DELTA {
		actual = append(actual, "sum_delta")
		if leaf.metric.GetSum().GetIsMonotonic() {
			actual = append(actual, "sum_delta_monotonic")
		}
	}
	for _, candidate := range actual {
		if candidate != "" && inboundStringValueMatches(expected, candidate) {
			return true
		}
	}
	return false
}

func inboundAnyValueHasType(value *commonpb.AnyValue, expected observability.InboundValueType) bool {
	if value == nil {
		return false
	}
	switch expected {
	case observability.InboundValueString:
		_, ok := value.Value.(*commonpb.AnyValue_StringValue)
		return ok
	case observability.InboundValueInt64:
		_, ok := value.Value.(*commonpb.AnyValue_IntValue)
		return ok
	default:
		return false
	}
}

func inboundAnyValueMatches(
	value *commonpb.AnyValue,
	expectedType observability.InboundValueType,
	expected []observability.InboundPredicateValue,
) bool {
	if value == nil {
		return false
	}
	switch expectedType {
	case observability.InboundValueString:
		typed, ok := value.Value.(*commonpb.AnyValue_StringValue)
		return ok && inboundStringValueMatches(expected, typed.StringValue)
	case observability.InboundValueInt64:
		typed, ok := value.Value.(*commonpb.AnyValue_IntValue)
		return ok && inboundInt64ValueMatches(expected, typed.IntValue)
	default:
		return false
	}
}

func inboundStringValueMatches(expected []observability.InboundPredicateValue, actual string) bool {
	for _, value := range expected {
		candidate, ok := value.StringValue()
		if ok && candidate == actual {
			return true
		}
	}
	return false
}

func inboundInt64ValueMatches(expected []observability.InboundPredicateValue, actual int64) bool {
	for _, value := range expected {
		candidate, ok := value.Int64Value()
		if ok && candidate == actual {
			return true
		}
	}
	return false
}

func firstInboundInt64(values []observability.InboundPredicateValue) (int64, bool) {
	if len(values) != 1 {
		return 0, false
	}
	return values[0].Int64Value()
}

func validInboundEndedSpan(leaf otlpDecodedLeaf) bool {
	span := leaf.span
	if span == nil || span.GetStartTimeUnixNano() == 0 || span.GetEndTimeUnixNano() == 0 ||
		span.GetEndTimeUnixNano() < span.GetStartTimeUnixNano() ||
		!validInboundOTelID(span.GetTraceId(), 16) || !validInboundOTelID(span.GetSpanId(), 8) {
		return false
	}
	parent := span.GetParentSpanId()
	return len(parent) == 0 || validInboundOTelID(parent, 8) && !bytes.Equal(parent, span.GetSpanId())
}

func validInboundOTelID(value []byte, size int) bool {
	if len(value) != size {
		return false
	}
	for _, item := range value {
		if item != 0 {
			return true
		}
	}
	return false
}

func (classifier otlpInboundClassifierV8) echoRecognizer(
	leaf otlpDecodedLeaf,
	signal observability.Signal,
) (observability.InboundEchoRecognizer, bool) {
	switch signal {
	case observability.SignalLogs:
		bucket, bucketState := leaf.leafAttributes.stringValue("defenseclaw.bucket")
		eventName, eventState := leaf.leafAttributes.stringValue("defenseclaw.event.name")
		if bucketState != otlpTypedAttributeUnique || eventState != otlpTypedAttributeUnique {
			return observability.InboundEchoRecognizer{}, false
		}
		return classifier.catalog.EchoRecognizerForWireIdentity(signal, observability.Bucket(bucket), observability.EventName(eventName), "")
	case observability.SignalTraces:
		bucket, bucketState := leaf.leafAttributes.stringValue("defenseclaw.bucket")
		family, familyState := leaf.leafAttributes.stringValue("defenseclaw.span.family")
		if bucketState != otlpTypedAttributeUnique || familyState != otlpTypedAttributeUnique {
			return observability.InboundEchoRecognizer{}, false
		}
		return classifier.catalog.EchoRecognizerForWireIdentity(signal, observability.Bucket(bucket), observability.EventName(family), "")
	case observability.SignalMetrics:
		if leaf.metric == nil {
			return observability.InboundEchoRecognizer{}, false
		}
		return classifier.catalog.EchoRecognizerForWireIdentity(signal, "", "", leaf.metric.GetName())
	default:
		return observability.InboundEchoRecognizer{}, false
	}
}

func (classifier otlpInboundClassifierV8) forwardInstanceID(
	leaf otlpDecodedLeaf,
	signal observability.Signal,
) string {
	key := classifier.catalog.WireContract().ForwardInstanceKey
	if signal == observability.SignalMetrics {
		value, state := leaf.resource.attributes.stringValue(key)
		if state == otlpTypedAttributeUnique {
			return value
		}
		return ""
	}
	value, state := leaf.leafAttributes.stringValue(key)
	if state == otlpTypedAttributeUnique {
		return value
	}
	return ""
}

func (classifier otlpInboundClassifierV8) validNativeEchoShape(
	leaf otlpDecodedLeaf,
	signal observability.Signal,
) bool {
	wire := classifier.catalog.WireContract()
	semanticInstance, semanticState := leaf.resource.attributes.stringValue(wire.SemanticInstanceKey)
	if semanticState != otlpTypedAttributeUnique || semanticInstance == "" {
		return false
	}
	transport := leaf.leafAttributes
	if signal == observability.SignalMetrics {
		transport = leaf.resource.attributes
	}
	forwardInstance, forwardState := transport.stringValue(wire.ForwardInstanceKey)
	destination, destinationState := transport.stringValue(wire.ForwardDestinationKey)
	hops, hopState := transport.int64Value(wire.ForwardHopCountKey)
	if forwardState != otlpTypedAttributeUnique || forwardInstance == "" ||
		destinationState != otlpTypedAttributeUnique || destination == "" ||
		hopState != otlpTypedAttributeUnique || hops < 0 || hops > int64(wire.MaxForwardHops) {
		return false
	}
	switch signal {
	case observability.SignalLogs:
		signalName, signalState := leaf.leafAttributes.stringValue("defenseclaw.signal")
		recordID, recordState := leaf.leafAttributes.stringValue(wire.RecordIDKey)
		return signalState == otlpTypedAttributeUnique && signalName == string(observability.SignalLogs) &&
			recordState == otlpTypedAttributeUnique && recordID != "" && validProjectedLogRecord(leaf)
	case observability.SignalTraces:
		version, versionState := leaf.leafAttributes.int64Value("defenseclaw.span.family_schema_version")
		return leaf.resource.schemaURL == wire.ResourceSchemaURL && leaf.scope.name == wire.ScopeName &&
			leaf.scope.schemaURL == wire.ScopeSchemaURL && versionState == otlpTypedAttributeUnique && version > 0 &&
			validInboundEndedSpan(leaf)
	case observability.SignalMetrics:
		return leaf.resource.schemaURL == wire.ResourceSchemaURL && leaf.scope.name == wire.ScopeName &&
			leaf.scope.schemaURL == wire.ScopeSchemaURL &&
			(leaf.metricShape == otlpTypedMetricGauge || leaf.metricShape == otlpTypedMetricSum ||
				leaf.metricShape == otlpTypedMetricHistogram)
	default:
		return false
	}
}

type projectedLogRecordV8 struct {
	SchemaVersion        json.Number     `json:"schema_version"`
	BucketCatalogVersion json.Number     `json:"bucket_catalog_version"`
	Timestamp            json.RawMessage `json:"timestamp"`
	ObservedAt           json.RawMessage `json:"observed_at,omitempty"`
	RecordID             string          `json:"record_id"`
	Bucket               string          `json:"bucket"`
	Signal               string          `json:"signal"`
	EventName            string          `json:"event_name"`
	SpanName             json.RawMessage `json:"span_name,omitempty"`
	Severity             json.RawMessage `json:"severity,omitempty"`
	LogLevel             json.RawMessage `json:"log_level,omitempty"`
	Source               string          `json:"source"`
	Connector            json.RawMessage `json:"connector,omitempty"`
	Action               json.RawMessage `json:"action,omitempty"`
	Phase                json.RawMessage `json:"phase,omitempty"`
	Outcome              json.RawMessage `json:"outcome,omitempty"`
	Mandatory            *bool           `json:"mandatory"`
	Correlation          json.RawMessage `json:"correlation"`
	Provenance           json.RawMessage `json:"provenance"`
	Body                 json.RawMessage `json:"body"`
	FieldClasses         json.RawMessage `json:"field_classes"`
	Projection           json.RawMessage `json:"projection"`
}

type projectedLogMetadataV8 struct {
	RedactionProfile       string `json:"redaction_profile"`
	DetectorCatalogVersion *int   `json:"detector_catalog_version"`
	State                  string `json:"state"`
	TransformedFields      *int   `json:"transformed_fields"`
	RemovedFields          *int   `json:"removed_fields"`
	OversizeFields         *int   `json:"oversize_fields"`
	FailureCount           *int   `json:"failure_count"`
	FailuresTruncated      *bool  `json:"failures_truncated"`
}

func projectedLogRecordStructure(body *commonpb.AnyValue) bool {
	text, ok := inboundLogBodyString(body)
	if !ok || len(text) > observability.MaxCanonicalRecordBytes+4096 {
		return false
	}
	var marker struct {
		SchemaVersion json.RawMessage `json:"schema_version"`
		Projection    json.RawMessage `json:"projection"`
	}
	if err := json.Unmarshal([]byte(text), &marker); err != nil {
		return false
	}
	return len(marker.SchemaVersion) != 0 && len(marker.Projection) != 0
}

func validProjectedLogRecord(leaf otlpDecodedLeaf) bool {
	if leaf.logRecord == nil {
		return false
	}
	text, ok := inboundLogBodyString(leaf.logRecord.GetBody())
	if !ok || len(text) > observability.MaxCanonicalRecordBytes+4096 ||
		validateUniqueOTLPJSONMembers([]byte(text)) != nil {
		return false
	}
	decoder := json.NewDecoder(bytes.NewReader([]byte(text)))
	decoder.UseNumber()
	decoder.DisallowUnknownFields()
	var wire projectedLogRecordV8
	if err := decoder.Decode(&wire); err != nil {
		return false
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); !errors.Is(err, io.EOF) {
		return false
	}
	schemaVersion, schemaErr := strconv.ParseUint(wire.SchemaVersion.String(), 10, 32)
	bucketVersion, bucketErr := strconv.ParseUint(wire.BucketCatalogVersion.String(), 10, 32)
	if schemaErr != nil || bucketErr != nil || schemaVersion != observability.CurrentRecordSchemaVersion ||
		bucketVersion != observability.CurrentBucketCatalogVersion || len(wire.Timestamp) == 0 ||
		wire.RecordID == "" || !observability.IsBucket(observability.Bucket(wire.Bucket)) ||
		wire.Signal != string(observability.SignalLogs) || observability.EventName(wire.EventName).Validate() != nil ||
		len(wire.SpanName) != 0 || !validProjectedLogEnvelopeScalars(wire) || wire.Mandatory == nil ||
		!inboundJSONObject(wire.Correlation) ||
		!inboundJSONObject(wire.Provenance) || !inboundJSONObject(wire.Body) ||
		!inboundJSONObject(wire.FieldClasses) || !inboundJSONObject(wire.Projection) {
		return false
	}
	var metadata projectedLogMetadataV8
	metadataDecoder := json.NewDecoder(bytes.NewReader(wire.Projection))
	metadataDecoder.DisallowUnknownFields()
	if err := metadataDecoder.Decode(&metadata); err != nil ||
		!observability.IsStableToken(metadata.RedactionProfile) ||
		(metadata.State != "raw" && metadata.State != "inspected" && metadata.State != "transformed") ||
		!validProjectedLogMetadataCounts(metadata) {
		return false
	}
	recordID, recordState := leaf.leafAttributes.stringValue("defenseclaw.record.id")
	bucket, bucketState := leaf.leafAttributes.stringValue("defenseclaw.bucket")
	signal, signalState := leaf.leafAttributes.stringValue("defenseclaw.signal")
	eventName, eventState := leaf.leafAttributes.stringValue("defenseclaw.event.name")
	return recordState == otlpTypedAttributeUnique && recordID == wire.RecordID &&
		bucketState == otlpTypedAttributeUnique && bucket == wire.Bucket &&
		signalState == otlpTypedAttributeUnique && signal == wire.Signal &&
		eventState == otlpTypedAttributeUnique && eventName == wire.EventName
}

func validProjectedLogEnvelopeScalars(wire projectedLogRecordV8) bool {
	if !validProjectedTimestamp(wire.Timestamp) ||
		(len(wire.ObservedAt) != 0 && !validProjectedTimestamp(wire.ObservedAt)) ||
		!observability.IsStableToken(wire.Source) {
		return false
	}
	if severity, present, valid := projectedOptionalString(wire.Severity); present {
		if !valid {
			return false
		}
		if _, ok := observability.SeverityRank(observability.Severity(severity)); !ok {
			return false
		}
	}
	if logLevel, present, valid := projectedOptionalString(wire.LogLevel); present {
		if !valid {
			return false
		}
		switch observability.LogLevel(logLevel) {
		case observability.LogLevelTrace, observability.LogLevelDebug, observability.LogLevelInfo,
			observability.LogLevelWarn, observability.LogLevelError, observability.LogLevelFatal:
		default:
			return false
		}
	}
	for _, raw := range []json.RawMessage{wire.Connector, wire.Action, wire.Phase} {
		value, present, valid := projectedOptionalString(raw)
		if present && (!valid || !observability.IsStableToken(value)) {
			return false
		}
	}
	outcome, present, valid := projectedOptionalString(wire.Outcome)
	return !present || valid && observability.IsOutcome(observability.Outcome(outcome))
}

func projectedOptionalString(raw json.RawMessage) (string, bool, bool) {
	if len(raw) == 0 {
		return "", false, true
	}
	var value string
	if json.Unmarshal(raw, &value) != nil || value == "" {
		return "", true, false
	}
	return value, true, true
}

func validProjectedTimestamp(raw json.RawMessage) bool {
	var text string
	if len(raw) == 0 || json.Unmarshal(raw, &text) != nil || text == "" {
		return false
	}
	_, err := time.Parse(time.RFC3339Nano, text)
	return err == nil
}

func validProjectedLogMetadataCounts(metadata projectedLogMetadataV8) bool {
	if metadata.DetectorCatalogVersion == nil || *metadata.DetectorCatalogVersion <= 0 {
		return false
	}
	for _, value := range []*int{
		metadata.TransformedFields,
		metadata.RemovedFields,
		metadata.OversizeFields,
		metadata.FailureCount,
	} {
		if value == nil || *value < 0 {
			return false
		}
	}
	if metadata.FailuresTruncated == nil ||
		*metadata.OversizeFields > *metadata.TransformedFields ||
		(metadata.State == "raw") != (metadata.RedactionProfile == "none") {
		return false
	}
	switch metadata.State {
	case "raw", "inspected":
		return *metadata.TransformedFields == 0 && *metadata.RemovedFields == 0 &&
			*metadata.FailureCount == 0 && !*metadata.FailuresTruncated
	case "transformed":
		return (*metadata.TransformedFields > 0 || *metadata.RemovedFields > 0) &&
			*metadata.FailureCount == 0 && !*metadata.FailuresTruncated
	default:
		return false
	}
}

func inboundLogBodyString(body *commonpb.AnyValue) (string, bool) {
	if body == nil {
		return "", false
	}
	value, ok := body.Value.(*commonpb.AnyValue_StringValue)
	if !ok || value == nil {
		return "", false
	}
	return value.StringValue, true
}

func inboundJSONObject(value json.RawMessage) bool {
	trimmed := bytes.TrimSpace(value)
	return len(trimmed) >= 2 && trimmed[0] == '{' && trimmed[len(trimmed)-1] == '}'
}
