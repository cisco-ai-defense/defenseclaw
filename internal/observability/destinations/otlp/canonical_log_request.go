// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package otlp

import (
	"encoding/base64"
	"encoding/hex"
	"encoding/json"
	"sort"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	collectorlogpb "go.opentelemetry.io/proto/otlp/collector/logs/v1"
	commonpb "go.opentelemetry.io/proto/otlp/common/v1"
	logspb "go.opentelemetry.io/proto/otlp/logs/v1"
	resourcepb "go.opentelemetry.io/proto/otlp/resource/v1"
	"google.golang.org/protobuf/encoding/protojson"
	"google.golang.org/protobuf/proto"
)

// CanonicalLogRequestBuilder is the shared, generation-bound conversion from
// destination-routed and redacted immutable log projections to OTLP. Custom
// transports must use this builder instead of reconstructing canonical records
// or reaching back to producer inputs.
type CanonicalLogRequestBuilder struct {
	destination string
	loggerName  string
	resource    *resourcepb.Resource
	resourceURL string
}

// NewCanonicalLogRequestBuilder validates and snapshots all generation-owned
// resource state. The returned builder retains no caller-owned map or proto.
func NewCanonicalLogRequestBuilder(
	destination string,
	loggerName string,
	snapshot LogResourceSnapshot,
) (*CanonicalLogRequestBuilder, error) {
	if !observability.IsStableToken(destination) || strings.TrimSpace(loggerName) == "" || !utf8.ValidString(loggerName) {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	resource, schemaURL, ok := cloneLogResourceSnapshot(snapshot)
	if !ok {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	return &CanonicalLogRequestBuilder{
		destination: destination, loggerName: loggerName,
		resource: resource, resourceURL: schemaURL,
	}, nil
}

func cloneLogResourceSnapshot(snapshot LogResourceSnapshot) (*resourcepb.Resource, string, bool) {
	if !utf8.ValidString(snapshot.SchemaURL) || strings.TrimSpace(snapshot.SchemaURL) == "" || len(snapshot.Values) == 0 {
		return nil, "", false
	}
	keys := make([]string, 0, len(snapshot.Values))
	for key, value := range snapshot.Values {
		if !utf8.ValidString(key) || !utf8.ValidString(value) || strings.TrimSpace(key) == "" || value == "" {
			return nil, "", false
		}
		keys = append(keys, key)
	}
	sort.Strings(keys)
	attributes := make([]*commonpb.KeyValue, 0, len(keys))
	for _, key := range keys {
		attributes = append(attributes, stringAttribute(key, snapshot.Values[key]))
	}
	return &resourcepb.Resource{
		Attributes: attributes, DroppedAttributesCount: snapshot.DroppedAttributesCount,
	}, snapshot.SchemaURL, true
}

// EncodedSize conservatively accounts for the protobuf OTLP request. Custom
// JSON transports may apply a larger representation-specific bound.
func (*CanonicalLogRequestBuilder) EncodedSize(projectedSizes []int) (int, bool) {
	return canonicalLogEncodedSize(projectedSizes)
}

func canonicalLogEncodedSize(projectedSizes []int) (int, bool) {
	total := logRequestBaseBytes
	for _, size := range projectedSizes {
		if size < 0 || size > maxInt-logRecordWrapperBytes || total > maxInt-size-logRecordWrapperBytes {
			return 0, false
		}
		total += size + logRecordWrapperBytes
	}
	return total, true
}

// Build consumes only immutable delivery payloads. It verifies the exact
// destination, log signal, and canonical JSON shape before constructing OTLP.
func (builder *CanonicalLogRequestBuilder) Build(batch delivery.Batch) (*collectorlogpb.ExportLogsServiceRequest, bool) {
	if builder == nil || batch.Destination() != builder.destination || batch.Len() == 0 {
		return nil, false
	}
	records := make([]*logspb.LogRecord, 0, batch.Len())
	for _, item := range batch.Items() {
		projected := item.Bytes()
		identity := item.Identity()
		if !utf8.Valid(projected) || !json.Valid(projected) ||
			identity.Signal != string(observability.SignalLogs) || identity.RecordID == "" ||
			identity.Bucket == "" || identity.EventName == "" {
			return nil, false
		}
		record := &logspb.LogRecord{
			Body: &commonpb.AnyValue{Value: &commonpb.AnyValue_StringValue{StringValue: string(projected)}},
			Attributes: []*commonpb.KeyValue{
				stringAttribute("defenseclaw.record.id", identity.RecordID),
				stringAttribute("defenseclaw.bucket", identity.Bucket),
				stringAttribute("defenseclaw.signal", identity.Signal),
				stringAttribute("defenseclaw.event.name", identity.EventName),
			},
		}
		if !projectCanonicalLogFields(record, projected) {
			return nil, false
		}
		records = append(records, record)
	}
	resource, ok := proto.Clone(builder.resource).(*resourcepb.Resource)
	if !ok || resource == nil {
		return nil, false
	}
	return &collectorlogpb.ExportLogsServiceRequest{ResourceLogs: []*logspb.ResourceLogs{{
		Resource: resource, SchemaUrl: builder.resourceURL,
		ScopeLogs: []*logspb.ScopeLogs{{
			Scope: &commonpb.InstrumentationScope{Name: builder.loggerName}, LogRecords: records,
		}},
	}}}, true
}

// MarshalCanonicalLogRequestJSON emits OTLP/JSON with the specification's hex
// trace/span identifiers. Protobuf JSON otherwise base64-encodes bytes fields.
func MarshalCanonicalLogRequestJSON(request *collectorlogpb.ExportLogsServiceRequest) ([]byte, error) {
	if request == nil {
		return nil, newError(ErrorInvalidConfig, nil)
	}
	encoded, err := (protojson.MarshalOptions{UseEnumNumbers: true}).Marshal(request)
	if err != nil {
		return nil, newError(ErrorInvalidConfig, err)
	}
	var root any
	if err := json.Unmarshal(encoded, &root); err != nil {
		return nil, newError(ErrorInvalidConfig, err)
	}
	convertCanonicalLogIDs(root)
	encoded, err = json.Marshal(root)
	if err != nil {
		return nil, newError(ErrorInvalidConfig, err)
	}
	return encoded, nil
}

func convertCanonicalLogIDs(node any) {
	switch value := node.(type) {
	case map[string]any:
		for key, child := range value {
			if key == "traceId" || key == "spanId" {
				if text, ok := child.(string); ok {
					if decoded, err := base64.StdEncoding.DecodeString(text); err == nil {
						value[key] = hex.EncodeToString(decoded)
					}
				}
				continue
			}
			convertCanonicalLogIDs(child)
		}
	case []any:
		for _, child := range value {
			convertCanonicalLogIDs(child)
		}
	}
}
