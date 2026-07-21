// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package localobservability owns the generated local-observability-v1 trace
// compatibility view consumed by the bundled Collector, Tempo, and Agent360
// spanmetrics pipeline. It accepts only an already route-redacted projection;
// raw canonical records and SDK spans are deliberately not projection inputs.
package localobservability

import (
	"bytes"
	"encoding/json"
	"io"
	"strings"
	"unicode/utf8"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/compatibility/profilemanifest"
	"github.com/defenseclaw/defenseclaw/internal/observability/delivery"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

const (
	DestinationName = observability.RuntimeLocalObservabilityDestination
	ProfileID       = observability.RuntimeLocalObservabilityProfile
)

type ProjectionReason string

const (
	ProjectionEligible       ProjectionReason = "eligible"
	ProjectionInvalidInput   ProjectionReason = "invalid_projection"
	ProjectionUnsupported    ProjectionReason = "unsupported_family"
	ProjectionAliasConflict  ProjectionReason = "alias_conflict"
	ProjectionOutputTooLarge ProjectionReason = "output_too_large"
)

// Result is an immutable compatibility projection. Bytes always returns a
// copy, and an ineligible result never retains source or projected content.
type Result struct {
	reason  ProjectionReason
	encoded []byte
}

func (result Result) Eligible() bool {
	return result.reason == ProjectionEligible && len(result.encoded) > 0
}
func (result Result) Reason() ProjectionReason {
	if result.reason == "" {
		return ProjectionInvalidInput
	}
	return result.reason
}
func (result Result) Bytes() ([]byte, bool) {
	if !result.Eligible() {
		return nil, false
	}
	return append([]byte(nil), result.encoded...), true
}

type projectedWire struct {
	Profile              string            `json:"compatibility_profile,omitempty"`
	SchemaVersion        int               `json:"schema_version"`
	BucketCatalogVersion int               `json:"bucket_catalog_version"`
	Timestamp            any               `json:"timestamp"`
	ObservedAt           any               `json:"observed_at,omitempty"`
	RecordID             string            `json:"record_id"`
	Bucket               string            `json:"bucket"`
	Signal               string            `json:"signal"`
	Family               string            `json:"event_name"`
	SpanName             string            `json:"span_name"`
	Source               string            `json:"source"`
	Connector            string            `json:"connector,omitempty"`
	Action               string            `json:"action,omitempty"`
	Phase                string            `json:"phase,omitempty"`
	Outcome              string            `json:"outcome,omitempty"`
	Correlation          map[string]any    `json:"correlation"`
	Provenance           map[string]any    `json:"provenance"`
	FieldClasses         map[string]string `json:"field_classes,omitempty"`
	Projection           projectedMetadata `json:"projection"`
	Body                 projectedBody     `json:"body"`
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
	DroppedAttributesCount json.Number    `json:"dropped_attributes_count,omitempty"`
	Attributes             map[string]any `json:"attributes,omitempty"`
}

type projectedEvent struct {
	Name                   string         `json:"name"`
	TimeUnixNano           json.Number    `json:"time_unix_nano"`
	DroppedAttributesCount json.Number    `json:"dropped_attributes_count,omitempty"`
	Attributes             map[string]any `json:"attributes,omitempty"`
}

type projectedLink struct {
	TraceID                string         `json:"trace_id"`
	SpanID                 string         `json:"span_id"`
	TraceState             string         `json:"trace_state,omitempty"`
	DroppedAttributesCount json.Number    `json:"dropped_attributes_count,omitempty"`
	Attributes             map[string]any `json:"attributes,omitempty"`
}

type projectedStatus struct {
	Code        any    `json:"code"`
	Message     string `json:"message,omitempty"`
	Description string `json:"description,omitempty"`
}

// Project creates the local compatibility view only after the central route
// projection. Aliases always copy the already-redacted canonical value and are
// omitted when the canonical source is missing.
func Project(input redaction.Projection) Result {
	encoded, err := input.Bytes()
	if err != nil {
		return rejected(ProjectionInvalidInput)
	}
	wire, ok := decodeWire(encoded, false)
	if !ok || wire.Profile != "" {
		return rejected(ProjectionInvalidInput)
	}
	if !profilemanifest.Eligible(
		ProfileID,
		observability.SignalTraces,
		observability.EventName(wire.Family),
	) {
		return rejected(ProjectionUnsupported)
	}
	profile, ok := profilemanifest.Runtime(ProfileID)
	if !ok || profile.Status != "available" {
		return rejected(ProjectionUnsupported)
	}
	attributes := sanitizeObject(wire.Body.Attributes)
	for index := range wire.Body.Events {
		wire.Body.Events[index].Attributes = sanitizeObject(wire.Body.Events[index].Attributes)
	}
	for index := range wire.Body.Links {
		wire.Body.Links[index].Attributes = sanitizeObject(wire.Body.Links[index].Attributes)
	}
	for _, alias := range profile.AttributeAliases {
		if !copyAlias(attributes, alias.Source, alias.Target) {
			return rejected(ProjectionAliasConflict)
		}
	}
	// Agent/model/tool spans may carry the final decision only as a registered
	// event. Preserve the two historical Agent360 TraceQL span attributes when
	// every observed event value agrees; ambiguity is represented by omission,
	// never by selecting or inventing a value.
	for _, alias := range profile.AttributeAliases {
		if !alias.EventDerived {
			continue
		}
		if _, present := attributes[alias.Target]; present {
			continue
		}
		if value, present := unambiguousEventValue(
			wire.Body.Events,
			alias.Source,
			profile.EventAliasSources,
		); present {
			attributes[alias.Target] = value
		}
	}
	wire.Profile = ProfileID
	wire.FieldClasses = nil
	wire.Body.Attributes = attributes
	output, err := json.Marshal(wire)
	if err != nil || !utf8.Valid(output) {
		return rejected(ProjectionInvalidInput)
	}
	if len(output) > delivery.MaxPayloadBytes {
		return rejected(ProjectionOutputTooLarge)
	}
	if _, ok := decodeWire(output, true); !ok {
		return rejected(ProjectionInvalidInput)
	}
	return Result{reason: ProjectionEligible, encoded: output}
}

func copyAlias(attributes map[string]any, canonical, alias string) bool {
	value, present := attributes[canonical]
	if !present {
		return true
	}
	if existing, exists := attributes[alias]; exists {
		return jsonScalarEqual(existing, value)
	}
	attributes[alias] = cloneJSON(value)
	return true
}

func unambiguousEventValue(events []projectedEvent, key string, allowedSources []string) (any, bool) {
	var selected any
	found := false
	for _, event := range events {
		allowed := false
		for _, source := range allowedSources {
			if event.Name == source {
				allowed = true
				break
			}
		}
		if !allowed {
			continue
		}
		value, present := event.Attributes[key]
		if !present {
			continue
		}
		if found && !jsonScalarEqual(selected, value) {
			return nil, false
		}
		selected, found = cloneJSON(value), true
	}
	return selected, found
}

func jsonScalarEqual(left, right any) bool {
	leftBytes, leftErr := json.Marshal(left)
	rightBytes, rightErr := json.Marshal(right)
	return leftErr == nil && rightErr == nil && bytes.Equal(leftBytes, rightBytes)
}

func decodeWire(encoded []byte, requireProfile bool) (projectedWire, bool) {
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
	if requireProfile && wire.Profile != ProfileID {
		return projectedWire{}, false
	}
	if wire.SchemaVersion != observability.CurrentRecordSchemaVersion ||
		wire.BucketCatalogVersion != observability.CurrentBucketCatalogVersion ||
		wire.Timestamp == nil || wire.RecordID == "" || wire.SpanName == "" ||
		wire.Source == "" || wire.Signal != string(observability.SignalTraces) ||
		!observability.IsRegisteredEventIdentity(observability.EventIdentity{
			Bucket: observability.Bucket(wire.Bucket), Signal: observability.SignalTraces,
			Name: observability.EventName(wire.Family),
		}) || wire.Correlation == nil || wire.Provenance == nil ||
		wire.Projection.RedactionProfile == "" || wire.Projection.State == "" ||
		wire.Projection.DetectorCatalogVersion <= 0 || wire.Body.Attributes == nil ||
		wire.Body.Resource.Attributes == nil || wire.Body.Scope.Attributes == nil ||
		strings.TrimSpace(stringValue(wire.Provenance["binary_version"])) == "" ||
		integerValue(wire.Provenance["registry_schema_version"]) <= 0 ||
		integerValue(wire.Provenance["config_generation"]) < 0 {
		return projectedWire{}, false
	}
	return wire, true
}

func rejected(reason ProjectionReason) Result { return Result{reason: reason} }

func cloneObject(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		output[key] = cloneJSON(value)
	}
	return output
}

func sanitizeObject(input map[string]any) map[string]any {
	output := make(map[string]any, len(input))
	for key, value := range input {
		if sanitized, present := sanitizeJSON(value); present {
			output[key] = sanitized
		}
	}
	return output
}

func sanitizeJSON(input any) (any, bool) {
	switch value := input.(type) {
	case nil:
		return nil, false
	case map[string]any:
		return sanitizeObject(value), true
	case []any:
		output := make([]any, 0, len(value))
		for _, item := range value {
			if sanitized, present := sanitizeJSON(item); present {
				output = append(output, sanitized)
			}
		}
		return output, true
	default:
		return cloneJSON(value), true
	}
}

func cloneJSON(input any) any {
	switch value := input.(type) {
	case map[string]any:
		return cloneObject(value)
	case []any:
		output := make([]any, len(value))
		for index := range value {
			output[index] = cloneJSON(value[index])
		}
		return output
	case string:
		return strings.Clone(value)
	case json.Number:
		return json.Number(strings.Clone(value.String()))
	default:
		return value
	}
}

func stringValue(value any) string {
	text, _ := value.(string)
	return text
}

func integerValue(value any) int64 {
	number, ok := value.(json.Number)
	if !ok {
		return -1
	}
	parsed, err := number.Int64()
	if err != nil {
		return -1
	}
	return parsed
}
