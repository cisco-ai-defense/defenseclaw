// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

// Package galileo owns the Galileo compatibility decision and projection.
// It deliberately accepts only a redaction.Projection: callers cannot pass a
// canonical record or an SDK span and accidentally bypass route redaction.
//
// The package is not a canonical span schema. It is the bounded,
// destination-owned galileo-rich-v2 view of an already-redacted canonical
// trace record. General OTLP destinations must continue to receive their own
// independent projections.
package galileo

import (
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

const ProfileID = observability.RuntimeGalileoCompatibilityProfile

// Shape is the closed set of span shapes accepted by galileo-rich-v2.
type Shape string

const (
	ShapeAgent     Shape = "agent"
	ShapeLLM       Shape = "llm"
	ShapeTool      Shape = "tool"
	ShapeRetriever Shape = "retriever"
	ShapeWorkflow  Shape = "workflow"
)

// Reason is a bounded compatibility outcome suitable for counters and health.
// It never contains attribute values, backend responses, or error strings.
type Reason string

const (
	ReasonEligible              Reason = "eligible"
	ReasonInvalidLimits         Reason = "invalid_limits"
	ReasonInvalidProjection     Reason = "invalid_projection"
	ReasonUnsupportedShape      Reason = "unsupported_shape"
	ReasonSchemaMissingRequired Reason = "schema_missing_required"
	ReasonProjectionTooLarge    Reason = "projection_too_large"
)

// Limits are destination-local bounds from the v8 rich trace contract. Zero
// selects the reviewed default for that field; non-zero values must be within
// the documented family minimum and hard maximum.
type Limits struct {
	MaxAttributesPerSpan   int
	MaxEventsPerSpan       int
	MaxLinksPerSpan        int
	MaxAttributesPerEvent  int
	MaxAttributeValueBytes int
	MaxProjectedSpanBytes  int
	MaxMessageItems        int
}

const (
	minAttributesPerSpan, defaultAttributesPerSpan, maxAttributesPerSpan       = 32, 128, 256
	minEventsPerSpan, defaultEventsPerSpan, maxEventsPerSpan                   = 1, 64, 128
	minLinksPerSpan, defaultLinksPerSpan, maxLinksPerSpan                      = 1, 32, 64
	minAttributesPerEvent, defaultAttributesPerEvent, maxAttributesPerEvent    = 4, 32, 64
	minAttributeValueBytes, defaultAttributeValueBytes, maxAttributeValueBytes = 256, 16 * 1024, 64 * 1024
	minProjectedSpanBytes, defaultProjectedSpanBytes, maxProjectedSpanBytes    = 4 * 1024, 256 * 1024, 1024 * 1024
	minMessageItems, defaultMessageItems, maxMessageItems                      = 1, 128, 512
)

// DefaultLimits returns the complete default galileo-rich-v2 limit set.
func DefaultLimits() Limits {
	return Limits{
		MaxAttributesPerSpan:   defaultAttributesPerSpan,
		MaxEventsPerSpan:       defaultEventsPerSpan,
		MaxLinksPerSpan:        defaultLinksPerSpan,
		MaxAttributesPerEvent:  defaultAttributesPerEvent,
		MaxAttributeValueBytes: defaultAttributeValueBytes,
		MaxProjectedSpanBytes:  defaultProjectedSpanBytes,
		MaxMessageItems:        defaultMessageItems,
	}
}

func (limits Limits) resolved() (Limits, bool) {
	defaults := DefaultLimits()
	if limits.MaxAttributesPerSpan == 0 {
		limits.MaxAttributesPerSpan = defaults.MaxAttributesPerSpan
	}
	if limits.MaxEventsPerSpan == 0 {
		limits.MaxEventsPerSpan = defaults.MaxEventsPerSpan
	}
	if limits.MaxLinksPerSpan == 0 {
		limits.MaxLinksPerSpan = defaults.MaxLinksPerSpan
	}
	if limits.MaxAttributesPerEvent == 0 {
		limits.MaxAttributesPerEvent = defaults.MaxAttributesPerEvent
	}
	if limits.MaxAttributeValueBytes == 0 {
		limits.MaxAttributeValueBytes = defaults.MaxAttributeValueBytes
	}
	if limits.MaxProjectedSpanBytes == 0 {
		limits.MaxProjectedSpanBytes = defaults.MaxProjectedSpanBytes
	}
	if limits.MaxMessageItems == 0 {
		limits.MaxMessageItems = defaults.MaxMessageItems
	}
	valid := within(limits.MaxAttributesPerSpan, minAttributesPerSpan, maxAttributesPerSpan) &&
		within(limits.MaxEventsPerSpan, minEventsPerSpan, maxEventsPerSpan) &&
		within(limits.MaxLinksPerSpan, minLinksPerSpan, maxLinksPerSpan) &&
		within(limits.MaxAttributesPerEvent, minAttributesPerEvent, maxAttributesPerEvent) &&
		within(limits.MaxAttributeValueBytes, minAttributeValueBytes, maxAttributeValueBytes) &&
		within(limits.MaxProjectedSpanBytes, minProjectedSpanBytes, maxProjectedSpanBytes) &&
		within(limits.MaxMessageItems, minMessageItems, maxMessageItems)
	return limits, valid
}

func within(value, minimum, maximum int) bool { return value >= minimum && value <= maximum }

// Result is an immutable compatibility decision. Eligible results retain only
// destination-projected bytes; ineligible results retain only a closed reason
// and bounded schema-key names.
type Result struct {
	reason  Reason
	shape   Shape
	missing []string
	encoded []byte
}

func rejected(reason Reason, missing ...string) Result {
	return Result{reason: reason, missing: append([]string(nil), missing...)}
}

func accepted(shape Shape, encoded []byte) Result {
	return Result{reason: ReasonEligible, shape: shape, encoded: append([]byte(nil), encoded...)}
}

// Eligible reports whether the projected span may be sent to Galileo.
func (result Result) Eligible() bool {
	return result.reason == ReasonEligible && len(result.encoded) > 0
}

// Reason reports a closed compatibility outcome.
func (result Result) Reason() Reason {
	if result.reason == "" {
		return ReasonInvalidProjection
	}
	return result.reason
}

// Shape reports the accepted Galileo span shape, or empty for a rejection.
func (result Result) Shape() Shape { return result.shape }

// MissingFields returns sorted, bounded schema-key identities only.
func (result Result) MissingFields() []string { return append([]string(nil), result.missing...) }

// ProjectionError carries only the closed rejection reason.
type ProjectionError struct{ Reason Reason }

func (err *ProjectionError) Error() string {
	return "galileo compatibility projection unavailable: " + string(err.Reason)
}

// Bytes returns a fresh deterministic galileo-rich-v2 JSON projection.
func (result Result) Bytes() ([]byte, error) {
	if !result.Eligible() {
		return nil, &ProjectionError{Reason: result.Reason()}
	}
	return append([]byte(nil), result.encoded...), nil
}

// IsProjectionError identifies a safe compatibility rejection.
func IsProjectionError(err error, reason Reason) bool {
	var target *ProjectionError
	return errors.As(err, &target) && target.Reason == reason
}

type projectedEnvelope struct {
	SchemaVersion        int            `json:"schema_version"`
	BucketCatalogVersion int            `json:"bucket_catalog_version"`
	Timestamp            any            `json:"timestamp"`
	ObservedAt           any            `json:"observed_at,omitempty"`
	RecordID             string         `json:"record_id"`
	Bucket               string         `json:"bucket"`
	Signal               string         `json:"signal"`
	Family               string         `json:"event_name"`
	SpanName             string         `json:"span_name"`
	Source               string         `json:"source"`
	Connector            string         `json:"connector,omitempty"`
	Action               string         `json:"action,omitempty"`
	Phase                string         `json:"phase,omitempty"`
	Outcome              string         `json:"outcome,omitempty"`
	Correlation          map[string]any `json:"correlation"`
	Provenance           map[string]any `json:"provenance"`
	Projection           map[string]any `json:"projection"`
	Body                 map[string]any `json:"body"`
}

type outputEnvelope struct {
	Profile              string         `json:"compatibility_profile"`
	Shape                Shape          `json:"compatibility_shape"`
	SchemaVersion        int            `json:"schema_version"`
	BucketCatalogVersion int            `json:"bucket_catalog_version"`
	Timestamp            any            `json:"timestamp"`
	ObservedAt           any            `json:"observed_at,omitempty"`
	RecordID             string         `json:"record_id"`
	Bucket               string         `json:"bucket"`
	Signal               string         `json:"signal"`
	Family               string         `json:"event_name"`
	SpanName             string         `json:"span_name"`
	Source               string         `json:"source"`
	Connector            string         `json:"connector,omitempty"`
	Action               string         `json:"action,omitempty"`
	Phase                string         `json:"phase,omitempty"`
	Outcome              string         `json:"outcome,omitempty"`
	Correlation          map[string]any `json:"correlation"`
	Provenance           map[string]any `json:"provenance"`
	Projection           map[string]any `json:"projection"`
	Body                 map[string]any `json:"body"`
}

type shapeContract struct {
	shape              Shape
	family             string
	operation          string
	oiKind             string
	allowedKinds       map[string]struct{}
	allowedAttributes  map[string]struct{}
	allowedEvents      map[string]struct{}
	allowedEventFields map[string]map[string]struct{}
	allowedLinks       map[string]struct{}
	allowedLinkFields  map[string]struct{}
	allowedScopeFields map[string]struct{}
	requiredAttributes []string
}

// Compile-time assertion that this package's only accepted input type remains
// the route-redaction result rather than a raw observability.Record.
var _ = func(_ redaction.Projection) {} //nolint:gochecknoglobals
