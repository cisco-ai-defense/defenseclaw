// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"bytes"
	"encoding/json"
	"errors"
	"strconv"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

const MaxSafeReportEntries = 32

const (
	MaxProjectionMetadataBytes = 4 * 1024
	MaxProjectedRecordBytes    = observability.MaxCanonicalRecordBytes + MaxProjectionMetadataBytes
)

// ProjectionState is the exact delivery-redaction aggregate state.
type ProjectionState string

const (
	ProjectionStateRaw          ProjectionState = "raw"
	ProjectionStateInspected    ProjectionState = "inspected"
	ProjectionStateTransformed  ProjectionState = "transformed"
	ProjectionStateFailedClosed ProjectionState = "failed_closed"
)

// ProjectionMetadata is the exact added top-level delivery member.
type ProjectionMetadata struct {
	RedactionProfile       string          `json:"redaction_profile"`
	DetectorCatalogVersion int             `json:"detector_catalog_version"`
	State                  ProjectionState `json:"state"`
	TransformedFields      int             `json:"transformed_fields"`
	RemovedFields          int             `json:"removed_fields"`
	OversizeFields         int             `json:"oversize_fields"`
	FailureCount           int             `json:"failure_count"`
	FailuresTruncated      bool            `json:"failures_truncated"`
}

// ProjectionErrorCode is a bounded record-level failure identity.
type ProjectionErrorCode string

const (
	ProjectionFailureClassification ProjectionErrorCode = "classification_failed"
	ProjectionFailureMetricClass    ProjectionErrorCode = "metric_classification_failed"
	ProjectionFailureContext        ProjectionErrorCode = "projection_context_mismatch"
	ProjectionFailureOutputLimit    ProjectionErrorCode = "output_limit"
	ProjectionFailureSerialization  ProjectionErrorCode = "serialization_failed"
)

// ProjectionError carries no record, pointer, profile input, or exception text.
type ProjectionError struct{ Code ProjectionErrorCode }

func (err *ProjectionError) Error() string {
	return "observability projection failed: " + string(err.Code)
}

// IsProjectionError reports a safe record-level projection failure.
func IsProjectionError(err error, code ProjectionErrorCode) bool {
	var target *ProjectionError
	return errors.As(err, &target) && target.Code == code
}

// FieldResult is the bounded outcome recorded for a failed field/sample.
type FieldResult string

const (
	FieldResultFailedClosed FieldResult = "failed_closed"
)

// SafeFailure contains only bounded catalog identities. In particular, it has
// no JSON pointer or raw diagnostic string.
type SafeFailure struct {
	FieldClass observability.FieldClass
	Mode       TransformationMode
	Result     FieldResult
	Code       string
}

// SafeReport is an immutable in-memory diagnostic result. Entries returns a
// fresh slice and every entry is value-only.
type SafeReport struct {
	metadata ProjectionMetadata
	entries  []SafeFailure
}

// Metadata returns a value copy of the aggregate counters and state.
func (report SafeReport) Metadata() ProjectionMetadata {
	return report.metadata
}

// Entries returns an independent copy in deterministic traversal order.
func (report SafeReport) Entries() []SafeFailure {
	return append([]SafeFailure(nil), report.entries...)
}

func (report SafeReport) clone() SafeReport {
	return SafeReport{metadata: report.metadata, entries: report.Entries()}
}

// Projection is the immutable per-route delivery representation. It retains
// only projected payload/bytes and trusted context, never hidden raw values.
type Projection struct {
	payload            observability.Value
	metadata           ProjectionMetadata
	report             SafeReport
	encoded            []byte
	origin             *engineOrigin
	profileFingerprint [32]byte
	keyID              string
	catalogVersion     int
}

// Payload returns an independent immutable payload clone.
func (projection Projection) Payload() observability.Value {
	return projection.payload.Clone()
}

// Metadata returns exact projection delivery metadata by value.
func (projection Projection) Metadata() ProjectionMetadata {
	return projection.metadata
}

// Report returns an independent immutable diagnostic copy.
func (projection Projection) Report() SafeReport { return projection.report.clone() }

// Bytes returns a fresh deterministic projected-record serialization.
func (projection Projection) Bytes() ([]byte, error) {
	if len(projection.encoded) == 0 || projection.origin == nil || projection.payload.IsZero() {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	return append([]byte(nil), projection.encoded...), nil
}

func (projection Projection) clone() Projection {
	projection.payload = projection.payload.Clone()
	projection.encoded = append([]byte(nil), projection.encoded...)
	projection.report = projection.report.clone()
	projection.keyID = strings.Clone(projection.keyID)
	return projection
}

type reportBuilder struct {
	metadata ProjectionMetadata
	entries  []SafeFailure
}

func newReportBuilder(profile Profile) *reportBuilder {
	state := ProjectionStateInspected
	if profile.name == ProfileNone {
		state = ProjectionStateRaw
	}
	return &reportBuilder{metadata: ProjectionMetadata{
		RedactionProfile:       string(profile.name),
		DetectorCatalogVersion: DetectorCatalogVersion(),
		State:                  state,
	}}
}

func (builder *reportBuilder) transformed(oversize bool) {
	builder.metadata.TransformedFields++
	if oversize {
		builder.metadata.OversizeFields++
	}
	if builder.metadata.State != ProjectionStateFailedClosed {
		builder.metadata.State = ProjectionStateTransformed
	}
}

func (builder *reportBuilder) removed() {
	builder.metadata.RemovedFields++
	if builder.metadata.State != ProjectionStateFailedClosed {
		builder.metadata.State = ProjectionStateTransformed
	}
}

func (builder *reportBuilder) failField(class observability.FieldClass, mode TransformationMode, code string) {
	builder.metadata.FailureCount++
	builder.metadata.State = ProjectionStateFailedClosed
	if len(builder.entries) < MaxSafeReportEntries {
		builder.entries = append(builder.entries, SafeFailure{
			FieldClass: class, Mode: mode, Result: FieldResultFailedClosed, Code: strings.Clone(code),
		})
	} else {
		builder.metadata.FailuresTruncated = true
	}
}

func (builder *reportBuilder) failRecord(code ProjectionErrorCode) {
	builder.metadata.FailureCount++
	builder.metadata.State = ProjectionStateFailedClosed
	_ = code // The returned ProjectionError carries record scope; no class/mode is guessed.
}

func validateProjectionMetadata(metadata ProjectionMetadata) error {
	if !observability.IsStableToken(metadata.RedactionProfile) || metadata.DetectorCatalogVersion <= 0 {
		return &ProjectionError{Code: ProjectionFailureSerialization}
	}
	switch metadata.State {
	case ProjectionStateRaw, ProjectionStateInspected, ProjectionStateTransformed, ProjectionStateFailedClosed:
	default:
		return &ProjectionError{Code: ProjectionFailureSerialization}
	}
	if metadata.TransformedFields < 0 || metadata.RemovedFields < 0 ||
		metadata.OversizeFields < 0 || metadata.FailureCount < 0 ||
		metadata.OversizeFields > metadata.TransformedFields {
		return &ProjectionError{Code: ProjectionFailureSerialization}
	}
	if (metadata.State == ProjectionStateRaw) != (metadata.RedactionProfile == string(ProfileNone)) {
		return &ProjectionError{Code: ProjectionFailureSerialization}
	}
	actions := metadata.TransformedFields + metadata.RemovedFields
	switch metadata.State {
	case ProjectionStateRaw, ProjectionStateInspected:
		if actions != 0 || metadata.FailureCount != 0 || metadata.FailuresTruncated {
			return &ProjectionError{Code: ProjectionFailureSerialization}
		}
	case ProjectionStateTransformed:
		if actions == 0 || metadata.FailureCount != 0 || metadata.FailuresTruncated {
			return &ProjectionError{Code: ProjectionFailureSerialization}
		}
	case ProjectionStateFailedClosed:
		if metadata.FailureCount == 0 {
			return &ProjectionError{Code: ProjectionFailureSerialization}
		}
	}
	if metadata.FailuresTruncated != (metadata.FailureCount > MaxSafeReportEntries) {
		return &ProjectionError{Code: ProjectionFailureSerialization}
	}
	return nil
}

// marshalProjectedRecord is deliberately package-private: destination adapters
// receive Projection.Bytes and cannot bless a canonical raw payload with
// fabricated redaction metadata. Removed object properties are also removed
// from the delivery field-class map so their dynamic names are not disclosed.
func marshalProjectedRecord(record observability.Record, payload observability.Value, metadata ProjectionMetadata) ([]byte, error) {
	if payload.IsZero() || validateProjectionMetadata(metadata) != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	metadataBytes, err := marshalProjectionJSON(metadata)
	if err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	if len(metadataBytes) > MaxProjectionMetadataBytes {
		return nil, &ProjectionError{Code: ProjectionFailureOutputLimit}
	}
	canonical, err := record.Bytes()
	if err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	decoder := json.NewDecoder(bytes.NewReader(canonical))
	decoder.UseNumber()
	var wire map[string]any
	if err := decoder.Decode(&wire); err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	payloadObject, err := payload.Object()
	if err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	switch record.Signal() {
	case observability.SignalLogs, observability.SignalTraces:
		wire["body"] = payload.Clone()
		delete(wire, "instrument_data")
	case observability.SignalMetrics:
		wire["instrument_data"] = payload.Clone()
		delete(wire, "body")
	default:
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	filteredClasses := make(map[string]observability.FieldClass)
	for pointer, class := range record.FieldClasses() {
		if projectionPointerResolves(payloadObject, pointer) {
			filteredClasses[pointer] = class
		}
	}
	wire["field_classes"] = filteredClasses
	wire["projection"] = metadata
	encoded, err := marshalProjectionJSON(wire)
	if err != nil {
		return nil, &ProjectionError{Code: ProjectionFailureSerialization}
	}
	if len(encoded) > MaxProjectedRecordBytes {
		return nil, &ProjectionError{Code: ProjectionFailureOutputLimit}
	}
	return append([]byte(nil), encoded...), nil
}

func marshalProjectionJSON(value any) ([]byte, error) {
	var buffer bytes.Buffer
	encoder := json.NewEncoder(&buffer)
	encoder.SetEscapeHTML(false)
	if err := encoder.Encode(value); err != nil {
		return nil, err
	}
	encoded := bytes.TrimSuffix(buffer.Bytes(), []byte{'\n'})
	return append([]byte(nil), unescapeProjectionLineSeparators(encoded)...), nil
}

func unescapeProjectionLineSeparators(encoded []byte) []byte {
	result := make([]byte, 0, len(encoded))
	for index := 0; index < len(encoded); {
		if encoded[index] != '\\' {
			result = append(result, encoded[index])
			index++
			continue
		}
		start := index
		for index < len(encoded) && encoded[index] == '\\' {
			index++
		}
		slashes := index - start
		separator := ""
		if slashes%2 == 1 && index+5 <= len(encoded) {
			switch string(encoded[index : index+5]) {
			case "u2028":
				separator = "\u2028"
			case "u2029":
				separator = "\u2029"
			}
		}
		if separator == "" {
			result = append(result, encoded[start:index]...)
			continue
		}
		result = append(result, encoded[start:index-1]...)
		result = append(result, separator...)
		index += 5
	}
	return result
}

func projectionPointerResolves(root any, pointer string) bool {
	if pointer == "" {
		return true
	}
	current := root
	for _, encodedToken := range strings.Split(pointer[1:], "/") {
		token := strings.ReplaceAll(strings.ReplaceAll(encodedToken, "~1", "/"), "~0", "~")
		switch typed := current.(type) {
		case map[string]any:
			var exists bool
			current, exists = typed[token]
			if !exists {
				return false
			}
		case []any:
			if token == "" || (len(token) > 1 && token[0] == '0') {
				return false
			}
			index, err := strconv.ParseUint(token, 10, 64)
			if err != nil || index >= uint64(len(typed)) {
				return false
			}
			current = typed[index]
		default:
			return false
		}
	}
	return true
}

func (builder *reportBuilder) report() SafeReport {
	return SafeReport{metadata: builder.metadata, entries: append([]SafeFailure(nil), builder.entries...)}
}
