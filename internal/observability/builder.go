// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package observability

import (
	"fmt"
	"reflect"
	"time"
)

// Clock supplies event occurrence time. Production and tests must inject it;
// builders do not read global time directly.
type Clock interface {
	Now() time.Time
}

type ClockFunc func() time.Time

func (function ClockFunc) Now() time.Time {
	return function()
}

// OccurrenceIDGenerator creates the unique occurrence ID for one canonical
// record. It is distinct from every domain/correlation ID in the envelope.
type OccurrenceIDGenerator interface {
	NewOccurrenceID() (string, error)
}

type OccurrenceIDGeneratorFunc func() (string, error)

func (function OccurrenceIDGeneratorFunc) NewOccurrenceID() (string, error) {
	return function()
}

// RecordBuilder has no mutable record state. Given deterministic injected
// dependencies and input, BuildClassifiedLog produces deterministic output.
type RecordBuilder struct {
	clock       Clock
	idGenerator OccurrenceIDGenerator
}

func NewRecordBuilder(clock Clock, idGenerator OccurrenceIDGenerator) (*RecordBuilder, error) {
	if nilInterface(clock) {
		return nil, fmt.Errorf("record builder clock is required")
	}
	if nilInterface(idGenerator) {
		return nil, fmt.Errorf("record builder occurrence ID generator is required")
	}
	return &RecordBuilder{clock: clock, idGenerator: idGenerator}, nil
}

// ClassifiedLogInput contains only data not already resolved by the immutable
// producer-classification registry. It cannot override bucket, event identity,
// severity, log level, or mandatory-floor status.
type ClassifiedLogInput struct {
	ProducerKind          ProducerKind
	ProducerKey           ProducerKey
	ClassificationContext ClassificationContext
	ObservedAt            *time.Time
	Source                Source
	Connector             string
	Action                string
	Phase                 string
	Outcome               Outcome
	Correlation           Correlation
	Provenance            Provenance
	// Body object member names are schema-owned stable tokens. Dynamic
	// producer/provider/tool names must be represented as classified string
	// values, never map keys. P5 generated builders replace this conservative
	// P2 syntax gate with exact registry-owned key validation.
	Body         any
	FieldClasses map[string]FieldClass
}

// MandatoryFloorLogInput deliberately has no body or field-class fields. The
// builder supplies the one fixed, content-free floor schema after registered
// classification proves that the occurrence qualifies as mandatory.
type MandatoryFloorLogInput struct {
	ProducerKind          ProducerKind
	ProducerKey           ProducerKey
	ClassificationContext ClassificationContext
	ObservedAt            *time.Time
	Source                Source
	Connector             string
	Action                string
	Phase                 string
	Outcome               Outcome
	Correlation           Correlation
	Provenance            Provenance
}

// BuildClassifiedLog snapshots one current log occurrence. The clock and ID
// generator are each consulted exactly once and only after classification-level
// validation, avoiding consumed IDs for structurally invalid classifications.
func (builder *RecordBuilder) BuildClassifiedLog(input ClassifiedLogInput) (Record, error) {
	return builder.buildClassifiedLog(input, false, false)
}

// BuildMandatoryFloorLog emits the minimal, content-free SQLite floor form.
// It fails unless the registered classification and typed context qualify the
// occurrence as mandatory.
func (builder *RecordBuilder) BuildMandatoryFloorLog(input MandatoryFloorLogInput) (Record, error) {
	return builder.buildClassifiedLog(ClassifiedLogInput{
		ProducerKind:          input.ProducerKind,
		ProducerKey:           input.ProducerKey,
		ClassificationContext: input.ClassificationContext,
		ObservedAt:            cloneTimePointer(input.ObservedAt),
		Source:                input.Source,
		Connector:             input.Connector,
		Action:                input.Action,
		Phase:                 input.Phase,
		Outcome:               input.Outcome,
		Correlation:           input.Correlation,
		Provenance:            input.Provenance,
		Body: map[string]any{
			"floor_only":   true,
			"detail_state": "omitted",
		},
		FieldClasses: map[string]FieldClass{
			"/floor_only":   FieldClassMetadata,
			"/detail_state": FieldClassMetadata,
		},
	}, true, true)
}

func (builder *RecordBuilder) buildClassifiedLog(
	input ClassifiedLogInput,
	requireMandatory bool,
	floorOnly bool,
) (Record, error) {
	if builder == nil || nilInterface(builder.clock) || nilInterface(builder.idGenerator) {
		return Record{}, fmt.Errorf("record builder is not initialized")
	}
	classification, err := resolveRegisteredClassification(
		input.ProducerKind,
		input.ProducerKey,
		input.ClassificationContext,
	)
	if err != nil {
		return Record{}, err
	}
	if requireMandatory && !classification.Mandatory {
		return Record{}, fmt.Errorf("classified log does not qualify for the mandatory floor")
	}
	if classification.Identity.Signal != SignalLogs {
		return Record{}, fmt.Errorf("classified-log builder requires a log identity")
	}
	if !IsRegisteredEventIdentity(classification.Identity) {
		return Record{}, fmt.Errorf("classified-log identity is not registered")
	}
	if !classification.Severity.Valid {
		return Record{}, fmt.Errorf("classified-log severity normalization is invalid")
	}

	var severity *Severity
	if classification.Severity.Present {
		canonical := classification.Severity.Severity
		if _, valid := SeverityRank(canonical); !valid {
			return Record{}, fmt.Errorf("classified-log severity is not canonical")
		}
		severity = &canonical
	}
	if classification.Severity.LogLevel != "" && !isLogLevel(classification.Severity.LogLevel) {
		return Record{}, fmt.Errorf("classified-log log level is not canonical")
	}
	if err := validateCurrentBuilderObjectKeys(input.Body); err != nil {
		return Record{}, err
	}

	timestamp := builder.clock.Now()
	recordID, err := builder.idGenerator.NewOccurrenceID()
	if err != nil {
		return Record{}, fmt.Errorf("generate canonical record occurrence ID: %w", err)
	}
	return newClassifiedLogRecord(RecordInput{
		Timestamp:    timestamp,
		ObservedAt:   cloneTimePointer(input.ObservedAt),
		RecordID:     recordID,
		Identity:     classification.Identity,
		Severity:     severity,
		LogLevel:     classification.Severity.LogLevel,
		Source:       input.Source,
		Connector:    input.Connector,
		Action:       input.Action,
		Phase:        input.Phase,
		Outcome:      input.Outcome,
		Correlation:  input.Correlation,
		Provenance:   input.Provenance,
		Body:         input.Body,
		FieldClasses: cloneFieldClasses(input.FieldClasses),
	}, classification.Mandatory, floorOnly)
}

func validateCurrentBuilderObjectKeys(body any) error {
	value, err := NewValue(body)
	if err != nil {
		return fmt.Errorf("classified-log body is invalid")
	}
	object, err := value.Object()
	if err != nil {
		return fmt.Errorf("classified-log body must be an object")
	}
	var visit func(any) bool
	visit = func(input any) bool {
		switch typed := input.(type) {
		case map[string]any:
			for key, child := range typed {
				if !IsStableToken(key) || !visit(child) {
					return false
				}
			}
		case []any:
			for _, child := range typed {
				if !visit(child) {
					return false
				}
			}
		}
		return true
	}
	if !visit(object) {
		return fmt.Errorf("classified-log body contains a non-schema object member name; encode dynamic names as classified values")
	}
	return nil
}

func resolveRegisteredClassification(
	kind ProducerKind,
	key ProducerKey,
	context ClassificationContext,
) (ResolvedClassification, error) {
	var (
		classification Classification
		found          bool
	)
	switch kind {
	case ProducerGatewayEvent:
		classification, found = GatewayEventClassification(key)
	case ProducerAuditAction:
		classification, found = AuditActionClassification(key)
	default:
		return ResolvedClassification{}, fmt.Errorf("unknown classified-log producer kind")
	}
	if !found {
		return ResolvedClassification{}, fmt.Errorf("unknown classified-log producer key")
	}
	if context.EventName != "" && !IsRegisteredEventNameForSignal(SignalLogs, context.EventName) {
		return ResolvedClassification{}, fmt.Errorf("classified-log event identity is not registered")
	}
	if classification.Bucket == "" && context.Bucket != "" && !IsBucket(context.Bucket) {
		return ResolvedClassification{}, fmt.Errorf("classified-log context bucket is not registered")
	}
	resolved, err := classification.Resolve(context)
	if err != nil {
		return ResolvedClassification{}, fmt.Errorf("registered classified-log context is invalid")
	}
	return resolved, nil
}

func cloneTimePointer(input *time.Time) *time.Time {
	if input == nil {
		return nil
	}
	cloned := *input
	return &cloned
}

func nilInterface(input any) bool {
	if input == nil {
		return true
	}
	value := reflect.ValueOf(input)
	switch value.Kind() {
	case reflect.Chan, reflect.Func, reflect.Interface, reflect.Map, reflect.Pointer, reflect.Slice:
		return value.IsNil()
	default:
		return false
	}
}
