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
	"errors"
	"fmt"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type countingClock struct {
	now   time.Time
	calls atomic.Int64
}

func (clock *countingClock) Now() time.Time {
	clock.calls.Add(1)
	return clock.now
}

type countingIDGenerator struct {
	calls atomic.Int64
	err   error
}

func (generator *countingIDGenerator) NewOccurrenceID() (string, error) {
	call := generator.calls.Add(1)
	if generator.err != nil {
		return "", generator.err
	}
	return fmt.Sprintf("occurrence-%d", call), nil
}

func validClassifiedLogInput() ClassifiedLogInput {
	return ClassifiedLogInput{
		ProducerKind: ProducerGatewayEvent,
		ProducerKey:  "activity",
		ClassificationContext: ClassificationContext{
			Bucket:      BucketComplianceActivity,
			EventName:   "config.change.applied",
			RawSeverity: "WARN",
			MandatoryFacts: MandatoryFacts{
				ControlPlaneMutation: true,
			},
		},
		Source:  SourceOperatorAPI,
		Action:  "config.change",
		Phase:   "apply",
		Outcome: OutcomeApplied,
		Correlation: Correlation{
			RequestID: "request-1",
		},
		Provenance: Provenance{
			Producer:              "operator_api",
			BinaryVersion:         "v8.0.0",
			RegistrySchemaVersion: 1,
			ConfigGeneration:      4,
		},
		Body: map[string]any{
			"target": "observability.routes",
			"reason": "approved change",
		},
		FieldClasses: map[string]FieldClass{
			"/target": FieldClassPath,
			"/reason": FieldClassReason,
		},
	}
}

func TestClassifiedLogBuilderUsesInjectedDependenciesExactlyOnce(t *testing.T) {
	now := time.Date(2026, 7, 3, 12, 0, 0, 5, time.FixedZone("offset", 7200))
	clock := &countingClock{now: now}
	ids := &countingIDGenerator{}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	record, err := builder.BuildClassifiedLog(validClassifiedLogInput())
	if err != nil {
		t.Fatal(err)
	}
	if clock.calls.Load() != 1 || ids.calls.Load() != 1 {
		t.Fatalf("dependency calls clock=%d ids=%d", clock.calls.Load(), ids.calls.Load())
	}
	if !record.Timestamp().Equal(now) || record.Timestamp().Location() != time.UTC {
		t.Fatalf("timestamp = %v", record.Timestamp())
	}
	if record.RecordID() != "occurrence-1" {
		t.Fatalf("record ID = %q", record.RecordID())
	}
	if record.Identity() != (EventIdentity{Bucket: BucketComplianceActivity, Signal: SignalLogs, Name: "config.change.applied"}) {
		t.Fatalf("identity = %#v", record.Identity())
	}
	severity, present := record.Severity()
	if !present || severity != SeverityMedium || record.LogLevel() != LogLevelWarn {
		t.Fatalf("severity = %s/%t, log level = %s", severity, present, record.LogLevel())
	}
	if !record.Mandatory() {
		t.Fatal("resolved mandatory floor was not preserved")
	}
}

func TestMandatoryFloorLogBuilderEmitsOnlyFixedSafeSchema(t *testing.T) {
	clock := &countingClock{now: time.Unix(100, 200)}
	ids := &countingIDGenerator{}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	full := validClassifiedLogInput()
	record, err := builder.BuildMandatoryFloorLog(MandatoryFloorLogInput{
		ProducerKind:          full.ProducerKind,
		ProducerKey:           full.ProducerKey,
		ClassificationContext: full.ClassificationContext,
		ObservedAt:            full.ObservedAt,
		Source:                full.Source,
		Connector:             full.Connector,
		Action:                full.Action,
		Phase:                 full.Phase,
		Outcome:               full.Outcome,
		Correlation:           full.Correlation,
		Provenance:            full.Provenance,
	})
	if err != nil {
		t.Fatal(err)
	}
	if !record.IsFloorOnly() || !record.Mandatory() {
		t.Fatalf("floor flags floor=%t mandatory=%t", record.IsFloorOnly(), record.Mandatory())
	}
	body, present := record.Body()
	if !present {
		t.Fatal("floor body missing")
	}
	if got := string(body.Bytes()); got != `{"detail_state":"omitted","floor_only":true}` {
		t.Fatalf("floor body = %s", got)
	}
	wantClasses := map[string]FieldClass{
		"/detail_state": FieldClassMetadata,
		"/floor_only":   FieldClassMetadata,
	}
	if !reflect.DeepEqual(record.FieldClasses(), wantClasses) {
		t.Fatalf("floor classes = %#v", record.FieldClasses())
	}
	encoded, err := record.MarshalJSON()
	if err != nil {
		t.Fatal(err)
	}
	if strings.Contains(string(encoded), "is_floor_only") {
		t.Fatalf("internal floor marker serialized: %s", encoded)
	}
}

func TestMandatoryFloorLogBuilderRejectsNonMandatoryClassification(t *testing.T) {
	clock := &countingClock{now: time.Now()}
	ids := &countingIDGenerator{}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	input := validClassifiedLogInput()
	input.ProducerKey = "diagnostic"
	input.ClassificationContext = ClassificationContext{RawSeverity: "INFO"}
	_, err = builder.BuildMandatoryFloorLog(MandatoryFloorLogInput{
		ProducerKind:          input.ProducerKind,
		ProducerKey:           input.ProducerKey,
		ClassificationContext: input.ClassificationContext,
		Source:                input.Source,
		Provenance:            input.Provenance,
	})
	if err == nil {
		t.Fatal("non-mandatory classification entered floor path")
	}
	if clock.calls.Load() != 0 || ids.calls.Load() != 0 {
		t.Fatal("rejected floor record consumed dependencies")
	}
}

func TestClassifiedLogBuilderCannotOverrideResolvedFields(t *testing.T) {
	clock := &countingClock{now: time.Now()}
	ids := &countingIDGenerator{}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	input := validClassifiedLogInput()
	record, err := builder.BuildClassifiedLog(input)
	if err != nil {
		t.Fatal(err)
	}
	if record.Bucket() != BucketComplianceActivity ||
		record.EventName() != input.ClassificationContext.EventName ||
		!record.Mandatory() {
		t.Fatalf("resolved fields not authoritative")
	}
}

func TestClassifiedLogBuilderSnapshotsInputs(t *testing.T) {
	builder, err := NewRecordBuilder(
		ClockFunc(func() time.Time { return time.Unix(1, 2) }),
		OccurrenceIDGeneratorFunc(func() (string, error) { return "occurrence", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	input := validClassifiedLogInput()
	body := input.Body.(map[string]any)
	classes := input.FieldClasses
	record, err := builder.BuildClassifiedLog(input)
	if err != nil {
		t.Fatal(err)
	}
	body["reason"] = "mutated"
	classes["/reason"] = FieldClassCredential

	value, _ := record.Body()
	object, _ := value.Object()
	if object["reason"] != "approved change" {
		t.Fatalf("body aliased: %#v", object)
	}
	if record.FieldClasses()["/reason"] != FieldClassReason {
		t.Fatalf("field classes aliased: %#v", record.FieldClasses())
	}
}

func TestClassifiedLogBuilderEnforcesSchemaOwnedObjectNames(t *testing.T) {
	clock := &countingClock{now: time.Now()}
	ids := &countingIDGenerator{}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	valid := validClassifiedLogInput()
	valid.Body = map[string]any{
		"outer_name": map[string]any{"safe_value": "x"},
		"entries":    []any{map[string]any{"name": "dynamic-name@example.invalid"}},
	}
	valid.FieldClasses = map[string]FieldClass{
		"/outer_name/safe_value": FieldClassMetadata,
		"/entries/0/name":        FieldClassContent,
	}
	if _, err := builder.BuildClassifiedLog(valid); err != nil {
		t.Fatalf("schema-owned names and classified dynamic value rejected: %v", err)
	}

	for _, dynamicKey := range []string{"person@example.invalid", "dynamic key", "π"} {
		beforeClock, beforeIDs := clock.calls.Load(), ids.calls.Load()
		input := validClassifiedLogInput()
		input.Body = map[string]any{dynamicKey: "value"}
		input.FieldClasses = map[string]FieldClass{"/placeholder": FieldClassContent}
		_, buildErr := builder.BuildClassifiedLog(input)
		if buildErr == nil || !strings.Contains(buildErr.Error(), "encode dynamic names as classified values") {
			t.Fatalf("dynamic object name was not rejected safely: %v", buildErr)
		}
		if strings.Contains(buildErr.Error(), dynamicKey) {
			t.Fatalf("builder error echoed dynamic object name: %v", buildErr)
		}
		if clock.calls.Load() != beforeClock || ids.calls.Load() != beforeIDs {
			t.Fatal("invalid object name consumed clock or occurrence ID")
		}
	}
}

func TestClassifiedLogBuilderRejectsUnknownOrInvalidClassificationBeforeDependencies(t *testing.T) {
	clock := &countingClock{now: time.Now()}
	ids := &countingIDGenerator{}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name   string
		mutate func(*ClassifiedLogInput)
	}{
		{name: "unknown kind", mutate: func(input *ClassifiedLogInput) {
			input.ProducerKind = "fabricated"
		}},
		{name: "unknown key", mutate: func(input *ClassifiedLogInput) {
			input.ProducerKey = "fabricated"
		}},
		{name: "unregistered identity", mutate: func(input *ClassifiedLogInput) {
			input.ClassificationContext.EventName = "config.change.unregistered"
		}},
		{name: "invalid severity", mutate: func(input *ClassifiedLogInput) {
			input.ClassificationContext.RawSeverity = "NOTICE"
		}},
		{name: "missing required event", mutate: func(input *ClassifiedLogInput) {
			input.ClassificationContext.EventName = ""
		}},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			beforeClock := clock.calls.Load()
			beforeIDs := ids.calls.Load()
			input := validClassifiedLogInput()
			test.mutate(&input)
			if _, err := builder.BuildClassifiedLog(input); err == nil {
				t.Fatal("invalid classification accepted")
			}
			if clock.calls.Load() != beforeClock || ids.calls.Load() != beforeIDs {
				t.Fatal("invalid classification consumed clock or occurrence ID")
			}
		})
	}
}

func TestClassifiedLogBuilderErrorsNeverEchoRejectedContextValues(t *testing.T) {
	builder, err := NewRecordBuilder(
		ClockFunc(func() time.Time { return time.Now() }),
		OccurrenceIDGeneratorFunc(func() (string, error) { return "id", nil }),
	)
	if err != nil {
		t.Fatal(err)
	}
	secret := "sensitive-rejected-value"
	for _, mutate := range []func(*ClassifiedLogInput){
		func(input *ClassifiedLogInput) { input.ClassificationContext.RawSeverity = secret },
		func(input *ClassifiedLogInput) { input.ClassificationContext.EventName = EventName(secret) },
	} {
		input := validClassifiedLogInput()
		mutate(&input)
		_, buildErr := builder.BuildClassifiedLog(input)
		if buildErr == nil {
			t.Fatal("invalid context accepted")
		}
		if strings.Contains(buildErr.Error(), secret) {
			t.Fatalf("builder error echoed rejected value: %v", buildErr)
		}
	}
}

func TestClassifiedLogBuilderHasNoForgedResolvedClassificationSurface(t *testing.T) {
	typeOfInput := reflect.TypeOf(ClassifiedLogInput{})
	if _, exists := typeOfInput.FieldByName("Classification"); exists {
		t.Fatal("classified-log input exposes forgeable resolved classification")
	}
	for index := 0; index < typeOfInput.NumField(); index++ {
		if typeOfInput.Field(index).Type == reflect.TypeOf(ResolvedClassification{}) {
			t.Fatal("classified-log input accepts a forgeable resolved classification")
		}
	}
}

func TestClassifiedLogBuilderPropagatesGeneratorFailure(t *testing.T) {
	clock := &countingClock{now: time.Now()}
	ids := &countingIDGenerator{err: errors.New("unavailable")}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := builder.BuildClassifiedLog(validClassifiedLogInput()); err == nil {
		t.Fatal("generator failure ignored")
	}
	if clock.calls.Load() != 1 || ids.calls.Load() != 1 {
		t.Fatalf("dependency calls clock=%d ids=%d", clock.calls.Load(), ids.calls.Load())
	}
}

func TestRecordBuilderRejectsNilDependencies(t *testing.T) {
	var typedNilClock *countingClock
	var typedNilIDs *countingIDGenerator
	validClock := ClockFunc(func() time.Time { return time.Now() })
	validIDs := OccurrenceIDGeneratorFunc(func() (string, error) { return "id", nil })
	for _, test := range []struct {
		name  string
		clock Clock
		ids   OccurrenceIDGenerator
	}{
		{name: "nil clock", ids: validIDs},
		{name: "typed nil clock", clock: typedNilClock, ids: validIDs},
		{name: "nil IDs", clock: validClock},
		{name: "typed nil IDs", clock: validClock, ids: typedNilIDs},
	} {
		t.Run(test.name, func(t *testing.T) {
			if _, err := NewRecordBuilder(test.clock, test.ids); err == nil {
				t.Fatal("nil dependency accepted")
			}
		})
	}
}

func TestRecordBuilderIsSafeForConcurrentUse(t *testing.T) {
	clock := &countingClock{now: time.Unix(10, 20)}
	ids := &countingIDGenerator{}
	builder, err := NewRecordBuilder(clock, ids)
	if err != nil {
		t.Fatal(err)
	}
	const workers = 64
	recordIDs := make(chan string, workers)
	errorsFound := make(chan error, workers)
	var wait sync.WaitGroup
	for range workers {
		wait.Add(1)
		go func() {
			defer wait.Done()
			record, buildErr := builder.BuildClassifiedLog(validClassifiedLogInput())
			if buildErr != nil {
				errorsFound <- buildErr
				return
			}
			recordIDs <- record.RecordID()
		}()
	}
	wait.Wait()
	close(recordIDs)
	close(errorsFound)
	for buildErr := range errorsFound {
		t.Fatal(buildErr)
	}
	seen := make(map[string]struct{}, workers)
	for recordID := range recordIDs {
		if _, duplicate := seen[recordID]; duplicate {
			t.Fatalf("duplicate record ID %q", recordID)
		}
		seen[recordID] = struct{}{}
	}
	if len(seen) != workers {
		t.Fatalf("built %d records, want %d", len(seen), workers)
	}
}
