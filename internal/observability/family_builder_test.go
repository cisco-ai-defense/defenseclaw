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
	"encoding/json"
	"math"
	"reflect"
	"strings"
	"sync"
	"sync/atomic"
	"testing"
	"time"
)

type testGeneratedLogFamily struct {
	contract  familyDescriptorContract
	identity  EventIdentity
	mandatory bool
}

func (family *testGeneratedLogFamily) familyDescriptorContract() familyDescriptorContract {
	return family.contract
}
func (family *testGeneratedLogFamily) schemaDerivedLogIdentity() EventIdentity {
	return family.identity
}
func (family *testGeneratedLogFamily) schemaDerivedLogMandatory() bool { return family.mandatory }

type testGeneratedTraceFamily struct {
	base  familyDescriptorContract
	trace familyTraceContract
}

func (family *testGeneratedTraceFamily) familyDescriptorContract() familyDescriptorContract {
	return family.base
}
func (family *testGeneratedTraceFamily) familyTraceContract() familyTraceContract {
	return family.trace
}

type testGeneratedMetricFamily struct {
	base   familyDescriptorContract
	metric familyMetricContract
}

func (family *testGeneratedMetricFamily) familyDescriptorContract() familyDescriptorContract {
	return family.base
}
func (family *testGeneratedMetricFamily) familyMetricContract() familyMetricContract {
	return family.metric
}

type testOccurrenceIDs struct{ count atomic.Int64 }

func (generator *testOccurrenceIDs) NewOccurrenceID() (string, error) {
	generator.count.Add(1)
	return "family-record-id", nil
}

func testFamilyBuilder(t *testing.T) (*FamilyBuilder, *testOccurrenceIDs) {
	t.Helper()
	ids := &testOccurrenceIDs{}
	builder, err := NewFamilyBuilder(
		ClockFunc(func() time.Time { return time.Date(2026, 7, 4, 12, 0, 0, 0, time.UTC) }),
		ids,
	)
	if err != nil {
		t.Fatal(err)
	}
	return builder, ids
}

func testFamilyEnvelope() FamilyEnvelopeInput {
	return FamilyEnvelopeInput{
		ObservedAt: Present(time.Date(2026, 7, 4, 11, 59, 59, 0, time.UTC)),
		Source:     SourceSystem,
		Connector:  "codex",
		Action:     "family.build",
		Phase:      "completed",
		Correlation: Correlation{
			RunID: "run-1",
		},
		Provenance: FamilyProvenanceInput{
			Producer: "family_test", BinaryVersion: "v8-test", ConfigGeneration: 9,
			BuildCommit: "abcd", ConfigDigest: "cafe",
		},
	}
}

func requiredStringField(key string, class FieldClass, maximum int) familyFieldDescriptor {
	return familyFieldDescriptor{
		key: key, typeOf: familyFieldString, requirement: familyRequirementRequired,
		fieldClass: class, source: familyValueInput,
		constraints: familyFieldConstraints{maxUTF8Bytes: maximum},
	}
}

func testFamilyStructuredLimits() familyStructuredLimits {
	return familyStructuredLimits{
		maxEncodedBytes: 262_144, maxItemUTF8Bytes: 65_536,
		maxItems: 256, maxDepth: 8, maxProperties: 256,
	}
}

func testLogFamily() *testGeneratedLogFamily {
	identity := EventIdentity{Bucket: BucketDiagnostic, Signal: SignalLogs, Name: "diagnostic.message"}
	contract := familyDescriptorContract{
		id: "log.diagnostic.message", identity: identity, familySchemaVersion: 1,
		outcome: familyOutcomePolicy{
			requirement: familyRequirementRequired,
			allowed:     []Outcome{OutcomeCompleted, OutcomeFailed},
		},
		fields: []familyFieldDescriptor{
			requiredStringField("message", FieldClassContent, 32),
			{
				key: "tags", typeOf: familyFieldStringArray, requirement: familyRequirementOptional,
				fieldClass: FieldClassIdentifier, source: familyValueInput,
				constraints: familyFieldConstraints{maxUTF8Bytes: 32, maxItemUTF8Bytes: 12, maxItems: 3},
			},
			{
				key: "secret", typeOf: familyFieldString, requirement: familyRequirementConditional,
				conditionID: "secret-available", falseRequirement: familyFalseForbidden,
				fieldClass: FieldClassCredential, source: familyValueInput,
				constraints: familyFieldConstraints{maxUTF8Bytes: 32},
			},
		},
	}
	return &testGeneratedLogFamily{contract: contract, identity: identity, mandatory: true}
}

func validLogBuildInput() familyLogBuildInput {
	return familyLogBuildInput{
		envelope: testFamilyEnvelope(), severity: Present(SeverityInfo), logLevel: Present(LogLevelInfo),
		outcome: Present(OutcomeCompleted),
		values: familyFieldValues{
			{key: "message", value: "safe message", present: true},
			{key: "tags", value: []string{"one", "two"}, present: true},
		},
		conditions: familyConditionFacts{{id: "secret-available", state: familyConditionFalse}},
	}
}

func TestFamilyBuilderStringArrayBoundsAreShapeAware(t *testing.T) {
	descriptor := familyFieldDescriptor{
		key: "tags", typeOf: familyFieldStringArray, requirement: familyRequirementOptional,
		fieldClass: FieldClassIdentifier, source: familyValueInput,
		constraints: familyFieldConstraints{
			maxUTF8Bytes: 20, maxItemUTF8Bytes: 4, minItems: 1, maxItems: 3,
		},
	}
	if err := validateFamilyFieldConstraintDescriptor(descriptor); err != nil {
		t.Fatalf("valid string-array descriptor: %v", err)
	}
	for _, tc := range []struct {
		name  string
		value []string
		ok    bool
	}{
		{name: "within item and aggregate limits", value: []string{"éé", "a"}, ok: true},
		{name: "item UTF-8 limit", value: []string{"aaaaa"}},
		{name: "canonical JSON aggregate limit", value: []string{"aaaa", "bbbb", "cccc"}},
		{name: "item count limit", value: []string{"a", "b", "c", "d"}},
		{name: "invalid UTF-8", value: []string{string([]byte{0xff})}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			err := validateFamilyFieldValue(descriptor, tc.value)
			if tc.ok && err != nil {
				t.Fatalf("valid string array rejected: %v", err)
			}
			if !tc.ok && !IsFamilyBuildError(err, FamilyBuildConstraint) {
				t.Fatalf("invalid string array error = %v", err)
			}
		})
	}
	if err := validateFamilyFieldValue(descriptor, []string(nil)); !IsFamilyBuildError(err, FamilyBuildInvalidType) {
		t.Fatalf("present nil string array error = %v", err)
	}
	multibyte := descriptor
	multibyte.constraints.maxItemUTF8Bytes = 3
	if err := validateFamilyFieldValue(multibyte, []string{"éé"}); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("four-byte string under three-byte item limit error = %v", err)
	}
	escaped := descriptor
	escaped.constraints.maxUTF8Bytes = 6
	if err := validateFamilyFieldValue(escaped, []string{"\n"}); err != nil {
		t.Fatalf("six-byte canonical escaped array rejected: %v", err)
	}
	escaped.constraints.maxUTF8Bytes = 5
	if err := validateFamilyFieldValue(escaped, []string{"\n"}); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("escaped canonical aggregate boundary error = %v", err)
	}

	builder, _ := testFamilyBuilder(t)
	input := validLogBuildInput()
	input.values[1].value = []string(nil)
	if _, err := builder.buildGeneratedLog(testLogFamily(), input); !IsFamilyBuildError(err, FamilyBuildInvalidType) {
		t.Fatalf("generated builder present nil string array error = %v", err)
	}
}

func testTraceFamily() *testGeneratedTraceFamily {
	identity := EventIdentity{Bucket: BucketAgentLifecycle, Signal: SignalTraces, Name: "span.workflow.run"}
	base := familyDescriptorContract{
		id: "span.workflow.run", identity: identity, familySchemaVersion: 1,
		outcome: familyOutcomePolicy{
			requirement: familyRequirementRequired,
			allowed:     []Outcome{OutcomeCompleted, OutcomeFailed},
		},
		fields: []familyFieldDescriptor{
			{
				key: "defenseclaw.bucket", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
				source: familyValueBucket,
			},
			{
				key: "defenseclaw.span.family", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassIdentifier,
				source: familyValueFamily,
			},
			{
				key: "defenseclaw.span.family_schema_version", typeOf: familyFieldUint32,
				requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
				source: familyValueFamilySchemaVersion,
			},
			{
				key: "defenseclaw.source", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassIdentifier,
				source: familyValueSourceName,
			},
			{
				key: "defenseclaw.config.generation", typeOf: familyFieldInt64,
				requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
				source: familyValueConfigGeneration,
			},
			{
				key: "defenseclaw.outcome", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
				source: familyValueOutcome,
			},
			{
				key: "defenseclaw.workflow.name", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassIdentifier,
				source: familyValueInput,
				constraints: familyFieldConstraints{
					maxUTF8Bytes: 128, pattern: `^[a-z0-9][a-z0-9_.-]{0,127}$`,
				},
			},
			{
				key: "error.type", typeOf: familyFieldString,
				requirement: familyRequirementConditional, conditionID: "technical-failure",
				falseRequirement: familyFalseOptional, fieldClass: FieldClassError,
				source: familyValueInput, constraints: familyFieldConstraints{maxUTF8Bytes: 32},
			},
		},
	}
	trace := familyTraceContract{
		familyDescriptorContract: base,
		allowedKinds:             []string{"INTERNAL"},
		attributeLimits:          testFamilyStructuredLimits(),
		spanName: []spanNamePart{
			{literal: "workflow "}, {field: "defenseclaw.workflow.name"},
		},
		resourceFields: []familyFieldDescriptor{
			requiredStringField("service.name", FieldClassMetadata, 64),
			{
				key: "service.version", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
				source: familyValueBinaryVersion,
			},
		},
		resourceLimits: testFamilyStructuredLimits(),
		scopeFields: []familyFieldDescriptor{
			{
				key: "defenseclaw.trace.schema_version", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
				source: familyValueTraceSchemaVersion,
			},
			{
				key: "defenseclaw.semantic_profile", typeOf: familyFieldString,
				requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
				source: familyValueSemanticProfile,
			},
		},
		scopeLimits:   testFamilyStructuredLimits(),
		allowedEvents: []familyEventContract{{id: "event.content.redacted", name: "content.redacted"}},
		eventLimits:   testFamilyStructuredLimits(),
		maxEvents:     128,
		allowedLinks:  []string{"caused_by"},
		linkFields: []familyFieldDescriptor{{
			key: "defenseclaw.link.relation", typeOf: familyFieldString,
			requirement: familyRequirementRequired, fieldClass: FieldClassMetadata,
			source:      familyValueLinkRelation,
			constraints: familyFieldConstraints{enum: []string{"caused_by"}},
		}},
		linkLimits: testFamilyStructuredLimits(), maxLinks: 64,
		scopeName: "defenseclaw.telemetry", scopeSchemaURL: "https://defenseclaw.io/schemas/telemetry/v8",
		traceSchemaVersion: RuntimeTraceSchemaVersion, semanticProfile: RuntimeSemanticProfileID,
	}
	return &testGeneratedTraceFamily{base: base, trace: trace}
}

func validTraceBuildInput(family *testGeneratedTraceFamily) familyTraceBuildInput {
	envelope := testFamilyEnvelope()
	envelope.Correlation.TraceID = "0123456789abcdef0123456789abcdef"
	envelope.Correlation.SpanID = "0123456789abcdef"
	return familyTraceBuildInput{
		envelope: envelope, outcome: Present(OutcomeCompleted), kind: "INTERNAL",
		startTimeUnixNano: 10, endTimeUnixNano: 20,
		parentSpanID: Present("1111111111111111"), traceState: Present("vendor=value"), flags: 0x301,
		status: NewTraceStatusOK(),
		resource: TraceResourceInput{
			SchemaURL:              "https://opentelemetry.io/schemas/1.42.0",
			DroppedAttributesCount: Present(uint32(0)),
			values:                 familyFieldValues{{key: "service.name", value: "defenseclaw", present: true}},
		},
		scope:      TraceScopeInput{DroppedAttributesCount: Present(uint32(0))},
		values:     familyFieldValues{{key: "defenseclaw.workflow.name", value: "retrieval-turn", present: true}},
		conditions: familyConditionFacts{{id: "technical-failure", state: familyConditionFalse}},
		events: []TraceEventInput{{
			TimeUnixNano: 15, DroppedAttributesCount: Present(uint32(0)),
			contract: family.trace.allowedEvents[0],
		}},
		droppedEventsCount: Present(uint32(0)),
		links: []TraceLinkInput{{
			TraceID: "11111111111111111111111111111111", SpanID: "2222222222222222",
			TraceState: Present("vendor=value"), DroppedAttributesCount: Present(uint32(0)),
			relation: "caused_by",
		}},
		droppedLinksCount: Present(uint32(0)), droppedAttributesCount: Present(uint32(0)),
	}
}

func testMetricFamily(valueType familyMetricNumberType) *testGeneratedMetricFamily {
	base := familyDescriptorContract{
		id: "metric.defenseclaw.activity.total",
		identity: EventIdentity{
			Bucket: BucketComplianceActivity, Signal: SignalMetrics, Name: "defenseclaw.activity.total",
		},
		familySchemaVersion: 1,
		fields: []familyFieldDescriptor{{
			key: "defenseclaw.metric.kind", typeOf: familyFieldString,
			requirement: familyRequirementOptional, fieldClass: FieldClassMetadata,
			source:      familyValueInput,
			constraints: familyFieldConstraints{maxUTF8Bytes: 16, enum: []string{"audit", "config"}},
		}},
	}
	metric := familyMetricContract{
		familyDescriptorContract: base, valueType: valueType, attributeLimits: testFamilyStructuredLimits(),
		instrumentName: "defenseclaw.activity.total", instrumentType: "counter",
		unit: "{event}", temporality: "delta",
	}
	return &testGeneratedMetricFamily{base: base, metric: metric}
}

func TestFamilyBuilderBuildsImmutableLogFromPrivateContract(t *testing.T) {
	builder, ids := testFamilyBuilder(t)
	family := testLogFamily()
	input := validLogBuildInput()
	record, err := builder.buildGeneratedLog(family, input)
	if err != nil {
		t.Fatal(err)
	}
	if !record.Mandatory() || !record.SchemaDerivedFieldClasses() || record.IsFloorOnly() ||
		record.Identity() != family.identity || record.Outcome() != OutcomeCompleted {
		t.Fatalf("record trust state changed: %#v", record.data)
	}
	classes := record.FieldClasses()
	for pointer, expected := range map[string]FieldClass{
		"/message": FieldClassContent, "/tags/0": FieldClassIdentifier, "/tags/1": FieldClassIdentifier,
	} {
		if classes[pointer] != expected {
			t.Fatalf("class %s = %q", pointer, classes[pointer])
		}
	}
	if ids.count.Load() != 1 {
		t.Fatalf("occurrence calls = %d", ids.count.Load())
	}
	input.values[0].value = "caller mutation"
	family.contract.fields[0].fieldClass = FieldClassCredential
	bodyValue, ok := record.Body()
	if !ok {
		t.Fatal("log record has no body")
	}
	body, _ := bodyValue.Object()
	if body["message"] != "safe message" || record.FieldClasses()["/message"] != FieldClassContent {
		t.Fatalf("record retained mutable aliases: body=%#v classes=%#v", body, record.FieldClasses())
	}
	provenance := record.Provenance()
	if provenance.RegistrySchemaVersion != CurrentRecordSchemaVersion || provenance.ConfigGeneration != 9 {
		t.Fatalf("derived provenance = %+v", provenance)
	}
}

func TestFamilyBuilderUsesPrivateResolvedMandatoryResult(t *testing.T) {
	for _, mandatory := range []bool{false, true} {
		t.Run("mandatory="+map[bool]string{false: "false", true: "true"}[mandatory], func(t *testing.T) {
			builder, ids := testFamilyBuilder(t)
			family := testLogFamily()
			family.mandatory = !mandatory
			record, err := builder.buildGeneratedResolvedLog(
				family,
				resolveGeneratedLogMandatory(mandatory),
				validLogBuildInput(),
			)
			if err != nil {
				t.Fatal(err)
			}
			if record.Mandatory() != mandatory {
				t.Fatalf("record mandatory = %t, want %t", record.Mandatory(), mandatory)
			}
			if ids.count.Load() != 1 {
				t.Fatalf("occurrence calls = %d", ids.count.Load())
			}
		})
	}

	t.Run("uninitialized contract rejected", func(t *testing.T) {
		builder, ids := testFamilyBuilder(t)
		_, err := builder.buildGeneratedResolvedLog(
			testLogFamily(),
			resolvedGeneratedLogContract{},
			validLogBuildInput(),
		)
		if !IsFamilyBuildError(err, FamilyBuildInvalidDescriptor) {
			t.Fatalf("uninitialized contract error = %v", err)
		}
		if ids.count.Load() != 0 {
			t.Fatalf("uninitialized contract consumed occurrence: %d", ids.count.Load())
		}
	})
}

func TestFamilyBuilderEnforcesForbiddenOutcomeContract(t *testing.T) {
	builder, ids := testFamilyBuilder(t)
	family := testLogFamily()
	family.contract.outcome = familyOutcomePolicy{requirement: familyRequirementForbidden}
	input := validLogBuildInput()
	input.outcome = Absent[Outcome]()
	if _, err := builder.buildGeneratedLog(family, input); err != nil {
		t.Fatalf("build outcome-free family: %v", err)
	}
	input.outcome = Present(OutcomeCompleted)
	if _, err := builder.buildGeneratedLog(family, input); !IsFamilyBuildError(err, FamilyBuildForbiddenField) {
		t.Fatalf("forbidden outcome error = %v", err)
	}
	if ids.count.Load() != 1 {
		t.Fatalf("forbidden outcome consumed an occurrence ID: %d", ids.count.Load())
	}
}

func TestFamilyBuilderAllowsSchemaDerivedEmptyLogBody(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	family := testLogFamily()
	family.contract.fields = nil
	family.contract.outcome = familyOutcomePolicy{requirement: familyRequirementForbidden}
	input := validLogBuildInput()
	input.values = nil
	input.conditions = nil
	input.outcome = Absent[Outcome]()
	record, err := builder.buildGeneratedLog(family, input)
	if err != nil {
		t.Fatal(err)
	}
	if classes := record.FieldClasses(); len(classes) != 0 || !record.SchemaDerivedFieldClasses() {
		t.Fatalf("empty body classification = %#v/schema-derived=%t", classes, record.SchemaDerivedFieldClasses())
	}
	body, present := record.Body()
	if !present || string(body.Bytes()) != "{}" {
		t.Fatalf("empty body = %q/present=%t", body.Bytes(), present)
	}
}

func TestFamilyBuilderBuildsExactTraceStructure(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	family := testTraceFamily()
	record, err := builder.buildGeneratedTrace(family, validTraceBuildInput(family))
	if err != nil {
		t.Fatal(err)
	}
	if record.SpanName() != "workflow retrieval-turn" || record.Signal() != SignalTraces ||
		record.Mandatory() || !record.SchemaDerivedFieldClasses() {
		t.Fatalf("trace identity/trust state changed: %#v", record.data)
	}
	bodyValue, ok := record.Body()
	if !ok {
		t.Fatal("trace record has no body")
	}
	body, err := bodyValue.Object()
	if err != nil {
		t.Fatal(err)
	}
	if body["trace_state"] != "vendor=value" || body["flags"] != json.Number("769") {
		t.Fatalf("trace context body = state=%#v flags=%#v", body["trace_state"], body["flags"])
	}
	attributes := body["attributes"].(map[string]any)
	for key, expected := range map[string]any{
		"defenseclaw.bucket":                     string(BucketAgentLifecycle),
		"defenseclaw.span.family":                "span.workflow.run",
		"defenseclaw.span.family_schema_version": json.Number("1"),
		"defenseclaw.source":                     string(SourceSystem),
		"defenseclaw.config.generation":          json.Number("9"),
		"defenseclaw.outcome":                    string(OutcomeCompleted),
		"defenseclaw.workflow.name":              "retrieval-turn",
	} {
		if !reflect.DeepEqual(attributes[key], expected) {
			t.Fatalf("trace attribute %s = %#v, want %#v", key, attributes[key], expected)
		}
	}
	classes := record.FieldClasses()
	for _, pointer := range []string{
		"/trace_state", "/flags",
		"/events/0/attributes", "/events/0/dropped_attributes_count",
		"/links/0/attributes/defenseclaw.link.relation", "/links/0/trace_state",
		"/resource/dropped_attributes_count", "/scope/dropped_attributes_count",
		"/dropped_attributes_count", "/dropped_events_count", "/dropped_links_count",
	} {
		if _, exists := classes[pointer]; !exists {
			t.Fatalf("missing concrete trace class %s in %#v", pointer, classes)
		}
	}
	if err := verifyFamilyFieldClassCoverage(body, classes); err != nil {
		t.Fatal(err)
	}
}

func TestFamilyBuilderBuildsMetricWithoutInstrumentOrLogState(t *testing.T) {
	builder, _ := testFamilyBuilder(t)
	family := testMetricFamily(familyMetricNumberInt64)
	record, err := builder.buildGeneratedMetric(family, familyMetricBuildInput{
		envelope: testFamilyEnvelope(), value: familyInt64MetricNumber(3),
		labels: familyFieldValues{{key: "defenseclaw.metric.kind", value: "audit", present: true}},
	})
	if err != nil {
		t.Fatal(err)
	}
	if record.Signal() != SignalMetrics || record.Outcome() != "" || record.Mandatory() || record.SpanName() != "" {
		t.Fatalf("metric envelope state = %#v", record.data)
	}
	instrumentValue, ok := record.InstrumentData()
	if !ok {
		t.Fatal("metric record has no instrument data")
	}
	instrument, err := instrumentValue.Object()
	if err != nil {
		t.Fatal(err)
	}
	if _, exists := instrument["instrument_name"]; exists || len(instrument) != 2 {
		t.Fatalf("metric repeated instrument metadata: %#v", instrument)
	}
	if got := instrument["value"]; got != json.Number("3") {
		t.Fatalf("metric value = %#v", got)
	}
	if err := verifyFamilyFieldClassCoverage(instrument, record.FieldClasses()); err != nil {
		t.Fatal(err)
	}
}

func TestFamilyBuilderRejectsAdversarialLogInputsBeforeOccurrence(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testGeneratedLogFamily, *familyLogBuildInput)
		code   FamilyBuildErrorCode
	}{
		{name: "missing required", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) { input.values[0].present = false }, code: FamilyBuildMissingRequired},
		{name: "unknown field", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) {
			input.values = append(input.values, familyFieldValue{key: "attacker.key", value: "secret", present: true})
		}, code: FamilyBuildUnknownField},
		{name: "duplicate field", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) {
			input.values = append(input.values, input.values[0])
		}, code: FamilyBuildDuplicateField},
		{name: "wrong type", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) { input.values[0].value = int64(7) }, code: FamilyBuildInvalidType},
		{name: "bounded string", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) {
			input.values[0].value = strings.Repeat("x", 33)
		}, code: FamilyBuildConstraint},
		{name: "conditional true missing", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) {
			input.conditions[0].state = familyConditionTrue
		}, code: FamilyBuildMissingRequired},
		{name: "conditional false forbidden", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) {
			input.values = append(input.values, familyFieldValue{key: "secret", value: "RAW-SECRET", present: true})
		}, code: FamilyBuildForbiddenField},
		{name: "unknown fact", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) { input.conditions[0].id = "attacker-fact" }, code: FamilyBuildInvalidCondition},
		{name: "invalid outcome", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) { input.outcome = Present(OutcomeBlocked) }, code: FamilyBuildInvalidOutcome},
		{name: "descriptor identity mismatch", mutate: func(family *testGeneratedLogFamily, _ *familyLogBuildInput) {
			family.identity.Name = "diagnostic.snapshot"
		}, code: FamilyBuildInvalidDescriptor},
		{name: "invalid observed timestamp", mutate: func(_ *testGeneratedLogFamily, input *familyLogBuildInput) {
			input.envelope.ObservedAt = Present(time.Date(10_000, 1, 1, 0, 0, 0, 0, time.UTC))
		}, code: FamilyBuildRecordRejected},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, ids := testFamilyBuilder(t)
			family := testLogFamily()
			input := validLogBuildInput()
			test.mutate(family, &input)
			_, err := builder.buildGeneratedLog(family, input)
			if !IsFamilyBuildError(err, test.code) {
				t.Fatalf("error = %v, want %s", err, test.code)
			}
			if err != nil && (strings.Contains(err.Error(), "RAW-SECRET") || strings.Contains(err.Error(), "attacker")) {
				t.Fatalf("error leaked rejected value: %q", err)
			}
			if ids.count.Load() != 0 {
				t.Fatalf("invalid input consumed %d occurrence IDs", ids.count.Load())
			}
		})
	}
}

func TestFamilyBuilderRejectsAdversarialTraceInputs(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*testGeneratedTraceFamily, *familyTraceBuildInput)
		code   FamilyBuildErrorCode
	}{
		{name: "zero trace ID", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.envelope.Correlation.TraceID = strings.Repeat("0", 32)
		}, code: FamilyBuildInvalidTrace},
		{name: "upper trace ID", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.envelope.Correlation.TraceID = "0123456789ABCDEF0123456789ABCDEF"
		}, code: FamilyBuildInvalidTrace},
		{name: "end before start", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.endTimeUnixNano = input.startTimeUnixNano - 1
		}, code: FamilyBuildInvalidTrace},
		{name: "noncanonical trace state", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.traceState = Present("vendor=value, vendor2=value")
		}, code: FamilyBuildInvalidTrace},
		{name: "unknown kind", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) { input.kind = "CLIENT" }, code: FamilyBuildInvalidTrace},
		{name: "bad workflow token", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.values[0].value = "Retrieval Turn"
		}, code: FamilyBuildConstraint},
		{name: "status contradiction", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.status = TraceStatusInput{code: TraceStatusOK, description: Present("secret error")}
		}, code: FamilyBuildInvalidTrace},
		{name: "unknown event", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.events[0].contract.id = "event.unknown"
		}, code: FamilyBuildInvalidTrace},
		{name: "unknown link relation", mutate: func(_ *testGeneratedTraceFamily, input *familyTraceBuildInput) {
			input.links[0].relation = "attacker_relation"
		}, code: FamilyBuildInvalidTrace},
		{name: "recommended span name field", mutate: func(family *testGeneratedTraceFamily, _ *familyTraceBuildInput) {
			for index := range family.trace.fields {
				if family.trace.fields[index].key == "defenseclaw.workflow.name" {
					family.trace.fields[index].requirement = familyRequirementRecommended
				}
			}
		}, code: FamilyBuildInvalidDescriptor},
		{name: "optional span name field", mutate: func(family *testGeneratedTraceFamily, _ *familyTraceBuildInput) {
			for index := range family.trace.fields {
				if family.trace.fields[index].key == "defenseclaw.workflow.name" {
					family.trace.fields[index].requirement = familyRequirementOptional
				}
			}
		}, code: FamilyBuildInvalidDescriptor},
		{name: "conditional span name field", mutate: func(family *testGeneratedTraceFamily, _ *familyTraceBuildInput) {
			for index := range family.trace.fields {
				if family.trace.fields[index].key == "defenseclaw.workflow.name" {
					family.trace.fields[index].requirement = familyRequirementConditional
					family.trace.fields[index].conditionID = "workflow-name-available"
					family.trace.fields[index].falseRequirement = familyFalseOptional
				}
			}
		}, code: FamilyBuildInvalidDescriptor},
		{name: "descriptor split brain", mutate: func(family *testGeneratedTraceFamily, _ *familyTraceBuildInput) { family.base.familySchemaVersion = 2 }, code: FamilyBuildInvalidDescriptor},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, ids := testFamilyBuilder(t)
			family := testTraceFamily()
			input := validTraceBuildInput(family)
			test.mutate(family, &input)
			_, err := builder.buildGeneratedTrace(family, input)
			if !IsFamilyBuildError(err, test.code) {
				t.Fatalf("trace error = %v, want %s", err, test.code)
			}
			if err != nil && (strings.Contains(err.Error(), "secret") || strings.Contains(err.Error(), "attacker")) {
				t.Fatalf("trace error leaked value: %q", err)
			}
			if ids.count.Load() != 0 {
				t.Fatalf("invalid trace consumed occurrence ID")
			}
		})
	}
}

func TestFamilyBuilderEnforcesTraceCollectionBounds(t *testing.T) {
	builder, ids := testFamilyBuilder(t)
	family := testTraceFamily()
	input := validTraceBuildInput(family)
	input.events = append(input.events, input.events[0])
	family.trace.maxEvents = 1
	if _, err := builder.buildGeneratedTrace(family, input); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("event bound error = %v", err)
	}

	family = testTraceFamily()
	input = validTraceBuildInput(family)
	input.links = append(input.links, input.links[0])
	family.trace.maxLinks = 1
	if _, err := builder.buildGeneratedTrace(family, input); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("link bound error = %v", err)
	}
	if ids.count.Load() != 0 {
		t.Fatalf("collection bound failures consumed occurrence IDs")
	}
}

func testConditionalTraceFamily() *testGeneratedTraceFamily {
	family := testTraceFamily()
	family.trace.allowedEvents[0].fields = []familyFieldDescriptor{{
		key: "event.detail", typeOf: familyFieldString, requirement: familyRequirementConditional,
		conditionID: "event-detail-present", falseRequirement: familyFalseForbidden,
		fieldClass: FieldClassEvidence, source: familyValueInput,
		constraints: familyFieldConstraints{maxUTF8Bytes: 32},
	}}
	family.trace.linkFields = append(family.trace.linkFields, familyFieldDescriptor{
		key: "link.detail", typeOf: familyFieldString, requirement: familyRequirementConditional,
		conditionID: "link-detail-present", falseRequirement: familyFalseForbidden,
		fieldClass: FieldClassReason, source: familyValueInput,
		constraints: familyFieldConstraints{maxUTF8Bytes: 32},
	})
	return family
}

func TestFamilyBuilderTraceConditionClosureUsesOnlyInstantiatedEventsAndLinks(t *testing.T) {
	t.Run("inactive families need no facts", func(t *testing.T) {
		builder, ids := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		input := validTraceBuildInput(family)
		input.events = nil
		input.links = nil
		if _, err := builder.buildGeneratedTrace(family, input); err != nil {
			t.Fatal(err)
		}
		if ids.count.Load() != 1 {
			t.Fatalf("occurrence calls = %d", ids.count.Load())
		}
	})

	t.Run("active false facts permit absent fields", func(t *testing.T) {
		builder, _ := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		input := validTraceBuildInput(family)
		input.events[0].conditions = familyConditionFacts{{
			id: "event-detail-present", state: familyConditionFalse,
		}}
		input.links[0].conditions = familyConditionFacts{{
			id: "link-detail-present", state: familyConditionFalse,
		}}
		if _, err := builder.buildGeneratedTrace(family, input); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("active true facts require and classify present fields", func(t *testing.T) {
		builder, _ := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		input := validTraceBuildInput(family)
		input.events[0].conditions = familyConditionFacts{{
			id: "event-detail-present", state: familyConditionTrue,
		}}
		input.links[0].conditions = familyConditionFacts{{
			id: "link-detail-present", state: familyConditionTrue,
		}}
		input.events[0].values = familyFieldValues{{key: "event.detail", value: "event evidence", present: true}}
		input.links[0].values = familyFieldValues{{key: "link.detail", value: "link reason", present: true}}
		record, err := builder.buildGeneratedTrace(family, input)
		if err != nil {
			t.Fatal(err)
		}
		classes := record.FieldClasses()
		if classes["/events/0/attributes/event.detail"] != FieldClassEvidence ||
			classes["/links/0/attributes/link.detail"] != FieldClassReason {
			t.Fatalf("conditional classes = %#v", classes)
		}
	})

	for _, instance := range []string{"event", "link"} {
		t.Run("active "+instance+" missing fact fails before occurrence", func(t *testing.T) {
			builder, ids := testFamilyBuilder(t)
			family := testConditionalTraceFamily()
			input := validTraceBuildInput(family)
			if instance == "event" {
				input.links = nil
			} else {
				input.events = nil
			}
			_, err := builder.buildGeneratedTrace(family, input)
			if !IsFamilyBuildError(err, FamilyBuildInvalidCondition) {
				t.Fatalf("missing %s fact error = %v", instance, err)
			}
			if ids.count.Load() != 0 {
				t.Fatalf("missing %s fact consumed occurrence", instance)
			}
		})
	}
}

func TestFamilyBuilderRejectsMissingExtraAndMisplacedComponentConditions(t *testing.T) {
	tests := []struct {
		name   string
		mutate func(*familyTraceBuildInput)
	}{
		{
			name: "family missing",
			mutate: func(input *familyTraceBuildInput) {
				input.conditions = nil
			},
		},
		{
			name: "family has event fact",
			mutate: func(input *familyTraceBuildInput) {
				input.conditions = append(input.conditions, familyConditionFact{
					id: "event-detail-present", state: familyConditionFalse,
				})
			},
		},
		{
			name: "event missing",
			mutate: func(input *familyTraceBuildInput) {
				input.events[0].conditions = nil
			},
		},
		{
			name: "event has family fact",
			mutate: func(input *familyTraceBuildInput) {
				input.events[0].conditions = append(input.events[0].conditions, familyConditionFact{
					id: "technical-failure", state: familyConditionFalse,
				})
			},
		},
		{
			name: "event duplicate",
			mutate: func(input *familyTraceBuildInput) {
				input.events[0].conditions = append(input.events[0].conditions, input.events[0].conditions[0])
			},
		},
		{
			name: "event invalid state",
			mutate: func(input *familyTraceBuildInput) {
				input.events[0].conditions[0].state = familyConditionUnknown
			},
		},
		{
			name: "link missing",
			mutate: func(input *familyTraceBuildInput) {
				input.links[0].conditions = nil
			},
		},
		{
			name: "link has family fact",
			mutate: func(input *familyTraceBuildInput) {
				input.links[0].conditions = append(input.links[0].conditions, familyConditionFact{
					id: "technical-failure", state: familyConditionFalse,
				})
			},
		},
		{
			name: "link duplicate",
			mutate: func(input *familyTraceBuildInput) {
				input.links[0].conditions = append(input.links[0].conditions, input.links[0].conditions[0])
			},
		},
		{
			name: "link invalid state",
			mutate: func(input *familyTraceBuildInput) {
				input.links[0].conditions[0].state = familyConditionUnknown
			},
		},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, ids := testFamilyBuilder(t)
			family := testConditionalTraceFamily()
			input := validTraceBuildInput(family)
			input.events[0].conditions = familyConditionFacts{{
				id: "event-detail-present", state: familyConditionFalse,
			}}
			input.links[0].conditions = familyConditionFacts{{
				id: "link-detail-present", state: familyConditionFalse,
			}}
			test.mutate(&input)
			_, err := builder.buildGeneratedTrace(family, input)
			if !IsFamilyBuildError(err, FamilyBuildInvalidCondition) {
				t.Fatalf("component condition error = %v", err)
			}
			if ids.count.Load() != 0 {
				t.Fatalf("invalid component condition consumed occurrence: %d", ids.count.Load())
			}
		})
	}
}

func TestFamilyBuilderMergesOnlyActiveComponentConditions(t *testing.T) {
	t.Run("inactive component fact rejected", func(t *testing.T) {
		builder, ids := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		input := validTraceBuildInput(family)
		input.events = nil
		input.links = nil
		input.conditions = append(input.conditions, familyConditionFact{
			id: "event-detail-present", state: familyConditionFalse,
		})
		_, err := builder.buildGeneratedTrace(family, input)
		if !IsFamilyBuildError(err, FamilyBuildInvalidCondition) {
			t.Fatalf("inactive component fact error = %v", err)
		}
		if ids.count.Load() != 0 {
			t.Fatalf("inactive component fact consumed occurrence: %d", ids.count.Load())
		}
	})

	t.Run("matching shared fact accepted", func(t *testing.T) {
		builder, _ := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		family.trace.linkFields[1].conditionID = "event-detail-present"
		input := validTraceBuildInput(family)
		input.events[0].conditions = familyConditionFacts{{
			id: "event-detail-present", state: familyConditionFalse,
		}}
		input.links[0].conditions = familyConditionFacts{{
			id: "event-detail-present", state: familyConditionFalse,
		}}
		if _, err := builder.buildGeneratedTrace(family, input); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("conflicting shared fact rejected", func(t *testing.T) {
		builder, ids := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		family.trace.linkFields[1].conditionID = "event-detail-present"
		input := validTraceBuildInput(family)
		input.events[0].conditions = familyConditionFacts{{
			id: "event-detail-present", state: familyConditionFalse,
		}}
		input.links[0].conditions = familyConditionFacts{{
			id: "event-detail-present", state: familyConditionTrue,
		}}
		_, err := builder.buildGeneratedTrace(family, input)
		if !IsFamilyBuildError(err, FamilyBuildInvalidCondition) {
			t.Fatalf("conflicting component fact error = %v", err)
		}
		if ids.count.Load() != 0 {
			t.Fatalf("conflicting component fact consumed occurrence: %d", ids.count.Load())
		}
	})

	t.Run("matching family and event fact accepted", func(t *testing.T) {
		builder, _ := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		family.trace.allowedEvents[0].fields[0].conditionID = "technical-failure"
		input := validTraceBuildInput(family)
		input.events[0].conditions = familyConditionFacts{{
			id: "technical-failure", state: familyConditionFalse,
		}}
		input.links = nil
		if _, err := builder.buildGeneratedTrace(family, input); err != nil {
			t.Fatal(err)
		}
	})

	t.Run("conflicting family and event fact rejected", func(t *testing.T) {
		builder, ids := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		family.trace.allowedEvents[0].fields[0].conditionID = "technical-failure"
		input := validTraceBuildInput(family)
		input.events[0].conditions = familyConditionFacts{{
			id: "technical-failure", state: familyConditionTrue,
		}}
		input.links = nil
		_, err := builder.buildGeneratedTrace(family, input)
		if !IsFamilyBuildError(err, FamilyBuildInvalidCondition) {
			t.Fatalf("conflicting family/event fact error = %v", err)
		}
		if ids.count.Load() != 0 {
			t.Fatalf("conflicting family/event fact consumed occurrence: %d", ids.count.Load())
		}
	})

	t.Run("every repeated event instance must provide its fact", func(t *testing.T) {
		builder, ids := testFamilyBuilder(t)
		family := testConditionalTraceFamily()
		input := validTraceBuildInput(family)
		input.events[0].conditions = familyConditionFacts{{
			id: "event-detail-present", state: familyConditionFalse,
		}}
		input.events = append(input.events, TraceEventInput{
			TimeUnixNano: 16,
			contract:     family.trace.allowedEvents[0],
		})
		input.links = nil
		_, err := builder.buildGeneratedTrace(family, input)
		if !IsFamilyBuildError(err, FamilyBuildInvalidCondition) {
			t.Fatalf("repeated event missing fact error = %v", err)
		}
		if ids.count.Load() != 0 {
			t.Fatalf("repeated event missing fact consumed occurrence: %d", ids.count.Load())
		}
	})
}

func TestFamilyBuilderRejectsMetricTypeAndFiniteViolations(t *testing.T) {
	builder, ids := testFamilyBuilder(t)
	_, err := builder.buildGeneratedMetric(testMetricFamily(familyMetricNumberInt64), familyMetricBuildInput{
		envelope: testFamilyEnvelope(), value: familyDoubleMetricNumber(1),
	})
	if !IsFamilyBuildError(err, FamilyBuildInvalidMetric) {
		t.Fatalf("metric type error = %v", err)
	}
	_, err = builder.buildGeneratedMetric(testMetricFamily(familyMetricNumberDouble), familyMetricBuildInput{
		envelope: testFamilyEnvelope(), value: familyDoubleMetricNumber(math.NaN()),
	})
	if !IsFamilyBuildError(err, FamilyBuildInvalidMetric) {
		t.Fatalf("metric finite error = %v", err)
	}
	_, err = builder.buildGeneratedMetric(testMetricFamily(familyMetricNumberInt64), familyMetricBuildInput{
		envelope: testFamilyEnvelope(), value: familyInt64MetricNumber(1),
		labels: familyFieldValues{{key: "unregistered.label", value: "secret", present: true}},
	})
	if !IsFamilyBuildError(err, FamilyBuildUnknownField) {
		t.Fatalf("metric closure error = %v", err)
	}
	if ids.count.Load() != 0 {
		t.Fatalf("invalid metrics consumed occurrence IDs")
	}
}

func TestFamilyBuilderRejectsSensitiveMetricLabelClasses(t *testing.T) {
	unsafeClasses := []FieldClass{
		FieldClassContent,
		FieldClassCredential,
		FieldClassPath,
		FieldClassReason,
		FieldClassEvidence,
		FieldClassError,
	}
	for _, fieldClass := range unsafeClasses {
		t.Run(string(fieldClass), func(t *testing.T) {
			builder, ids := testFamilyBuilder(t)
			family := testMetricFamily(familyMetricNumberInt64)
			family.base.fields[0].fieldClass = fieldClass
			family.metric.familyDescriptorContract = family.base
			_, err := builder.buildGeneratedMetric(family, familyMetricBuildInput{
				envelope: testFamilyEnvelope(), value: familyInt64MetricNumber(1),
			})
			if !IsFamilyBuildError(err, FamilyBuildInvalidDescriptor) {
				t.Fatalf("unsafe metric class error = %v", err)
			}
			if ids.count.Load() != 0 {
				t.Fatal("unsafe metric class consumed occurrence")
			}
		})
	}

	builder, _ := testFamilyBuilder(t)
	family := testMetricFamily(familyMetricNumberInt64)
	family.base.fields[0].fieldClass = FieldClassIdentifier
	family.metric.familyDescriptorContract = family.base
	if _, err := builder.buildGeneratedMetric(family, familyMetricBuildInput{
		envelope: testFamilyEnvelope(), value: familyInt64MetricNumber(1),
	}); err != nil {
		t.Fatalf("identifier metric label rejected: %v", err)
	}
}

func TestFamilyBuilderRejectsDerivedSourceTypeMismatch(t *testing.T) {
	derivedSources := []struct {
		name   string
		source familyValueSource
	}{
		{name: "bucket", source: familyValueBucket},
		{name: "family", source: familyValueFamily},
		{name: "family schema version", source: familyValueFamilySchemaVersion},
		{name: "source", source: familyValueSourceName},
		{name: "config generation", source: familyValueConfigGeneration},
		{name: "outcome", source: familyValueOutcome},
		{name: "binary version", source: familyValueBinaryVersion},
		{name: "trace schema version", source: familyValueTraceSchemaVersion},
		{name: "semantic profile", source: familyValueSemanticProfile},
		{name: "link relation", source: familyValueLinkRelation},
	}
	for _, test := range derivedSources {
		t.Run(test.name, func(t *testing.T) {
			descriptor := familyFieldDescriptor{
				key: "derived.field", typeOf: familyFieldBoolean,
				requirement: familyRequirementRequired,
				fieldClass:  FieldClassMetadata,
				source:      test.source,
			}
			if err := validateFamilyFieldDescriptors([]familyFieldDescriptor{descriptor}); !IsFamilyBuildError(err, FamilyBuildInvalidDescriptor) {
				t.Fatalf("derived source %d mismatch error = %v", test.source, err)
			}
		})
	}
	inputDescriptor := familyFieldDescriptor{
		key: "input.boolean", typeOf: familyFieldBoolean,
		requirement: familyRequirementRequired,
		fieldClass:  FieldClassMetadata,
		source:      familyValueInput,
	}
	if err := validateFamilyFieldDescriptors([]familyFieldDescriptor{inputDescriptor}); err != nil {
		t.Fatalf("typed producer input was treated as a derivation: %v", err)
	}
}

func TestFamilyBuilderStructuredLimitsAndLeafClasses(t *testing.T) {
	descriptor := familyFieldDescriptor{
		key: "structured", typeOf: familyFieldStructured, requirement: familyRequirementRequired,
		fieldClass: FieldClassEvidence, source: familyValueInput,
		constraints: familyFieldConstraints{structured: familyStructuredLimits{
			maxEncodedBytes: 64, maxItemUTF8Bytes: 8, maxItems: 4, maxDepth: 2, maxProperties: 3,
		}},
	}
	value := map[string]any{"a/b": []any{"one", "two"}}
	object, classes, err := materializeFamilyFields(
		[]familyFieldDescriptor{descriptor},
		familyFieldValues{{key: "structured", value: value, present: true}}, nil,
		familyDerivationContext{},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, pointer := range []string{"/structured/a~1b/0", "/structured/a~1b/1"} {
		if classes[pointer] != FieldClassEvidence {
			t.Fatalf("structured class %s = %q", pointer, classes[pointer])
		}
	}
	if err := verifyFamilyFieldClassCoverage(object, classes); err != nil {
		t.Fatal(err)
	}
	delete(classes, "/structured/a~1b/0")
	if err := verifyFamilyFieldClassCoverage(object, classes); !IsFamilyBuildError(err, FamilyBuildFieldClassCoverage) {
		t.Fatalf("missing class error = %v", err)
	}
	if err := validateFamilyStructuredValue(
		map[string]any{"key": strings.Repeat("x", 9)}, descriptor.constraints.structured,
	); !IsFamilyBuildError(err, FamilyBuildConstraint) {
		t.Fatalf("structured item bound error = %v", err)
	}
}

func TestFamilyBuilderCanonicalizesTypedStructuredContainersBeforeClassification(t *testing.T) {
	descriptor := familyFieldDescriptor{
		key: "structured", typeOf: familyFieldStructured, requirement: familyRequirementRequired,
		fieldClass: FieldClassEvidence, source: familyValueInput,
		constraints: familyFieldConstraints{structured: testFamilyStructuredLimits()},
	}
	object, classes, err := materializeFamilyFields(
		[]familyFieldDescriptor{descriptor},
		familyFieldValues{{key: "structured", value: map[string][]string{"typed": {"one", "two"}}, present: true}},
		nil,
		familyDerivationContext{},
	)
	if err != nil {
		t.Fatal(err)
	}
	for _, pointer := range []string{"/structured/typed/0", "/structured/typed/1"} {
		if classes[pointer] != FieldClassEvidence {
			t.Fatalf("typed structured class %s = %q", pointer, classes[pointer])
		}
	}
	if err := verifyFamilyFieldClassCoverage(object, classes); err != nil {
		t.Fatal(err)
	}
}

func TestFamilyBuilderOptionalPresenceAndEmptyContainers(t *testing.T) {
	absent := Absent[uint32]()
	if _, present := absent.Get(); present || absent.IsPresent() {
		t.Fatal("absent optional became present")
	}
	present := Present(uint32(0))
	if value, ok := present.Get(); !ok || value != 0 || !present.IsPresent() {
		t.Fatalf("present zero lost presence: %d/%t", value, ok)
	}
	classes := make(map[string]FieldClass)
	addFamilyLeafClasses(classes, "/empty_array", []any{}, FieldClassMetadata)
	addFamilyLeafClasses(classes, "/empty_object", map[string]any{}, FieldClassReason)
	payload := map[string]any{"empty_array": []any{}, "empty_object": map[string]any{}}
	if err := verifyFamilyFieldClassCoverage(payload, classes); err != nil {
		t.Fatal(err)
	}
}

func TestFamilyBuilderConcurrentConstructionHasNoSharedMutation(t *testing.T) {
	builder, ids := testFamilyBuilder(t)
	family := testLogFamily()
	const workers = 64
	var wait sync.WaitGroup
	errors := make(chan error, workers)
	for index := 0; index < workers; index++ {
		wait.Add(1)
		go func() {
			defer wait.Done()
			_, err := builder.buildGeneratedLog(family, validLogBuildInput())
			errors <- err
		}()
	}
	wait.Wait()
	close(errors)
	for err := range errors {
		if err != nil {
			t.Fatal(err)
		}
	}
	if ids.count.Load() != workers {
		t.Fatalf("occurrence calls = %d", ids.count.Load())
	}
}

func TestFamilyBuilderRejectsNilDependenciesAndValueSafeOccurrenceFailure(t *testing.T) {
	if _, err := NewFamilyBuilder(nil, &testOccurrenceIDs{}); !IsFamilyBuildError(err, FamilyBuildInvalidDependency) {
		t.Fatalf("nil clock error = %v", err)
	}
	var typedNilClock *testNilClock
	if _, err := NewFamilyBuilder(typedNilClock, &testOccurrenceIDs{}); !IsFamilyBuildError(err, FamilyBuildInvalidDependency) {
		t.Fatalf("typed nil clock error = %v", err)
	}
	builder, err := NewFamilyBuilder(
		ClockFunc(func() time.Time { return time.Now() }),
		OccurrenceIDGeneratorFunc(func() (string, error) { return "", &secretOccurrenceError{} }),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = builder.buildGeneratedLog(testLogFamily(), validLogBuildInput())
	if !IsFamilyBuildError(err, FamilyBuildOccurrence) || strings.Contains(err.Error(), "RAW-OCCURRENCE-SECRET") {
		t.Fatalf("occurrence error = %v", err)
	}

	var consumed atomic.Int64
	builder, err = NewFamilyBuilder(
		ClockFunc(func() time.Time { return time.Now() }),
		OccurrenceIDGeneratorFunc(func() (string, error) {
			consumed.Add(1)
			return "RAW-INVALID-ID\x00", nil
		}),
	)
	if err != nil {
		t.Fatal(err)
	}
	_, err = builder.buildGeneratedLog(testLogFamily(), validLogBuildInput())
	if !IsFamilyBuildError(err, FamilyBuildOccurrence) || strings.Contains(err.Error(), "RAW-INVALID-ID") {
		t.Fatalf("invalid candidate error = %v", err)
	}
	if consumed.Load() != 1 {
		t.Fatalf("invalid occurrence candidate consumption = %d", consumed.Load())
	}
}

type testNilClock struct{}

func (*testNilClock) Now() time.Time { return time.Time{} }

type secretOccurrenceError struct{}

func (*secretOccurrenceError) Error() string { return "RAW-OCCURRENCE-SECRET" }
