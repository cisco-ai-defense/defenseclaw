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
	"strings"
	"testing"
)

func testPhaseRelationFields() ([]familyFieldDescriptor, familyCrossFieldRelation) {
	fields := []familyFieldDescriptor{
		{
			key: "defenseclaw.agent.phase", typeOf: familyFieldString,
			requirement: familyRequirementOptional, fieldClass: FieldClassMetadata,
			source: familyValueInput,
			constraints: familyFieldConstraints{
				maxUTF8Bytes: 16, enum: []string{"planning", "model"},
			},
		},
		{
			key: "defenseclaw.agent.phase.code", typeOf: familyFieldInt64,
			requirement: familyRequirementOptional, fieldClass: FieldClassMetadata,
			source: familyValueInput,
			constraints: familyFieldConstraints{
				hasIntMin: true, intMin: 1, hasIntMax: true, intMax: 2,
			},
		},
	}
	relation := familyCrossFieldRelation{
		valueKey: "defenseclaw.agent.phase",
		codeKey:  "defenseclaw.agent.phase.code",
		entries: []familyValueCodeEntry{
			{value: "planning", code: 1},
			{value: "model", code: 2},
		},
		mismatchCode: FamilyBuildLifecyclePhaseCodeMismatch,
	}
	return fields, relation
}

func testPhaseRelationValues(code int64) familyFieldValues {
	return familyFieldValues{
		{key: "defenseclaw.agent.phase", value: "planning", present: true},
		{key: "defenseclaw.agent.phase.code", value: code, present: true},
	}
}

func TestFamilyCrossFieldRelationRejectsMismatchBeforeOccurrenceForEverySignal(t *testing.T) {
	fields, relation := testPhaseRelationFields()
	tests := []struct {
		name  string
		build func(*testing.T, *FamilyBuilder) error
	}{
		{
			name: "log",
			build: func(t *testing.T, builder *FamilyBuilder) error {
				family := testLogFamily()
				family.contract.fields = append(family.contract.fields, fields...)
				family.contract.crossFieldRelations = []familyCrossFieldRelation{relation}
				input := validLogBuildInput()
				input.values = append(input.values, testPhaseRelationValues(2)...)
				_, err := builder.buildGeneratedLog(family, input)
				return err
			},
		},
		{
			name: "span",
			build: func(t *testing.T, builder *FamilyBuilder) error {
				family := testTraceFamily()
				family.base.fields = append(family.base.fields, fields...)
				family.base.crossFieldRelations = []familyCrossFieldRelation{relation}
				family.trace.familyDescriptorContract = family.base
				input := validTraceBuildInput(family)
				input.values = append(input.values, testPhaseRelationValues(2)...)
				_, err := builder.buildGeneratedTrace(family, input)
				return err
			},
		},
		{
			name: "metric",
			build: func(t *testing.T, builder *FamilyBuilder) error {
				family := testMetricFamily(familyMetricNumberInt64)
				family.base.fields = append(family.base.fields, fields...)
				family.base.crossFieldRelations = []familyCrossFieldRelation{relation}
				family.metric.familyDescriptorContract = family.base
				_, err := builder.buildGeneratedMetric(family, familyMetricBuildInput{
					envelope: testFamilyEnvelope(),
					value:    familyInt64MetricNumber(1),
					labels:   testPhaseRelationValues(2),
				})
				return err
			},
		},
	}
	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			builder, ids := testFamilyBuilder(t)
			err := test.build(t, builder)
			if !IsFamilyBuildError(err, FamilyBuildLifecyclePhaseCodeMismatch) {
				t.Fatalf("build error = %v", err)
			}
			if ids.count.Load() != 0 {
				t.Fatalf("occurrence IDs consumed = %d", ids.count.Load())
			}
			if strings.Contains(err.Error(), "planning") || strings.Contains(err.Error(), "2") {
				t.Fatalf("cross-field error leaked values: %v", err)
			}
		})
	}
}

func TestFamilyCrossFieldRelationAcceptsMatchAndIgnoresAbsentSide(t *testing.T) {
	fields, relation := testPhaseRelationFields()
	contract := testLogFamily().contract
	contract.fields = fields
	contract.crossFieldRelations = []familyCrossFieldRelation{relation}
	if err := validateFamilyDescriptor(contract, familySignalLog); err != nil {
		t.Fatalf("descriptor error = %v", err)
	}
	for _, values := range []familyFieldValues{
		testPhaseRelationValues(1),
		{{key: "defenseclaw.agent.phase", value: "planning", present: true}},
		{{key: "defenseclaw.agent.phase.code", value: int64(1), present: true}},
	} {
		object, _, err := materializeFamilyFields(fields, values, nil, familyDerivationContext{})
		if err != nil {
			t.Fatalf("materialization error = %v", err)
		}
		if err := validateFamilyCrossFieldValues(contract.crossFieldRelations, object); err != nil {
			t.Fatalf("relation error = %v", err)
		}
	}
}

func TestFamilyCrossFieldRelationAcceptsScientificCanonicalInt64Code(t *testing.T) {
	fields, relation := testPhaseRelationFields()
	fields[1].constraints.intMax = 1000
	relation.entries[0].code = 1000
	contract := testLogFamily().contract
	contract.fields = fields
	contract.crossFieldRelations = []familyCrossFieldRelation{relation}
	if err := validateFamilyDescriptor(contract, familySignalLog); err != nil {
		t.Fatalf("descriptor error = %v", err)
	}

	object, _, err := materializeFamilyFields(
		fields,
		testPhaseRelationValues(1000),
		nil,
		familyDerivationContext{},
	)
	if err != nil {
		t.Fatalf("materialization error = %v", err)
	}
	number, ok := object["defenseclaw.agent.phase.code"].(json.Number)
	if !ok || number.String() != "1e3" {
		t.Fatalf("canonical phase code = %#v", object["defenseclaw.agent.phase.code"])
	}
	if err := validateFamilyCrossFieldValues(contract.crossFieldRelations, object); err != nil {
		t.Fatalf("matching scientific phase code error = %v", err)
	}

	object["defenseclaw.agent.phase.code"] = json.Number("2")
	err = validateFamilyCrossFieldValues(contract.crossFieldRelations, object)
	if !IsFamilyBuildError(err, FamilyBuildLifecyclePhaseCodeMismatch) {
		t.Fatalf("mismatched phase code error = %v", err)
	}
	if strings.Contains(err.Error(), "planning") || strings.Contains(err.Error(), "1000") ||
		strings.Contains(err.Error(), "1e3") || strings.Contains(err.Error(), "2") {
		t.Fatalf("cross-field error leaked values: %v", err)
	}
}

func TestFamilyCrossFieldRelationDescriptorAndCloneFailClosed(t *testing.T) {
	fields, relation := testPhaseRelationFields()
	base := testLogFamily().contract
	base.fields = fields
	base.crossFieldRelations = []familyCrossFieldRelation{relation}
	mutations := []struct {
		name   string
		mutate func(*familyDescriptorContract)
	}{
		{"missing key", func(contract *familyDescriptorContract) {
			contract.crossFieldRelations[0].codeKey = "unknown"
		}},
		{"duplicate value", func(contract *familyDescriptorContract) {
			contract.crossFieldRelations[0].entries[1].value = "planning"
		}},
		{"duplicate code", func(contract *familyDescriptorContract) {
			contract.crossFieldRelations[0].entries[1].code = 1
		}},
		{"unreviewed error", func(contract *familyDescriptorContract) {
			contract.crossFieldRelations[0].mismatchCode = FamilyBuildConstraint
		}},
		{"incomplete enum", func(contract *familyDescriptorContract) {
			contract.crossFieldRelations[0].entries = contract.crossFieldRelations[0].entries[:1]
		}},
		{"duplicate relation", func(contract *familyDescriptorContract) {
			contract.crossFieldRelations = append(contract.crossFieldRelations, contract.crossFieldRelations[0])
		}},
	}
	for _, test := range mutations {
		t.Run(test.name, func(t *testing.T) {
			contract := cloneFamilyDescriptorContract(base)
			test.mutate(&contract)
			if err := validateFamilyDescriptor(contract, familySignalLog); !IsFamilyBuildError(
				err, FamilyBuildInvalidDescriptor,
			) {
				t.Fatalf("descriptor error = %v", err)
			}
		})
	}

	clone := cloneFamilyDescriptorContract(base)
	clone.crossFieldRelations[0].entries[0].value = "changed"
	if base.crossFieldRelations[0].entries[0].value != "planning" {
		t.Fatal("descriptor clone shares relation entries")
	}
}

func TestConditionalDerivedValuesAreSuppressedWhenConditionIsFalse(t *testing.T) {
	descriptor := familyFieldDescriptor{
		key: "defenseclaw.outcome", typeOf: familyFieldString,
		requirement: familyRequirementConditional, conditionID: "operation-terminal-v1",
		falseRequirement: familyFalseOptional, fieldClass: FieldClassMetadata,
		source: familyValueOutcome,
	}
	context := familyDerivationContext{outcome: Present(OutcomeAttempted)}
	falseFacts := familyConditionFacts{{id: "operation-terminal-v1", state: familyConditionFalse}}
	object, classes, err := materializeFamilyFields(
		[]familyFieldDescriptor{descriptor}, nil, falseFacts, context,
	)
	if err != nil {
		t.Fatalf("false derived condition error = %v", err)
	}
	if len(object) != 0 || len(classes) != 0 {
		t.Fatalf("false derived condition materialized value: object=%v classes=%v", object, classes)
	}

	trueFacts := familyConditionFacts{{id: "operation-terminal-v1", state: familyConditionTrue}}
	object, _, err = materializeFamilyFields(
		[]familyFieldDescriptor{descriptor}, nil, trueFacts, context,
	)
	if err != nil {
		t.Fatalf("true derived condition error = %v", err)
	}
	if object["defenseclaw.outcome"] != string(OutcomeAttempted) {
		t.Fatalf("true derived outcome = %#v", object["defenseclaw.outcome"])
	}
	if _, _, err := materializeFamilyFields(
		[]familyFieldDescriptor{descriptor}, nil, trueFacts, familyDerivationContext{},
	); !IsFamilyBuildError(err, FamilyBuildMissingRequired) {
		t.Fatalf("missing true derived value error = %v", err)
	}
}

func TestConditionalFalseInputAndDerivedForbiddenSemanticsRemainDistinct(t *testing.T) {
	inputDescriptor := familyFieldDescriptor{
		key: "input", typeOf: familyFieldString,
		requirement: familyRequirementConditional, conditionID: "available-v1",
		falseRequirement: familyFalseOptional, fieldClass: FieldClassMetadata,
		source: familyValueInput,
	}
	falseFacts := familyConditionFacts{{id: "available-v1", state: familyConditionFalse}}
	object, _, err := materializeFamilyFields(
		[]familyFieldDescriptor{inputDescriptor},
		familyFieldValues{{key: "input", value: "present", present: true}},
		falseFacts,
		familyDerivationContext{},
	)
	if err != nil || object["input"] != "present" {
		t.Fatalf("false optional input behavior changed: object=%v err=%v", object, err)
	}

	inputDescriptor.falseRequirement = familyFalseForbidden
	if _, _, err := materializeFamilyFields(
		[]familyFieldDescriptor{inputDescriptor},
		familyFieldValues{{key: "input", value: "present", present: true}},
		falseFacts,
		familyDerivationContext{},
	); !IsFamilyBuildError(err, FamilyBuildForbiddenField) {
		t.Fatalf("false forbidden input error = %v", err)
	}

	derivedDescriptor := familyFieldDescriptor{
		key: "derived", typeOf: familyFieldString,
		requirement: familyRequirementConditional, conditionID: "available-v1",
		falseRequirement: familyFalseForbidden, fieldClass: FieldClassMetadata,
		source: familyValueOutcome,
	}
	object, _, err = materializeFamilyFields(
		[]familyFieldDescriptor{derivedDescriptor}, nil, falseFacts,
		familyDerivationContext{outcome: Present(OutcomeAttempted)},
	)
	if err != nil || len(object) != 0 {
		t.Fatalf("false forbidden derived value was not suppressed: object=%v err=%v", object, err)
	}
	if _, _, err := materializeFamilyFields(
		[]familyFieldDescriptor{derivedDescriptor},
		familyFieldValues{{key: "derived", value: "caller", present: true}},
		falseFacts,
		familyDerivationContext{outcome: Present(OutcomeAttempted)},
	); !IsFamilyBuildError(err, FamilyBuildForbiddenField) {
		t.Fatalf("caller supplied derived field error = %v", err)
	}

	derivedDescriptor.requirement = familyRequirementOptional
	derivedDescriptor.conditionID = ""
	derivedDescriptor.falseRequirement = familyFalseInvalid
	object, _, err = materializeFamilyFields(
		[]familyFieldDescriptor{derivedDescriptor}, nil, nil,
		familyDerivationContext{outcome: Present(OutcomeAttempted)},
	)
	if err != nil || object["derived"] != string(OutcomeAttempted) {
		t.Fatalf("ordinary optional derived behavior changed: object=%v err=%v", object, err)
	}
}
