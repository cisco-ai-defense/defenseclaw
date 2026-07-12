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
	"errors"
	"fmt"
	"math"
	"regexp"
	"strconv"
	"strings"
	"unicode/utf8"
)

// FamilyBuildErrorCode is a value-free, stable family-construction failure.
// Neither codes nor Error strings include producer values, field values, IDs,
// content, credentials, endpoints, or underlying decoder diagnostics.
type FamilyBuildErrorCode string

const (
	FamilyBuildInvalidDependency          FamilyBuildErrorCode = "invalid_dependency"
	FamilyBuildInvalidDescriptor          FamilyBuildErrorCode = "invalid_descriptor"
	FamilyBuildMissingRequired            FamilyBuildErrorCode = "missing_required"
	FamilyBuildForbiddenField             FamilyBuildErrorCode = "forbidden_field"
	FamilyBuildUnknownField               FamilyBuildErrorCode = "unknown_field"
	FamilyBuildDuplicateField             FamilyBuildErrorCode = "duplicate_field"
	FamilyBuildInvalidType                FamilyBuildErrorCode = "invalid_type"
	FamilyBuildConstraint                 FamilyBuildErrorCode = "constraint_violation"
	FamilyBuildInvalidCondition           FamilyBuildErrorCode = "invalid_condition"
	FamilyBuildInvalidOutcome             FamilyBuildErrorCode = "invalid_outcome"
	FamilyBuildInvalidTrace               FamilyBuildErrorCode = "invalid_trace"
	FamilyBuildInvalidMetric              FamilyBuildErrorCode = "invalid_metric"
	FamilyBuildFieldClassCoverage         FamilyBuildErrorCode = "field_class_coverage"
	FamilyBuildLifecyclePhaseCodeMismatch FamilyBuildErrorCode = "lifecycle_phase_code_mismatch"
	FamilyBuildOccurrence                 FamilyBuildErrorCode = "occurrence_generation"
	FamilyBuildRecordRejected             FamilyBuildErrorCode = "record_rejected"
)

type FamilyBuildError struct{ code FamilyBuildErrorCode }

func (buildError *FamilyBuildError) Error() string {
	if buildError == nil {
		return "telemetry family build failed"
	}
	return "telemetry family build failed: " + string(buildError.code)
}

func (buildError *FamilyBuildError) Code() FamilyBuildErrorCode {
	if buildError == nil {
		return ""
	}
	return buildError.code
}

func IsFamilyBuildError(err error, code FamilyBuildErrorCode) bool {
	var target *FamilyBuildError
	return errors.As(err, &target) && target.code == code
}

func familyBuildFailure(code FamilyBuildErrorCode) error { return &FamilyBuildError{code: code} }

type familyDerivationContext struct {
	bucket              Bucket
	family              string
	familySchemaVersion uint32
	source              Source
	configGeneration    int64
	outcome             Optional[Outcome]
	binaryVersion       string
	traceSchemaVersion  string
	semanticProfile     string
	linkRelation        string
}

func validateFamilyDescriptor(contract familyDescriptorContract, signal familySignal) error {
	if !IsStableToken(contract.id) || contract.familySchemaVersion == 0 ||
		contract.identity.Signal != signal.canonical() || !IsRegisteredEventIdentity(contract.identity) {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	if err := validateFamilyOutcomePolicy(contract.outcome, signal); err != nil {
		return err
	}
	if err := validateFamilyFieldDescriptors(contract.fields); err != nil {
		return err
	}
	return validateFamilyCrossFieldRelations(contract.fields, contract.crossFieldRelations)
}

func validateFamilyOutcomePolicy(policy familyOutcomePolicy, signal familySignal) error {
	if signal == familySignalMetric {
		if policy.requirement != familyRequirementInvalid || len(policy.allowed) != 0 {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		return nil
	}
	if policy.requirement != familyRequirementRequired &&
		policy.requirement != familyRequirementOptional &&
		policy.requirement != familyRequirementForbidden {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	seen := make(map[Outcome]struct{}, len(policy.allowed))
	for _, outcome := range policy.allowed {
		if !IsOutcome(outcome) {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seen[outcome]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seen[outcome] = struct{}{}
	}
	if policy.requirement == familyRequirementForbidden && len(policy.allowed) != 0 ||
		policy.requirement != familyRequirementForbidden && len(policy.allowed) == 0 {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return nil
}

func validateFamilyFieldDescriptors(descriptors []familyFieldDescriptor) error {
	seen := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		if descriptor.key == "" || !utf8.ValidString(descriptor.key) || len(descriptor.key) > MaxCanonicalValueBytes ||
			descriptor.typeOf <= familyFieldInvalid || descriptor.typeOf > familyFieldStructured ||
			!IsFieldClass(descriptor.fieldClass) || descriptor.source < familyValueInput ||
			descriptor.source > familyValueLinkRelation {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seen[descriptor.key]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seen[descriptor.key] = struct{}{}
		if expected, derived := familyDerivedSourceType(descriptor.source); derived && descriptor.typeOf != expected {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if descriptor.conditionID != "" {
			if descriptor.requirement != familyRequirementConditional &&
				descriptor.requirement != familyRequirementOptional {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
			if descriptor.conditionID == "" ||
				(descriptor.falseRequirement != familyFalseOptional &&
					descriptor.falseRequirement != familyFalseForbidden) {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
		} else if descriptor.requirement != familyRequirementRequired &&
			descriptor.requirement != familyRequirementRecommended &&
			descriptor.requirement != familyRequirementOptional {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		} else if descriptor.conditionID != "" || descriptor.falseRequirement != familyFalseInvalid {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if descriptor.source != familyValueInput && descriptor.requirement == familyRequirementRecommended {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if err := validateFamilyFieldConstraintDescriptor(descriptor); err != nil {
			return err
		}
	}
	return nil
}

func validateFamilyCrossFieldRelations(
	descriptors []familyFieldDescriptor,
	relations []familyCrossFieldRelation,
) error {
	if len(relations) > len(descriptors) {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	fields := make(map[string]familyFieldDescriptor, len(descriptors))
	for _, descriptor := range descriptors {
		fields[descriptor.key] = descriptor
	}
	seenRelations := make(map[string]struct{}, len(relations))
	for _, relation := range relations {
		valueField, valueExists := fields[relation.valueKey]
		codeField, codeExists := fields[relation.codeKey]
		relationID := relation.valueKey + "\x00" + relation.codeKey
		if relation.valueKey == "" || relation.codeKey == "" || relation.valueKey == relation.codeKey ||
			!valueExists || !codeExists || len(relation.entries) == 0 ||
			len(relation.entries) > MaxCanonicalValueMembers ||
			valueField.typeOf != familyFieldString || codeField.typeOf != familyFieldInt64 ||
			valueField.source != familyValueInput || codeField.source != familyValueInput ||
			relation.mismatchCode != FamilyBuildLifecyclePhaseCodeMismatch {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seenRelations[relationID]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seenRelations[relationID] = struct{}{}
		seenValues := make(map[string]struct{}, len(relation.entries))
		seenCodes := make(map[int64]struct{}, len(relation.entries))
		for _, entry := range relation.entries {
			if _, duplicate := seenValues[entry.value]; duplicate {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
			if _, duplicate := seenCodes[entry.code]; duplicate {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
			if err := validateFamilyFieldValue(valueField, entry.value); err != nil {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
			if err := validateFamilyFieldValue(codeField, entry.code); err != nil {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
			seenValues[entry.value] = struct{}{}
			seenCodes[entry.code] = struct{}{}
		}
		if len(valueField.constraints.enum) != 0 {
			if len(valueField.constraints.enum) != len(seenValues) {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
			for _, value := range valueField.constraints.enum {
				if _, exists := seenValues[value]; !exists {
					return familyBuildFailure(FamilyBuildInvalidDescriptor)
				}
			}
		}
	}
	return nil
}

func validateFamilyCrossFieldValues(
	relations []familyCrossFieldRelation,
	values map[string]any,
) error {
	for _, relation := range relations {
		value, valuePresent := values[relation.valueKey]
		code, codePresent := values[relation.codeKey]
		if !valuePresent || !codePresent {
			continue
		}
		text, textOK := value.(string)
		number, numberOK := code.(json.Number)
		if !textOK || !numberOK {
			return familyBuildFailure(relation.mismatchCode)
		}
		canonicalNumber, numberErr := normalizeJSONNumber(number)
		if numberErr != nil {
			return familyBuildFailure(relation.mismatchCode)
		}
		matched := false
		for _, entry := range relation.entries {
			if entry.value == text && canonicalFamilyInt64Equal(canonicalNumber, entry.code) {
				matched = true
				break
			}
		}
		if !matched {
			return familyBuildFailure(relation.mismatchCode)
		}
	}
	return nil
}

// canonicalFamilyInt64Equal compares exact numeric values after applying the
// same shortest plain/scientific spelling used by Value normalization. Calling
// json.Number.Int64 directly is insufficient because canonical integral values
// such as 1000 are deliberately represented as 1e3.
func canonicalFamilyInt64Equal(canonical json.Number, expected int64) bool {
	expectedText, ok := normalizeExactDecimal(strconv.FormatInt(expected, 10))
	return ok && canonical.String() == expectedText
}

func familyDerivedSourceType(source familyValueSource) (familyFieldType, bool) {
	switch source {
	case familyValueInput:
		return familyFieldInvalid, false
	case familyValueBucket,
		familyValueFamily,
		familyValueSourceName,
		familyValueOutcome,
		familyValueBinaryVersion,
		familyValueTraceSchemaVersion,
		familyValueSemanticProfile,
		familyValueLinkRelation:
		return familyFieldString, true
	case familyValueFamilySchemaVersion:
		return familyFieldUint32, true
	case familyValueConfigGeneration:
		return familyFieldInt64, true
	default:
		return familyFieldInvalid, true
	}
}

func validateFamilyFieldConstraintDescriptor(descriptor familyFieldDescriptor) error {
	constraints := descriptor.constraints
	if constraints.maxUTF8Bytes < 0 || constraints.minItems < 0 || constraints.maxItems < 0 ||
		(constraints.maxItems > 0 && constraints.minItems > constraints.maxItems) ||
		constraints.structured.maxEncodedBytes < 0 || constraints.structured.maxItemUTF8Bytes < 0 ||
		constraints.structured.maxItems < 0 || constraints.structured.maxDepth < 0 ||
		constraints.structured.maxProperties < 0 {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	if constraints.pattern != "" {
		if _, err := regexp.Compile(constraints.pattern); err != nil {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	}
	seenEnums := make(map[string]struct{}, len(constraints.enum))
	for _, candidate := range constraints.enum {
		if !utf8.ValidString(candidate) {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if _, duplicate := seenEnums[candidate]; duplicate {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		seenEnums[candidate] = struct{}{}
	}
	if constraints.hasIntMin && constraints.hasIntMax && constraints.intMin > constraints.intMax ||
		constraints.hasUintMin && constraints.hasUintMax && constraints.uintMin > constraints.uintMax ||
		constraints.hasFloatMin && constraints.hasFloatMax && constraints.floatMin > constraints.floatMax ||
		constraints.hasFloatMin && !isFinite(constraints.floatMin) ||
		constraints.hasFloatMax && !isFinite(constraints.floatMax) {
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	hasText := constraints.maxUTF8Bytes != 0 || constraints.pattern != "" || len(constraints.enum) != 0
	hasItems := constraints.minItems != 0 || constraints.maxItems != 0
	hasInt := constraints.hasIntMin || constraints.hasIntMax
	hasUint := constraints.hasUintMin || constraints.hasUintMax
	hasFloat := constraints.hasFloatMin || constraints.hasFloatMax
	hasStructured := constraints.structured != (familyStructuredLimits{})
	switch descriptor.typeOf {
	case familyFieldString:
		if hasItems || hasInt || hasUint || hasFloat || hasStructured {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	case familyFieldStringArray:
		if hasInt || hasUint || hasFloat || hasStructured {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	case familyFieldBoolean:
		if hasText || hasItems || hasInt || hasUint || hasFloat || hasStructured {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	case familyFieldInt64:
		if hasText || hasItems || hasUint || hasFloat || hasStructured {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	case familyFieldUint32, familyFieldUint64:
		if hasText || hasItems || hasInt || hasFloat || hasStructured {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	case familyFieldDouble:
		if hasText || hasItems || hasInt || hasUint || hasStructured {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	case familyFieldStructured:
		if hasText || hasItems || hasInt || hasUint || hasFloat {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
	}
	for _, candidate := range constraints.enum {
		if constraints.maxUTF8Bytes > 0 && len(candidate) > constraints.maxUTF8Bytes {
			return familyBuildFailure(FamilyBuildInvalidDescriptor)
		}
		if constraints.pattern != "" {
			pattern, _ := regexp.Compile(constraints.pattern)
			if !pattern.MatchString(candidate) {
				return familyBuildFailure(FamilyBuildInvalidDescriptor)
			}
		}
	}
	return nil
}

func validRequiredFamilyStructuredLimits(limits familyStructuredLimits) bool {
	return limits.maxEncodedBytes > 0 && limits.maxEncodedBytes <= MaxCanonicalValueBytes &&
		limits.maxItemUTF8Bytes > 0 && limits.maxItemUTF8Bytes <= MaxCanonicalValueBytes &&
		limits.maxItems > 0 && limits.maxItems <= MaxCanonicalValueMembers &&
		limits.maxDepth > 0 && limits.maxDepth <= MaxCanonicalValueDepth &&
		limits.maxProperties > 0 && limits.maxProperties <= MaxCanonicalValueMembers
}

func materializeFamilyFields(
	descriptors []familyFieldDescriptor,
	values familyFieldValues,
	facts familyConditionFacts,
	context familyDerivationContext,
) (map[string]any, map[string]FieldClass, error) {
	if err := validateFamilyFieldDescriptors(descriptors); err != nil {
		return nil, nil, err
	}
	conditionStates, err := validatedConditionStates(descriptors, facts)
	if err != nil {
		return nil, nil, err
	}
	provided := make(map[string]familyFieldValue, len(values))
	for _, value := range values {
		if _, duplicate := provided[value.key]; duplicate {
			return nil, nil, familyBuildFailure(FamilyBuildDuplicateField)
		}
		provided[value.key] = value
	}
	known := make(map[string]struct{}, len(descriptors))
	for _, descriptor := range descriptors {
		known[descriptor.key] = struct{}{}
	}
	for key := range provided {
		if _, exists := known[key]; !exists {
			return nil, nil, familyBuildFailure(FamilyBuildUnknownField)
		}
	}

	object := make(map[string]any, len(descriptors))
	classes := make(map[string]FieldClass, len(descriptors))
	for _, descriptor := range descriptors {
		required, forbidden, err := resolvedFamilyRequirement(descriptor, conditionStates)
		if err != nil {
			return nil, nil, err
		}
		providedValue := provided[descriptor.key]
		// A derived conditional value has no caller-owned presence. When its
		// condition is false, both false-requirement arms mean that the derived
		// value is absent; the forbidden arm still rejects an attempted raw
		// caller value here. Input-sourced false+optional fields retain their
		// existing behavior and may be supplied by the caller.
		if descriptor.requirement == familyRequirementConditional && !required &&
			descriptor.source != familyValueInput {
			if providedValue.present {
				return nil, nil, familyBuildFailure(FamilyBuildForbiddenField)
			}
			continue
		}
		value, present, err := resolvedFamilyFieldValue(descriptor, providedValue, context)
		if err != nil {
			return nil, nil, err
		}
		if forbidden && present {
			return nil, nil, familyBuildFailure(FamilyBuildForbiddenField)
		}
		if required && !present {
			return nil, nil, familyBuildFailure(FamilyBuildMissingRequired)
		}
		if !present {
			continue
		}
		if err := validateFamilyFieldValue(descriptor, value); err != nil {
			return nil, nil, err
		}
		canonical, err := canonicalFamilyJSONValue(value)
		if err != nil {
			return nil, nil, err
		}
		object[descriptor.key] = canonical
		addFamilyLeafClasses(classes, "/"+encodeJSONPointerToken(descriptor.key), canonical, descriptor.fieldClass)
	}
	return object, classes, nil
}

func validatedConditionStates(
	descriptors []familyFieldDescriptor,
	facts familyConditionFacts,
) (map[string]familyConditionState, error) {
	known := make(map[string]struct{})
	for _, descriptor := range descriptors {
		if descriptor.conditionID != "" {
			known[descriptor.conditionID] = struct{}{}
		}
	}
	states := make(map[string]familyConditionState, len(facts))
	for _, fact := range facts {
		if _, exists := known[fact.id]; !exists ||
			(fact.state != familyConditionFalse && fact.state != familyConditionTrue) {
			return nil, familyBuildFailure(FamilyBuildInvalidCondition)
		}
		if _, duplicate := states[fact.id]; duplicate {
			return nil, familyBuildFailure(FamilyBuildInvalidCondition)
		}
		states[fact.id] = fact.state
	}
	for conditionID := range known {
		if _, exists := states[conditionID]; !exists {
			return nil, familyBuildFailure(FamilyBuildInvalidCondition)
		}
	}
	return states, nil
}

func resolvedFamilyRequirement(
	descriptor familyFieldDescriptor,
	states map[string]familyConditionState,
) (required, forbidden bool, err error) {
	switch descriptor.requirement {
	case familyRequirementRequired:
		return true, false, nil
	case familyRequirementRecommended:
		return false, false, nil
	case familyRequirementOptional:
		if descriptor.conditionID == "" {
			return false, false, nil
		}
		switch states[descriptor.conditionID] {
		case familyConditionTrue:
			return false, false, nil
		case familyConditionFalse:
			return false, descriptor.falseRequirement == familyFalseForbidden, nil
		default:
			return false, false, familyBuildFailure(FamilyBuildInvalidCondition)
		}
	case familyRequirementConditional:
		switch states[descriptor.conditionID] {
		case familyConditionTrue:
			return true, false, nil
		case familyConditionFalse:
			return false, descriptor.falseRequirement == familyFalseForbidden, nil
		default:
			return false, false, familyBuildFailure(FamilyBuildInvalidCondition)
		}
	default:
		return false, false, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
}

func resolvedFamilyFieldValue(
	descriptor familyFieldDescriptor,
	provided familyFieldValue,
	context familyDerivationContext,
) (any, bool, error) {
	if descriptor.source != familyValueInput && provided.present {
		return nil, false, familyBuildFailure(FamilyBuildForbiddenField)
	}
	switch descriptor.source {
	case familyValueInput:
		return provided.value, provided.present, nil
	case familyValueBucket:
		return string(context.bucket), context.bucket != "", nil
	case familyValueFamily:
		return context.family, context.family != "", nil
	case familyValueFamilySchemaVersion:
		return context.familySchemaVersion, context.familySchemaVersion != 0, nil
	case familyValueSourceName:
		return string(context.source), context.source != "", nil
	case familyValueConfigGeneration:
		return context.configGeneration, context.configGeneration >= 0, nil
	case familyValueOutcome:
		value, present := context.outcome.Get()
		return string(value), present, nil
	case familyValueBinaryVersion:
		return context.binaryVersion, context.binaryVersion != "", nil
	case familyValueTraceSchemaVersion:
		return context.traceSchemaVersion, context.traceSchemaVersion != "", nil
	case familyValueSemanticProfile:
		return context.semanticProfile, context.semanticProfile != "", nil
	case familyValueLinkRelation:
		return context.linkRelation, context.linkRelation != "", nil
	default:
		return nil, false, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
}

func validateFamilyFieldValue(descriptor familyFieldDescriptor, value any) error {
	constraints := descriptor.constraints
	switch descriptor.typeOf {
	case familyFieldString:
		text, ok := value.(string)
		if !ok {
			return familyBuildFailure(FamilyBuildInvalidType)
		}
		if err := validateFamilyString(text, constraints); err != nil {
			return err
		}
	case familyFieldBoolean:
		if _, ok := value.(bool); !ok {
			return familyBuildFailure(FamilyBuildInvalidType)
		}
	case familyFieldInt64:
		integer, ok := value.(int64)
		if !ok {
			return familyBuildFailure(FamilyBuildInvalidType)
		}
		if constraints.hasIntMin && integer < constraints.intMin ||
			constraints.hasIntMax && integer > constraints.intMax {
			return familyBuildFailure(FamilyBuildConstraint)
		}
	case familyFieldUint32:
		integer, ok := value.(uint32)
		if !ok {
			return familyBuildFailure(FamilyBuildInvalidType)
		}
		if constraints.hasUintMin && uint64(integer) < constraints.uintMin ||
			constraints.hasUintMax && uint64(integer) > constraints.uintMax {
			return familyBuildFailure(FamilyBuildConstraint)
		}
	case familyFieldUint64:
		integer, ok := value.(uint64)
		if !ok {
			return familyBuildFailure(FamilyBuildInvalidType)
		}
		if constraints.hasUintMin && integer < constraints.uintMin ||
			constraints.hasUintMax && integer > constraints.uintMax {
			return familyBuildFailure(FamilyBuildConstraint)
		}
	case familyFieldDouble:
		floating, ok := value.(float64)
		if !ok {
			return familyBuildFailure(FamilyBuildInvalidType)
		}
		if !isFinite(floating) || constraints.hasFloatMin && floating < constraints.floatMin ||
			constraints.hasFloatMax && floating > constraints.floatMax {
			return familyBuildFailure(FamilyBuildConstraint)
		}
	case familyFieldStringArray:
		items, ok := value.([]string)
		if !ok {
			return familyBuildFailure(FamilyBuildInvalidType)
		}
		if len(items) < constraints.minItems || constraints.maxItems > 0 && len(items) > constraints.maxItems {
			return familyBuildFailure(FamilyBuildConstraint)
		}
		for _, item := range items {
			if err := validateFamilyString(item, constraints); err != nil {
				return err
			}
		}
	case familyFieldStructured:
		if err := validateFamilyStructuredValue(value, constraints.structured); err != nil {
			return err
		}
	default:
		return familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	return nil
}

func validateFamilyString(value string, constraints familyFieldConstraints) error {
	if !utf8.ValidString(value) || constraints.maxUTF8Bytes > 0 && len(value) > constraints.maxUTF8Bytes {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	if constraints.pattern != "" {
		pattern, err := regexp.Compile(constraints.pattern)
		if err != nil || !pattern.MatchString(value) {
			return familyBuildFailure(FamilyBuildConstraint)
		}
	}
	if len(constraints.enum) > 0 && !containsString(constraints.enum, value) {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	return nil
}

func mergeFamilyTraceResource(
	resource TraceResourceInput,
	fixed familyFieldValues,
	contract familyResourceDynamicContract,
) (TraceResourceInput, []familyFieldDescriptor, error) {
	if contract.maxItems <= 0 || contract.maxValueUTF8Bytes <= 0 ||
		contract.maxAggregateUTF8Bytes <= 0 || !IsFieldClass(contract.fieldClass) ||
		contract.validate == nil || contract.prometheusKey == nil ||
		len(resource.customValues) > contract.maxItems {
		return TraceResourceInput{}, nil, familyBuildFailure(FamilyBuildInvalidDescriptor)
	}

	descriptors := make([]familyFieldDescriptor, 0, len(resource.customValues)+len(contract.aliases))
	values := make(familyFieldValues, 0, len(resource.customValues)+len(fixed)+len(contract.aliases))
	normalizedKeys := make(map[string]struct{}, len(resource.customValues))
	totalBytes := 0
	previousKey := ""
	for _, entry := range resource.customValues {
		value, ok := entry.value.(string)
		if !ok || !entry.present {
			return TraceResourceInput{}, nil, familyBuildFailure(FamilyBuildInvalidType)
		}
		if err := contract.validate(entry.key, value); err != nil {
			return TraceResourceInput{}, nil, err
		}
		if previousKey != "" && entry.key <= previousKey {
			if entry.key == previousKey {
				return TraceResourceInput{}, nil, familyBuildFailure(FamilyBuildDuplicateField)
			}
			return TraceResourceInput{}, nil, familyBuildFailure(FamilyBuildConstraint)
		}
		previousKey = entry.key
		normalized := contract.prometheusKey(entry.key)
		if _, duplicate := normalizedKeys[normalized]; duplicate {
			return TraceResourceInput{}, nil, familyBuildFailure(FamilyBuildDuplicateField)
		}
		normalizedKeys[normalized] = struct{}{}
		totalBytes += len(entry.key) + len(value)
		if totalBytes > contract.maxAggregateUTF8Bytes {
			return TraceResourceInput{}, nil, familyBuildFailure(FamilyBuildConstraint)
		}
		values = append(values, familyFieldValue{key: entry.key, value: value, present: true})
		descriptors = append(descriptors, familyFieldDescriptor{
			key:         entry.key,
			typeOf:      familyFieldString,
			requirement: familyRequirementRecommended,
			fieldClass:  contract.fieldClass,
			constraints: familyFieldConstraints{maxUTF8Bytes: contract.maxValueUTF8Bytes},
			source:      familyValueInput,
		})
	}

	values = append(values, fixed...)
	if resource.compatibilityAliases {
		for _, alias := range contract.aliases {
			for _, entry := range fixed {
				if entry.key != alias.canonical || !entry.present {
					continue
				}
				values = append(values, familyFieldValue{
					key: alias.descriptor.key, value: entry.value, present: true,
				})
				descriptors = append(descriptors, alias.descriptor)
				break
			}
		}
	}
	resource.values = values
	return resource, descriptors, nil
}

type familyStructuredStats struct {
	items             int
	properties        int
	depth             int
	maxStringUTF8Byte int
}

func validateFamilyStructuredValue(value any, limits familyStructuredLimits) error {
	wrapped, err := NewValue(map[string]any{"value": value})
	if err != nil {
		return familyBuildFailure(FamilyBuildInvalidType)
	}
	object, err := wrapped.Object()
	if err != nil {
		return familyBuildFailure(FamilyBuildInvalidType)
	}
	normalized := object["value"]
	if normalized == nil {
		return familyBuildFailure(FamilyBuildInvalidType)
	}
	encoded, err := json.Marshal(normalized)
	if err != nil {
		return familyBuildFailure(FamilyBuildInvalidType)
	}
	stats := familyStructuredStats{}
	collectFamilyStructuredStats(normalized, 0, &stats)
	if limits.maxEncodedBytes > 0 && len(encoded) > limits.maxEncodedBytes ||
		limits.maxItemUTF8Bytes > 0 && stats.maxStringUTF8Byte > limits.maxItemUTF8Bytes ||
		limits.maxItems > 0 && stats.items > limits.maxItems ||
		limits.maxDepth > 0 && stats.depth > limits.maxDepth ||
		limits.maxProperties > 0 && stats.properties > limits.maxProperties {
		return familyBuildFailure(FamilyBuildConstraint)
	}
	return nil
}

func collectFamilyStructuredStats(value any, depth int, stats *familyStructuredStats) {
	if depth > stats.depth {
		stats.depth = depth
	}
	switch typed := value.(type) {
	case map[string]any:
		stats.items += len(typed)
		stats.properties += len(typed)
		for key, child := range typed {
			if len(key) > stats.maxStringUTF8Byte {
				stats.maxStringUTF8Byte = len(key)
			}
			collectFamilyStructuredStats(child, depth+1, stats)
		}
	case []any:
		stats.items += len(typed)
		for _, child := range typed {
			collectFamilyStructuredStats(child, depth+1, stats)
		}
	case string:
		if len(typed) > stats.maxStringUTF8Byte {
			stats.maxStringUTF8Byte = len(typed)
		}
	}
}

func validateFamilyOutcome(policy familyOutcomePolicy, input Optional[Outcome]) error {
	outcome, present := input.Get()
	if !present {
		if policy.requirement == familyRequirementRequired {
			return familyBuildFailure(FamilyBuildMissingRequired)
		}
		return nil
	}
	if policy.requirement == familyRequirementForbidden {
		return familyBuildFailure(FamilyBuildForbiddenField)
	}
	if !IsOutcome(outcome) || !containsOutcome(policy.allowed, outcome) {
		return familyBuildFailure(FamilyBuildInvalidOutcome)
	}
	return nil
}

func validateOTelID(value string, width int) bool {
	if len(value) != width {
		return false
	}
	nonzero := false
	for _, character := range []byte(value) {
		if character >= '1' && character <= '9' || character >= 'a' && character <= 'f' {
			nonzero = true
		}
		if character < '0' || character > '9' {
			if character < 'a' || character > 'f' {
				return false
			}
		}
	}
	return nonzero
}

func validateTraceStatus(status TraceStatusInput) error {
	description, present := status.Description()
	switch status.Code() {
	case TraceStatusUnset, TraceStatusOK:
		if present {
			return familyBuildFailure(FamilyBuildInvalidTrace)
		}
	case TraceStatusError:
		if present && (!utf8.ValidString(description) || len(description) > 65_536) {
			return familyBuildFailure(FamilyBuildInvalidTrace)
		}
	default:
		return familyBuildFailure(FamilyBuildInvalidTrace)
	}
	return nil
}

func renderFamilySpanName(parts []spanNamePart, attributes map[string]any) (string, error) {
	if len(parts) == 0 {
		return "", familyBuildFailure(FamilyBuildInvalidDescriptor)
	}
	var builder strings.Builder
	for _, part := range parts {
		if part.field == "" {
			builder.WriteString(part.literal)
			continue
		}
		value, ok := attributes[part.field].(string)
		if !ok || value == "" {
			return "", familyBuildFailure(FamilyBuildMissingRequired)
		}
		builder.WriteString(value)
	}
	name := builder.String()
	if !utf8.ValidString(name) || name == "" || len(name) > MaxSpanNameBytes || strings.ContainsAny(name, "\r\n\x00") {
		return "", familyBuildFailure(FamilyBuildInvalidTrace)
	}
	return name, nil
}

func addFamilyLeafClasses(classes map[string]FieldClass, pointer string, value any, class FieldClass) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 0 {
			classes[pointer] = class
			return
		}
		for key, child := range typed {
			addFamilyLeafClasses(classes, pointer+"/"+encodeJSONPointerToken(key), child, class)
		}
	case []any:
		if len(typed) == 0 {
			classes[pointer] = class
			return
		}
		for index, child := range typed {
			addFamilyLeafClasses(classes, fmt.Sprintf("%s/%d", pointer, index), child, class)
		}
	case []string:
		if len(typed) == 0 {
			classes[pointer] = class
			return
		}
		for index := range typed {
			classes[fmt.Sprintf("%s/%d", pointer, index)] = class
		}
	default:
		classes[pointer] = class
	}
}

func verifyFamilyFieldClassCoverage(payload any, classes map[string]FieldClass) error {
	value, err := NewValue(payload)
	if err != nil {
		return familyBuildFailure(FamilyBuildFieldClassCoverage)
	}
	object, err := value.Object()
	if err != nil {
		return familyBuildFailure(FamilyBuildFieldClassCoverage)
	}
	// The payload root is an envelope container, not a registry field. An empty
	// family body therefore has no classifiable field; nested empty containers
	// remain concrete leaves and are handled by payloadLeafPointers below.
	if len(object) == 0 {
		if len(classes) != 0 {
			return familyBuildFailure(FamilyBuildFieldClassCoverage)
		}
		return nil
	}
	leaves := payloadLeafPointers(object)
	if len(leaves) != len(classes) {
		return familyBuildFailure(FamilyBuildFieldClassCoverage)
	}
	for _, pointer := range leaves {
		class, exists := classes[pointer]
		if !exists || !IsFieldClass(class) {
			return familyBuildFailure(FamilyBuildFieldClassCoverage)
		}
	}
	for pointer := range classes {
		if !validJSONPointer(pointer) || !jsonPointerResolves(object, pointer) {
			return familyBuildFailure(FamilyBuildFieldClassCoverage)
		}
	}
	return nil
}

func canonicalFamilyJSONValue(value any) (any, error) {
	wrapped, err := NewValue(map[string]any{"value": value})
	if err != nil {
		return nil, familyBuildFailure(FamilyBuildInvalidType)
	}
	object, err := wrapped.Object()
	if err != nil {
		return nil, familyBuildFailure(FamilyBuildInvalidType)
	}
	return object["value"], nil
}

func cloneFamilyFieldDescriptors(input []familyFieldDescriptor) []familyFieldDescriptor {
	output := make([]familyFieldDescriptor, len(input))
	for index, descriptor := range input {
		descriptor.constraints.enum = append([]string(nil), descriptor.constraints.enum...)
		output[index] = descriptor
	}
	return output
}

func cloneFamilyDescriptorContract(input familyDescriptorContract) familyDescriptorContract {
	input.fields = cloneFamilyFieldDescriptors(input.fields)
	input.outcome.allowed = append([]Outcome(nil), input.outcome.allowed...)
	input.crossFieldRelations = append([]familyCrossFieldRelation(nil), input.crossFieldRelations...)
	for index := range input.crossFieldRelations {
		input.crossFieldRelations[index].entries = append(
			[]familyValueCodeEntry(nil),
			input.crossFieldRelations[index].entries...,
		)
	}
	return input
}

func containsString(values []string, expected string) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func containsOutcome(values []Outcome, expected Outcome) bool {
	for _, value := range values {
		if value == expected {
			return true
		}
	}
	return false
}

func isFinite(value float64) bool { return !math.IsNaN(value) && !math.IsInf(value, 0) }
