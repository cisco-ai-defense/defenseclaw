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
	"reflect"
	"sort"
	"strings"
	"testing"
)

func TestDeriveGeneratedInboundNativeCatalogPreservesExpandedContract(t *testing.T) {
	baseMatches, baseTargets := generatedInboundNonNativeInputs()
	matches, targets := deriveGeneratedInboundNativeCatalog(baseMatches, baseTargets)

	expectedFamilies := expectedInboundNativeFamilies(t)
	expectedMatchIDs := make([]string, 0, len(matches))
	for _, match := range baseMatches {
		expectedMatchIDs = append(expectedMatchIDs, match.ID)
	}
	for _, classID := range []string{
		generatedInboundNativeLogClass,
		generatedInboundNativeMetricClass,
		generatedInboundNativeSpanClass,
	} {
		for _, familyID := range expectedFamilies[classID] {
			expectedMatchIDs = append(expectedMatchIDs, classID+"."+familyID)
		}
	}
	if got := inboundMatchIDs(matches); !reflect.DeepEqual(got, expectedMatchIDs) {
		t.Fatalf("derived match order differs from class/family order\ngot:  %v\nwant: %v", got, expectedMatchIDs)
	}

	expectedTargetIDs := make([]string, 0, len(targets))
	for _, target := range baseTargets {
		expectedTargetIDs = append(expectedTargetIDs, target.ID)
	}
	nativeTargetIDs := make([]string, 0, len(matches)-len(baseMatches))
	for _, matchID := range expectedMatchIDs[len(baseMatches):] {
		familyID := strings.TrimPrefix(matchID, nativeClassForMatchID(t, matchID)+".")
		nativeTargetIDs = append(nativeTargetIDs, matchID+"."+familyID)
	}
	sort.Strings(nativeTargetIDs)
	expectedTargetIDs = append(expectedTargetIDs, nativeTargetIDs...)
	if got := inboundTargetIDs(targets); !reflect.DeepEqual(got, expectedTargetIDs) {
		t.Fatalf("derived target order differs from full target-ID order\ngot:  %v\nwant: %v", got, expectedTargetIDs)
	}

	targetByID := make(map[string]generatedInboundTarget, len(targets))
	for _, target := range targets {
		targetByID[target.ID] = target
	}
	for _, match := range matches[len(baseMatches):] {
		if len(match.TargetIDs) != 1 {
			t.Fatalf("native match %q target count = %d, want 1", match.ID, len(match.TargetIDs))
		}
		target, ok := targetByID[match.TargetIDs[0]]
		if !ok {
			t.Fatalf("native match %q target %q is absent", match.ID, match.TargetIDs[0])
		}
		assertGeneratedInboundNativePair(t, match, target)
	}

	source := generatedInboundCatalogSourceValue()
	source.matches = matches
	source.targets = targets
	if _, err := buildInboundCatalog(source); err != nil {
		t.Fatalf("buildInboundCatalog(derived native catalog) error = %v", err)
	}

}

func TestDeriveGeneratedInboundNativeCatalogClonesBaseInputs(t *testing.T) {
	baseMatches, baseTargets := generatedInboundNonNativeInputs()
	inputMatch := cloneGeneratedInboundMatch(baseMatches[0])
	inputTarget := cloneGeneratedInboundTarget(baseTargets[0])
	matches, targets := deriveGeneratedInboundNativeCatalog(
		[]generatedInboundMatch{inputMatch},
		[]generatedInboundTarget{inputTarget},
	)
	wantMatch := cloneGeneratedInboundMatch(matches[0])
	wantTarget := cloneGeneratedInboundTarget(targets[0])

	inputMatch.Sources[0] = "mutated"
	inputMatch.Predicates[0].Key = "mutated"
	inputMatch.TargetIDs[0] = "mutated"
	if len(inputMatch.SourceUnitRule.Accepted) != 0 {
		inputMatch.SourceUnitRule.Accepted[0].SourceUnit = "mutated"
	}
	if inputMatch.TargetOverride != nil {
		inputMatch.TargetOverride.Source = "mutated"
	}
	inputTarget.FieldRefs[0] = "mutated"
	inputTarget.FieldDescriptorIDs[0] = "mutated"
	if len(inputTarget.SourceUnitRule.Accepted) != 0 {
		inputTarget.SourceUnitRule.Accepted[0].SourceUnit = "mutated"
	}

	if !reflect.DeepEqual(matches[0], wantMatch) {
		t.Fatal("derived base match aliases caller-owned storage")
	}
	if !reflect.DeepEqual(targets[0], wantTarget) {
		t.Fatal("derived base target aliases caller-owned storage")
	}
}

func generatedInboundNonNativeInputs() ([]generatedInboundMatch, []generatedInboundTarget) {
	matches := make([]generatedInboundMatch, 0)
	for _, match := range generatedInboundMatches {
		if !match.NativeRoundTrip {
			matches = append(matches, match)
		}
	}
	targets := make([]generatedInboundTarget, 0)
	for _, target := range generatedInboundTargets {
		if !isGeneratedInboundNativeClass(target.ClassID) {
			targets = append(targets, target)
		}
	}
	return matches, targets
}

func expectedInboundNativeFamilies(t *testing.T) map[string][]string {
	t.Helper()
	result := map[string][]string{
		generatedInboundNativeLogClass:    {},
		generatedInboundNativeMetricClass: {},
		generatedInboundNativeSpanClass:   {},
	}
	for _, item := range generatedFamilyIdentityDescriptors() {
		switch item.Identity.Signal {
		case SignalLogs:
			result[generatedInboundNativeLogClass] = append(result[generatedInboundNativeLogClass], item.FamilyID)
		case SignalTraces:
			result[generatedInboundNativeSpanClass] = append(result[generatedInboundNativeSpanClass], item.FamilyID)
		case SignalMetrics:
			descriptor, ok := item.Descriptor.(generatedMetricFamilyContract)
			if !ok {
				t.Fatalf("metric family %q does not implement generatedMetricFamilyContract", item.FamilyID)
			}
			switch descriptor.familyMetricContract().instrumentType {
			case "counter", "gauge", "updowncounter":
				result[generatedInboundNativeMetricClass] = append(result[generatedInboundNativeMetricClass], item.FamilyID)
			case "histogram":
			default:
				t.Fatalf("metric family %q has unknown instrument type", item.FamilyID)
			}
		default:
			t.Fatalf("family %q has unknown signal %q", item.FamilyID, item.Identity.Signal)
		}
	}
	for classID := range result {
		sort.Strings(result[classID])
		if len(result[classID]) == 0 {
			t.Fatalf("native class %q has no eligible families", classID)
		}
	}
	return result
}

func assertGeneratedInboundNativePair(t *testing.T, match generatedInboundMatch, target generatedInboundTarget) {
	t.Helper()
	classID := nativeClassForMatchID(t, match.ID)
	familyID := strings.TrimPrefix(match.ID, classID+".")
	if match.ClassID != classID || target.ClassID != classID || target.MatchID != match.ID ||
		target.ID != match.ID+"."+familyID || target.Family != familyID || target.Role != "import" ||
		target.TargetKind != "primary" || !match.NativeRoundTrip || match.Shape != "native_exact" ||
		!reflect.DeepEqual(match.Sources, []string{"any_authenticated"}) || len(match.AliasIDs) != 0 ||
		match.SourceProjectionPlanID != "" || match.TargetOverride != nil || target.SourceProjectionPlanID != "" {
		t.Fatalf("native match/target fixed contract drift for %q", match.ID)
	}
	contract := target.Descriptor.familyDescriptorContract()
	if contract.id != familyID || contract.identity.Bucket != Bucket(target.Bucket) ||
		contract.identity.Signal != Signal(target.Signal) || contract.identity.Name != EventName(target.EventName) ||
		int(contract.familySchemaVersion) != target.FamilySchemaVersion {
		t.Fatalf("native target identity drift for %q", target.ID)
	}
	if len(target.FieldRefs) != len(contract.fields) || len(target.FieldDescriptorIDs) != len(contract.fields) {
		t.Fatalf("native target field count drift for %q", target.ID)
	}
	prefix, _, _ := strings.Cut(familyID, ".")
	for index, field := range contract.fields {
		if target.FieldRefs[index] != field.key || target.FieldDescriptorIDs[index] != prefix+":"+familyID+":"+field.key {
			t.Fatalf("native target field %d drift for %q", index, target.ID)
		}
	}

	switch classID {
	case generatedInboundNativeLogClass:
		if match.Signal != string(SignalLogs) || target.Signal != string(SignalLogs) ||
			match.DiscriminatorKind != "native-v8-log" || match.MappingStrategy != "native-projected-log-v1" ||
			target.MappingStrategy != "native-projected-log-v1" || target.ImportContextID != "otlp.import."+familyID ||
			match.TimeRuleJSON != `"log-time-observed-receipt-v1"` || match.OutcomeRuleJSON != `"projected-record-v1"` ||
			len(match.Predicates) != 9 {
			t.Fatalf("native log contract drift for %q", match.ID)
		}
		wantPredicates := []generatedInboundPredicate{
			{Location: "resource_attribute", Key: generatedInboundSemanticInstanceKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "leaf_attribute", Key: generatedInboundRecordIDKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "leaf_attribute", Key: "defenseclaw.bucket", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, target.Bucket), ValueType: "string"},
			{Location: "leaf_attribute", Key: "defenseclaw.signal", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, string(SignalLogs)), ValueType: "string"},
			{Location: "leaf_attribute", Key: "defenseclaw.event.name", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, target.EventName), ValueType: "string"},
			{Location: "leaf_attribute", Key: generatedInboundForwardInstanceKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "leaf_attribute", Key: generatedInboundForwardDestinationKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "leaf_attribute", Key: generatedInboundForwardHopCountKey, Operator: "uint32_max", ValuesJSON: inboundTestJSONValues(t, generatedInboundMaxForwardHops), ValueType: "int64"},
			{Location: "log_body", Key: "$body", Operator: "projected_record_json", ValuesJSON: "[]", ValueType: "string"},
		}
		if !reflect.DeepEqual(match.Predicates, wantPredicates) {
			t.Fatalf("native log predicate order/content drift for %q", match.ID)
		}
	case generatedInboundNativeMetricClass:
		if match.Signal != string(SignalMetrics) || target.Signal != string(SignalMetrics) ||
			match.DiscriminatorKind != "native-v8-metric" || match.MappingStrategy != "generated-reverse-metric-v1" ||
			target.MappingStrategy != "generated-reverse-metric-v1" || target.ImportContextID != "" ||
			match.TimeRuleJSON != `"metric-point-receipt-v1"` || match.OutcomeRuleJSON != `"forbidden"` ||
			len(match.Predicates) != 9 || match.SourceUnitRule.Kind != "target-unit-equality-v1" ||
			!reflect.DeepEqual(match.SourceUnitRule, target.SourceUnitRule) {
			t.Fatalf("native metric contract drift for %q", match.ID)
		}
		pointShape := map[string]string{
			"counter":       "sum_delta_monotonic",
			"updowncounter": "sum_delta",
			"gauge":         "gauge",
		}[target.InstrumentType]
		if pointShape == "" || target.InstrumentName == "" ||
			match.SourceUnitRule.TargetUnit != target.InstrumentUnit || len(match.SourceUnitRule.Accepted) != 1 ||
			match.SourceUnitRule.Accepted[0] != (generatedInboundUnitScale{SourceUnit: target.InstrumentUnit, Scale: 1}) {
			t.Fatalf("native metric instrument/unit drift for %q", match.ID)
		}
		wantPredicates := []generatedInboundPredicate{
			{Location: "resource_schema_url", Key: "$resource_schema_url", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, generatedInboundResourceSchemaURL), ValueType: "string"},
			{Location: "resource_attribute", Key: generatedInboundSemanticInstanceKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "resource_attribute", Key: generatedInboundForwardInstanceKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "resource_attribute", Key: generatedInboundForwardDestinationKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "resource_attribute", Key: generatedInboundForwardHopCountKey, Operator: "uint32_max", ValuesJSON: inboundTestJSONValues(t, generatedInboundMaxForwardHops), ValueType: "int64"},
			{Location: "scope_name", Key: "$scope_name", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, generatedInboundScopeName), ValueType: "string"},
			{Location: "scope_schema_url", Key: "$scope_schema_url", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, generatedInboundScopeSchemaURL), ValueType: "string"},
			{Location: "instrument_name", Key: "$instrument_name", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, target.InstrumentName), ValueType: "string"},
			{Location: "metric_point", Key: "$point_shape", Operator: "one_of", ValuesJSON: inboundTestJSONValues(t, pointShape), ValueType: "string"},
		}
		if !reflect.DeepEqual(match.Predicates, wantPredicates) {
			t.Fatalf("native metric predicate order/content drift for %q", match.ID)
		}
	case generatedInboundNativeSpanClass:
		if match.Signal != string(SignalTraces) || target.Signal != string(SignalTraces) ||
			match.DiscriminatorKind != "native-v8-span" || match.MappingStrategy != "generated-reverse-span-v1" ||
			target.MappingStrategy != "generated-reverse-span-v1" || target.ImportContextID != "" ||
			match.TimeRuleJSON != `"span-end-v1"` || match.OutcomeRuleJSON != `"native-span-v1"` ||
			len(match.Predicates) != 10 {
			t.Fatalf("native span contract drift for %q", match.ID)
		}
		wantPredicates := []generatedInboundPredicate{
			{Location: "resource_schema_url", Key: "$resource_schema_url", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, generatedInboundResourceSchemaURL), ValueType: "string"},
			{Location: "resource_attribute", Key: generatedInboundSemanticInstanceKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "scope_name", Key: "$scope_name", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, generatedInboundScopeName), ValueType: "string"},
			{Location: "scope_schema_url", Key: "$scope_schema_url", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, generatedInboundScopeSchemaURL), ValueType: "string"},
			{Location: "leaf_attribute", Key: "defenseclaw.bucket", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, target.Bucket), ValueType: "string"},
			{Location: "leaf_attribute", Key: "defenseclaw.span.family", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, target.Family), ValueType: "string"},
			{Location: "leaf_attribute", Key: "defenseclaw.span.family_schema_version", Operator: "equals", ValuesJSON: inboundTestJSONValues(t, target.FamilySchemaVersion), ValueType: "int64"},
			{Location: "leaf_attribute", Key: generatedInboundForwardInstanceKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "leaf_attribute", Key: generatedInboundForwardDestinationKey, Operator: "present", ValuesJSON: "[]", ValueType: "string"},
			{Location: "leaf_attribute", Key: generatedInboundForwardHopCountKey, Operator: "uint32_max", ValuesJSON: inboundTestJSONValues(t, generatedInboundMaxForwardHops), ValueType: "int64"},
		}
		if !reflect.DeepEqual(match.Predicates, wantPredicates) {
			t.Fatalf("native span predicate order/content drift for %q", match.ID)
		}
	default:
		t.Fatalf("unknown native class %q", classID)
	}
	if match.TimeRuleJSON != target.TimeRuleJSON || match.OutcomeRuleJSON != target.OutcomeRuleJSON {
		t.Fatalf("native match/target rules disagree for %q", match.ID)
	}
}

func inboundTestJSONValues(t *testing.T, values ...any) string {
	t.Helper()
	encoded, err := json.Marshal(values)
	if err != nil {
		t.Fatalf("json.Marshal(%v) error = %v", values, err)
	}
	return string(encoded)
}

func nativeClassForMatchID(t *testing.T, matchID string) string {
	t.Helper()
	for _, classID := range []string{
		generatedInboundNativeLogClass,
		generatedInboundNativeMetricClass,
		generatedInboundNativeSpanClass,
	} {
		if strings.HasPrefix(matchID, classID+".") {
			return classID
		}
	}
	t.Fatalf("match %q does not belong to a native class", matchID)
	return ""
}

func isGeneratedInboundNativeClass(classID string) bool {
	return classID == generatedInboundNativeLogClass ||
		classID == generatedInboundNativeMetricClass ||
		classID == generatedInboundNativeSpanClass
}

func inboundMatchIDs(matches []generatedInboundMatch) []string {
	result := make([]string, len(matches))
	for index := range matches {
		result[index] = matches[index].ID
	}
	return result
}

func inboundTargetIDs(targets []generatedInboundTarget) []string {
	result := make([]string, len(targets))
	for index := range targets {
		result[index] = targets[index].ID
	}
	return result
}
