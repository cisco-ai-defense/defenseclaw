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
	"fmt"
	"sort"
	"strings"
)

const (
	generatedInboundNativeLogClass    = "otlp.native.log.v8"
	generatedInboundNativeMetricClass = "otlp.native.metric.v8"
	generatedInboundNativeSpanClass   = "otlp.native.span.v8"
)

type generatedInboundNativeFamily struct {
	familyID   string
	identity   EventIdentity
	descriptor familyDescriptor
	contract   familyDescriptorContract
	metric     familyMetricContract
}

// deriveGeneratedInboundNativeCatalog expands the closed native round-trip
// formula from the generated family descriptors once during package
// initialization. The authored non-native records retain their generated order;
// native matches use signal-class/family order and native targets use full target
// ID order, matching the registry compiler's deterministic contract.
func deriveGeneratedInboundNativeCatalog(
	baseMatches []generatedInboundMatch,
	baseTargets []generatedInboundTarget,
) ([]generatedInboundMatch, []generatedInboundTarget) {
	logFamilies, metricFamilies, spanFamilies := generatedInboundNativeFamilies()
	nativeCount := len(logFamilies) + len(metricFamilies) + len(spanFamilies)

	matches := make([]generatedInboundMatch, len(baseMatches), len(baseMatches)+nativeCount)
	for index := range baseMatches {
		matches[index] = cloneGeneratedInboundMatch(baseMatches[index])
	}
	targets := make([]generatedInboundTarget, len(baseTargets), len(baseTargets)+nativeCount)
	for index := range baseTargets {
		targets[index] = cloneGeneratedInboundTarget(baseTargets[index])
	}

	nativeTargets := make([]generatedInboundTarget, 0, nativeCount)
	appendFamily := func(classID, signal string, family generatedInboundNativeFamily) {
		match, target := generatedInboundNativePair(classID, signal, family)
		matches = append(matches, match)
		nativeTargets = append(nativeTargets, target)
	}
	for _, family := range logFamilies {
		appendFamily(generatedInboundNativeLogClass, string(SignalLogs), family)
	}
	for _, family := range metricFamilies {
		appendFamily(generatedInboundNativeMetricClass, string(SignalMetrics), family)
	}
	for _, family := range spanFamilies {
		appendFamily(generatedInboundNativeSpanClass, string(SignalTraces), family)
	}
	sort.Slice(nativeTargets, func(left, right int) bool {
		return nativeTargets[left].ID < nativeTargets[right].ID
	})
	targets = append(targets, nativeTargets...)
	return matches, targets
}

func generatedInboundNativeFamilies() (logs, metrics, spans []generatedInboundNativeFamily) {
	for _, item := range generatedFamilyIdentityDescriptors() {
		contract := item.Descriptor.familyDescriptorContract()
		if contract.id != item.FamilyID || contract.identity != item.Identity {
			panic(fmt.Sprintf("generated inbound native family identity drift: %s", item.FamilyID))
		}
		family := generatedInboundNativeFamily{
			familyID: item.FamilyID, identity: item.Identity, descriptor: item.Descriptor, contract: contract,
		}
		switch item.Identity.Signal {
		case SignalLogs:
			if !strings.HasPrefix(item.FamilyID, "log.") {
				panic(fmt.Sprintf("generated inbound native log family prefix drift: %s", item.FamilyID))
			}
			logs = append(logs, family)
		case SignalMetrics:
			if !strings.HasPrefix(item.FamilyID, "metric.") {
				panic(fmt.Sprintf("generated inbound native metric family prefix drift: %s", item.FamilyID))
			}
			descriptor, ok := item.Descriptor.(generatedMetricFamilyContract)
			if !ok {
				panic(fmt.Sprintf("generated inbound native metric contract unavailable: %s", item.FamilyID))
			}
			family.metric = descriptor.familyMetricContract()
			switch family.metric.instrumentType {
			case "counter", "gauge", "updowncounter":
				metrics = append(metrics, family)
			case "histogram":
				// Histogram aggregation cannot be reversed into a native metric point.
			default:
				panic(fmt.Sprintf("generated inbound native metric instrument drift: %s", item.FamilyID))
			}
		case SignalTraces:
			if !strings.HasPrefix(item.FamilyID, "span.") {
				panic(fmt.Sprintf("generated inbound native span family prefix drift: %s", item.FamilyID))
			}
			if _, ok := item.Descriptor.(generatedTraceFamilyContract); !ok {
				panic(fmt.Sprintf("generated inbound native span contract unavailable: %s", item.FamilyID))
			}
			spans = append(spans, family)
		default:
			panic(fmt.Sprintf("generated inbound native signal drift: %s", item.FamilyID))
		}
	}
	byFamilyID := func(items []generatedInboundNativeFamily) {
		sort.Slice(items, func(left, right int) bool { return items[left].familyID < items[right].familyID })
		for index := 1; index < len(items); index++ {
			if items[index-1].familyID == items[index].familyID {
				panic(fmt.Sprintf("duplicate generated inbound native family: %s", items[index].familyID))
			}
		}
	}
	byFamilyID(logs)
	byFamilyID(metrics)
	byFamilyID(spans)
	return logs, metrics, spans
}

func generatedInboundNativePair(
	classID, signal string,
	family generatedInboundNativeFamily,
) (generatedInboundMatch, generatedInboundTarget) {
	matchID := classID + "." + family.familyID
	targetID := matchID + "." + family.familyID
	mapping, discriminator, timeRule, outcomeRule := "", "", "", ""
	unitRule := generatedInboundUnitRule{Kind: "none", Accepted: []generatedInboundUnitScale{}}
	var predicates []generatedInboundPredicate

	switch signal {
	case string(SignalLogs):
		mapping = "native-projected-log-v1"
		discriminator = "native-v8-log"
		timeRule = generatedInboundJSONString("log-time-observed-receipt-v1")
		outcomeRule = generatedInboundJSONString("projected-record-v1")
		predicates = []generatedInboundPredicate{
			generatedInboundPresentPredicate("resource_attribute", generatedInboundSemanticInstanceKey, "string"),
			generatedInboundPresentPredicate("leaf_attribute", generatedInboundRecordIDKey, "string"),
			generatedInboundEqualsPredicate("leaf_attribute", "defenseclaw.bucket", "string", string(family.identity.Bucket)),
			generatedInboundEqualsPredicate("leaf_attribute", "defenseclaw.signal", "string", string(SignalLogs)),
			generatedInboundEqualsPredicate("leaf_attribute", "defenseclaw.event.name", "string", string(family.identity.Name)),
			generatedInboundPresentPredicate("leaf_attribute", generatedInboundForwardInstanceKey, "string"),
			generatedInboundPresentPredicate("leaf_attribute", generatedInboundForwardDestinationKey, "string"),
			generatedInboundMaxHopsPredicate("leaf_attribute"),
			{Location: "log_body", Key: "$body", Operator: "projected_record_json", ValuesJSON: "[]", ValueType: "string"},
		}
	case string(SignalMetrics):
		mapping = "generated-reverse-metric-v1"
		discriminator = "native-v8-metric"
		timeRule = generatedInboundJSONString("metric-point-receipt-v1")
		outcomeRule = generatedInboundJSONString("forbidden")
		pointShape := ""
		switch family.metric.instrumentType {
		case "counter":
			pointShape = "sum_delta_monotonic"
		case "updowncounter":
			pointShape = "sum_delta"
		case "gauge":
			pointShape = "gauge"
		default:
			panic(fmt.Sprintf("non-reversible generated inbound metric: %s", family.familyID))
		}
		predicates = []generatedInboundPredicate{
			generatedInboundEqualsPredicate("resource_schema_url", "$resource_schema_url", "string", generatedInboundResourceSchemaURL),
			generatedInboundPresentPredicate("resource_attribute", generatedInboundSemanticInstanceKey, "string"),
			generatedInboundPresentPredicate("resource_attribute", generatedInboundForwardInstanceKey, "string"),
			generatedInboundPresentPredicate("resource_attribute", generatedInboundForwardDestinationKey, "string"),
			generatedInboundMaxHopsPredicate("resource_attribute"),
			generatedInboundEqualsPredicate("scope_name", "$scope_name", "string", generatedInboundScopeName),
			generatedInboundEqualsPredicate("scope_schema_url", "$scope_schema_url", "string", generatedInboundScopeSchemaURL),
			generatedInboundEqualsPredicate("instrument_name", "$instrument_name", "string", family.metric.instrumentName),
			{Location: "metric_point", Key: "$point_shape", Operator: "one_of", ValuesJSON: generatedInboundJSONStringArray(pointShape), ValueType: "string"},
		}
		unitRule = generatedInboundUnitRule{
			Kind: "target-unit-equality-v1", TargetUnit: family.metric.unit,
			Accepted: []generatedInboundUnitScale{{SourceUnit: family.metric.unit, Scale: 1.0}},
		}
	case string(SignalTraces):
		mapping = "generated-reverse-span-v1"
		discriminator = "native-v8-span"
		timeRule = generatedInboundJSONString("span-end-v1")
		outcomeRule = generatedInboundJSONString("native-span-v1")
		predicates = []generatedInboundPredicate{
			generatedInboundEqualsPredicate("resource_schema_url", "$resource_schema_url", "string", generatedInboundResourceSchemaURL),
			generatedInboundPresentPredicate("resource_attribute", generatedInboundSemanticInstanceKey, "string"),
			generatedInboundEqualsPredicate("scope_name", "$scope_name", "string", generatedInboundScopeName),
			generatedInboundEqualsPredicate("scope_schema_url", "$scope_schema_url", "string", generatedInboundScopeSchemaURL),
			generatedInboundEqualsPredicate("leaf_attribute", "defenseclaw.bucket", "string", string(family.identity.Bucket)),
			generatedInboundEqualsPredicate("leaf_attribute", "defenseclaw.span.family", "string", family.familyID),
			generatedInboundEqualsPredicate("leaf_attribute", "defenseclaw.span.family_schema_version", "int64", int(family.contract.familySchemaVersion)),
			generatedInboundPresentPredicate("leaf_attribute", generatedInboundForwardInstanceKey, "string"),
			generatedInboundPresentPredicate("leaf_attribute", generatedInboundForwardDestinationKey, "string"),
			generatedInboundMaxHopsPredicate("leaf_attribute"),
		}
	default:
		panic(fmt.Sprintf("unknown generated inbound native signal: %s", signal))
	}

	fieldRefs := make([]string, len(family.contract.fields))
	fieldDescriptorIDs := make([]string, len(family.contract.fields))
	prefix, _, ok := strings.Cut(family.familyID, ".")
	if !ok {
		panic(fmt.Sprintf("generated inbound native family lacks signal prefix: %s", family.familyID))
	}
	for index, field := range family.contract.fields {
		fieldRefs[index] = field.key
		fieldDescriptorIDs[index] = prefix + ":" + family.familyID + ":" + field.key
	}

	importContextID := ""
	if signal == string(SignalLogs) {
		importContextID = "otlp.import." + family.familyID
	}
	match := generatedInboundMatch{
		ID: matchID, ClassID: classID, Signal: signal, Sources: []string{"any_authenticated"},
		Shape: "native_exact", DiscriminatorKind: discriminator, Predicates: predicates,
		MappingStrategy: mapping, AliasIDs: []string{}, SourceUnitRule: unitRule,
		TargetIDs: []string{targetID}, TimeRuleJSON: timeRule, OutcomeRuleJSON: outcomeRule,
		NativeRoundTrip: true,
	}
	target := generatedInboundTarget{
		ID: targetID, MatchID: matchID, ClassID: classID, Signal: signal, Role: "import", TargetKind: "primary",
		Family: family.familyID, Bucket: string(family.identity.Bucket), EventName: string(family.identity.Name),
		FamilySchemaVersion: int(family.contract.familySchemaVersion), FieldRefs: fieldRefs,
		FieldDescriptorIDs: fieldDescriptorIDs, Descriptor: family.descriptor, MappingStrategy: mapping,
		TimeRuleJSON: timeRule, OutcomeRuleJSON: outcomeRule, ImportContextID: importContextID,
		SourceUnitRule: unitRule,
	}
	if signal == string(SignalMetrics) {
		target.InstrumentName = family.metric.instrumentName
		target.InstrumentType = family.metric.instrumentType
		target.InstrumentUnit = family.metric.unit
	}
	return match, target
}

func generatedInboundPresentPredicate(location, key, valueType string) generatedInboundPredicate {
	return generatedInboundPredicate{Location: location, Key: key, Operator: "present", ValuesJSON: "[]", ValueType: valueType}
}

func generatedInboundEqualsPredicate(location, key, valueType string, value any) generatedInboundPredicate {
	return generatedInboundPredicate{
		Location: location, Key: key, Operator: "equals", ValuesJSON: generatedInboundJSONValues(value), ValueType: valueType,
	}
}

func generatedInboundMaxHopsPredicate(location string) generatedInboundPredicate {
	return generatedInboundPredicate{
		Location: location, Key: generatedInboundForwardHopCountKey, Operator: "uint32_max",
		ValuesJSON: generatedInboundJSONValues(generatedInboundMaxForwardHops), ValueType: "int64",
	}
}

func generatedInboundJSONString(value string) string {
	encoded, err := json.Marshal(value)
	if err != nil {
		panic(fmt.Sprintf("marshal generated inbound string: %v", err))
	}
	return string(encoded)
}

func generatedInboundJSONStringArray(values ...string) string {
	items := make([]any, len(values))
	for index := range values {
		items[index] = values[index]
	}
	return generatedInboundJSONValues(items...)
}

func generatedInboundJSONValues(values ...any) string {
	encoded, err := json.Marshal(values)
	if err != nil {
		panic(fmt.Sprintf("marshal generated inbound predicate values: %v", err))
	}
	return string(encoded)
}

func cloneGeneratedInboundMatch(input generatedInboundMatch) generatedInboundMatch {
	cloned := input
	cloned.Sources = cloneGeneratedInboundSlice(input.Sources)
	cloned.Predicates = cloneGeneratedInboundSlice(input.Predicates)
	cloned.AliasIDs = cloneGeneratedInboundSlice(input.AliasIDs)
	cloned.SourceUnitRule.Accepted = cloneGeneratedInboundSlice(input.SourceUnitRule.Accepted)
	cloned.TargetIDs = cloneGeneratedInboundSlice(input.TargetIDs)
	if input.TargetOverride != nil {
		override := *input.TargetOverride
		cloned.TargetOverride = &override
	}
	return cloned
}

func cloneGeneratedInboundTarget(input generatedInboundTarget) generatedInboundTarget {
	cloned := input
	cloned.FieldRefs = cloneGeneratedInboundSlice(input.FieldRefs)
	cloned.FieldDescriptorIDs = cloneGeneratedInboundSlice(input.FieldDescriptorIDs)
	cloned.SourceUnitRule.Accepted = cloneGeneratedInboundSlice(input.SourceUnitRule.Accepted)
	return cloned
}

func cloneGeneratedInboundSlice[T any](input []T) []T {
	if input == nil {
		return nil
	}
	cloned := make([]T, len(input))
	copy(cloned, input)
	return cloned
}
