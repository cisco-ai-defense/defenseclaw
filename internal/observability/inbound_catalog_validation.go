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
	"io"
	"math"
	"reflect"
	"regexp"
	"sort"
	"strings"
	"unicode/utf8"
)

type generatedInboundCatalogSource struct {
	aliases     []generatedInboundAlias
	normalizers []generatedInboundSourceNormalizer
	projections []generatedInboundSourceProjectionPlan
	matches     []generatedInboundMatch
	targets     []generatedInboundTarget
	markers     []generatedInboundNativeMarker
	echoes      []generatedInboundEchoRecognizer
	contexts    []generatedInboundImportContext
	policies    InboundTerminalPolicies
	wire        InboundWireContract
}

func generatedInboundCatalogSourceValue() generatedInboundCatalogSource {
	return generatedInboundCatalogSource{
		aliases:     generatedInboundAliases,
		normalizers: generatedInboundSourceNormalizers,
		projections: generatedInboundSourceProjectionPlans,
		matches:     generatedInboundMatches,
		targets:     generatedInboundTargets,
		markers:     generatedInboundNativeMarkers,
		echoes:      generatedInboundEchoRecognizers,
		contexts:    generatedInboundImportContexts,
		policies: InboundTerminalPolicies{
			UnknownFields:                   generatedInboundUnknownFields,
			NativeMarkerRule:                generatedInboundNativeMarkerRule,
			StructuralMarkerRule:            generatedInboundStructuralMarkerRule,
			NativeMalformedDisposition:      generatedInboundNativeMalformedDisposition,
			NativeMalformedExternalFallback: generatedInboundNativeMalformedExternalFallback,
		},
		wire: InboundWireContract{
			ScopeName:             generatedInboundScopeName,
			ScopeSchemaURL:        generatedInboundScopeSchemaURL,
			ResourceSchemaURL:     generatedInboundResourceSchemaURL,
			SemanticInstanceKey:   generatedInboundSemanticInstanceKey,
			ForwardInstanceKey:    generatedInboundForwardInstanceKey,
			ForwardDestinationKey: generatedInboundForwardDestinationKey,
			ForwardHopCountKey:    generatedInboundForwardHopCountKey,
			RecordIDKey:           generatedInboundRecordIDKey,
			MaxForwardHops:        uint32(generatedInboundMaxForwardHops),
		},
	}
}

func buildInboundCatalog(source generatedInboundCatalogSource) (InboundCatalog, error) {
	if err := validateInboundPolicies(source.policies, source.wire); err != nil {
		return InboundCatalog{}, err
	}
	if len(source.aliases) == 0 || len(source.normalizers) == 0 || len(source.projections) == 0 || len(source.matches) == 0 || len(source.targets) == 0 ||
		len(source.markers) == 0 || len(source.echoes) == 0 || len(source.contexts) == 0 {
		return InboundCatalog{}, invalidInboundCatalog("one or more generated tables are empty")
	}

	snapshot := &inboundCatalogSnapshot{
		aliases:         make([]inboundAliasEntry, 0, len(source.aliases)),
		normalizers:     make([]inboundSourceNormalizerEntry, 0, len(source.normalizers)),
		projections:     make([]inboundSourceProjectionPlanEntry, 0, len(source.projections)),
		matches:         make([]inboundMatchEntry, 0, len(source.matches)),
		targets:         make([]inboundTargetEntry, 0, len(source.targets)),
		markers:         make([]inboundMarkerEntry, 0, len(source.markers)),
		echoes:          make([]inboundEchoEntry, 0, len(source.echoes)),
		contexts:        make([]inboundImportContextEntry, 0, len(source.contexts)),
		aliasByID:       make(map[string]int, len(source.aliases)),
		normalizerByID:  make(map[string]int, len(source.normalizers)),
		projectionByID:  make(map[string]int, len(source.projections)),
		matchByID:       make(map[string]int, len(source.matches)),
		targetByID:      make(map[string]int, len(source.targets)),
		markerByKey:     make(map[inboundMarkerLookupKey]int, len(source.markers)),
		echoByIdentity:  make(map[inboundEchoLookupKey]int, len(source.echoes)),
		echoByWire:      make(map[inboundEchoWireLookupKey]int, len(source.echoes)),
		contextByID:     make(map[string]int, len(source.contexts)),
		contextByFamily: make(map[string]int, len(source.contexts)),
		policies:        source.policies,
		wire:            source.wire,
	}

	if err := buildInboundAliases(snapshot, source.aliases); err != nil {
		return InboundCatalog{}, err
	}
	if err := buildInboundSourceNormalizers(snapshot, source.normalizers); err != nil {
		return InboundCatalog{}, err
	}
	if err := buildInboundImportContexts(snapshot, source.contexts); err != nil {
		return InboundCatalog{}, err
	}
	if err := buildInboundTargets(snapshot, source.targets); err != nil {
		return InboundCatalog{}, err
	}
	if err := buildInboundSourceProjectionPlans(snapshot, source.projections); err != nil {
		return InboundCatalog{}, err
	}
	if err := buildInboundMatches(snapshot, source.matches, source.targets); err != nil {
		return InboundCatalog{}, err
	}
	if err := buildInboundMarkers(snapshot, source.markers); err != nil {
		return InboundCatalog{}, err
	}
	if err := buildInboundEchoes(snapshot, source.echoes); err != nil {
		return InboundCatalog{}, err
	}
	if err := validateInboundCrossReferences(snapshot); err != nil {
		return InboundCatalog{}, err
	}
	return InboundCatalog{snapshot: snapshot}, nil
}

func validateInboundPolicies(policies InboundTerminalPolicies, wire InboundWireContract) error {
	if policies.UnknownFields != "drop_and_count" ||
		policies.NativeMarkerRule != "any_declared_native_marker_selects_native_candidate" ||
		policies.StructuralMarkerRule != "exact_declared_structure_only" ||
		policies.NativeMalformedDisposition != "invalid_record" ||
		policies.NativeMalformedExternalFallback != "forbidden" {
		return invalidInboundCatalog("terminal shape policy drift")
	}
	if wire.ScopeName != "defenseclaw.telemetry" ||
		wire.ScopeSchemaURL != "https://defenseclaw.io/schemas/telemetry/v8" ||
		wire.ResourceSchemaURL != "https://opentelemetry.io/schemas/1.42.0" ||
		wire.SemanticInstanceKey != "defenseclaw.instance.id" ||
		wire.ForwardInstanceKey != "defenseclaw.telemetry.forward.instance_id" ||
		wire.ForwardDestinationKey != "defenseclaw.telemetry.forward.destination" ||
		wire.ForwardHopCountKey != "defenseclaw.telemetry.forward.hop_count" ||
		wire.RecordIDKey != "defenseclaw.record.id" || wire.MaxForwardHops != MaxImportForwardHops {
		return invalidInboundCatalog("wire contract drift")
	}
	return nil
}

func buildInboundAliases(snapshot *inboundCatalogSnapshot, aliases []generatedInboundAlias) error {
	for _, input := range aliases {
		if !validInboundID(input.ID) || input.Target == "" || !utf8.ValidString(input.Target) ||
			!validInboundValueType(InboundValueType(input.ValueType), true) ||
			!containsInboundString([]string{"identifier-v1", "bounded-v1", "structured-genai-v1", "nonnegative-int64-v1", "duration-seconds-v1"}, input.Normalization) ||
			input.ConflictPolicy != "reject" || input.AbsencePolicy != "omit" ||
			!IsFieldClass(FieldClass(input.FieldClass)) ||
			!containsInboundString([]string{"safe", "internal", "sensitive"}, input.Sensitivity) || len(input.Sources) == 0 {
			return invalidInboundCatalog("malformed alias descriptor")
		}
		if _, duplicate := snapshot.aliasByID[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate alias ID")
		}
		if err := validateInboundStrings(input.Sources, true); err != nil {
			return invalidInboundCatalog("malformed alias sources")
		}
		index := len(snapshot.aliases)
		snapshot.aliasByID[input.ID] = index
		snapshot.aliases = append(snapshot.aliases, inboundAliasEntry{
			id: input.ID, target: input.Target, valueType: InboundValueType(input.ValueType),
			normalization: input.Normalization, sources: append([]string(nil), input.Sources...),
			conflictPolicy: input.ConflictPolicy, absencePolicy: input.AbsencePolicy,
			fieldClass: FieldClass(input.FieldClass), sensitivity: input.Sensitivity,
		})
	}
	return nil
}

func buildInboundSourceNormalizers(snapshot *inboundCatalogSnapshot, inputs []generatedInboundSourceNormalizer) error {
	expected := []struct{ id, kind string }{
		{"bounded-label-v1", "bounded"},
		{"identifier-label-v1", "identifier"},
		{"genai-provider-label-v1", "ordered-exact-contains"},
		{"genai-model-label-v1", "ordered-prefix-family"},
		{"genai-operation-label-v1", "exact-map"},
		{"token-type-label-v1", "exact-map"},
	}
	if len(inputs) != len(expected) {
		return invalidInboundCatalog("source normalizer inventory drift")
	}
	for position, input := range inputs {
		if input.ID != expected[position].id || input.Kind != expected[position].kind ||
			!containsInboundString([]string{"none", "unicode-space"}, input.Trim) ||
			!containsInboundString([]string{"preserve", "lowercase"}, input.Case) ||
			!containsInboundString([]string{"reject", "unknown"}, input.Empty) ||
			!containsInboundString([]string{"", "reject", "other"}, input.Overflow) ||
			!containsInboundString([]string{"", "reject", "other"}, input.Unmatched) || input.MaxUTF8Bytes < 0 {
			return invalidInboundCatalog("malformed source normalizer")
		}
		if _, duplicate := snapshot.normalizerByID[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate source normalizer ID")
		}
		entry := inboundSourceNormalizerEntry{
			id: input.ID, kind: input.Kind, trim: input.Trim, casePolicy: input.Case,
			maxUTF8Bytes: input.MaxUTF8Bytes, empty: input.Empty, overflow: input.Overflow,
			unmatched: input.Unmatched, pattern: input.Pattern,
			values: append([]string(nil), input.Values...), separators: append([]string(nil), input.Separators...),
			prefixes: append([]string(nil), input.Prefixes...),
		}
		if input.Pattern != "" {
			compiled, err := regexp.Compile(input.Pattern)
			if err != nil {
				return invalidInboundCatalog("invalid source normalizer pattern")
			}
			entry.compiled = compiled
		}
		seenMatchers := make(map[string]struct{})
		for _, inputRule := range input.Rules {
			if inputRule.Output == "" || !utf8.ValidString(inputRule.Output) {
				return invalidInboundCatalog("malformed source normalizer rule")
			}
			rule := inboundSourceNormalizerRuleEntry{
				output: inputRule.Output, exact: append([]string(nil), inputRule.Exact...),
				contains: append([]string(nil), inputRule.Contains...), inputs: append([]string(nil), inputRule.Inputs...),
			}
			for kind, values := range map[string][]string{"exact": rule.exact, "contains": rule.contains, "input": rule.inputs} {
				// Exact-map inputs are sealed wire values, not catalog IDs. They
				// may therefore contain connector syntax such as cached_input.
				allowWireSyntax := kind == "input" && input.ID == "token-type-label-v1"
				if err := validateInboundStrings(values, allowWireSyntax); err != nil {
					return invalidInboundCatalog("malformed source normalizer matcher")
				}
				for _, value := range values {
					identity := kind + "\x00" + value
					if _, duplicate := seenMatchers[identity]; duplicate {
						return invalidInboundCatalog("colliding source normalizer matcher")
					}
					seenMatchers[identity] = struct{}{}
				}
			}
			entry.rules = append(entry.rules, rule)
		}
		if err := validateInboundSourceNormalizerShape(entry); err != nil {
			return err
		}
		index := len(snapshot.normalizers)
		snapshot.normalizerByID[input.ID] = index
		snapshot.normalizers = append(snapshot.normalizers, entry)
	}
	return nil
}

func validateInboundSourceNormalizerShape(entry inboundSourceNormalizerEntry) error {
	switch entry.kind {
	case "bounded":
		if entry.maxUTF8Bytes != 256 || entry.trim != "unicode-space" || entry.casePolicy != "preserve" ||
			entry.empty != "reject" || entry.overflow != "reject" || entry.unmatched != "" ||
			entry.pattern != "" || len(entry.values)+len(entry.separators)+len(entry.prefixes)+len(entry.rules) != 0 {
			return invalidInboundCatalog("bounded source normalizer drift")
		}
	case "identifier":
		if entry.maxUTF8Bytes != 256 || entry.compiled == nil || entry.trim != "unicode-space" ||
			entry.casePolicy != "preserve" || entry.empty != "reject" || entry.overflow != "reject" ||
			entry.unmatched != "" || len(entry.values)+len(entry.separators)+len(entry.prefixes)+len(entry.rules) != 0 {
			return invalidInboundCatalog("identifier source normalizer drift")
		}
	case "ordered-exact-contains":
		if entry.maxUTF8Bytes != 64 || entry.trim != "unicode-space" || entry.casePolicy != "lowercase" ||
			entry.empty != "unknown" || entry.overflow != "other" || entry.unmatched != "other" ||
			len(entry.rules) != 8 || entry.pattern != "" || len(entry.values)+len(entry.separators)+len(entry.prefixes) != 0 {
			return invalidInboundCatalog("provider source normalizer drift")
		}
	case "ordered-prefix-family":
		if entry.maxUTF8Bytes != 64 || entry.trim != "unicode-space" || entry.casePolicy != "lowercase" ||
			entry.empty != "unknown" || entry.overflow != "other" || entry.unmatched != "other" ||
			len(entry.prefixes) != 25 || !reflect.DeepEqual(entry.separators, []string{"-", ".", ":"}) ||
			entry.pattern != "" || len(entry.values)+len(entry.rules) != 0 {
			return invalidInboundCatalog("model source normalizer drift")
		}
	case "exact-map":
		switch entry.id {
		case "genai-operation-label-v1":
			if entry.maxUTF8Bytes != 0 || entry.trim != "unicode-space" || entry.casePolicy != "lowercase" ||
				entry.empty != "reject" || entry.overflow != "" || entry.unmatched != "reject" || len(entry.rules) != 17 ||
				entry.pattern != "" || len(entry.values)+len(entry.separators)+len(entry.prefixes) != 0 {
				return invalidInboundCatalog("operation source normalizer drift")
			}
		case "token-type-label-v1":
			want := []inboundSourceNormalizerRuleEntry{
				{output: "input", inputs: []string{"input"}},
				{output: "output", inputs: []string{"output"}},
				{output: "cacheRead", inputs: []string{"cacheRead", "cached_input"}},
				{output: "cacheCreation", inputs: []string{"cacheCreation"}},
			}
			if entry.maxUTF8Bytes != 0 || entry.trim != "none" || entry.casePolicy != "preserve" ||
				entry.empty != "reject" || entry.overflow != "" || entry.unmatched != "reject" ||
				entry.pattern != "" || len(entry.values)+len(entry.separators)+len(entry.prefixes) != 0 ||
				!reflect.DeepEqual(entry.rules, want) {
				return invalidInboundCatalog("token type source normalizer drift")
			}
		default:
			return invalidInboundCatalog("unknown exact-map source normalizer")
		}
	case "enum":
		if entry.maxUTF8Bytes != 0 || entry.trim != "none" || entry.casePolicy != "preserve" ||
			entry.empty != "reject" || entry.overflow != "" || entry.unmatched != "reject" ||
			!reflect.DeepEqual(entry.values, []string{"input", "output", "cacheRead", "cacheCreation"}) ||
			entry.pattern != "" || len(entry.separators)+len(entry.prefixes)+len(entry.rules) != 0 {
			return invalidInboundCatalog("token type source normalizer drift")
		}
	default:
		return invalidInboundCatalog("unknown source normalizer kind")
	}
	return nil
}

func buildInboundSourceProjectionPlans(snapshot *inboundCatalogSnapshot, inputs []generatedInboundSourceProjectionPlan) error {
	expectedIDs := []string{"genai-token-metric-v1", "genai-duration-metric-v1"}
	expectedFamilies := []string{"metric.gen_ai.client.token.usage", "metric.gen_ai.client.operation.duration"}
	if len(inputs) != len(expectedIDs) {
		return invalidInboundCatalog("source projection plan inventory drift")
	}
	for position, input := range inputs {
		if input.ID != expectedIDs[position] || input.TargetFamily != expectedFamilies[position] {
			return invalidInboundCatalog("source projection plan identity drift")
		}
		if _, duplicate := snapshot.projectionByID[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate source projection plan ID")
		}
		var target *inboundTargetEntry
		for index := range snapshot.targets {
			if snapshot.targets[index].family == input.TargetFamily {
				target = &snapshot.targets[index]
				break
			}
		}
		if target == nil || len(input.FieldRules) != len(target.fields) {
			return invalidInboundCatalog("source projection does not exhaust target family")
		}
		entry := inboundSourceProjectionPlanEntry{id: input.ID, targetFamily: input.TargetFamily}
		for fieldIndex, inputField := range input.FieldRules {
			if inputField.Target != target.fields[fieldIndex].fieldRef {
				return invalidInboundCatalog("source projection field order disagrees with target family")
			}
			field := inboundProjectionFieldEntry{
				target: inputField.Target, disposition: InboundProjectionDisposition(inputField.Disposition),
				requirement:   InboundSourceRequirement(inputField.Requirement),
				allowedValues: append([]string(nil), inputField.AllowedValues...),
			}
			if field.disposition == InboundProjectionOmit {
				if field.requirement != "" || inputField.Normalization != "" || len(field.allowedValues)+len(inputField.SourceGroups) != 0 {
					return invalidInboundCatalog("omitted source projection field acquired mapping authority")
				}
			} else if field.disposition == InboundProjectionProject {
				if field.requirement != InboundSourceRequired && field.requirement != InboundSourceOptional {
					return invalidInboundCatalog("invalid source projection requirement")
				}
				normalizer, ok := snapshot.normalizerByID[inputField.Normalization]
				if !ok {
					return invalidInboundCatalog("source projection references unknown normalizer")
				}
				field.normalizer = cloneInboundSourceNormalizer(snapshot.normalizers[normalizer])
				groups, err := buildInboundSourceGroups(inputField.SourceGroups)
				if err != nil {
					return err
				}
				field.sourceGroups = groups
			} else {
				return invalidInboundCatalog("invalid source projection disposition")
			}
			entry.fieldRules = append(entry.fieldRules, field)
		}
		if input.CumulativeSeries != nil {
			series, err := buildInboundCumulativeSeries(snapshot, *input.CumulativeSeries)
			if err != nil {
				return err
			}
			entry.cumulativeSeries = Present(series)
		}
		if (position == 0) != entry.cumulativeSeries.IsPresent() {
			return invalidInboundCatalog("cumulative source projection coverage drift")
		}
		index := len(snapshot.projections)
		snapshot.projectionByID[input.ID] = index
		snapshot.projections = append(snapshot.projections, entry)
	}
	for index := range snapshot.targets {
		target := &snapshot.targets[index]
		if target.projectionID == "" {
			continue
		}
		projectionIndex, ok := snapshot.projectionByID[target.projectionID]
		if !ok || snapshot.projections[projectionIndex].targetFamily != target.family {
			return invalidInboundCatalog("target references incompatible source projection plan")
		}
		target.projectionIndex = projectionIndex
	}
	return nil
}

func buildInboundSourceGroups(inputs []generatedInboundSourceGroup) ([]InboundSourceGroup, error) {
	if len(inputs) == 0 {
		return nil, invalidInboundCatalog("source projection has no fallback groups")
	}
	result := make([]InboundSourceGroup, 0, len(inputs))
	seen := make(map[string]struct{})
	for _, input := range inputs {
		placement := InboundSourcePlacement(input.Placement)
		if !containsInboundString([]string{
			string(InboundSourceMetricPointAttribute), string(InboundSourceResourceAttribute),
			string(InboundSourceAuthenticated), string(InboundSourceFixed), string(InboundSourceInstrumentName),
		}, input.Placement) || len(input.Keys) == 0 {
			return nil, invalidInboundCatalog("malformed source projection group")
		}
		if err := validateInboundStrings(input.Keys, true); err != nil {
			return nil, invalidInboundCatalog("malformed source projection key")
		}
		for _, key := range input.Keys {
			identity := input.Placement + "\x00" + key
			if _, duplicate := seen[identity]; duplicate {
				return nil, invalidInboundCatalog("colliding source projection declaration")
			}
			seen[identity] = struct{}{}
		}
		if (placement == InboundSourceAuthenticated && !reflect.DeepEqual(input.Keys, []string{"$authenticated_source"})) ||
			(placement == InboundSourceInstrumentName && !reflect.DeepEqual(input.Keys, []string{"$instrument_name"})) ||
			(placement == InboundSourceFixed && len(input.Keys) != 1) {
			return nil, invalidInboundCatalog("source projection pseudo-placement drift")
		}
		if placement == InboundSourceMetricPointAttribute || placement == InboundSourceResourceAttribute {
			for _, key := range input.Keys {
				if !IsStableToken(key) {
					return nil, invalidInboundCatalog("source projection attribute key is invalid")
				}
			}
		}
		result = append(result, InboundSourceGroup{placement: placement, keys: append([]string(nil), input.Keys...)})
	}
	return result, nil
}

func buildInboundCumulativeSeries(snapshot *inboundCatalogSnapshot, input generatedInboundCumulativeSeries) (inboundCumulativeSeriesEntry, error) {
	if input.Applicability != "monotonic-cumulative-sum" || input.Framing != "length-prefixed-presence-v1" ||
		input.NormalizationStage != "before_framing" || len(input.Components) != 7 ||
		input.ResetEpoch.Role != "reset_only" || input.ResetEpoch.Identity ||
		input.ResetEpoch.Placement != "metric_point_start_time" || input.ResetEpoch.Key != "$start_time_unix_nano" ||
		input.ResetEpoch.Normalization != "unsigned-epoch-nanos-v1" {
		return inboundCumulativeSeriesEntry{}, invalidInboundCatalog("cumulative series policy drift")
	}
	expectedIDs := []string{"authenticated_source", "resource_service_name", "resource_service_instance_id", "instrument_name", "normalized_model", "token_type", "normalized_conversation"}
	entry := inboundCumulativeSeriesEntry{
		applicability: input.Applicability, framing: input.Framing, normalizationStage: input.NormalizationStage,
		resetEpoch: InboundResetEpoch{role: input.ResetEpoch.Role, identity: input.ResetEpoch.Identity,
			placement: input.ResetEpoch.Placement, key: input.ResetEpoch.Key, normalization: input.ResetEpoch.Normalization},
	}
	for index, inputComponent := range input.Components {
		if inputComponent.ID != expectedIDs[index] {
			return inboundCumulativeSeriesEntry{}, invalidInboundCatalog("cumulative series component order drift")
		}
		requirement := InboundSourceRequirement(inputComponent.Requirement)
		if requirement != InboundSourceRequired && requirement != InboundSourceOptional {
			return inboundCumulativeSeriesEntry{}, invalidInboundCatalog("invalid cumulative series requirement")
		}
		normalizerIndex, ok := snapshot.normalizerByID[inputComponent.Normalization]
		if !ok {
			return inboundCumulativeSeriesEntry{}, invalidInboundCatalog("cumulative series references unknown normalizer")
		}
		groups, err := buildInboundSourceGroups(inputComponent.SourceGroups)
		if err != nil {
			return inboundCumulativeSeriesEntry{}, err
		}
		entry.components = append(entry.components, inboundSeriesComponentEntry{
			id: inputComponent.ID, requirement: requirement,
			normalizer:    cloneInboundSourceNormalizer(snapshot.normalizers[normalizerIndex]),
			allowedValues: append([]string(nil), inputComponent.AllowedValues...), sourceGroups: groups,
		})
	}
	return entry, nil
}

func buildInboundImportContexts(snapshot *inboundCatalogSnapshot, contexts []generatedInboundImportContext) error {
	descriptorTypes := make(map[string]reflect.Type, len(contexts))
	for _, input := range contexts {
		if !validInboundID(input.ID) || !validInboundID(input.FamilyDescriptorID) ||
			input.ConstructionMode != "ordinary_import_only" ||
			!reflect.DeepEqual(input.Capabilities, []string{"validate", "construct_ordinary"}) ||
			nilInterface(input.Descriptor) {
			return invalidInboundCatalog("malformed import context")
		}
		if _, duplicate := snapshot.contextByID[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate import-context ID")
		}
		if _, duplicate := snapshot.contextByFamily[input.FamilyDescriptorID]; duplicate {
			return invalidInboundCatalog("duplicate import-context family")
		}
		contract := cloneFamilyDescriptorContract(input.Descriptor.familyDescriptorContract())
		if err := validateInboundBaseDescriptor(contract, familySignalLog); err != nil ||
			contract.id != input.FamilyDescriptorID || contract.identity.Bucket != Bucket(input.Bucket) ||
			contract.identity.Name != EventName(input.EventName) {
			return invalidInboundCatalog(fmt.Sprintf("import-context descriptor identity mismatch for %s", input.ID))
		}
		descriptorType, err := validateInboundConcreteDescriptor(input.Descriptor)
		if err != nil {
			return err
		}
		if prior, exists := descriptorTypes[input.FamilyDescriptorID]; exists && prior != descriptorType {
			return invalidInboundCatalog("import-context concrete descriptor mismatch")
		}
		descriptorTypes[input.FamilyDescriptorID] = descriptorType
		index := len(snapshot.contexts)
		snapshot.contextByID[input.ID] = index
		snapshot.contextByFamily[input.FamilyDescriptorID] = index
		snapshot.contexts = append(snapshot.contexts, inboundImportContextEntry{
			id: input.ID, familyDescriptorID: input.FamilyDescriptorID,
			bucket: Bucket(input.Bucket), eventName: EventName(input.EventName),
			constructionMode: input.ConstructionMode,
			capabilities:     append([]string(nil), input.Capabilities...),
			descriptor:       input.Descriptor, descriptorType: descriptorType.String(),
		})
	}
	return nil
}

func buildInboundTargets(snapshot *inboundCatalogSnapshot, targets []generatedInboundTarget) error {
	familyTypes := make(map[string]reflect.Type)
	for _, input := range targets {
		if !validInboundID(input.ID) || !validInboundID(input.MatchID) || !validInboundID(input.ClassID) ||
			!IsSignal(Signal(input.Signal)) || !validInboundID(input.Family) ||
			!IsBucket(Bucket(input.Bucket)) || input.EventName == "" || input.FamilySchemaVersion <= 0 ||
			uint64(input.FamilySchemaVersion) > uint64(^uint32(0)) ||
			len(input.FieldRefs) != len(input.FieldDescriptorIDs) || nilInterface(input.Descriptor) {
			return invalidInboundCatalog("malformed target descriptor")
		}
		if input.SourceProjectionPlanID != "" && !validInboundID(input.SourceProjectionPlanID) {
			return invalidInboundCatalog("malformed target source projection ID")
		}
		if _, duplicate := snapshot.targetByID[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate target ID")
		}
		role := InboundTargetRole(input.Role)
		kind := InboundTargetKind(input.TargetKind)
		strategy := InboundMappingStrategy(input.MappingStrategy)
		derivation := InboundDerivationStrategy(input.DerivationStrategy)
		if !validInboundTargetRole(role) || !validInboundTargetKind(kind) || !validInboundMappingStrategy(strategy) ||
			!validInboundDerivationStrategy(derivation) ||
			(role == InboundTargetImport && derivation != InboundDerivationNone) ||
			(role == InboundTargetDerive && derivation == InboundDerivationNone) {
			return invalidInboundCatalog("invalid target construction policy")
		}
		timeRule, err := parseInboundTimeRule(input.TimeRuleJSON)
		if err != nil {
			return err
		}
		outcomeRule, err := parseInboundOutcomeRule(input.OutcomeRuleJSON)
		if err != nil {
			return err
		}
		contract := cloneFamilyDescriptorContract(input.Descriptor.familyDescriptorContract())
		if err := validateInboundTargetDescriptor(input, contract); err != nil {
			return err
		}
		descriptorType, err := validateInboundConcreteDescriptor(input.Descriptor)
		if err != nil {
			return err
		}
		unitRule, err := parseInboundSourceUnitRule(
			input.SourceUnitRule,
			strategy,
			Signal(input.Signal),
			input.InstrumentUnit,
		)
		if err != nil {
			return err
		}
		if prior, exists := familyTypes[input.Family]; exists && prior != descriptorType {
			return invalidInboundCatalog("target concrete descriptor mismatch")
		}
		familyTypes[input.Family] = descriptorType

		fields := make([]InboundTargetField, len(input.FieldRefs))
		familyPrefix, _, found := strings.Cut(input.Family, ".")
		if !found || !containsInboundString([]string{"log", "span", "metric"}, familyPrefix) {
			return invalidInboundCatalog("target family prefix is invalid")
		}
		if len(contract.fields) != len(input.FieldRefs) {
			return invalidInboundCatalog("target field inventory differs from descriptor")
		}
		seenFields := make(map[string]struct{}, len(input.FieldRefs))
		for index, fieldRef := range input.FieldRefs {
			expectedID := familyPrefix + ":" + input.Family + ":" + fieldRef
			if fieldRef == "" || input.FieldDescriptorIDs[index] != expectedID || contract.fields[index].key != fieldRef {
				return invalidInboundCatalog("target field descriptor identity or order mismatch")
			}
			if _, duplicate := seenFields[fieldRef]; duplicate {
				return invalidInboundCatalog("duplicate target field reference")
			}
			seenFields[fieldRef] = struct{}{}
			fields[index] = InboundTargetField{fieldRef: fieldRef, descriptorID: input.FieldDescriptorIDs[index]}
		}

		contextIndex := -1
		if input.ImportContextID != "" {
			resolved, ok := snapshot.contextByID[input.ImportContextID]
			if !ok || Signal(input.Signal) != SignalLogs || role != InboundTargetImport ||
				snapshot.contexts[resolved].familyDescriptorID != input.Family ||
				snapshot.contexts[resolved].descriptorType != descriptorType.String() {
				return invalidInboundCatalog("target import-context binding mismatch")
			}
			contextIndex = resolved
		} else if Signal(input.Signal) == SignalLogs && role == InboundTargetImport {
			return invalidInboundCatalog("imported log target lacks ordinary import context")
		}

		index := len(snapshot.targets)
		snapshot.targetByID[input.ID] = index
		snapshot.targets = append(snapshot.targets, inboundTargetEntry{
			id: input.ID, matchIndex: -1, classID: input.ClassID, signal: Signal(input.Signal),
			role: role, targetKind: kind, family: input.Family, bucket: Bucket(input.Bucket),
			eventName: EventName(input.EventName), familySchemaVersion: uint32(input.FamilySchemaVersion),
			instrumentName: input.InstrumentName, instrumentType: input.InstrumentType,
			instrumentUnit: input.InstrumentUnit, sourceUnitRule: unitRule,
			fields: fields, descriptor: input.Descriptor, descriptorType: descriptorType.String(),
			mappingStrategy: strategy, derivationStrategy: derivation,
			timeRule: timeRule, outcomeRule: outcomeRule, importContextIndex: contextIndex,
			projectionID: input.SourceProjectionPlanID, projectionIndex: -1,
		})
	}
	return nil
}

func validateInboundTargetDescriptor(input generatedInboundTarget, contract familyDescriptorContract) error {
	signal := Signal(input.Signal)
	if contract.id != input.Family || contract.identity.Signal != signal ||
		contract.identity.Bucket != Bucket(input.Bucket) || contract.identity.Name != EventName(input.EventName) ||
		contract.familySchemaVersion != uint32(input.FamilySchemaVersion) {
		return invalidInboundCatalog("target descriptor identity mismatch")
	}
	switch signal {
	case SignalLogs:
		if input.InstrumentName != "" || input.InstrumentType != "" || input.InstrumentUnit != "" || validateInboundBaseDescriptor(contract, familySignalLog) != nil {
			return invalidInboundCatalog("invalid generated log target descriptor")
		}
	case SignalTraces:
		descriptor, ok := input.Descriptor.(generatedTraceFamilyContract)
		if !ok || input.InstrumentName != "" || input.InstrumentType != "" || input.InstrumentUnit != "" {
			return invalidInboundCatalog("invalid generated trace target descriptor")
		}
		traceContract := cloneFamilyTraceContract(descriptor.familyTraceContract())
		if !reflect.DeepEqual(traceContract.familyDescriptorContract, contract) || validateFamilyTraceContract(traceContract) != nil {
			return invalidInboundCatalog("invalid generated trace target contract")
		}
	case SignalMetrics:
		descriptor, ok := input.Descriptor.(generatedMetricFamilyContract)
		if !ok || input.InstrumentName == "" || input.InstrumentType == "" {
			return invalidInboundCatalog("invalid generated metric target descriptor")
		}
		metricContract := cloneFamilyMetricContract(descriptor.familyMetricContract())
		if !reflect.DeepEqual(metricContract.familyDescriptorContract, contract) ||
			validateFamilyMetricContract(metricContract) != nil ||
			metricContract.instrumentName != input.InstrumentName || metricContract.instrumentType != input.InstrumentType ||
			metricContract.unit != input.InstrumentUnit {
			return invalidInboundCatalog("invalid generated metric target contract")
		}
	default:
		return invalidInboundCatalog("invalid target signal")
	}
	return nil
}

// validateInboundBaseDescriptor intentionally validates against the generated
// catalog identity itself instead of the transitional hand-authored event-name
// list. P-071 is the authority for this runtime view; requiring the legacy list
// here would make new generated families impossible to import until that list is
// removed in the producer cutover.
func validateInboundBaseDescriptor(contract familyDescriptorContract, signal familySignal) error {
	if !IsStableToken(contract.id) || contract.familySchemaVersion == 0 ||
		contract.identity.Signal != signal.canonical() || !IsBucket(contract.identity.Bucket) ||
		contract.identity.Name.Validate() != nil {
		return invalidInboundCatalog("invalid generated family descriptor identity")
	}
	if err := validateFamilyOutcomePolicy(contract.outcome, signal); err != nil {
		return invalidInboundCatalog("invalid generated family outcome policy")
	}
	if err := validateFamilyFieldDescriptors(contract.fields); err != nil {
		return invalidInboundCatalog("invalid generated family field inventory")
	}
	if err := validateFamilyCrossFieldRelations(contract.fields, contract.crossFieldRelations); err != nil {
		return invalidInboundCatalog("invalid generated family cross-field relation")
	}
	return nil
}

func buildInboundMatches(snapshot *inboundCatalogSnapshot, matches []generatedInboundMatch, targets []generatedInboundTarget) error {
	overrideCount := 0
	seenSignatures := make(map[string]struct{}, len(matches))
	for _, input := range matches {
		if !validInboundID(input.ID) || !validInboundID(input.ClassID) || !IsSignal(Signal(input.Signal)) ||
			len(input.Sources) == 0 || !validInboundShape(InboundShape(input.Shape)) ||
			!validInboundDiscriminator(InboundDiscriminatorKind(input.DiscriminatorKind)) ||
			!validInboundMappingStrategy(InboundMappingStrategy(input.MappingStrategy)) || len(input.TargetIDs) == 0 {
			return invalidInboundCatalog("malformed match descriptor")
		}
		if input.SourceProjectionPlanID != "" && !validInboundID(input.SourceProjectionPlanID) {
			return invalidInboundCatalog("malformed match source projection ID")
		}
		if _, duplicate := snapshot.matchByID[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate match ID")
		}
		if err := validateInboundSources(input.Sources); err != nil {
			return err
		}
		predicates := make([]InboundPredicate, len(input.Predicates))
		seenPredicates := make(map[inboundMarkerLookupKey]struct{}, len(input.Predicates))
		for index, predicate := range input.Predicates {
			parsed, err := parseInboundPredicate(predicate)
			if err != nil {
				return err
			}
			key := inboundMarkerLookupKey{signal: Signal(input.Signal), location: parsed.location, key: parsed.key}
			if _, duplicate := seenPredicates[key]; duplicate {
				return invalidInboundCatalog("duplicate match predicate identity")
			}
			seenPredicates[key] = struct{}{}
			predicates[index] = parsed
		}
		signature := inboundMatchSignature(Signal(input.Signal), input.Sources, InboundShape(input.Shape), predicates)
		if _, duplicate := seenSignatures[signature]; duplicate {
			return invalidInboundCatalog("duplicate exact match discriminator")
		}
		seenSignatures[signature] = struct{}{}
		aliasIndexes := make([]int, len(input.AliasIDs))
		seenAliases := make(map[string]struct{}, len(input.AliasIDs))
		for index, aliasID := range input.AliasIDs {
			resolved, ok := snapshot.aliasByID[aliasID]
			if !ok {
				return invalidInboundCatalog("match references unknown alias")
			}
			if _, duplicate := seenAliases[aliasID]; duplicate {
				return invalidInboundCatalog("match repeats alias")
			}
			seenAliases[aliasID] = struct{}{}
			aliasIndexes[index] = resolved
		}
		targetIndexes := make([]int, len(input.TargetIDs))
		primaryCount := 0
		primaryTargetIndex := -1
		seenTargets := make(map[string]struct{}, len(input.TargetIDs))
		for index, targetID := range input.TargetIDs {
			resolved, ok := snapshot.targetByID[targetID]
			if !ok {
				return invalidInboundCatalog("match references unknown target")
			}
			if _, duplicate := seenTargets[targetID]; duplicate {
				return invalidInboundCatalog("match repeats target")
			}
			seenTargets[targetID] = struct{}{}
			target := &snapshot.targets[resolved]
			if targets[resolved].MatchID != input.ID || target.mappingStrategy != InboundMappingStrategy(input.MappingStrategy) {
				return invalidInboundCatalog(fmt.Sprintf("match and target contract disagree for %s -> %s", input.ID, targetID))
			}
			if target.targetKind == InboundTargetPrimary {
				primaryCount++
				primaryTargetIndex = resolved
				if target.signal != Signal(input.Signal) {
					return invalidInboundCatalog(fmt.Sprintf("primary target changes signal for %s -> %s", input.ID, targetID))
				}
			}
			targetIndexes[index] = resolved
		}
		if primaryCount != 1 {
			return invalidInboundCatalog("match does not own exactly one primary target")
		}
		primaryTarget := snapshot.targets[primaryTargetIndex]
		unitRule, err := parseInboundSourceUnitRule(
			input.SourceUnitRule,
			InboundMappingStrategy(input.MappingStrategy),
			Signal(input.Signal),
			primaryTarget.instrumentUnit,
		)
		if err != nil || !reflect.DeepEqual(unitRule, primaryTarget.sourceUnitRule) {
			return invalidInboundCatalog("match and primary target source-unit rules disagree")
		}
		projectionIndex := -1
		if input.SourceProjectionPlanID != "" {
			resolved, ok := snapshot.projectionByID[input.SourceProjectionPlanID]
			if !ok || primaryTarget.projectionIndex != resolved ||
				snapshot.projections[resolved].targetFamily != primaryTarget.family {
				return invalidInboundCatalog("match and primary target source projection plans disagree")
			}
			projectionIndex = resolved
		} else if primaryTarget.projectionIndex >= 0 {
			return invalidInboundCatalog("primary target projection plan is absent from match")
		}
		timeRule, err := parseInboundTimeRule(input.TimeRuleJSON)
		if err != nil {
			return err
		}
		outcomeRule, err := parseInboundOutcomeRule(input.OutcomeRuleJSON)
		if err != nil {
			return err
		}
		override := Absent[InboundTargetOverride]()
		if input.TargetOverride != nil {
			overrideCount++
			if input.TargetOverride.Source != "gen_ai.workflow.name" ||
				input.TargetOverride.Target != "defenseclaw.workflow.name" ||
				input.TargetOverride.Normalization != "identifier-v1" {
				return invalidInboundCatalog("unknown target override")
			}
			override = Present(InboundTargetOverride{
				source:        input.TargetOverride.Source,
				target:        input.TargetOverride.Target,
				normalization: input.TargetOverride.Normalization,
			})
		}
		index := len(snapshot.matches)
		snapshot.matchByID[input.ID] = index
		snapshot.matches = append(snapshot.matches, inboundMatchEntry{
			id: input.ID, classID: input.ClassID, signal: Signal(input.Signal),
			sources: append([]string(nil), input.Sources...), shape: InboundShape(input.Shape),
			discriminatorKind: InboundDiscriminatorKind(input.DiscriminatorKind),
			predicates:        predicates, mappingStrategy: InboundMappingStrategy(input.MappingStrategy),
			aliasIndexes: aliasIndexes, targetOverride: override, sourceUnitRule: unitRule, targetIndexes: targetIndexes,
			timeRule: timeRule, outcomeRule: outcomeRule, nativeRoundTrip: input.NativeRoundTrip,
			projectionIndex: projectionIndex,
		})
		for _, targetIndex := range targetIndexes {
			if snapshot.targets[targetIndex].matchIndex >= 0 {
				return invalidInboundCatalog("target belongs to multiple matches")
			}
			snapshot.targets[targetIndex].matchIndex = index
		}
	}
	if overrideCount != 1 {
		return invalidInboundCatalog("workflow target override coverage drift")
	}
	return nil
}

func buildInboundMarkers(snapshot *inboundCatalogSnapshot, markers []generatedInboundNativeMarker) error {
	seenIDs := make(map[string]struct{}, len(markers))
	for _, input := range markers {
		expectedID := "otlp.native.marker." + input.Signal + "." + input.Location + "." + input.Key
		if input.ID != expectedID || !IsSignal(Signal(input.Signal)) ||
			!validInboundLocation(InboundLocation(input.Location)) || input.Key == "" ||
			!containsInboundMarkerKind(InboundMarkerKind(input.MarkerKind)) {
			return invalidInboundCatalog("malformed native marker")
		}
		if _, duplicate := seenIDs[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate native-marker ID")
		}
		seenIDs[input.ID] = struct{}{}
		valueType := InboundValueType(input.ValueType)
		values, err := parseInboundValues(input.ValuesJSON, valueType)
		if err != nil {
			return err
		}
		key := inboundMarkerLookupKey{signal: Signal(input.Signal), location: InboundLocation(input.Location), key: input.Key}
		if _, duplicate := snapshot.markerByKey[key]; duplicate {
			return invalidInboundCatalog("duplicate native-marker identity")
		}
		if err := validateInboundMarkerCardinality(InboundMarkerKind(input.MarkerKind), valueType, values); err != nil {
			return err
		}
		index := len(snapshot.markers)
		snapshot.markerByKey[key] = index
		snapshot.markers = append(snapshot.markers, inboundMarkerEntry{
			id: input.ID, signal: Signal(input.Signal), location: InboundLocation(input.Location),
			key: input.Key, markerKind: InboundMarkerKind(input.MarkerKind), valueType: valueType, values: values,
		})
	}
	return nil
}

func buildInboundEchoes(snapshot *inboundCatalogSnapshot, echoes []generatedInboundEchoRecognizer) error {
	seenIDs := make(map[string]struct{}, len(echoes))
	for _, input := range echoes {
		signal := Signal(input.Signal)
		identity := EventIdentity{Bucket: Bucket(input.Bucket), Signal: signal, Name: EventName(input.EventName)}
		if !validInboundID(input.ID) || !validInboundID(input.Family) || !IsSignal(signal) ||
			!IsBucket(identity.Bucket) || identity.Name.Validate() != nil ||
			!containsInboundString([]string{string(InboundForwardLeaf), string(InboundForwardResource)}, input.ForwardPlacement) ||
			input.CompareSelfWith != snapshot.wire.ForwardInstanceKey ||
			(signal == SignalMetrics && input.InstrumentName == "") ||
			(signal != SignalMetrics && input.InstrumentName != "") {
			return invalidInboundCatalog("malformed echo recognizer")
		}
		if _, duplicate := seenIDs[input.ID]; duplicate {
			return invalidInboundCatalog("duplicate echo-recognizer ID")
		}
		seenIDs[input.ID] = struct{}{}
		key := inboundEchoLookupKey{
			signal: signal, family: input.Family, bucket: Bucket(input.Bucket),
			eventName: EventName(input.EventName), instrumentName: input.InstrumentName,
		}
		if _, duplicate := snapshot.echoByIdentity[key]; duplicate {
			return invalidInboundCatalog("duplicate echo-recognizer identity")
		}
		wireKey := inboundEchoWireLookupKey{signal: signal}
		switch signal {
		case SignalLogs, SignalTraces:
			wireKey.bucket = Bucket(input.Bucket)
			wireKey.eventOrFamily = EventName(input.EventName)
		case SignalMetrics:
			wireKey.instrumentName = input.InstrumentName
		default:
			return invalidInboundCatalog("invalid echo-recognizer signal")
		}
		if _, duplicate := snapshot.echoByWire[wireKey]; duplicate {
			return invalidInboundCatalog("duplicate echo-recognizer wire identity")
		}
		index := len(snapshot.echoes)
		snapshot.echoByIdentity[key] = index
		snapshot.echoByWire[wireKey] = index
		snapshot.echoes = append(snapshot.echoes, inboundEchoEntry{
			id: input.ID, signal: signal, family: input.Family, bucket: Bucket(input.Bucket),
			eventName: EventName(input.EventName), instrumentName: input.InstrumentName,
			forwardPlacement: InboundForwardPlacement(input.ForwardPlacement), compareSelfWith: input.CompareSelfWith,
		})
	}
	return nil
}

func validateInboundCrossReferences(snapshot *inboundCatalogSnapshot) error {
	targetsByFamily := make(map[string][]inboundTargetEntry, len(snapshot.targets))
	for index := range snapshot.targets {
		if snapshot.targets[index].matchIndex < 0 {
			return invalidInboundCatalog("orphan target descriptor")
		}
		targetsByFamily[snapshot.targets[index].family] = append(targetsByFamily[snapshot.targets[index].family], snapshot.targets[index])
	}
	for _, context := range snapshot.contexts {
		found := false
		for _, target := range snapshot.targets {
			if target.importContextIndex >= 0 && snapshot.contexts[target.importContextIndex].id == context.id {
				found = true
				if target.descriptorType != context.descriptorType {
					return invalidInboundCatalog("target/context descriptor type drift")
				}
			}
		}
		if !found {
			return invalidInboundCatalog("unused import context")
		}
	}
	for _, match := range snapshot.matches {
		if match.shape == InboundShapeNativeExact {
			if !match.nativeRoundTrip || len(match.aliasIndexes) != 0 {
				return invalidInboundCatalog("native match round-trip policy mismatch")
			}
		} else if match.nativeRoundTrip {
			return invalidInboundCatalog("external match claims native round trip")
		}
	}
	for _, echo := range snapshot.echoes {
		switch echo.signal {
		case SignalLogs:
			contextIndex, ok := snapshot.contextByFamily[echo.family]
			if !ok {
				return invalidInboundCatalog("log echo has no generated family context")
			}
			context := snapshot.contexts[contextIndex]
			if context.bucket != echo.bucket || context.eventName != echo.eventName {
				return invalidInboundCatalog("log echo disagrees with generated family context")
			}
		case SignalTraces:
			if string(echo.eventName) != echo.family || len(targetsByFamily[echo.family]) == 0 {
				return invalidInboundCatalog("trace echo has no exact generated target identity")
			}
		case SignalMetrics:
			if string(echo.eventName) != echo.family || echo.family != "metric."+echo.instrumentName {
				return invalidInboundCatalog("metric echo identity is inconsistent")
			}
		default:
			return invalidInboundCatalog("echo signal is invalid")
		}
	}
	return nil
}

func inboundMatchSignature(signal Signal, sources []string, shape InboundShape, predicates []InboundPredicate) string {
	canonicalSources := append([]string(nil), sources...)
	sort.Strings(canonicalSources)
	canonicalPredicates := make([]string, len(predicates))
	for index, predicate := range predicates {
		values := make([]string, len(predicate.values))
		for valueIndex, value := range predicate.values {
			switch value.kind {
			case InboundPredicateValueString:
				values[valueIndex] = fmt.Sprintf("s:%q", value.stringValue)
			case InboundPredicateValueInt64:
				values[valueIndex] = fmt.Sprintf("i:%d", value.int64Value)
			}
		}
		sort.Strings(values)
		canonicalPredicates[index] = fmt.Sprintf(
			"%q:%q:%q:%q:%s",
			predicate.location,
			predicate.key,
			predicate.operator,
			predicate.valueType,
			strings.Join(values, ","),
		)
	}
	sort.Strings(canonicalPredicates)
	var builder strings.Builder
	fmt.Fprintf(&builder, "%q:%q", signal, shape)
	for _, source := range canonicalSources {
		fmt.Fprintf(&builder, ":source=%q", source)
	}
	for _, predicate := range canonicalPredicates {
		fmt.Fprintf(&builder, ":predicate=%q", predicate)
	}
	return builder.String()
}

func parseInboundPredicate(input generatedInboundPredicate) (InboundPredicate, error) {
	location := InboundLocation(input.Location)
	operator := InboundPredicateOperator(input.Operator)
	valueType := InboundValueType(input.ValueType)
	if !validInboundLocation(location) || input.Key == "" || !utf8.ValidString(input.Key) ||
		!validInboundPredicateOperator(operator) {
		return InboundPredicate{}, invalidInboundCatalog("malformed predicate")
	}
	values, err := parseInboundValues(input.ValuesJSON, valueType)
	if err != nil {
		return InboundPredicate{}, err
	}
	if err := validateInboundPredicateCardinality(operator, valueType, values); err != nil {
		return InboundPredicate{}, err
	}
	return InboundPredicate{location: location, key: input.Key, operator: operator, valueType: valueType, values: values}, nil
}

func parseInboundSourceUnitRule(
	input generatedInboundUnitRule,
	strategy InboundMappingStrategy,
	signal Signal,
	instrumentUnit string,
) (inboundSourceUnitRuleEntry, error) {
	kind := InboundSourceUnitRuleKind(input.Kind)
	accepted := make([]InboundSourceUnitScale, len(input.Accepted))
	seen := make(map[string]struct{}, len(input.Accepted))
	for index, item := range input.Accepted {
		if !utf8.ValidString(item.SourceUnit) || len(item.SourceUnit) > 64 ||
			math.IsNaN(item.Scale) || math.IsInf(item.Scale, 0) || item.Scale <= 0 {
			return inboundSourceUnitRuleEntry{}, invalidInboundCatalog("malformed source-unit scale")
		}
		if _, duplicate := seen[item.SourceUnit]; duplicate {
			return inboundSourceUnitRuleEntry{}, invalidInboundCatalog("duplicate source-unit spelling")
		}
		seen[item.SourceUnit] = struct{}{}
		accepted[index] = InboundSourceUnitScale{sourceUnit: item.SourceUnit, scale: item.Scale}
	}
	rule := inboundSourceUnitRuleEntry{kind: kind, targetUnit: input.TargetUnit, accepted: accepted}
	switch strategy {
	case InboundMappingReverseMetric:
		if signal != SignalMetrics || kind != InboundSourceUnitTargetEquality ||
			input.TargetUnit != instrumentUnit || len(accepted) != 1 ||
			accepted[0].sourceUnit != instrumentUnit || accepted[0].scale != 1 {
			return inboundSourceUnitRuleEntry{}, invalidInboundCatalog("native metric source unit differs from sealed target unit")
		}
	case InboundMappingDurationMetric:
		if signal != SignalMetrics || kind != InboundSourceUnitScaleTable || input.TargetUnit != "s" || instrumentUnit != "s" ||
			len(accepted) == 0 {
			return inboundSourceUnitRuleEntry{}, invalidInboundCatalog("duration source-unit table drift")
		}
	case InboundMappingClaudeTokenUsage:
		if signal != SignalMetrics || kind != InboundSourceUnitScaleTable || input.TargetUnit != "{token}" || instrumentUnit != "{token}" ||
			len(accepted) == 0 {
			return inboundSourceUnitRuleEntry{}, invalidInboundCatalog("token source-unit table drift")
		}
	default:
		if kind != InboundSourceUnitNone || input.TargetUnit != "" || len(accepted) != 0 {
			return inboundSourceUnitRuleEntry{}, invalidInboundCatalog("unexpected source-unit rule")
		}
	}
	return rule, nil
}

func parseInboundValues(raw string, valueType InboundValueType) ([]InboundPredicateValue, error) {
	if !validInboundValueType(valueType, false) {
		return nil, invalidInboundCatalog("unknown predicate value type")
	}
	switch valueType {
	case InboundValueString, InboundValueStructural:
		var values []string
		if err := json.Unmarshal([]byte(raw), &values); err != nil || values == nil {
			return nil, invalidInboundCatalog("malformed string predicate values")
		}
		result := make([]InboundPredicateValue, len(values))
		seen := make(map[string]struct{}, len(values))
		for index, value := range values {
			if !utf8.ValidString(value) {
				return nil, invalidInboundCatalog("predicate value is not UTF-8")
			}
			if _, duplicate := seen[value]; duplicate {
				return nil, invalidInboundCatalog("duplicate predicate value")
			}
			seen[value] = struct{}{}
			result[index] = InboundPredicateValue{kind: InboundPredicateValueString, stringValue: value}
		}
		return result, nil
	case InboundValueInt64:
		var values []int64
		if err := json.Unmarshal([]byte(raw), &values); err != nil || values == nil {
			return nil, invalidInboundCatalog("malformed integer predicate values")
		}
		result := make([]InboundPredicateValue, len(values))
		seen := make(map[int64]struct{}, len(values))
		for index, value := range values {
			if _, duplicate := seen[value]; duplicate {
				return nil, invalidInboundCatalog("duplicate predicate value")
			}
			seen[value] = struct{}{}
			result[index] = InboundPredicateValue{kind: InboundPredicateValueInt64, int64Value: value}
		}
		return result, nil
	default:
		return nil, invalidInboundCatalog("unsupported predicate value type")
	}
}

func parseInboundTimeRule(raw string) (InboundTimeRule, error) {
	var value string
	if err := json.Unmarshal([]byte(raw), &value); err != nil || !containsInboundString([]string{
		string(InboundTimeLogObservedReceipt), string(InboundTimeMetricPointReceipt),
		string(InboundTimeSpanElapsed), string(InboundTimeSpanEnd),
	}, value) {
		return "", invalidInboundCatalog("malformed time rule")
	}
	return InboundTimeRule(value), nil
}

func parseInboundOutcomeRule(raw string) (InboundOutcomeRule, error) {
	var scalar string
	if err := json.Unmarshal([]byte(raw), &scalar); err == nil {
		kind := InboundOutcomeRuleKind(scalar)
		if !containsInboundString([]string{
			string(InboundOutcomeForbidden), string(InboundOutcomeNativeSpan),
			string(InboundOutcomeOTelStatus), string(InboundOutcomeProjectedRecord),
		}, scalar) {
			return InboundOutcomeRule{}, invalidInboundCatalog("unknown outcome rule")
		}
		return InboundOutcomeRule{kind: kind}, nil
	}
	decoder := json.NewDecoder(strings.NewReader(raw))
	opening, err := decoder.Token()
	if err != nil || opening != json.Delim('{') {
		return InboundOutcomeRule{}, invalidInboundCatalog("malformed fixed outcome rule")
	}
	key, err := decoder.Token()
	if err != nil || key != "fixed" {
		return InboundOutcomeRule{}, invalidInboundCatalog("malformed fixed outcome rule")
	}
	var fixed Outcome
	if err := decoder.Decode(&fixed); err != nil || !IsOutcome(fixed) ||
		!containsInboundString([]string{string(OutcomeAttempted), string(OutcomeCompleted)}, string(fixed)) {
		return InboundOutcomeRule{}, invalidInboundCatalog("malformed fixed outcome rule")
	}
	closing, err := decoder.Token()
	if err != nil || closing != json.Delim('}') {
		return InboundOutcomeRule{}, invalidInboundCatalog("malformed fixed outcome rule")
	}
	var trailing json.RawMessage
	if err := decoder.Decode(&trailing); err != io.EOF {
		return InboundOutcomeRule{}, invalidInboundCatalog("fixed outcome rule has trailing data")
	}
	return InboundOutcomeRule{kind: InboundOutcomeFixed, fixed: fixed}, nil
}

func validateInboundPredicateCardinality(operator InboundPredicateOperator, valueType InboundValueType, values []InboundPredicateValue) error {
	switch operator {
	case InboundPredicateAbsent, InboundPredicatePresent, InboundPredicateProjectedRecordJSON, InboundPredicateValidEndedSpan:
		if len(values) != 0 {
			return invalidInboundCatalog("presence/structural predicate carries values")
		}
	case InboundPredicateEquals:
		if len(values) != 1 {
			return invalidInboundCatalog("equals predicate cardinality is not one")
		}
	case InboundPredicateOneOf:
		if len(values) < 1 {
			return invalidInboundCatalog("one-of predicate is empty")
		}
	case InboundPredicateUint32Max:
		if valueType != InboundValueInt64 || len(values) != 1 {
			return invalidInboundCatalog("uint32-max predicate is malformed")
		}
		value, ok := values[0].Int64Value()
		if !ok || value < 0 || value > int64(^uint32(0)) {
			return invalidInboundCatalog("uint32-max predicate is out of range")
		}
	default:
		return invalidInboundCatalog("unknown predicate operator")
	}
	if operator == InboundPredicateValidEndedSpan && valueType != InboundValueStructural {
		return invalidInboundCatalog("ended-span predicate has wrong type")
	}
	return nil
}

func validateInboundMarkerCardinality(kind InboundMarkerKind, valueType InboundValueType, values []InboundPredicateValue) error {
	switch kind {
	case InboundMarkerExactStructuralValue:
		if len(values) != 1 {
			return invalidInboundCatalog("exact structural marker cardinality is not one")
		}
	case InboundMarkerProjectedStructure, InboundMarkerReservedKeyPresence:
		if len(values) != 0 {
			return invalidInboundCatalog("presence marker carries values")
		}
	default:
		return invalidInboundCatalog("unknown native marker kind")
	}
	if valueType != InboundValueString && valueType != InboundValueInt64 {
		return invalidInboundCatalog("native marker has unsupported value type")
	}
	return nil
}

func validateInboundConcreteDescriptor(descriptor familyDescriptor) (reflect.Type, error) {
	valueType := reflect.TypeOf(descriptor)
	if valueType == nil || valueType.Kind() != reflect.Struct ||
		valueType.PkgPath() != reflect.TypeOf(FamilyBuilder{}).PkgPath() ||
		!strings.HasPrefix(valueType.Name(), "generated") || !strings.HasSuffix(valueType.Name(), "Descriptor") {
		return nil, invalidInboundCatalog(fmt.Sprintf("descriptor is not a concrete generated capability: %v", valueType))
	}
	value := reflect.ValueOf(descriptor)
	for index := 0; index < valueType.NumField(); index++ {
		field := valueType.Field(index)
		fieldValue := value.Field(index)
		if field.PkgPath == "" {
			return nil, invalidInboundCatalog(fmt.Sprintf("descriptor carries mutable or exported state: %v", valueType))
		}
		switch fieldValue.Kind() {
		case reflect.Map, reflect.Pointer, reflect.Interface, reflect.Slice:
			if !fieldValue.IsNil() {
				return nil, invalidInboundCatalog(fmt.Sprintf("descriptor carries mutable or exported state: %v", valueType))
			}
		case reflect.Chan, reflect.Func, reflect.UnsafePointer:
			return nil, invalidInboundCatalog(fmt.Sprintf("descriptor carries mutable or exported state: %v", valueType))
		}
	}
	return valueType, nil
}

func validateInboundSources(values []string) error {
	if err := validateInboundStrings(values, false); err != nil {
		return invalidInboundCatalog("malformed match sources")
	}
	for _, value := range values {
		if value != "any_authenticated" && !IsStableToken(value) {
			return invalidInboundCatalog("invalid authenticated source token")
		}
	}
	return nil
}

func validateInboundStrings(values []string, allowSpecial bool) error {
	seen := make(map[string]struct{}, len(values))
	for _, value := range values {
		if value == "" || !utf8.ValidString(value) {
			return invalidInboundCatalog("empty or non-UTF8 string")
		}
		if !allowSpecial && !IsStableToken(value) {
			return invalidInboundCatalog("invalid stable token")
		}
		if _, duplicate := seen[value]; duplicate {
			return invalidInboundCatalog("duplicate string")
		}
		seen[value] = struct{}{}
	}
	return nil
}

func validInboundID(value string) bool { return IsStableToken(value) }

func validInboundLocation(value InboundLocation) bool {
	return containsInboundString([]string{
		string(InboundLocationInstrumentName), string(InboundLocationLeafAttribute),
		string(InboundLocationLogBody), string(InboundLocationMetricPoint),
		string(InboundLocationMetricPointAttribute), string(InboundLocationResourceAttribute),
		string(InboundLocationResourceSchemaURL), string(InboundLocationScopeName),
		string(InboundLocationScopeSchemaURL), string(InboundLocationSpan),
	}, string(value))
}

func validInboundPredicateOperator(value InboundPredicateOperator) bool {
	return containsInboundString([]string{
		string(InboundPredicateAbsent), string(InboundPredicateEquals), string(InboundPredicateOneOf),
		string(InboundPredicatePresent), string(InboundPredicateProjectedRecordJSON),
		string(InboundPredicateUint32Max), string(InboundPredicateValidEndedSpan),
	}, string(value))
}

func validInboundValueType(value InboundValueType, aliases bool) bool {
	values := []string{string(InboundValueString), string(InboundValueInt64), string(InboundValueStructural)}
	if aliases {
		values = []string{string(InboundValueString), string(InboundValueInt64), string(InboundValueDouble), string(InboundValueStructured)}
	}
	return containsInboundString(values, string(value))
}

func validInboundShape(value InboundShape) bool {
	return value == InboundShapeExternal || value == InboundShapeNativeExact
}

func validInboundDiscriminator(value InboundDiscriminatorKind) bool {
	return containsInboundString([]string{
		string(InboundDiscriminatorConnectorLog), string(InboundDiscriminatorConnectorMetric),
		string(InboundDiscriminatorDurationMetric), string(InboundDiscriminatorGenAIOperation),
		string(InboundDiscriminatorNativeLog), string(InboundDiscriminatorNativeMetric),
		string(InboundDiscriminatorNativeSpan),
	}, string(value))
}

func validInboundMappingStrategy(value InboundMappingStrategy) bool {
	return containsInboundString([]string{
		string(InboundMappingClaudeTokenUsage), string(InboundMappingConnectorModelLog),
		string(InboundMappingDurationMetric), string(InboundMappingReverseMetric),
		string(InboundMappingReverseSpan), string(InboundMappingNativeLog),
		string(InboundMappingStandardGenAISpan),
	}, string(value))
}

func validInboundTargetRole(value InboundTargetRole) bool {
	return value == InboundTargetImport || value == InboundTargetDerive
}

func validInboundTargetKind(value InboundTargetKind) bool {
	return value == InboundTargetPrimary || value == InboundTargetDerived
}

func validInboundDerivationStrategy(value InboundDerivationStrategy) bool {
	return containsInboundString([]string{
		string(InboundDerivationNone), string(InboundDerivationClaudeTokenUsage),
		string(InboundDerivationCodexTokenFields), string(InboundDerivationDurationMetric),
		string(InboundDerivationElapsedTime), string(InboundDerivationFieldValue),
	}, string(value))
}

func containsInboundMarkerKind(value InboundMarkerKind) bool {
	return containsInboundString([]string{
		string(InboundMarkerExactStructuralValue), string(InboundMarkerProjectedStructure),
		string(InboundMarkerReservedKeyPresence),
	}, string(value))
}

func containsInboundString(values []string, want string) bool {
	for _, value := range values {
		if value == want {
			return true
		}
	}
	return false
}

func invalidInboundCatalog(reason string) error {
	return fmt.Errorf("%w: %s", ErrInboundCatalogInvalid, reason)
}
