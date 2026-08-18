// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"encoding/json"
	"fmt"
	"sort"
	"strings"
)

type observabilityV8EffectiveLeaf struct {
	path  string
	parts []any
}

// completeObservabilityV8EffectiveProvenance adds one exact value_path entry
// for every scalar or null value in the effective JSON document. Existing Path
// entries remain the human-facing source/derivation anchors. ValuePath is the
// unambiguous effective-output location, so clients never have to reconstruct
// named bucket/destination identities from arrays.
func completeObservabilityV8EffectiveProvenance(
	effective ObservabilityV8EffectivePlan,
) ([]ObservabilityV8Provenance, error) {
	base := make([]ObservabilityV8Provenance, 0, len(effective.Provenance))
	for _, provenance := range effective.Provenance {
		if provenance.ValuePath == "" {
			base = append(base, provenance)
		}
	}
	value := cloneObservabilityV8EffectivePlan(effective)
	value.Provenance = nil
	encoded, err := json.Marshal(value)
	if err != nil {
		return nil, fmt.Errorf("marshal effective plan for provenance: %w", err)
	}
	var document map[string]any
	if err := json.Unmarshal(encoded, &document); err != nil {
		return nil, fmt.Errorf("decode effective plan for provenance: %w", err)
	}
	delete(document, "provenance")
	leaves := make([]observabilityV8EffectiveLeaf, 0, 512)
	collectObservabilityV8EffectiveLeaves(document, "observability", nil, &leaves)
	result := append([]ObservabilityV8Provenance(nil), base...)
	for _, leaf := range leaves {
		basis, ok := observabilityV8EffectiveLeafBasis(leaf.parts, effective, base)
		if !ok {
			basis = ObservabilityV8Provenance{
				Path: leaf.path, Origin: "compiled-effective", Detail: "derived effective value",
			}
		}
		basis.ValuePath = leaf.path
		result = append(result, basis)
	}
	sort.SliceStable(result, func(left, right int) bool {
		if result[left].ValuePath != result[right].ValuePath {
			return result[left].ValuePath < result[right].ValuePath
		}
		if result[left].Path != result[right].Path {
			return result[left].Path < result[right].Path
		}
		return result[left].Origin < result[right].Origin
	})
	return result, nil
}

func collectObservabilityV8EffectiveLeaves(value any, path string, parts []any, result *[]observabilityV8EffectiveLeaf) {
	switch typed := value.(type) {
	case map[string]any:
		if len(typed) == 0 {
			*result = append(*result, observabilityV8EffectiveLeaf{path: path, parts: append([]any(nil), parts...)})
			return
		}
		keys := make([]string, 0, len(typed))
		for key := range typed {
			keys = append(keys, key)
		}
		sort.Strings(keys)
		for _, key := range keys {
			collectObservabilityV8EffectiveLeaves(
				typed[key],
				v8YAMLChildPath(path, key),
				appendObservabilityV8PathPart(parts, key),
				result,
			)
		}
	case []any:
		if len(typed) == 0 {
			*result = append(*result, observabilityV8EffectiveLeaf{path: path, parts: append([]any(nil), parts...)})
			return
		}
		for index, item := range typed {
			collectObservabilityV8EffectiveLeaves(
				item,
				fmt.Sprintf("%s[%d]", path, index),
				appendObservabilityV8PathPart(parts, index),
				result,
			)
		}
	default:
		*result = append(*result, observabilityV8EffectiveLeaf{
			path: path, parts: append([]any(nil), parts...),
		})
	}
}

func appendObservabilityV8PathPart(parts []any, value any) []any {
	result := make([]any, len(parts), len(parts)+1)
	copy(result, parts)
	return append(result, value)
}

func observabilityV8EffectiveLeafBasis(
	parts []any,
	effective ObservabilityV8EffectivePlan,
	base []ObservabilityV8Provenance,
) (ObservabilityV8Provenance, bool) {
	candidates := observabilityV8EffectiveLeafCandidatePaths(parts, effective)
	byPath := make(map[string]ObservabilityV8Provenance, len(base))
	for _, provenance := range base {
		byPath[provenance.Path] = provenance
	}
	for _, candidate := range candidates {
		if provenance, ok := byPath[candidate]; ok {
			return provenance, true
		}
	}
	for _, candidate := range candidates {
		bestLength := -1
		var best ObservabilityV8Provenance
		for _, provenance := range base {
			if observabilityV8ProvenancePathContains(provenance.Path, candidate) && len(provenance.Path) > bestLength {
				bestLength = len(provenance.Path)
				best = provenance
			}
		}
		if bestLength >= 0 {
			return best, true
		}
	}
	return ObservabilityV8Provenance{}, false
}

func observabilityV8ProvenancePathContains(prefix, value string) bool {
	return value == prefix || strings.HasPrefix(value, prefix+".") || strings.HasPrefix(value, prefix+"[")
}

func observabilityV8EffectiveLeafCandidatePaths(parts []any, effective ObservabilityV8EffectivePlan) []string {
	if len(parts) == 0 {
		return nil
	}
	root, ok := parts[0].(string)
	if !ok {
		return nil
	}
	switch root {
	case "buckets":
		return observabilityV8BucketLeafCandidatePaths(parts, effective)
	case "destinations":
		return observabilityV8DestinationLeafCandidatePaths(parts, effective)
	case "redaction_profiles":
		return observabilityV8ProfileLeafCandidatePaths(parts, effective)
	case "resource_attributes":
		result := []string{observabilityV8PathFromParts("observability.resource.attributes", parts[1:])}
		return append(result, "observability.resource_attributes")
	case "warnings":
		return []string{"observability.warnings"}
	default:
		return []string{observabilityV8PathFromParts("observability", parts)}
	}
}

func observabilityV8BucketLeafCandidatePaths(parts []any, effective ObservabilityV8EffectivePlan) []string {
	if len(parts) < 2 {
		return nil
	}
	index, ok := parts[1].(int)
	if !ok || index < 0 || index >= len(effective.Buckets) {
		return nil
	}
	bucket := string(effective.Buckets[index].Bucket)
	rest := parts[2:]
	sourceBase := v8YAMLChildPath("observability.buckets", bucket)
	semanticBase := "observability.buckets." + bucket
	result := []string{observabilityV8PathFromParts(sourceBase, rest)}
	if len(rest) > 0 {
		if field, stringField := rest[0].(string); stringField && (field == "collect" || field == "redaction_profile") {
			result = append(result, observabilityV8PathFromParts("observability.defaults", rest))
		}
	}
	result = append(result, observabilityV8PathFromParts(semanticBase, rest))
	return result
}

func observabilityV8DestinationLeafCandidatePaths(parts []any, effective ObservabilityV8EffectivePlan) []string {
	if len(parts) < 2 {
		return nil
	}
	index, ok := parts[1].(int)
	if !ok || index < 0 || index >= len(effective.Destinations) {
		return nil
	}
	destination := effective.Destinations[index]
	rest := parts[2:]
	semanticBase := "observability.destinations." + destination.Name
	result := make([]string, 0, 4)
	if index > 0 {
		sourceBase := fmt.Sprintf("observability.destinations[%d]", index-1)
		sourceRest := rest
		if len(rest) > 0 {
			if field, stringField := rest[0].(string); stringField && field == "transport" {
				sourceRest = rest[1:]
			}
		}
		result = append(result, observabilityV8PathFromParts(sourceBase, sourceRest))
	}
	if len(rest) > 0 {
		field, _ := rest[0].(string)
		switch field {
		case "transport":
			result = append(result, observabilityV8PathFromParts(semanticBase+".transport", rest[1:]))
		case "routes", "capabilities", "selected_signals", "policy_form", "first_match_per_signal":
			result = append(result, semanticBase+".policy")
		case "compatibility_profiles":
			if len(rest) > 1 {
				if profileIndex, valid := rest[1].(int); valid && profileIndex >= 0 && profileIndex < len(destination.CompatibilityProfiles) {
					result = append(result, semanticBase+".compatibility_profiles."+destination.CompatibilityProfiles[profileIndex].ID)
				}
			}
		default:
			result = append(result, observabilityV8PathFromParts(semanticBase, rest))
		}
	}
	return result
}

func observabilityV8ProfileLeafCandidatePaths(parts []any, effective ObservabilityV8EffectivePlan) []string {
	if len(parts) < 2 {
		return nil
	}
	index, ok := parts[1].(int)
	if !ok || index < 0 || index >= len(effective.Profiles) {
		return nil
	}
	base := v8YAMLChildPath("observability.redaction_profiles", effective.Profiles[index].Name)
	return []string{observabilityV8PathFromParts(base, parts[2:])}
}

func observabilityV8PathFromParts(base string, parts []any) string {
	result := base
	for _, part := range parts {
		switch typed := part.(type) {
		case string:
			result = v8YAMLChildPath(result, typed)
		case int:
			result = fmt.Sprintf("%s[%d]", result, typed)
		}
	}
	return result
}
