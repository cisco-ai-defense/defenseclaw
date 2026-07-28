// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"fmt"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

// RedactionProfileCatalog adapts the plan's resolved profile snapshot to the
// runtime redaction namespace. The adapter revalidates the complete effective
// representation instead of trusting that its producer was the v8 compiler.
func (plan *ObservabilityV8Plan) RedactionProfileCatalog() (observabilityredaction.ProfileCatalog, error) {
	if plan == nil {
		return observabilityredaction.ProfileCatalog{}, fmt.Errorf("observability v8 redaction profile catalog: plan is nil")
	}
	return buildObservabilityV8RedactionProfileCatalog(plan.effective.Profiles)
}

// ResolveLocalRedactionProfile exposes the immutable compiled local SQLite
// bucket binding without exposing mutable route maps. It satisfies the audit
// event-history resolver boundary while keeping config independent of storage.
func (plan *ObservabilityV8Plan) ResolveLocalRedactionProfile(
	bucket observability.Bucket,
) (observabilityredaction.ProfileName, error) {
	if plan == nil {
		return "", fmt.Errorf("observability v8 local profile: plan is nil")
	}
	for _, policy := range plan.effective.Buckets {
		if policy.Bucket != bucket {
			continue
		}
		profile := observabilityredaction.ProfileName(policy.RedactionProfile)
		if !observability.IsStableToken(string(profile)) {
			return "", fmt.Errorf("observability v8 local profile: bucket %s has an invalid profile", bucket)
		}
		return profile, nil
	}
	return "", fmt.Errorf("observability v8 local profile: bucket %s is not in the compiled catalog", bucket)
}

func buildObservabilityV8RedactionProfileCatalog(
	profiles []ObservabilityV8EffectiveProfile,
) (observabilityredaction.ProfileCatalog, error) {
	builtIns := observabilityredaction.BuiltInProfiles()
	if len(profiles) > len(builtIns)+ObservabilityV8MaxRedactionProfiles {
		return observabilityredaction.ProfileCatalog{}, fmt.Errorf(
			"observability.redaction_profiles: got %d effective profiles, maximum is %d",
			len(profiles), len(builtIns)+ObservabilityV8MaxRedactionProfiles,
		)
	}
	seen := make(map[string]struct{}, len(profiles))
	custom := make([]observabilityredaction.Profile, 0, len(profiles))

	for index, effective := range profiles {
		path := fmt.Sprintf("observability.redaction_profiles[%d]", index)
		if effective.Name == "" {
			return observabilityredaction.ProfileCatalog{}, fmt.Errorf("%s.name: must not be empty", path)
		}
		if _, duplicate := seen[effective.Name]; duplicate {
			return observabilityredaction.ProfileCatalog{}, fmt.Errorf("%s.name: profile %q is duplicated", path, effective.Name)
		}
		seen[effective.Name] = struct{}{}

		profileName := observabilityredaction.ProfileName(effective.Name)
		builtIn, isBuiltInName := observabilityredaction.BuiltInProfile(profileName)
		if isBuiltInName {
			if err := validateObservabilityV8EffectiveBuiltIn(effective, builtIn, path); err != nil {
				return observabilityredaction.ProfileCatalog{}, err
			}
			continue
		}
		if effective.BuiltIn {
			return observabilityredaction.ProfileCatalog{}, fmt.Errorf("%s: unknown built-in profile %q", path, effective.Name)
		}

		adapted, err := adaptObservabilityV8EffectiveCustomProfile(effective, path)
		if err != nil {
			return observabilityredaction.ProfileCatalog{}, err
		}
		custom = append(custom, adapted)
	}

	for _, builtIn := range builtIns {
		name := builtIn.Name()
		if _, ok := seen[string(name)]; !ok {
			return observabilityredaction.ProfileCatalog{}, fmt.Errorf("observability.redaction_profiles: required built-in profile %q is missing", name)
		}
	}

	catalog, err := observabilityredaction.NewProfileCatalog(custom)
	if err != nil {
		return observabilityredaction.ProfileCatalog{}, fmt.Errorf("observability.redaction_profiles: construct runtime catalog: %w", err)
	}
	return catalog, nil
}

func validateObservabilityV8EffectiveBuiltIn(
	effective ObservabilityV8EffectiveProfile,
	want observabilityredaction.Profile,
	path string,
) error {
	if !effective.BuiltIn {
		return fmt.Errorf("%s.built_in: required built-in profile %q is marked custom", path, effective.Name)
	}
	if effective.Extends != "" {
		return fmt.Errorf("%s.extends: built-in profile must not extend another profile", path)
	}
	groups, err := adaptObservabilityV8DetectorGroups(effective.Detectors, path+".detectors")
	if err != nil {
		return err
	}
	if !sameObservabilityV8DetectorGroups(groups, want.DetectorGroups()) {
		return fmt.Errorf("%s.detectors: built-in profile %q detector groups drifted from the runtime contract", path, effective.Name)
	}
	modes, err := adaptObservabilityV8FieldModes(effective.FieldClasses, path+".field_classes")
	if err != nil {
		return err
	}
	for _, class := range observability.FieldClasses() {
		wantMode, ok := want.Mode(class)
		if !ok || modes[class] != wantMode {
			return fmt.Errorf("%s.field_classes.%s: built-in profile %q mode drifted from the runtime contract", path, class, effective.Name)
		}
	}
	return nil
}

func adaptObservabilityV8EffectiveCustomProfile(
	effective ObservabilityV8EffectiveProfile,
	path string,
) (observabilityredaction.Profile, error) {
	if effective.BuiltIn {
		return observabilityredaction.Profile{}, fmt.Errorf("%s.built_in: custom profile is marked built-in", path)
	}
	base, ok := adaptObservabilityV8ProfileName(effective.Extends)
	if !ok || (base != observabilityredaction.ProfileSensitive &&
		base != observabilityredaction.ProfileContent &&
		base != observabilityredaction.ProfileStrict) {
		return observabilityredaction.Profile{}, fmt.Errorf("%s.extends: expected sensitive, content, or strict", path)
	}
	groups, err := adaptObservabilityV8DetectorGroups(effective.Detectors, path+".detectors")
	if err != nil {
		return observabilityredaction.Profile{}, err
	}
	modes, err := adaptObservabilityV8FieldModes(effective.FieldClasses, path+".field_classes")
	if err != nil {
		return observabilityredaction.Profile{}, err
	}
	profile, err := observabilityredaction.NewCustomProfile(
		observabilityredaction.ProfileName(effective.Name),
		base,
		groups,
		modes,
	)
	if err != nil {
		return observabilityredaction.Profile{}, fmt.Errorf("%s: invalid effective custom profile: %w", path, err)
	}
	return profile, nil
}

func adaptObservabilityV8ProfileName(value string) (observabilityredaction.ProfileName, bool) {
	switch value {
	case string(observabilityredaction.ProfileNone):
		return observabilityredaction.ProfileNone, true
	case string(observabilityredaction.ProfileSensitive):
		return observabilityredaction.ProfileSensitive, true
	case string(observabilityredaction.ProfileContent):
		return observabilityredaction.ProfileContent, true
	case string(observabilityredaction.ProfileStrict):
		return observabilityredaction.ProfileStrict, true
	case string(observabilityredaction.ProfileLegacyV7):
		return observabilityredaction.ProfileLegacyV7, true
	default:
		return "", false
	}
}

func adaptObservabilityV8DetectorGroups(
	values []ObservabilityV8DetectorGroup,
	path string,
) ([]observabilityredaction.DetectorGroup, error) {
	// Effective profiles contain a fully resolved detector selection. Preserve
	// an empty selection as explicitly empty so corruption cannot turn it into
	// NewCustomProfile's nil-means-inherit input.
	result := make([]observabilityredaction.DetectorGroup, 0, len(values))
	seen := make(map[observabilityredaction.DetectorGroup]struct{}, len(values))
	for _, value := range values {
		var group observabilityredaction.DetectorGroup
		switch value {
		case ObservabilityV8DetectorPII:
			group = observabilityredaction.DetectorGroupPII
		case ObservabilityV8DetectorCredentials:
			group = observabilityredaction.DetectorGroupCredentials
		case ObservabilityV8DetectorSecrets:
			group = observabilityredaction.DetectorGroupSecrets
		default:
			return nil, fmt.Errorf("%s: unknown detector group %q", path, value)
		}
		if _, duplicate := seen[group]; duplicate {
			return nil, fmt.Errorf("%s: duplicate detector group %q", path, value)
		}
		seen[group] = struct{}{}
		result = append(result, group)
	}
	return result, nil
}

func adaptObservabilityV8FieldModes(
	values map[ObservabilityV8FieldClass]ObservabilityV8FieldMode,
	path string,
) (map[observability.FieldClass]observabilityredaction.TransformationMode, error) {
	canonicalClasses := observability.FieldClasses()
	if len(values) != len(canonicalClasses) {
		return nil, fmt.Errorf("%s: expected exactly %d canonical field classes, got %d", path, len(canonicalClasses), len(values))
	}
	result := make(map[observability.FieldClass]observabilityredaction.TransformationMode, len(values))
	for _, fieldClass := range [...]ObservabilityV8FieldClass{
		ObservabilityV8FieldMetadata,
		ObservabilityV8FieldIdentifier,
		ObservabilityV8FieldContent,
		ObservabilityV8FieldReason,
		ObservabilityV8FieldEvidence,
		ObservabilityV8FieldError,
		ObservabilityV8FieldPath,
		ObservabilityV8FieldCredential,
	} {
		mode, present := values[fieldClass]
		if !present {
			return nil, fmt.Errorf("%s.%s: canonical field class is missing", path, fieldClass)
		}
		adaptedClass, ok := adaptObservabilityV8FieldClass(fieldClass)
		if !ok {
			return nil, fmt.Errorf("%s: adapter does not map canonical field class %q", path, fieldClass)
		}
		adaptedMode, ok := adaptObservabilityV8FieldMode(mode)
		if !ok {
			return nil, fmt.Errorf("%s.%s: unknown transformation mode %q", path, fieldClass, mode)
		}
		result[adaptedClass] = adaptedMode
	}
	for _, fieldClass := range canonicalClasses {
		if _, ok := result[fieldClass]; !ok {
			return nil, fmt.Errorf("%s.%s: runtime field class is not mapped by the adapter", path, fieldClass)
		}
	}
	return result, nil
}

func adaptObservabilityV8FieldClass(value ObservabilityV8FieldClass) (observability.FieldClass, bool) {
	switch value {
	case ObservabilityV8FieldMetadata:
		return observability.FieldClassMetadata, true
	case ObservabilityV8FieldIdentifier:
		return observability.FieldClassIdentifier, true
	case ObservabilityV8FieldContent:
		return observability.FieldClassContent, true
	case ObservabilityV8FieldReason:
		return observability.FieldClassReason, true
	case ObservabilityV8FieldEvidence:
		return observability.FieldClassEvidence, true
	case ObservabilityV8FieldError:
		return observability.FieldClassError, true
	case ObservabilityV8FieldPath:
		return observability.FieldClassPath, true
	case ObservabilityV8FieldCredential:
		return observability.FieldClassCredential, true
	default:
		return "", false
	}
}

func adaptObservabilityV8FieldMode(value ObservabilityV8FieldMode) (observabilityredaction.TransformationMode, bool) {
	switch value {
	case ObservabilityV8ModePreserve:
		return observabilityredaction.ModePreserve, true
	case ObservabilityV8ModeDetect:
		return observabilityredaction.ModeDetect, true
	case ObservabilityV8ModeWhole:
		return observabilityredaction.ModeWhole, true
	case ObservabilityV8ModeHash:
		return observabilityredaction.ModeHash, true
	case ObservabilityV8ModeRemove:
		return observabilityredaction.ModeRemove, true
	default:
		return "", false
	}
}

func sameObservabilityV8DetectorGroups(left, right []observabilityredaction.DetectorGroup) bool {
	if len(left) != len(right) {
		return false
	}
	seen := make(map[observabilityredaction.DetectorGroup]struct{}, len(left))
	for _, group := range left {
		seen[group] = struct{}{}
	}
	for _, group := range right {
		if _, ok := seen[group]; !ok {
			return false
		}
	}
	return true
}
