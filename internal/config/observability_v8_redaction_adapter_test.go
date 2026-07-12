// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityredaction "github.com/defenseclaw/defenseclaw/internal/observability/redaction"
)

func TestObservabilityV8RedactionProfileCatalogDefaultParity(t *testing.T) {
	plan := mustCompileObservabilityV8(t, nil)
	catalog, err := plan.RedactionProfileCatalog()
	if err != nil {
		t.Fatal(err)
	}

	wantNames := []observabilityredaction.ProfileName{
		observabilityredaction.ProfileContent,
		observabilityredaction.ProfileLegacyV7,
		observabilityredaction.ProfileNone,
		observabilityredaction.ProfileSensitive,
		observabilityredaction.ProfileStrict,
	}
	if got := catalog.Names(); !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("catalog names = %v, want %v", got, wantNames)
	}

	for _, effective := range plan.Snapshot().Profiles {
		profile, ok := catalog.Resolve(observabilityredaction.ProfileName(effective.Name))
		if !ok {
			t.Fatalf("catalog is missing %q", effective.Name)
		}
		if profile.Name() != observabilityredaction.ProfileName(effective.Name) ||
			profile.Base() != observabilityredaction.ProfileName(effective.Name) {
			t.Fatalf("built-in identity for %q = name %q, base %q", effective.Name, profile.Name(), profile.Base())
		}
		assertEffectiveProfileParity(t, effective, profile)
	}

	legacy, ok := catalog.Resolve(observabilityredaction.ProfileLegacyV7)
	if !ok {
		t.Fatal("legacy-v7 is missing")
	}
	if got := legacy.DetectorGroups(); len(got) != 0 {
		t.Fatalf("legacy-v7 detector groups = %v, want none", got)
	}
	for _, class := range observability.FieldClasses() {
		mode, _ := legacy.Mode(class)
		want := observabilityredaction.ModeWhole
		if class == observability.FieldClassMetadata {
			want = observabilityredaction.ModePreserve
		}
		if mode != want {
			t.Fatalf("legacy-v7 %s mode = %q, want %q", class, mode, want)
		}
	}
}

func TestObservabilityV8PlanResolvesImmutableLocalProfiles(t *testing.T) {
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		Buckets: map[observability.Bucket]ObservabilityV8BucketPolicySource{
			observability.BucketSecurityFinding: {RedactionProfile: "strict"},
		},
	})
	for _, bucket := range observability.Buckets() {
		got, err := plan.ResolveLocalRedactionProfile(bucket)
		if err != nil {
			t.Fatalf("bucket %s: %v", bucket, err)
		}
		want := observabilityredaction.ProfileNone
		if bucket == observability.BucketSecurityFinding {
			want = observabilityredaction.ProfileStrict
		}
		if got != want {
			t.Errorf("bucket %s local profile = %q, want %q", bucket, got, want)
		}
	}
	if _, err := plan.ResolveLocalRedactionProfile("future.unreviewed"); err == nil {
		t.Fatal("unreviewed bucket resolved a local profile")
	}
}

func TestObservabilityV8RedactionProfileCatalogCustomParityAndCopySafety(t *testing.T) {
	plan := mustCompileObservabilityV8(t, &ObservabilityV8Source{
		RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{
			"zeta": {Extends: "strict"},
			"alpha": {
				Extends:   "sensitive",
				Detectors: []ObservabilityV8DetectorGroup{ObservabilityV8DetectorPII, ObservabilityV8DetectorCredentials},
				FieldClasses: map[ObservabilityV8FieldClass]ObservabilityV8FieldMode{
					ObservabilityV8FieldEvidence:   ObservabilityV8ModeWhole,
					ObservabilityV8FieldPath:       ObservabilityV8ModeRemove,
					ObservabilityV8FieldCredential: ObservabilityV8ModeWhole,
				},
			},
		},
	})
	snapshot := plan.Snapshot()
	catalog, err := buildObservabilityV8RedactionProfileCatalog(snapshot.Profiles)
	if err != nil {
		t.Fatal(err)
	}

	wantNames := []observabilityredaction.ProfileName{
		"alpha",
		observabilityredaction.ProfileContent,
		observabilityredaction.ProfileLegacyV7,
		observabilityredaction.ProfileNone,
		observabilityredaction.ProfileSensitive,
		observabilityredaction.ProfileStrict,
		"zeta",
	}
	if got := catalog.Names(); !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("catalog names = %v, want deterministic lexical order %v", got, wantNames)
	}
	reversed := append([]ObservabilityV8EffectiveProfile(nil), snapshot.Profiles...)
	for left, right := 0, len(reversed)-1; left < right; left, right = left+1, right-1 {
		reversed[left], reversed[right] = reversed[right], reversed[left]
	}
	reorderedCatalog, err := buildObservabilityV8RedactionProfileCatalog(reversed)
	if err != nil {
		t.Fatal(err)
	}
	if got := reorderedCatalog.Names(); !reflect.DeepEqual(got, wantNames) {
		t.Fatalf("reordered catalog names = %v, want %v", got, wantNames)
	}

	alphaEffective := effectiveProfileByName(t, snapshot.Profiles, "alpha")
	alpha, ok := catalog.Resolve("alpha")
	if !ok {
		t.Fatal("custom profile alpha is missing")
	}
	if alpha.Base() != observabilityredaction.ProfileSensitive {
		t.Fatalf("alpha base = %q", alpha.Base())
	}
	assertEffectiveProfileParity(t, alphaEffective, alpha)
	if got := alpha.DetectorGroups(); !reflect.DeepEqual(got, []observabilityredaction.DetectorGroup{
		observabilityredaction.DetectorGroupCredentials,
		observabilityredaction.DetectorGroupPII,
	}) {
		t.Fatalf("alpha detector groups = %v", got)
	}

	// Mutating both the adapter input and accessor results must not mutate the
	// catalog's immutable profiles.
	for index := range snapshot.Profiles {
		if snapshot.Profiles[index].Name == "alpha" {
			snapshot.Profiles[index].Name = "changed"
			snapshot.Profiles[index].Detectors[0] = ObservabilityV8DetectorSecrets
			snapshot.Profiles[index].FieldClasses[ObservabilityV8FieldEvidence] = ObservabilityV8ModeRemove
		}
	}
	groups := alpha.DetectorGroups()
	groups[0] = observabilityredaction.DetectorGroupSecrets
	alphaAgain, ok := catalog.Resolve("alpha")
	if !ok || alphaAgain.Name() != "alpha" {
		t.Fatal("catalog changed after source mutation")
	}
	if got, _ := alphaAgain.Mode(observability.FieldClassEvidence); got != observabilityredaction.ModeWhole {
		t.Fatalf("alpha evidence mode changed to %q", got)
	}
	if got := alphaAgain.DetectorGroups(); !reflect.DeepEqual(got, []observabilityredaction.DetectorGroup{
		observabilityredaction.DetectorGroupCredentials,
		observabilityredaction.DetectorGroupPII,
	}) {
		t.Fatalf("alpha detector groups changed to %v", got)
	}
}

func TestObservabilityV8RedactionAdapterMapsCompleteVocabulary(t *testing.T) {
	profileNames := map[string]observabilityredaction.ProfileName{
		"none":      observabilityredaction.ProfileNone,
		"sensitive": observabilityredaction.ProfileSensitive,
		"content":   observabilityredaction.ProfileContent,
		"strict":    observabilityredaction.ProfileStrict,
		"legacy-v7": observabilityredaction.ProfileLegacyV7,
	}
	if got := len(observabilityredaction.BuiltInProfiles()); len(profileNames) != got {
		t.Fatalf("profile-name adapter covers %d built-ins, runtime exposes %d", len(profileNames), got)
	}
	for _, profile := range observabilityredaction.BuiltInProfiles() {
		if _, ok := profileNames[string(profile.Name())]; !ok {
			t.Errorf("runtime built-in profile %q is not covered", profile.Name())
		}
	}
	for source, want := range profileNames {
		got, ok := adaptObservabilityV8ProfileName(source)
		if !ok || got != want {
			t.Errorf("profile name %q = %q/%t, want %q/true", source, got, ok, want)
		}
	}
	if _, ok := adaptObservabilityV8ProfileName("future"); ok {
		t.Fatal("unknown profile name was mapped")
	}

	detectorGroups := map[ObservabilityV8DetectorGroup]observabilityredaction.DetectorGroup{
		ObservabilityV8DetectorPII:         observabilityredaction.DetectorGroupPII,
		ObservabilityV8DetectorCredentials: observabilityredaction.DetectorGroupCredentials,
		ObservabilityV8DetectorSecrets:     observabilityredaction.DetectorGroupSecrets,
	}
	if got := len(observabilityredaction.DetectorGroups()); len(detectorGroups) != got {
		t.Fatalf("detector-group adapter covers %d groups, runtime exposes %d", len(detectorGroups), got)
	}
	for _, group := range observabilityredaction.DetectorGroups() {
		found := false
		for _, mapped := range detectorGroups {
			found = found || mapped == group
		}
		if !found {
			t.Errorf("runtime detector group %q is not covered", group)
		}
	}
	for source, want := range detectorGroups {
		got, err := adaptObservabilityV8DetectorGroups([]ObservabilityV8DetectorGroup{source}, "test")
		if err != nil || len(got) != 1 || got[0] != want {
			t.Errorf("detector group %q = %v, %v; want [%q], nil", source, got, err, want)
		}
	}

	fieldClasses := map[ObservabilityV8FieldClass]observability.FieldClass{
		ObservabilityV8FieldMetadata:   observability.FieldClassMetadata,
		ObservabilityV8FieldIdentifier: observability.FieldClassIdentifier,
		ObservabilityV8FieldContent:    observability.FieldClassContent,
		ObservabilityV8FieldReason:     observability.FieldClassReason,
		ObservabilityV8FieldEvidence:   observability.FieldClassEvidence,
		ObservabilityV8FieldError:      observability.FieldClassError,
		ObservabilityV8FieldPath:       observability.FieldClassPath,
		ObservabilityV8FieldCredential: observability.FieldClassCredential,
	}
	if got := len(observability.FieldClasses()); len(fieldClasses) != got {
		t.Fatalf("field-class adapter covers %d classes, runtime exposes %d", len(fieldClasses), got)
	}
	for _, class := range observability.FieldClasses() {
		found := false
		for _, mapped := range fieldClasses {
			found = found || mapped == class
		}
		if !found {
			t.Errorf("runtime field class %q is not covered", class)
		}
	}
	for source, want := range fieldClasses {
		got, ok := adaptObservabilityV8FieldClass(source)
		if !ok || got != want {
			t.Errorf("field class %q = %q/%t, want %q/true", source, got, ok, want)
		}
	}

	fieldModes := map[ObservabilityV8FieldMode]observabilityredaction.TransformationMode{
		ObservabilityV8ModePreserve: observabilityredaction.ModePreserve,
		ObservabilityV8ModeDetect:   observabilityredaction.ModeDetect,
		ObservabilityV8ModeWhole:    observabilityredaction.ModeWhole,
		ObservabilityV8ModeHash:     observabilityredaction.ModeHash,
		ObservabilityV8ModeRemove:   observabilityredaction.ModeRemove,
	}
	for source, want := range fieldModes {
		got, ok := adaptObservabilityV8FieldMode(source)
		if !ok || got != want {
			t.Errorf("field mode %q = %q/%t, want %q/true", source, got, ok, want)
		}
	}

	if _, err := adaptObservabilityV8DetectorGroups([]ObservabilityV8DetectorGroup{"future"}, "test"); err == nil {
		t.Error("unknown detector group was mapped")
	}
	if _, ok := adaptObservabilityV8FieldClass("future"); ok {
		t.Error("unknown field class was mapped")
	}
	if _, ok := adaptObservabilityV8FieldMode("future"); ok {
		t.Error("unknown field mode was mapped")
	}
}

func TestObservabilityV8RedactionProfileCatalogRejectsMutatedEffectiveSnapshots(t *testing.T) {
	defaultProfiles := func() []ObservabilityV8EffectiveProfile {
		return mustCompileObservabilityV8(t, nil).Snapshot().Profiles
	}
	customProfiles := func() []ObservabilityV8EffectiveProfile {
		return mustCompileObservabilityV8(t, &ObservabilityV8Source{
			RedactionProfiles: map[string]ObservabilityV8RedactionProfileSource{
				"custom": {Extends: "sensitive"},
			},
		}).Snapshot().Profiles
	}

	tests := []struct {
		name   string
		base   func() []ObservabilityV8EffectiveProfile
		mutate func([]ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile
	}{
		{name: "empty", base: defaultProfiles, mutate: func([]ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile { return nil }},
		{name: "effective profile limit", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			return make([]ObservabilityV8EffectiveProfile, len(values)+ObservabilityV8MaxRedactionProfiles+1)
		}},
		{name: "missing built-in", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile { return values[1:] }},
		{name: "duplicate", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			return append(values, cloneObservabilityV8Profile(values[0]))
		}},
		{name: "empty name", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[0].Name = ""
			return values
		}},
		{name: "built-in flag", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[1].BuiltIn = false
			return values
		}},
		{name: "built-in extends", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[1].Extends = "strict"
			return values
		}},
		{name: "unknown built-in", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[0].Name = "future"
			return values
		}},
		{name: "built-in mode drift", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[1].FieldClasses[ObservabilityV8FieldContent] = ObservabilityV8ModeWhole
			return values
		}},
		{name: "built-in group drift", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[1].Detectors = values[1].Detectors[:2]
			return values
		}},
		{name: "built-in duplicate group", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[1].Detectors[1] = values[1].Detectors[0]
			return values
		}},
		{name: "built-in unknown group", base: defaultProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			values[1].Detectors[0] = "future"
			return values
		}},
		{name: "custom marked built-in", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			effectiveProfilePointerByName(t, values, "custom").BuiltIn = true
			return values
		}},
		{name: "custom bad base", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			effectiveProfilePointerByName(t, values, "custom").Extends = "legacy-v7"
			return values
		}},
		{name: "custom missing field", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			delete(effectiveProfilePointerByName(t, values, "custom").FieldClasses, ObservabilityV8FieldContent)
			return values
		}},
		{name: "custom unknown field", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			profile := effectiveProfilePointerByName(t, values, "custom")
			delete(profile.FieldClasses, ObservabilityV8FieldContent)
			profile.FieldClasses["future"] = ObservabilityV8ModeWhole
			return values
		}},
		{name: "custom unknown mode", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			effectiveProfilePointerByName(t, values, "custom").FieldClasses[ObservabilityV8FieldContent] = "future"
			return values
		}},
		{name: "custom invalid strength", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			effectiveProfilePointerByName(t, values, "custom").FieldClasses[ObservabilityV8FieldContent] = ObservabilityV8ModePreserve
			return values
		}},
		{name: "custom empty resolved groups", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			effectiveProfilePointerByName(t, values, "custom").Detectors = []ObservabilityV8DetectorGroup{}
			return values
		}},
		{name: "custom duplicate group", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			profile := effectiveProfilePointerByName(t, values, "custom")
			profile.Detectors = append(profile.Detectors, profile.Detectors[0])
			return values
		}},
		{name: "custom unknown group", base: customProfiles, mutate: func(values []ObservabilityV8EffectiveProfile) []ObservabilityV8EffectiveProfile {
			effectiveProfilePointerByName(t, values, "custom").Detectors[0] = "future"
			return values
		}},
	}

	for _, test := range tests {
		t.Run(test.name, func(t *testing.T) {
			profiles := test.mutate(test.base())
			if _, err := buildObservabilityV8RedactionProfileCatalog(profiles); err == nil {
				t.Fatal("mutated effective snapshot was accepted")
			}
		})
	}

	var nilPlan *ObservabilityV8Plan
	if _, err := nilPlan.RedactionProfileCatalog(); err == nil {
		t.Fatal("nil plan produced a profile catalog")
	}
}

func TestObservabilityV8RedactionAdapterDiagnosticsAreDeterministic(t *testing.T) {
	profiles := mustCompileObservabilityV8(t, nil).Snapshot().Profiles
	profiles[1].FieldClasses[ObservabilityV8FieldContent] = "future-content"
	profiles[1].FieldClasses[ObservabilityV8FieldEvidence] = "future-evidence"

	var first string
	for attempt := 0; attempt < 32; attempt++ {
		_, err := buildObservabilityV8RedactionProfileCatalog(profiles)
		if err == nil {
			t.Fatal("invalid modes were accepted")
		}
		if attempt == 0 {
			first = err.Error()
		} else if err.Error() != first {
			t.Fatalf("diagnostic changed between attempts: %q != %q", err, first)
		}
	}
}

func assertEffectiveProfileParity(
	t *testing.T,
	effective ObservabilityV8EffectiveProfile,
	profile observabilityredaction.Profile,
) {
	t.Helper()
	groups, err := adaptObservabilityV8DetectorGroups(effective.Detectors, "test")
	if err != nil {
		t.Fatal(err)
	}
	if !sameObservabilityV8DetectorGroups(groups, profile.DetectorGroups()) {
		t.Fatalf("%s detector groups = %v, want %v", effective.Name, profile.DetectorGroups(), groups)
	}
	for sourceClass, sourceMode := range effective.FieldClasses {
		class, classOK := adaptObservabilityV8FieldClass(sourceClass)
		mode, modeOK := adaptObservabilityV8FieldMode(sourceMode)
		got, gotOK := profile.Mode(class)
		if !classOK || !modeOK || !gotOK || got != mode {
			t.Fatalf("%s/%s mode = %q/%t, want %q", effective.Name, sourceClass, got, gotOK, mode)
		}
	}
}

func effectiveProfileByName(t *testing.T, profiles []ObservabilityV8EffectiveProfile, name string) ObservabilityV8EffectiveProfile {
	t.Helper()
	for _, profile := range profiles {
		if profile.Name == name {
			return profile
		}
	}
	t.Fatalf("effective profile %q is missing", name)
	return ObservabilityV8EffectiveProfile{}
}

func effectiveProfilePointerByName(t *testing.T, profiles []ObservabilityV8EffectiveProfile, name string) *ObservabilityV8EffectiveProfile {
	t.Helper()
	for index := range profiles {
		if profiles[index].Name == name {
			return &profiles[index]
		}
	}
	t.Fatalf("effective profile %q is missing", name)
	return nil
}
