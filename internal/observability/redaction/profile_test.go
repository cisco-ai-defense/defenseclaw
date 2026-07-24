// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"reflect"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

func TestBuiltInProfileMatrixIsExact(t *testing.T) {
	classes := observability.FieldClasses()
	want := map[ProfileName][]TransformationMode{
		ProfileNone: {
			ModePreserve, ModePreserve, ModePreserve, ModePreserve,
			ModePreserve, ModePreserve, ModePreserve, ModePreserve,
		},
		ProfileSensitive: {
			ModePreserve, ModePreserve, ModeDetect, ModeDetect,
			ModeDetect, ModeDetect, ModeHash, ModeRemove,
		},
		ProfileContent: {
			ModePreserve, ModePreserve, ModeWhole, ModeWhole,
			ModeWhole, ModeWhole, ModeHash, ModeRemove,
		},
		ProfileStrict: {
			ModePreserve, ModePreserve, ModeRemove, ModeRemove,
			ModeRemove, ModeRemove, ModeRemove, ModeRemove,
		},
		ProfileLegacyV7: {
			ModePreserve, ModeWhole, ModeWhole, ModeWhole,
			ModeWhole, ModeWhole, ModeWhole, ModeWhole,
		},
	}
	for name, expected := range want {
		profile, ok := BuiltInProfile(name)
		if !ok {
			t.Fatalf("built-in %q is missing", name)
		}
		for index, class := range classes {
			got, ok := profile.Mode(class)
			if !ok || got != expected[index] {
				t.Fatalf("%s/%s mode = %q/%t, want %q", name, class, got, ok, expected[index])
			}
		}
		wantGroups := []DetectorGroup{}
		if name != ProfileNone && name != ProfileLegacyV7 {
			wantGroups = DetectorGroups()
		}
		if !reflect.DeepEqual(profile.DetectorGroups(), wantGroups) {
			t.Fatalf("%s groups = %v, want %v", name, profile.DetectorGroups(), wantGroups)
		}
	}
}

func TestCustomProfileCompositionAndValidation(t *testing.T) {
	inherited, err := NewCustomProfile("inherited.groups", ProfileContent, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	if got := inherited.DetectorGroups(); !reflect.DeepEqual(got, DetectorGroups()) {
		t.Fatalf("inherited groups = %v", got)
	}
	profile, err := NewCustomProfile(
		"soc.partial",
		ProfileContent,
		[]DetectorGroup{DetectorGroupPII},
		map[observability.FieldClass]TransformationMode{
			observability.FieldClassContent: ModeDetect,
			observability.FieldClassPath:    ModeRemove,
		},
	)
	if err != nil {
		t.Fatal(err)
	}
	if got, _ := profile.Mode(observability.FieldClassContent); got != ModeDetect {
		t.Fatalf("content mode = %q", got)
	}
	if got := profile.DetectorGroups(); !reflect.DeepEqual(got, []DetectorGroup{DetectorGroupPII}) {
		t.Fatalf("groups = %v", got)
	}
	groups := profile.DetectorGroups()
	groups[0] = DetectorGroupSecrets
	if got := profile.DetectorGroups()[0]; got != DetectorGroupPII {
		t.Fatal("detector group accessor exposed profile state")
	}

	tests := []struct {
		name      ProfileName
		base      ProfileName
		groups    []DetectorGroup
		overrides map[observability.FieldClass]TransformationMode
	}{
		{name: ProfileNone, base: ProfileContent, groups: DetectorGroups()},
		{name: "bad name", base: ProfileContent, groups: DetectorGroups()},
		{name: "bad-base", base: ProfileNone, groups: DetectorGroups()},
		{name: "legacy-base", base: ProfileLegacyV7, groups: DetectorGroups()},
		{name: "unknown-group", base: ProfileContent, groups: []DetectorGroup{"unknown"}},
		{name: "duplicate-group", base: ProfileContent, groups: []DetectorGroup{DetectorGroupPII, DetectorGroupPII}},
		{name: "unknown-class", base: ProfileContent, groups: DetectorGroups(), overrides: map[observability.FieldClass]TransformationMode{"unknown": ModeRemove}},
		{name: "unknown-mode", base: ProfileContent, groups: DetectorGroups(), overrides: map[observability.FieldClass]TransformationMode{observability.FieldClassContent: "scrub"}},
		{name: "raw-content", base: ProfileContent, groups: DetectorGroups(), overrides: map[observability.FieldClass]TransformationMode{observability.FieldClassContent: ModePreserve}},
		{name: "credential-detect", base: ProfileContent, groups: DetectorGroups(), overrides: map[observability.FieldClass]TransformationMode{observability.FieldClassCredential: ModeDetect}},
		{name: "metadata-remove", base: ProfileContent, groups: DetectorGroups(), overrides: map[observability.FieldClass]TransformationMode{observability.FieldClassMetadata: ModeRemove}},
		{name: "identifier-hash", base: ProfileContent, groups: DetectorGroups(), overrides: map[observability.FieldClass]TransformationMode{observability.FieldClassIdentifier: ModeHash}},
		{name: "empty-groups", base: ProfileContent, groups: []DetectorGroup{}},
	}
	for _, test := range tests {
		if _, err := NewCustomProfile(test.name, test.base, test.groups, test.overrides); err == nil {
			t.Errorf("NewCustomProfile(%q) unexpectedly succeeded", test.name)
		}
	}
}

func TestProfileCatalogSnapshotsNamespace(t *testing.T) {
	custom, err := NewCustomProfile("console.strict", ProfileStrict, DetectorGroups(), nil)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewProfileCatalog([]Profile{custom})
	if err != nil {
		t.Fatal(err)
	}
	if got, ok := catalog.Resolve("console.strict"); !ok || got.Name() != "console.strict" {
		t.Fatalf("resolve = %#v/%t", got, ok)
	}
	if _, err := NewProfileCatalog([]Profile{custom, custom}); err == nil {
		t.Fatal("duplicate custom profile was accepted")
	}
	if _, err := NewProfileCatalog([]Profile{{}}); err == nil {
		t.Fatal("zero profile was accepted")
	}
}
