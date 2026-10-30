// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import "testing"

// validProfile runs for every projection (Project, Reproject and the sink
// policy resolver), and it looked the built-in profile up by building all
// four built-ins and their SHA-256 fingerprints again each time.
func BenchmarkValidBuiltInProfile(b *testing.B) {
	profile, ok := BuiltInProfile(ProfileSensitive)
	if !ok {
		b.Fatal("sensitive profile is unavailable")
	}
	b.ReportAllocs()
	for b.Loop() {
		if !validProfile(profile) {
			b.Fatal("built-in profile is not valid")
		}
	}
}

func TestBuiltInProfilesAreResolvedOnceAndStayImmutable(t *testing.T) {
	for _, name := range []ProfileName{ProfileNone, ProfileSensitive, ProfileContent, ProfileStrict} {
		profile, ok := BuiltInProfile(name)
		if !ok || profile.name != name || profile.base != name || profile.fingerprint != profileFingerprint(profile) {
			t.Fatalf("built-in %s = %+v, %v", name, profile, ok)
		}
	}
	// A catalog extends its own copy of the built-ins; the shared table is
	// never changed by it.
	custom, err := NewCustomProfile("r106custom", ProfileStrict, nil, nil)
	if err != nil {
		t.Fatal(err)
	}
	catalog, err := NewProfileCatalog([]Profile{custom})
	if err != nil {
		t.Fatal(err)
	}
	if _, ok := catalog.Resolve("r106custom"); !ok {
		t.Fatal("catalog lost its custom profile")
	}
	if _, ok := BuiltInProfile("r106custom"); ok {
		t.Fatal("a catalog's custom profile leaked into the built-in table")
	}
	copied := builtInProfiles()
	delete(copied, ProfileSensitive)
	if _, ok := BuiltInProfile(ProfileSensitive); !ok {
		t.Fatal("deleting from a builtInProfiles copy changed the built-in table")
	}
	if _, err := NewCustomProfile(ProfileStrict, ProfileStrict, nil, nil); err == nil {
		t.Fatal("a built-in name was accepted as a custom profile name")
	}
	if allocs := testing.AllocsPerRun(100, func() { _, _ = BuiltInProfile(ProfileContent) }); allocs != 0 {
		t.Fatalf("BuiltInProfile allocates %.0f times per call, want 0", allocs)
	}
}
