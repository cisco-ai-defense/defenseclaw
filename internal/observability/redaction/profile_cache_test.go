// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"crypto/sha256"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/observability"
)

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

// referenceProfileFingerprint is the strings.Builder form profileFingerprint
// had before r106; the fingerprints must stay byte for byte the same.
func referenceProfileFingerprint(profile Profile) [32]byte {
	var builder strings.Builder
	builder.WriteString(string(profile.name))
	builder.WriteByte(0)
	builder.WriteString(string(profile.base))
	for _, mode := range profile.modes {
		builder.WriteByte(0)
		builder.WriteString(string(mode))
	}
	for _, enabled := range profile.groups {
		if enabled {
			builder.WriteByte(1)
		} else {
			builder.WriteByte(0)
		}
	}
	return sha256.Sum256([]byte(builder.String()))
}

func TestProfileFingerprintIsUnchanged(t *testing.T) {
	profiles := BuiltInProfiles()
	custom, err := NewCustomProfile("r106custom", ProfileSensitive,
		[]DetectorGroup{DetectorGroups()[0]}, map[observability.FieldClass]TransformationMode{observability.FieldClassContent: ModeWhole})
	if err != nil {
		t.Fatal(err)
	}
	long := custom
	long.name = ProfileName(strings.Repeat("a", 300))
	for _, profile := range append(profiles, custom, long) {
		if got, want := profileFingerprint(profile), referenceProfileFingerprint(profile); got != want {
			t.Fatalf("fingerprint of %q changed", profile.name)
		}
	}
	builtIn, _ := BuiltInProfile(ProfileStrict)
	if allocs := testing.AllocsPerRun(100, func() { _ = profileFingerprint(builtIn) }); allocs != 0 {
		t.Fatalf("profileFingerprint allocates %.0f times per call, want 0", allocs)
	}
}
