// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build ignore

package main

import (
	"encoding/json"
	"strings"
	"testing"
	"unicode/utf16"
)

func units(value string) []uint16 { return utf16.Encode([]rune(value)) }

func TestClassifierDistinguishesKnownPrivateCaseAndExtendedPrefixes(t *testing.T) {
	private := `C:\fixed-private\home\AppData\Local`
	known := `C:\fixed-known\AppData\Local`
	for _, test := range []struct {
		native               string
		known, knownFold     bool
		private, privateFold bool
		extended             bool
	}{
		{known + `\Packages\fixed-profile_1\AC`, true, true, false, false, false},
		{private + `\Packages\fixed-profile_1\AC`, false, false, true, true, false},
		{strings.ToLower(known) + `\Packages\fixed-profile_1\AC`, false, true, false, false, false},
		{`\\?\` + private + `\Packages\fixed-profile_1\AC`, false, false, true, true, true},
	} {
		r := classify(units(private), units(known), units(test.native))
		if !r.WellFormed || r.KnownExact == nil || *r.KnownExact != test.known ||
			*r.KnownASCIIFold != test.knownFold || *r.PrivateExact != test.private ||
			*r.PrivateASCIIFold != test.privateFold || r.NativeExtended != test.extended ||
			r.NativePackageTailShape == nil || !*r.NativePackageTailShape {
			t.Fatalf("unexpected public classification: %+v", r)
		}
		encoded, err := json.Marshal(r)
		if err != nil || strings.Contains(string(encoded), "fixed-private") || strings.Contains(string(encoded), "fixed-known") ||
			strings.Contains(string(encoded), "fixed-profile") {
			t.Fatal("classification leaked input paths or profile component")
		}
	}
}

func TestMalformedPathsLeaveComparisonsUnknownAndNeverAdmitAnything(t *testing.T) {
	for _, value := range []string{`\\server\share`, `C:\fixed\..\Local`, `C:\fixed\Local:stream`, "C:\\fixed\x00Local", strings.Repeat("x", 2049)} {
		r := classify(units(`C:\fixed\Local`), units(`C:\known\Local`), units(value))
		if r.WellFormed || r.KnownExact != nil || r.PrivateExact != nil || r.NativePackageTailShape != nil {
			t.Fatal("malformed input produced measured comparison facts")
		}
	}
	// Unicode folding is deliberately not Windows object-identity evidence.
	r := classify(units(`C:\fixed\Local`), units(`C:\É\Local`), units(`C:\é\Local\Packages\fixed\AC`))
	if !r.WellFormed || *r.KnownASCIIFold {
		t.Fatal("ASCII diagnostic silently applied Unicode/object case equivalence")
	}
}

func TestOnlyOneFixedSelectorAndSyntheticSIDExist(t *testing.T) {
	if !fixedSelector([]string{"--query-fixed"}) || syntheticSID != "S-1-15-2-1-2-3-4-5-6-7" {
		t.Fatal("fixed read-only contract changed")
	}
	for _, args := range [][]string{nil, {"--query"}, {"--query-fixed", "other"}, {"--query-fixed", "--sid", syntheticSID}} {
		if fixedSelector(args) {
			t.Fatal("arbitrary or ambiguous selector accepted")
		}
	}
}
