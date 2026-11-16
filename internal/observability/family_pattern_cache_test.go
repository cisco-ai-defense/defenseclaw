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

import "testing"

func TestCompileFamilyPatternCompilesOncePerPattern(t *testing.T) {
	first, err := compileFamilyPattern(`^r106-[a-z]+$`)
	if err != nil {
		t.Fatal(err)
	}
	second, err := compileFamilyPattern(`^r106-[a-z]+$`)
	if err != nil || second != first {
		t.Fatalf("second compile = %p, %v; want the cached %p", second, err, first)
	}
	if !second.MatchString("r106-perf") || second.MatchString("r106-Perf") {
		t.Fatal("cached pattern does not match like the source pattern")
	}
	for range 2 {
		if re, err := compileFamilyPattern(`([`); err == nil || re != nil {
			t.Fatalf("invalid pattern = %v, %v; want the compile error every time", re, err)
		}
	}
}

func TestValidateFamilyStringStillAppliesThePattern(t *testing.T) {
	constraints := familyFieldConstraints{pattern: `^[a-z]{2,4}$`, maxUTF8Bytes: 8}
	for value, ok := range map[string]bool{"ab": true, "abcd": true, "a": false, "ABC": false, "abcde": false} {
		for range 2 {
			if err := validateFamilyString(value, constraints); (err == nil) != ok {
				t.Fatalf("validateFamilyString(%q) = %v, want ok=%v", value, err, ok)
			}
		}
	}
}

// BenchmarkValidateFamilyStringPattern is the per-field cost of a patterned
// string field: before r106 it compiled the pattern on every call.
func BenchmarkValidateFamilyStringPattern(b *testing.B) {
	constraints := familyFieldConstraints{pattern: `^[a-z][a-z0-9_.-]{0,63}$`, maxUTF8Bytes: 64}
	b.ReportAllocs()
	for b.Loop() {
		if err := validateFamilyString("defenseclaw.hook", constraints); err != nil {
			b.Fatal(err)
		}
	}
}
