// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sandboxauth

import (
	"strings"
	"testing"
)

func TestTokenShapeAndUniqueness(t *testing.T) {
	seen := map[string]bool{}
	for i := 0; i < 64; i++ {
		tok, err := newToken()
		if err != nil || !LooksLikeToken(tok) || !HasTokenPrefix(tok) || seen[tok] {
			t.Fatalf("token %q (%v) has the wrong shape or repeated", tok, err)
		}
		seen[tok] = true
		if id, err := newBindingID(); err != nil || !bindingIDPattern.MatchString(id) {
			t.Fatalf("binding id %q: %v", id, err)
		}
	}
}

func TestHashAndLooksLikeToken(t *testing.T) {
	// printf dcsb_test | shasum -a 256
	const want = "e3a49790fc6fd0819767d9a13a62c3cc498a48676a275f8e2c9bfcbce93d78c6"
	if got := HashToken("dcsb_test"); got != want || !tokenHashPattern.MatchString(got) || HashToken("dcsb_tesT") == want {
		t.Fatalf("HashToken = %q, want the lowercase hex sha256 %q", got, want)
	}
	for s, want := range map[string]bool{
		"":                                 false,
		"dcsb_":                            false,
		"dcsb_" + strings.Repeat("A", 42):  false,
		"dcsb_" + strings.Repeat("A", 43):  true,
		"dcsb_" + strings.Repeat("-", 43):  true,
		"dcsb_" + strings.Repeat("A", 44):  false,
		"dcsb_" + strings.Repeat("+", 43):  false,
		" dcsb_" + strings.Repeat("A", 43): false,
		"DCSB_" + strings.Repeat("A", 43):  false,
		"openshell:resolve:env:KEY":        false,
	} {
		if got := LooksLikeToken(s); got != want {
			t.Errorf("LooksLikeToken(%q) = %v, want %v", s, got, want)
		}
	}
	if !HasTokenPrefix(" dcsb_x") || HasTokenPrefix("xdcsb_") {
		t.Fatal("HasTokenPrefix")
	}
}
