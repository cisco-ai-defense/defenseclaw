// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"encoding/base64"
	"path/filepath"
	"testing"
)

// The path in a hold tag is shown to the operator, so the tag keeps the
// spelling the copy was written with whatever the platform.
func TestPolicyCopyKeyKeepsTheSpellingOfThePath(t *testing.T) {
	path := filepath.Join(t.TempDir(), "Held", "Shared-Name")
	raw, err := base64.RawURLEncoding.DecodeString(policyCopyKey(path))
	if err != nil {
		t.Fatal(err)
	}
	if string(raw) != filepath.Clean(path) {
		t.Errorf("tag path = %q, want %q", raw, filepath.Clean(path))
	}
}

// Where the file system folds case, two spellings of one folder are one copy
// (a tag written by an earlier build holds the folded spelling); elsewhere
// they are two. A key that is not a tag key matches only itself.
func TestPolicyCopyKeysMatchBySpellingOrFoldedCase(t *testing.T) {
	upper, lower := policyCopyKey(filepath.Join(string(filepath.Separator), "Skills", "Name")), policyCopyKey(filepath.Join(string(filepath.Separator), "skills", "name"))
	other := policyCopyKey(filepath.Join(string(filepath.Separator), "skills", "other"))
	for _, tc := range []struct {
		name string
		a, b string
		fold bool
		want bool
	}{
		{"same spelling", upper, upper, false, true},
		{"folded spelling where case folds", upper, lower, true, true},
		{"other spelling where case matters", upper, lower, false, false},
		{"other copy where case folds", upper, other, true, false},
		{"not a tag key", "not a key!", lower, true, false},
		{"not a tag key twice", "not a key!", "NOT A KEY!", true, false},
	} {
		if got := policyCopyKeysEqual(tc.a, tc.b, tc.fold); got != tc.want {
			t.Errorf("%s: policyCopyKeysEqual = %v, want %v", tc.name, got, tc.want)
		}
	}
}
