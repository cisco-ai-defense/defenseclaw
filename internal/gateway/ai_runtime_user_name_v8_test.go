// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestRuntimeUserNameKeepsFittingNamesAndBaresTheRest pins the normaliser:
// a recorded name that fits the field is kept as it is (alice@realm), a
// DOMAIN\name keeps its account, and nothing that fits neither form reaches
// the builder.
func TestRuntimeUserNameKeepsFittingNamesAndBaresTheRest(t *testing.T) {
	t.Parallel()
	for name, want := range map[string]string{
		"alice":           "alice",
		"alice@realm":     "alice@realm",
		`CORP\alice`:      "alice",
		`DCFC-WINM\dcw-1`: "dcw-1",
		"John Smith":      "",
		`CORP\John Smith`: "",
		"":                "",
	} {
		got, present := runtimeUserName(name).Get()
		if want == "" {
			if present {
				t.Errorf("runtimeUserName(%q) = %q, want absent", name, got)
			}
			continue
		}
		if !present || got != want {
			t.Errorf("runtimeUserName(%q) = %q/%v, want %q", name, got, present, want)
		}
	}
}
