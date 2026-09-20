// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

package sensitivequery

import (
	"strings"
	"testing"
)

func TestClassify(t *testing.T) {
	t.Parallel()
	tests := []struct {
		name      string
		key       string
		sensitive bool
		valid     bool
	}{
		{name: "literal", key: "token", sensitive: true, valid: true},
		{name: "case", key: "X-AmZ-SiGnAtUrE", sensitive: true, valid: true},
		{name: "partial encoding", key: "tok%65n", sensitive: true, valid: true},
		{name: "encoded underscore", key: "api%5Fkey", sensitive: true, valid: true},
		{name: "nested encoding", key: "%2574oken", sensitive: true, valid: true},
		{name: "maximum decode passes", key: "%252574oken", sensitive: true, valid: true},
		{name: "safe", key: "model", sensitive: false, valid: true},
		{name: "malformed", key: "tok%6Zn", sensitive: false, valid: false},
		{name: "c1 control", key: "safe%C2%80", sensitive: false, valid: false},
		{name: "invalid utf8", key: string([]byte{'t', 0xff}), sensitive: false, valid: false},
		{name: "maximum bytes", key: strings.Repeat("a", maxKeyBytes), sensitive: false, valid: true},
		{name: "over maximum bytes", key: strings.Repeat("a", maxKeyBytes+1), sensitive: false, valid: false},
		{name: "encoded separator", key: "safe%26token", sensitive: false, valid: false},
		{name: "excessive nesting", key: "%25252574oken", sensitive: false, valid: false},
	}
	for _, test := range tests {
		test := test
		t.Run(test.name, func(t *testing.T) {
			t.Parallel()
			sensitive, valid := Classify(test.key)
			if sensitive != test.sensitive || valid != test.valid {
				t.Fatalf("Classify(%q) = (%v, %v), want (%v, %v)",
					test.key, sensitive, valid, test.sensitive, test.valid)
			}
		})
	}
}

func TestCanonical(t *testing.T) {
	t.Parallel()
	tests := []struct {
		key   string
		want  string
		valid bool
	}{
		{key: "API_KEY", want: "api_key", valid: true},
		{key: "api%5Fkey", want: "api_key", valid: true},
		{key: "%252574oken", want: "token", valid: true},
		{key: strings.Repeat("a", maxKeyBytes), want: strings.Repeat("a", maxKeyBytes), valid: true},
		{key: "%25252574oken", valid: false},
		{key: "safe%C2%80", valid: false},
	}
	for _, test := range tests {
		got, valid := Canonical(test.key)
		if got != test.want || valid != test.valid {
			t.Fatalf("Canonical(%q) = (%q, %v), want (%q, %v)",
				test.key, got, valid, test.want, test.valid)
		}
	}
}
