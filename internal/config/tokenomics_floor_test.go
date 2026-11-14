// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package config

import (
	"slices"
	"testing"
)

func TestTokenomicsMinVersionKeysInRaw(t *testing.T) {
	cases := []struct {
		name string
		raw  string
		want []string
	}{
		{"empty file", "", nil},
		{"not yaml", "observability: [", nil},
		{"no observability block", "config_version: 9\nguardrail:\n  enabled: true\n", nil},
		{"1.0.9 observability keys only", "observability:\n  destinations:\n    - name: a\n  local:\n    enabled: true\n", nil},
		{"tokenomics at the top level is not the key", "tokenomics:\n  enabled: true\npricing: {}\n", nil},
		{"tokenomics enabled", "observability:\n  tokenomics:\n    enabled: true\n", []string{"observability.tokenomics"}},
		{"explicit zero value", "observability:\n  tokenomics:\n    enabled: false\n", []string{"observability.tokenomics"}},
		{"empty mapping", "observability:\n  pricing: {}\n", []string{"observability.pricing"}},
		{"null value", "observability:\n  pricing:\n", []string{"observability.pricing"}},
		{"both blocks", "observability:\n  pricing:\n    version: \"2026-11-12.1\"\n  tokenomics:\n    enabled: true\n", []string{"observability.tokenomics", "observability.pricing"}},
	}
	for _, tc := range cases {
		t.Run(tc.name, func(t *testing.T) {
			if got := TokenomicsMinVersionKeysInRaw([]byte(tc.raw)); !slices.Equal(got, tc.want) {
				t.Fatalf("keys = %v, want %v", got, tc.want)
			}
		})
	}
}

// The floor of the tokenomics keys is the release that adds them, and it is
// not below the routing floor: a bundle with both blocks signs with one floor.
func TestTokenomicsFloorIsTheRoutingFloor(t *testing.T) {
	if TokenomicsMinProductVersion != RoutingMinProductVersion {
		t.Fatalf("tokenomics floor %s, routing floor %s: both arrive in 1.0.10", TokenomicsMinProductVersion, RoutingMinProductVersion)
	}
}
