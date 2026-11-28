// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package testenv

import (
	"strings"
	"testing"
)

// GAP-1101: a test that needs an administrator token skips with the reason on
// a standard-user token and fails (never skips) where the run must be elevated.
func TestElevationOutcome(t *testing.T) {
	const why = "the writer sets an Administrators owner"
	for _, tc := range []struct {
		name         string
		have, strict bool
		wantAction   string
		wantReason   []string
	}{
		{"administrator runs", true, false, "", nil},
		{"administrator runs when strict", true, true, "", nil},
		{"standard user skips with the reason", false, false, "skip", []string{"administrator token", why}},
		{"strict run without the rights fails", false, true, "fail", []string{"administrator token", RequireElevatedEnv, why}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			action, reason := elevationOutcome(tc.have, tc.strict, why)
			if action != tc.wantAction {
				t.Fatalf("action = %q, want %q", action, tc.wantAction)
			}
			for _, want := range tc.wantReason {
				if !strings.Contains(reason, want) {
					t.Fatalf("reason %q lacks %q", reason, want)
				}
			}
			if tc.wantAction == "" && reason != "" {
				t.Fatalf("a run that proceeds carries reason %q", reason)
			}
		})
	}
}

func TestElevationStrictFollowsTheCIEnvironment(t *testing.T) {
	for _, tc := range []struct {
		name, actions, require string
		want                   bool
	}{
		{"plain", "", "", false},
		{"github actions", "true", "", true},
		{"explicit", "", "1", true},
		{"explicit wrong value", "", "yes", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			t.Setenv("GITHUB_ACTIONS", tc.actions)
			t.Setenv(RequireElevatedEnv, tc.require)
			if got := elevationStrict(); got != tc.want {
				t.Fatalf("elevationStrict() = %v, want %v", got, tc.want)
			}
		})
	}
}
