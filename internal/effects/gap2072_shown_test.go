// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package effects

import "testing"

func TestEffectsShownThroughSubstitutionTransformAndStderr(t *testing.T) {
	const key = "/home/u/.ssh/id_rsa"
	opts := Options{Flavor: FlavorPOSIX, Home: "/home/u", CWD: "/home/u/proj",
		Env: map[string]string{"HOME": "/home/u"}}
	for _, tc := range []struct {
		name, command string
		shown         bool
	}{
		{"plain", "cat " + key, true},
		{"echo substitution", "echo \"$(cat " + key + ")\"", true},
		{"captured variable", "k=$(cat " + key + "); echo \"$k\"", true},
		{"tr transform", "cat " + key + " | tr a a", true},
		{"xxd transform", "cat " + key + " | xxd", true},
		{"stderr", "cat " + key + " >&2", true},
		{"stderr closed", "cat " + key + " 2>/dev/null >&2", false},
		{"stderr then duplicate", "cat " + key + " >&2 2>&1", true},
		{"count pipe", "cat " + key + " | wc -l", false},
		{"count program", "grep -c x " + key, false},
		{"discard", "cat " + key + " > /dev/null", false},
		{"captured count", "echo \"$(wc -l " + key + ")\"", false},
		{"assigned count", "k=$(wc -l " + key + "); echo \"$k\"", false},
		{"reassigned value", "k=$(cat " + key + "); export k=constant; echo \"$k\"", false},
		{"echo ignores pipe", "cat " + key + " | echo constant", false},
		{"printf ignores pipe", "cat " + key + " | printf constant", false},
	} {
		t.Run(tc.name, func(t *testing.T) {
			result := Extract(Call{Surface: SurfaceShell, Command: tc.command}, opts)
			found := false
			for _, e := range result.Effects {
				if e.Kind != KindRead || e.Target.Path != key {
					continue
				}
				found = true
				if e.Shown != tc.shown {
					t.Errorf("read shown=%t, want %t", e.Shown, tc.shown)
				}
			}
			if !found {
				t.Fatal("credential read was not extracted")
			}
		})
	}
}
