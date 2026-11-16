// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import "testing"

// The shell hook golden must not depend on the curl of the computer that
// runs it: a hosted runner image moved from curl 8.5.0 to 8.18.0 and every
// case digest changed with it.
func TestHookGoldenDigestIgnoresTheCurlReleaseOnly(t *testing.T) {
	for _, tc := range []struct{ name, in, want string }{
		{"recorded release", "curl/8.5.0", "curl/8.5.0"},
		{"newer release", "curl/8.18.0", "curl/8.5.0"},
		{"older release", "curl/7.81.0", "curl/8.5.0"},
		{"two part release", "curl/8.5", "curl/8.5.0"},
		{"another program", "wget/1.21.4", "wget/1.21.4"},
		{"curl with a suffix", "curl/8.5.0 extra", "curl/8.5.0 extra"},
		{"curl without a release", "curl/", "curl/"},
		{"a changed agent", "defenseclaw-hook/1.0", "defenseclaw-hook/1.0"},
		{"empty", "", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := hookGoldenCurlAgent(tc.in); got != tc.want {
				t.Fatalf("hookGoldenCurlAgent(%q) = %q, want %q", tc.in, got, tc.want)
			}
		})
	}
}
