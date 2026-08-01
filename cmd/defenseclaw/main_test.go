// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package main

import "testing"

func TestReleaseCommandNameForPathRecognizesOnlyCLIReleaseName(t *testing.T) {
	for _, test := range []struct {
		path string
		want string
	}{
		{path: "defenseclaw.exe", want: "defenseclaw"},
		{path: "DEFENSECLAW.EXE", want: "defenseclaw"},
		{path: "defenseclaw", want: "defenseclaw"},
		{path: "defenseclaw-gateway.exe"},
		{path: "renamed-by-user.exe"},
	} {
		if got := releaseCommandNameForPath(test.path); got != test.want {
			t.Fatalf("releaseCommandNameForPath(%q) = %q, want %q", test.path, got, test.want)
		}
	}
}
