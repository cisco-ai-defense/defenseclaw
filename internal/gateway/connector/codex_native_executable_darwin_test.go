// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import "testing"

func TestCodexMacOSArchitectureListContains(t *testing.T) {
	for _, tc := range []struct {
		name     string
		output   string
		expected string
		want     bool
	}{
		{name: "thin arm", output: "arm64\n", expected: "arm64", want: true},
		{name: "thin intel rejected", output: "x86_64\n", expected: "arm64", want: false},
		{name: "universal host slice", output: "x86_64 arm64\n", expected: "arm64", want: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := codexMacOSArchitectureListContains(tc.output, tc.expected); got != tc.want {
				t.Fatalf("codexMacOSArchitectureListContains(%q, %q) = %v, want %v", tc.output, tc.expected, got, tc.want)
			}
		})
	}
}
