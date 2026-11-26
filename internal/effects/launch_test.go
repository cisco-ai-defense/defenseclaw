// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"slices"
	"testing"
)

// TestLaunchedArgvReadsTheWrapperRows: LaunchedArgv peels the launchers the
// program table's wrapper rows know, as Extract does, and says when the child
// is not certain (rel-1-0-10 GAP-1190).
func TestLaunchedArgvReadsTheWrapperRows(t *testing.T) {
	for _, tc := range []struct {
		argv     []string
		child    []string
		wrappers []string
		known    bool
	}{
		{[]string{"node", "mcp-server.js"}, []string{"node", "mcp-server.js"}, nil, true},
		{[]string{"env", "X=1", "node", "a.js"}, []string{"node", "a.js"}, []string{"env"}, true},
		{[]string{"/usr/bin/env", "node", "a.js"}, []string{"node", "a.js"}, []string{"env"}, true},
		{[]string{"sudo", "-u", "svc", "node", "a.js"}, []string{"node", "a.js"}, []string{"sudo"}, true},
		{[]string{"timeout", "5", "uvx", "x"}, []string{"uvx", "x"}, []string{"timeout"}, true},
		{[]string{"nice", "-n", "5", "nohup", "python3", "-m", "x"}, []string{"python3", "-m", "x"}, []string{"nice", "nohup"}, true},
		{[]string{"setsid", "sh", "-c", "node a.js"}, []string{"sh", "-c", "node a.js"}, []string{"setsid"}, true},
		{[]string{"chroot", "/srv", "node", "a.js"}, []string{"node", "a.js"}, []string{"chroot"}, true},
		{[]string{"sudo", "--some-new-option", "node", "a.js"}, nil, []string{"sudo"}, false},
		{[]string{"nohup", "$RUNNER", "a.js"}, []string{"$RUNNER", "a.js"}, []string{"nohup"}, false},
	} {
		child, wrappers, known := LaunchedArgv(tc.argv, FlavorPOSIX)
		if known != tc.known || !slices.Equal(wrappers, tc.wrappers) || tc.child != nil && !slices.Equal(child, tc.child) {
			t.Errorf("LaunchedArgv(%q) = (%q, %q, %t), want (%q, %q, %t)", tc.argv, child, wrappers, known, tc.child, tc.wrappers, tc.known)
		}
	}
}

func TestModeledProgramReadsTheTable(t *testing.T) {
	for _, tc := range []struct {
		program string
		flavor  Flavor
		want    bool
	}{
		{"cat", FlavorPOSIX, true},
		{"/usr/bin/grep", FlavorPOSIX, true},
		{"vim", FlavorPOSIX, false},
		{"/tmp/x/fake", FlavorPOSIX, false},
		{`C:\Windows\System32\cmd.exe`, FlavorWindows, true},
	} {
		if got := ModeledProgram(tc.program, tc.flavor); got != tc.want {
			t.Errorf("ModeledProgram(%q) = %t, want %t", tc.program, got, tc.want)
		}
	}
}
