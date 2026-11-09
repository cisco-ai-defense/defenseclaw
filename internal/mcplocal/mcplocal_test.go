// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package mcplocal

import (
	"strings"
	"testing"
)

// The verdict is a function of the complete definition; a stated class
// decides for a claim whose arguments are a bounded part of the list.
func TestJudgeClassesAndStatedVerdict(t *testing.T) {
	long := func(n int, arg string, tail ...string) []string {
		out := make([]string, n)
		for i := range out {
			out[i] = arg
		}
		return append(out, tail...)
	}
	for _, tc := range []struct {
		name, command, stated, class string
		args                         []string
	}{
		{"interpreter", "python3", "", Launcher, []string{"server.py"}},
		{"path", "/usr/bin/npx", "", Launcher, []string{"-y", "pkg"}},
		{"npx with package", "npx", "", None, []string{"-y", "pkg"}},
		{"uvx with package", "UVX", "", None, []string{"mcp-server-time"}},
		{"execution flag", "npx", "", Arguments, []string{"-y", "pkg", "-c", "x"}},
		{"flag with value", "uvx", "", Arguments, []string{"--eval=1", "pkg"}},
		{"no package", "npx", "", Arguments, []string{"-y"}},
		{"no command", "", "", None, nil},
		{"flag past 32 arguments", "npx", "", Arguments, long(40, "--quiet", "-c", "x")},
		{"package past 32 options", "npx", "", None, long(40, "-y", "pkg")},
		{"stated refusal over carried arguments", "npx", Arguments, Arguments, []string{"-y", "pkg"}},
		{"stated none over carried flag", "npx", None, None, []string{"-c", "x"}},
		{"stated launcher", "python3", Launcher, Launcher, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			class, reason := Judge(tc.command, tc.args, tc.stated)
			if class != tc.class || (class == None) != (reason == "") {
				t.Fatalf("Judge = %q, %q; want class %q (and a reason only for a refusal)", class, reason, tc.class)
			}
			if tc.stated == "" && Class(tc.command, tc.args) != tc.class {
				t.Fatalf("Class = %q, want %q", Class(tc.command, tc.args), tc.class)
			}
			if class != None && !strings.Contains(reason, tc.command) && tc.command != "" {
				t.Fatalf("reason %q does not name the launcher %q", reason, tc.command)
			}
		})
	}
}

// A claim that states no verdict is judged only as far as its first arguments
// prove: a launcher or an execution flag decides whatever follows, a missing
// package does not.
func TestProvenIsWhatTheFirstArgumentsAloneProve(t *testing.T) {
	for _, tc := range []struct {
		name, command, class string
		args                 []string
	}{
		{"interpreter", "python3", Launcher, []string{"server.py"}},
		{"flag among the arguments", "npx", Arguments, []string{"-y", "pkg", "-c", "x"}},
		{"flag with value, any case", "uvx", Arguments, []string{"--EVAL=1"}},
		{"options only, a package may follow", "npx", None, []string{"-y", "--quiet"}},
		{"package", "npx", None, []string{"-y", "pkg"}},
		{"no command", "", None, nil},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if got := Proven(tc.command, tc.args); got != tc.class {
				t.Fatalf("Proven = %q, want %q", got, tc.class)
			}
		})
	}
}
