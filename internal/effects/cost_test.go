// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package effects

import (
	"strings"
	"testing"
	"time"
)

// TestNestedSubstitutionIsBounded guards the hot path against the round-3 DoS:
// deeply nested $( ), <( ), PowerShell $( ) and & { } must stay fast and cannot
// allocate exponentially (review R3-1). Each shape at depth 64 must finish well
// under 50 ms; a 100 KB input likewise.
func TestNestedSubstitutionIsBounded(t *testing.T) {
	nest := func(open, close, mid string, d int) string {
		return strings.Repeat(open, d) + mid + strings.Repeat(close, d)
	}
	cases := []struct {
		name string
		o    Options
		cmd  string
	}{
		{"posix cmdsubst", envOpts, "echo " + nest("$(echo ", ")", "x", 64)},
		{"posix cmdsubst dq", envOpts, "echo " + nest(`"$(echo `, `)"`, "x", 64)},
		{"posix procsubst", envOpts, nest("cat <(", ")", "rm a", 64)},
		{"posix cmdsubst rm", envOpts, nest("$(", ")", "rm a", 64)},
		{"ps subexpr", winPS, "Write-Output " + nest("$(Write-Output ", ")", "x", 64)},
		{"ps scriptblock", winPS, nest("& { ", " }", "Remove-Item a", 64)},
		{"posix depth 200", envOpts, "echo " + nest("$(echo ", ")", "x", 200)},
		{"posix 100kb nested word", envOpts, "cat " + strings.Repeat("a", 100000)},
	}
	for _, c := range cases {
		t.Run(c.name, func(t *testing.T) {
			start := time.Now()
			r := Extract(sh(c.cmd), c.o)
			if d := time.Since(start); d > 50*time.Millisecond {
				t.Fatalf("%s took %v (> 50ms): nested work not bounded", c.name, d)
			}
			_ = r
		})
	}
}
