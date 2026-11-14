// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package psparse

import (
	"strings"
	"testing"
)

// TestDepthGuardIsADiagnostic (rel-1-0-10:GAP-0478): past the depth guard the
// tree is not the script, and the parse says so with one ps_depth_limit
// diagnostic; within the guard there is none.
func TestDepthGuardIsADiagnostic(t *testing.T) {
	blocks := func(layers int) string {
		return strings.Repeat("& { ", layers) + "Get-Date" + strings.Repeat(" }", layers)
	}
	count := func(script *Script) int {
		n := 0
		for _, diagnostic := range script.Diagnostics {
			if diagnostic.Reason == ReasonDepthLimit {
				n++
			}
		}
		return n
	}
	for _, layers := range []int{1, 50, 150} {
		script, _ := Parse(blocks(layers), Options{})
		if len(script.Diagnostics) != 0 || len(script.Statements) != 1 {
			t.Fatalf("%d call blocks: %d diagnostics, %d statements", layers, len(script.Diagnostics), len(script.Statements))
		}
	}
	for _, layers := range []int{250, 1000} {
		script, _ := Parse(blocks(layers), Options{})
		if got := count(script); got != 1 {
			t.Fatalf("%d call blocks: %d depth diagnostics, want 1", layers, got)
		}
	}
	parens := "Write-Output " + strings.Repeat("(", 400) + "1" + strings.Repeat(")", 400)
	if script, _ := Parse(parens, Options{}); count(script) != 1 {
		t.Fatalf("400 nested parentheses: %d depth diagnostics, want 1", count(script))
	}
}
