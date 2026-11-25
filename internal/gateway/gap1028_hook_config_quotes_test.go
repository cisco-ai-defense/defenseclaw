// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import "testing"

// TestGAP1028HookConfigQuoteReplacerIsBuiltOnce: the sandbox hook-config
// guard asks sandboxStatementMayNameHookConfig about every placed statement
// (710 a hook on a long loop of declarations and calls). The answer for a
// plain statement that names no hook file allocates nothing; the quote
// replacer it reads is built once, not per statement (substrate-1 GAP-1028).
func TestGAP1028HookConfigQuoteReplacerIsBuiltOnce(t *testing.T) {
	for _, tc := range []struct {
		statement string
		want      bool
	}{
		{"echo step0 > out.txt", false},
		{"f12x", false},
		{`cat .claude/sett"ings.js"on`, true},
		{`cat .cursor/'hooks'.json`, true},
		{"cat hooks.json", true},
	} {
		if got := sandboxStatementMayNameHookConfig(tc.statement); got != tc.want {
			t.Fatalf("sandboxStatementMayNameHookConfig(%q) = %v, want %v", tc.statement, got, tc.want)
		}
	}
	for _, statement := range []string{"echo step0 > out.txt", "f12x"} {
		if allocs := testing.AllocsPerRun(200, func() { _ = sandboxStatementMayNameHookConfig(statement) }); allocs != 0 {
			t.Fatalf("%q: %.0f allocations a statement, want 0 (a replacer built per statement)", statement, allocs)
		}
	}
}
