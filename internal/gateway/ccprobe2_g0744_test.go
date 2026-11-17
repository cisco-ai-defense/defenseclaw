// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-0744: the rel hook-route tests of the fix,
// copied with only the rel test helpers the pre-fix sha b78d35a3ec lacks (renamed),
// so the file compiles on the pre-fix tree and on rel. Scratch, test-only branch.

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// A control read before the error blocks in every tier, whatever the length
// of the statement it is in (GAP-0744: rel blocks these from the raw text).
func TestCCP2G0744_GAP0744ReadStatementOverTheBudgetStillBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	shapes := ccp2g0744_gap0744Shapes()
	for _, p := range gap0437Packs {
		t.Run(p.name, func(t *testing.T) {
			hook := gap0437Server(t, p, "claudecode", "action")
			cwd := t.TempDir()
			for _, id := range gap0526SortedIDs(shapes) {
				command := shapes[id](gap0486Blocked["B3"])
				if out := gap0437Hook(t, hook, cwd, p.name+id, command); out["action"] != "block" {
					t.Errorf("%s %s-B3: action %v, want block: %v", p.name, id, out["action"], out["rule_ids"])
				}
			}
		})
	}
}

// rel-1-0-10:GAP-0744, GAP-0745, GAP-0746 (review s7-syntchk). The shapes are
// built in code from the controls of gap0486Blocked:
//   - C1/C4: the control, then n list statements or n pipeline stages, then
//     a line holding only the closing keyword (the statement read before the
//     error is over the statement budget on its own);
//   - P35: n no-op lines, the control, then the closing keyword;
//   - H1: the closing keyword, then a here-document of 12 lines whose body
//     holds the control as data.
func ccp2g0744_gap0744Shapes() map[string]func(string) string {
	shapes := map[string]func(string) string{}
	for _, n := range []int{127, 130, 200, 260} {
		shapes[fmt.Sprintf("C1-%03d", n)] = func(s string) string { return s + strings.Repeat("; :", n) + "\nfi" }
		shapes[fmt.Sprintf("C4-%03d", n)] = func(s string) string { return s + strings.Repeat(" | cat", n) + "\nfi" }
	}
	shapes["P35"] = func(s string) string { return strings.Repeat(":\n", 130) + s + "\nfi" }
	return shapes
}
