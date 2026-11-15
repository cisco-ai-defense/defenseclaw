// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"runtime"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-0744, GAP-0745, GAP-0746 (review s7-syntchk). The shapes are
// built in code from the controls of gap0486Blocked:
//   - C1/C4: the control, then n list statements or n pipeline stages, then
//     a line holding only the closing keyword (the statement read before the
//     error is over the statement budget on its own);
//   - P35: n no-op lines, the control, then the closing keyword;
//   - H1: the closing keyword, then a here-document of 12 lines whose body
//     holds the control as data.
func gap0744Shapes() map[string]func(string) string {
	shapes := map[string]func(string) string{}
	for _, n := range []int{127, 130, 200, 260} {
		shapes[fmt.Sprintf("C1-%03d", n)] = func(s string) string { return s + strings.Repeat("; :", n) + "\nfi" }
		shapes[fmt.Sprintf("C4-%03d", n)] = func(s string) string { return s + strings.Repeat(" | cat", n) + "\nfi" }
	}
	shapes["P35"] = func(s string) string { return strings.Repeat(":\n", 130) + s + "\nfi" }
	return shapes
}

// A control read before the error blocks in every tier, whatever the length
// of the statement it is in (GAP-0744: rel blocks these from the raw text).
func TestGAP0744ReadStatementOverTheBudgetStillBlocks(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	shapes := gap0744Shapes()
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

// A here-document after the error is data: its body lines are not judged as
// commands (GAP-0746), as rel does not judge them.
func TestGAP0746HereDocumentAfterTheErrorIsData(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the fixtures are POSIX shell text")
	}
	for _, p := range gap0437Packs {
		hook := gap0437Server(t, p, "claudecode", "action")
		cwd := t.TempDir()
		for _, id := range []string{"B1", "B3"} {
			body := strings.Repeat("line\n", 11) + gap0486Blocked[id] + "\n"
			command := "fi\ncat <<'EOF'\n" + body + "EOF"
			out := gap0437Hook(t, hook, cwd, p.name+"h1"+id, command)
			if out["action"] == "block" {
				t.Errorf("%s H1-%s: the here-document body was judged as commands: %v", p.name, id, out["rule_ids"])
			}
		}
	}
}
