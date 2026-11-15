// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// TestChainStatementFindingsAreTheUnion (rel-1-0-10:GAP-0951): a list's
// findings are the union of its statements' findings, so its verdict is at
// least the verdict of each statement sent alone. On int/r110-b11d4 a copy of
// a developer-token file of the home alerted (CRITICAL) alone and was allowed
// as soon as any other statement came before or after it, chmod or not: the
// facts of the whole list leave its "~/" operand dynamic (an earlier statement
// may change HOME), and the shell lane read only those facts.
//
// The statements come from the credentials-file table (one probe per row),
// each copied out of the home, in all five packs. A statement whose lone
// verdict is allow decides nothing, so only the others are wrapped.
func TestChainStatementFindingsAreTheUnion(t *testing.T) {
	const home = "/home/alice"
	t.Setenv("HOME", home)
	cwd := home + "/proj"
	rank := map[any]int{"allow": 0, "alert": 1, "block": 2}
	severity := map[any]int{"NONE": 0, "": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	forms := []struct{ name, format string }{
		{"and", "%s && true"},
		{"seq", "%s; true"},
		{"or", "%s || true"},
		{"second", "true && %s"},
		{"chmod", "%s && chmod 644 /tmp/n"},
	}
	judged := 0
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "claudecode", "action")
		call := 0
		hook := func(command string) map[string]any {
			call++
			return gap0437Hook(t, server, cwd, fmt.Sprintf("union-%s-%d", pack.name, call), command)
		}
		for _, probe := range actionfacts.CredentialFileShapeProbePaths() {
			statement := "cp ~/" + probe + " /tmp/n"
			alone := hook(statement)
			if rank[alone["action"]] == 0 {
				continue
			}
			judged++
			aloneIDs, _ := alone["rule_ids"].([]any)
			for _, form := range forms {
				list := fmt.Sprintf(form.format, statement)
				got := hook(list)
				if rank[got["action"]] < rank[alone["action"]] ||
					severity[got["severity"]] < severity[alone["severity"]] {
					t.Errorf("%s: %s (%s): %v %v %v, weaker than the statement alone: %v %v %v",
						pack.name, probe, form.name, got["action"], got["severity"], got["rule_ids"],
						alone["action"], alone["severity"], aloneIDs)
					continue
				}
				gotIDs, _ := got["rule_ids"].([]any)
				if len(gotIDs) >= 8 {
					// The answer names at most eight rules.
					continue
				}
				for _, id := range aloneIDs {
					if !slices.Contains(gotIDs, id) {
						t.Errorf("%s: %s (%s): rule %v of the statement alone is gone: %v",
							pack.name, probe, form.name, id, gotIDs)
					}
				}
			}
		}
	}
	if judged == 0 {
		t.Fatal("no credentials-file copy was judged alone; the table or the packs changed")
	}
}
