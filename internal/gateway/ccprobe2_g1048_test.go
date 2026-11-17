// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

// s7-probe2 old-API probe for rel-1-0-10:GAP-1048: a find whose -exec program
// copies the handed entry reads the start-point file, so a find -exec copy of
// a developer-token file of the account home is never weaker than the same
// copy alone (action and severity), in all five packs. Hook route through the
// Claude Code hook (gap0437Server / gap0437Hook, present at the pre-fix sha);
// the files come from the credentials-file table (CredentialFileShapeProbePaths,
// also present there). Only the rows whose copy alone names the developer-token
// rule are judged, as in the gap. Scratch, test-only branch.

package gateway

import (
	"fmt"
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

func TestCCP2G1048_FindExecCopyOfDeveloperTokenFileKeepsTheCopyVerdict(t *testing.T) {
	const home = "/home/alice"
	t.Setenv("HOME", home)
	cwd := home + "/proj"
	rank := map[any]int{"allow": 0, "alert": 1, "block": 2}
	severity := map[any]int{"NONE": 0, "": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}
	judged, weaker := 0, 0
	for _, pack := range gap0437Packs {
		server := gap0437Server(t, pack, "claudecode", "action")
		call := 0
		hook := func(command string) map[string]any {
			call++
			return gap0437Hook(t, server, cwd, fmt.Sprintf("ccp2g1048-%s-%d", pack.name, call), command)
		}
		for _, probe := range actionfacts.CredentialFileShapeProbePaths() {
			alone := hook("cp ~/" + probe + " /tmp/n")
			ids, _ := alone["rule_ids"].([]any)
			if rank[alone["action"]] == 0 || !slices.Contains(ids, any("PATH-GIT-CREDS")) {
				continue
			}
			judged++
			got := hook("true; find ~/" + probe + " -exec cp {} /tmp/n \\;")
			t.Logf("%s %s: alone %v %v, find-exec %v %v %v", pack.name, probe, alone["action"], alone["severity"],
				got["action"], got["severity"], got["rule_ids"])
			if rank[got["action"]] < rank[alone["action"]] || severity[got["severity"]] < severity[alone["severity"]] {
				weaker++
				t.Errorf("%s: %s (find-exec copy): %v %v %v, weaker than the copy alone: %v %v %v",
					pack.name, probe, got["action"], got["severity"], got["rule_ids"],
					alone["action"], alone["severity"], ids)
			}
		}
	}
	t.Logf("judged %d developer-token rows, %d weaker", judged, weaker)
	if judged == 0 {
		t.Fatal("no developer-token copy named PATH-GIT-CREDS alone; the probe judged nothing")
	}
}
