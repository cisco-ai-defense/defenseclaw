// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// The path rules read a Windows path in its slash form. A Windows physical
// path reached through a link is spelled that way too, so a link to a
// protected file matches the rule the protected name matches, and a link to
// an ordinary file matches none.
func TestWindowsPhysicalTargetOfALinkMatchesTheRuleOfItsName(t *testing.T) {
	operand := actionfacts.PathFact{Access: actionfacts.PathAccessWrite, Flavor: actionfacts.PathFlavorWindows}
	rulesOf := func(path string) []string {
		var ids []string
		for _, finding := range ScanAllRules(path, "Write") {
			ids = append(ids, finding.RuleID)
		}
		return ids
	}
	for _, physical := range []string{
		`C:\ProgramData\fx\Users\fixture\.netrc`,
		`\\?\C:\ProgramData\fx\Users\fixture\.netrc`,
	} {
		if ids := rulesOf(physical); slices.Contains(ids, "PATH-NETRC") {
			t.Fatalf("the OS spelling %q already matches; the fixture no longer shows the gap", physical)
		}
		if ids := rulesOf(actionfacts.LinkedPathFact(operand, physical).Resolved); !slices.Contains(ids, "PATH-NETRC") {
			t.Fatalf("link target %q: rules %v lack PATH-NETRC", physical, ids)
		}
	}
	// A drive-rooted link target is placed on the drive of its link, so the
	// physical file is the one the PowerShell history rule names.
	history := `C:\Users\acct\AppData\Roaming\Microsoft\Windows\PowerShell\PSReadLine\ConsoleHost_history.txt`
	if ids := rulesOf(actionfacts.LinkedPathFact(operand, history).Resolved); !slices.Contains(ids, "PATH-WIN-PS-HISTORY") {
		t.Fatalf("link target %q: rules %v lack PATH-WIN-PS-HISTORY", history, ids)
	}
	ordinary := actionfacts.LinkedPathFact(operand, `C:\Users\acct\proj\notes.txt`).Resolved
	if ids := rulesOf(ordinary); len(ids) != 0 {
		t.Fatalf("ordinary project file %q matched %v", ordinary, ids)
	}
}
