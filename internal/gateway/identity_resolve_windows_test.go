// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestWindowsFailedDirectoryLookupUsesDefaultProfile keeps an unavailable LSA
// lookup from selecting a connector-only assignment ahead of the strict default.
func TestWindowsFailedDirectoryLookupUsesDefaultProfile(t *testing.T) {
	previousDir := currentIdentitySpoolDir()
	setIdentitySpoolDir("")
	t.Cleanup(func() { setIdentitySpoolDir(previousDir) })
	sid := "S-1-5-21-4294967294-4294967294-4294967294-4294967294"
	facts, err := resolveWindowsDirectoryFacts(sid, 0)
	if err == nil || !facts.ResolvedAt.IsZero() {
		t.Fatalf("failed SID lookup = %+v, %v; want unresolved facts and an error", facts, err)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: sid, IDKind: useridentity.KindWindowsSID, UserName: "alice", Directory: facts,
	}, true)
	set := &guardrailProfileSet{
		defaultProfile: "strict",
		profiles:       map[string]config.DerivedGuardrailProfile{"strict": {}, "group": {}, "lenient": {}},
		assignments: []config.ProfileAssignment{
			{Profile: "group", Match: config.ProfileMatch{Groups: []string{"CORP\\Members"}}},
			{Profile: "lenient", Match: config.ProfileMatch{Connectors: []string{"codex"}}},
		},
	}
	if got := set.matchUncached(&subject, profileSubjectVerified, "codex", ""); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed {
		t.Fatalf("failed SID lookup selected %+v; want strict default_lookup_failed", got)
	}
}
