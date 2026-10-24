// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"errors"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
	"golang.org/x/sys/windows"
)

// TestWindowsFailedDirectoryLookupRefusesUnprovenGroups keeps an unavailable
// LSA lookup from selecting a connector-only assignment while an unproven
// group assignment could change the outcome.
func TestWindowsFailedDirectoryLookupRefusesUnprovenGroups(t *testing.T) {
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
	if got := set.matchUncached(&subject, profileSubjectVerified, "codex", ""); got.Name != "strict" || got.Match != profileMatchDefaultLookupFailed ||
		!strings.Contains(got.Refused, "group") {
		t.Fatalf("failed SID lookup selected %+v; want refusal naming the missing group fact, with strict only as candidate", got)
	}
}

// An unmapped SID is a definitive missing account, not an unknown directory error.
func TestResolveWindowsDirectoryFactsUnmappedSID(t *testing.T) {
	sid := "S-1-5-21-4294967294-4294967294-4294967294-4294967294"
	facts, err := resolveWindowsDirectoryFacts(sid, 0)
	if !facts.Empty() || !errors.Is(err, windows.ERROR_NONE_MAPPED) {
		t.Fatalf("unmapped SID = %+v, %v; want ERROR_NONE_MAPPED", facts, err)
	}
}
