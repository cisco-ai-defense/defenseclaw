// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

func TestWindowsProfileAssignmentsUseAccountAndGroupSIDs(t *testing.T) {
	const (
		localSID     = "S-1-5-21-1-2-3-2100"
		directorySID = "S-1-5-21-4-5-6-8001"
		localGroup   = "S-1-5-21-1-2-3-3000"
		policyGroup  = "S-1-5-21-4-5-6-5000"
	)
	assignments := []config.ProfileAssignment{
		{Profile: "team", Match: config.ProfileMatch{Groups: []string{`CORP\policy-team`}}},
	}
	set := &guardrailProfileSet{
		defaultProfile: "default", assignments: assignments, matches: newProfileMatchCache(),
		profiles:  map[string]config.DerivedGuardrailProfile{"default": {}, "team": {}},
		groupSIDs: newProfileGroupSIDs(assignments, func(name string) (string, error) { return policyGroup, nil }, time.Second),
	}
	now := time.Now()
	local := profileSubjectFromVerified(VerifiedSubject{UserID: localSID, IDKind: useridentity.KindWindowsSID, UserName: "alex",
		Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal, Source: useridentity.SourceWindowsLSA,
			AccountDomain: "HOST", Groups: []string{localGroup, `HOST\policy-team`}, ResolvedAt: now}}, true)
	directory := profileSubjectFromVerified(VerifiedSubject{UserID: directorySID, IDKind: useridentity.KindWindowsSID, UserName: "alex",
		Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceWindowsLSA,
			AccountDomain: "CORP", Groups: []string{policyGroup}, ResolvedAt: now}}, true)
	if got := set.match(&local, profileSubjectVerified, "codex", ""); got.Name != "default" {
		t.Fatalf("local SID selected directory group assignment: %+v", got)
	}
	if got := set.match(&directory, profileSubjectVerified, "codex", ""); got.Name != "team" {
		t.Fatalf("directory SID missed its group assignment: %+v", got)
	}
	for _, entry := range []string{"alex", `CORP\alex`} {
		if userEntryMatches(&local, entry) || !userEntryMatches(&directory, entry) {
			t.Fatalf("users entry %q did not bind to the directory account SID", entry)
		}
	}
	if !userEntryMatches(&local, localSID) || !userEntryMatches(&directory, directorySID) {
		t.Fatal("SID entries did not select their own accounts")
	}
}
