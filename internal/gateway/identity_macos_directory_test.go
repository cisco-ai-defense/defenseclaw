// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// TestFailedPlatformSSOListingKeepsALocalAccountLocal is GAP-1612: a failed
// or slow AltSecurityIdentities listing made a plain local Mac account
// non-local, so a bare users entry written for its directory namesake
// selected it (GAP-0305 class). It stays local now, and only a UPN entry
// waits for the guardian's record (named, not a silent default).
func TestFailedPlatformSSOListingKeepsALocalAccountLocal(t *testing.T) {
	for _, tc := range []struct {
		localNode bool
		link      platformSSOLink
		directory useridentity.Directory
		pending   bool
	}{
		{true, ssoUnlinked, useridentity.DirectoryLocal, false},
		{true, ssoLinked, "", false},
		{true, ssoLinkUnknown, useridentity.DirectoryLocal, true},
		{false, ssoLinkUnknown, "", false},
	} {
		if directory, pending := macOSOwnDirectory(tc.localNode, tc.link); directory != tc.directory || pending != tc.pending {
			t.Errorf("macOSOwnDirectory(%v, %d) = %q, %v; want %q, %v", tc.localNode, tc.link, directory, pending, tc.directory, tc.pending)
		}
	}
	prevDir := currentIdentitySpoolDir()
	setIdentitySpoolDir(t.TempDir())
	t.Cleanup(func() { setIdentitySpoolDir(prevDir) })
	directory, pending := macOSOwnDirectory(true, ssoLinkUnknown)
	facts := useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory, Directory: directory, UPNPending: pending,
		Groups: []string{"staff"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: "503", IDKind: useridentity.KindPOSIXUID, UserName: "alice", Directory: facts}, true)
	match := func(users string) profileDecision {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "observe"
		cfg.Guardrail.Connector = "codex"
		cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{"relaxed": {Mode: "observe"}, "strict": {Mode: "action"}}
		cfg.Guardrail.DefaultProfile = "relaxed"
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "strict", Match: config.ProfileMatch{Users: []string{users}}}}
		return newGuardrailProfileSetFor(t, cfg).match(&subject, profileSubjectVerified, "codex", "")
	}
	if got := match("alice"); got.Name != "relaxed" || got.Refused != "" {
		t.Errorf("bare users entry for the directory namesake = %+v; want the local account on the default", got)
	}
	if got := match("alice@corp.example"); !strings.Contains(got.Refused, "UPN is unconfirmed") {
		t.Errorf("UPN entry while the link is unknown = %+v; want the UPN fact named", got)
	}
	facts.UPNPending = false
	plain := profileSubjectFromVerified(VerifiedSubject{UserID: "503", IDKind: useridentity.KindPOSIXUID, UserName: "alice", Directory: facts}, true)
	if plain.upnUnproven {
		t.Error("a plain local account waits for a UPN (GAP-0532)")
	}
}
