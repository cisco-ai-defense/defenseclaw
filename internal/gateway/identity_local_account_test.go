// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux || darwin

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A managed Mac's local node account has no UPN. Once any assignment named
// a directory account by UPN or DOMAIN\name, the gateway waited for a UPN
// the guardian could never give it, so the local account's every request
// was refused (default_lookup_failed, upn:unknown) and its sandbox run never
// started (GAP-0532). It resolves by its local facts: the default profile.
// An Active Directory account still waiting for its guardian record keeps
// the refusal.
func TestManagedMacLocalAccountResolvesByLocalFactsWithUPNAssignments(t *testing.T) {
	previousDir := currentIdentitySpoolDir()
	setIdentitySpoolDir(t.TempDir())
	t.Cleanup(func() { setIdentitySpoolDir(previousDir) })
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"strict": {Mode: "action", BlockAt: "low"}, "relaxed": {Mode: "observe"},
	}
	cfg.Guardrail.DefaultProfile = "relaxed"
	for _, entry := range []string{"dcad-r103-eng1@dclab.test", `DCLAB\dcad-r103-eng1`} {
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{
			Profile: "strict", Match: config.ProfileMatch{Users: []string{entry}},
		}}
		set, err := newGuardrailProfileSet(cfg, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		local := profileSubjectFromVerified(VerifiedSubject{
			UserID: "502", IDKind: useridentity.KindPOSIXUID, UserName: "dcm-std2",
			Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal,
				Source: useridentity.SourceMacOSOpenDirectory, Groups: []string{"staff"}, ResolvedAt: time.Now()},
		}, true)
		if got := set.match(&local, profileSubjectVerified, "codex", ""); got.Name != "relaxed" || got.Refused != "" ||
			got.Match != profileMatchDefault || len(got.Unproven) != 0 {
			t.Errorf("%s: local account decision %+v; want the default by its local facts", entry, got)
		}
		pending := profileSubjectFromVerified(VerifiedSubject{
			UserID: "94404136", IDKind: useridentity.KindPOSIXUID, UserName: "dcad-r103-eng2",
			Directory: useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory,
				Groups: []string{"staff"}, ResolvedAt: time.Now()},
		}, true)
		if got := set.match(&pending, profileSubjectVerified, "codex", ""); got.Refused == "" {
			t.Errorf("%s: an account whose directory and UPN await the guardian record was not refused: %+v", entry, got)
		}
	}
}
