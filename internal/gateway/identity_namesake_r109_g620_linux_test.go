// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package gateway

import (
	"slices"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// An OSS gateway can prove its process groups while the NSS account holder
// still awaits a root-only directory answer. The default policy tier keeps
// ordinary work on the configured default and reports that uncertainty;
// proven assignments, managed installs and the strict tier keep their rules.
func TestGAP0620UnconfirmedLocalNamesakeUsesOSSDefaultWithWarning(t *testing.T) {
	const localID = "700002"
	assignment := config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{
		Users: []string{"alice@corp.example"},
	}}
	newSet := func(t *testing.T, mode, pack string) *guardrailProfileSet {
		t.Helper()
		set := identityTestSet(t, identityTestPlatforms[0], "watch", assignment)
		set.base.DeploymentMode = mode
		set.base.Guardrail.RulePack = pack
		return set
	}
	local := profileSubjectFromVerified(VerifiedSubject{
		UserID: localID, IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{
			Source: useridentity.SourceProcessCredentials, HolderUnproven: true,
			Groups: []string{"staff"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, Source: subjectSourceProcessOwner,
	}, true)
	for _, pack := range []string{"", "permissive"} {
		set := newSet(t, "", pack)
		got := set.match(&local, profileSubjectProcessOwner, "claudecode", "")
		if got.Name != "watch" || got.Refused != "" || got.Match != profileMatchDefaultLookupFailed ||
			!slices.Equal(got.Unproven, []string{"account:unknown"}) {
			t.Errorf("OSS pack %q: decision = %+v; want warned default", pack, got)
		}
		if warnings := profileExplainWarnings(set, got, &local); !slices.ContainsFunc(warnings, func(note string) bool {
			return strings.Contains(note, "account holder is unconfirmed")
		}) {
			t.Errorf("OSS pack %q: warnings = %q; want holder note", pack, warnings)
		}
	}
	set := newSet(t, "", "")
	inspect := set.selectProfile(&local, resolveIdentity(&local, nil), profileSubjectProcessOwner,
		"claudecode", nil, profilePathInspect, "")
	if inspect.Refused == "" || !slices.Equal(inspect.Unproven, []string{"account:unknown"}) {
		t.Errorf("inspection still needs account proof: %+v", inspect)
	}
	for _, tc := range []struct{ mode, pack string }{
		{"", "strict"}, {managed.DeploymentModeManagedEnterprise, ""},
	} {
		set := newSet(t, tc.mode, tc.pack)
		got := set.match(&local, profileSubjectProcessOwner, "claudecode", "")
		if got.Refused == "" || !slices.Equal(got.Unproven, []string{"account:unknown"}) {
			t.Errorf("mode %q pack %q: decision = %+v; want holder refusal", tc.mode, tc.pack, got)
		}
	}
	provenLocal := profileSubjectFromVerified(VerifiedSubject{
		UserID: localID, IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
			Groups: []string{"staff"}, Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, Source: subjectSourceProcessOwner,
	}, true)
	if got := set.match(&provenLocal, profileSubjectProcessOwner, "claudecode", ""); got.Name != "watch" || got.Refused != "" || got.Match != profileMatchDefault {
		t.Errorf("proven local namesake = %+v; want default", got)
	}
	ad := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700003", IDKind: useridentity.KindPOSIXUID, UserName: "alice@corp.example",
		Directory: useridentity.DirectoryFacts{
			Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceSSSD,
			Principal: "alice@corp.example", UPN: "alice@corp.example", Domain: "corp.example",
			Groups: []string{"domain-users"}, AccountSID: "S-1-5-21-1-2-3-1105",
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now(),
		}, Source: subjectSourcePeerCredentials,
	}, true)
	if got := set.match(&ad, profileSubjectVerified, "claudecode", ""); got.Name != "strict" || got.Refused != "" || got.Match != profileMatchUser {
		t.Errorf("directory namesake = %+v; want its assigned profile", got)
	}
}

func TestReviewG620ProvenConnectorAssignmentKeepsOrdinaryOSSWork(t *testing.T) {
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	for _, selected := range []string{"watch", "tooling"} {
		for _, pack := range []string{"", "permissive", "strict"} {
			set := identityTestSet(t, identityTestPlatforms[0], "watch",
				config.ProfileAssignment{Profile: selected, Match: config.ProfileMatch{Connectors: []string{"claudecode"}}},
				config.ProfileAssignment{Profile: "strict", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}})
			set.base.Guardrail.RulePack = pack
			got := set.match(&subject, profileSubjectProcessOwner, "claudecode", "")
			if pack == "strict" {
				if got.Refused == "" {
					t.Errorf("strict tier with %q assignment allowed uncertain holder: %+v", selected, got)
				}
			} else if got.Refused != "" || got.Name != selected || got.Assignment != 1 ||
				!slices.Equal(got.Unproven, []string{"account:unknown"}) {
				t.Errorf("OSS tier %q with %q assignment did not retain proven profile: %+v", pack, selected, got)
			} else if warnings := profileExplainWarnings(set, got, &subject); !slices.ContainsFunc(warnings, func(note string) bool {
				return strings.Contains(note, "account holder is unconfirmed") && strings.Contains(note, "proven connector assignment")
			}) {
				t.Errorf("OSS tier %q with %q assignment has no holder warning: %q", pack, selected, warnings)
			}
		}
	}
}

func TestReviewG620UnprovenAssignmentMustKeepApprovalControl(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "action"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"base": {Mode: "action", BlockAt: "CRITICAL"},
		"approval": {Mode: "action", BlockAt: "HIGH",
			HILT: &config.HILTConfig{Enabled: true, MinSeverity: "LOW"}},
	}
	cfg.Guardrail.DefaultProfile = "base"
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{{Profile: "approval",
		Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}}}
	set, err := newGuardrailProfileSet(cfg, nil, true)
	if err != nil {
		t.Fatal(err)
	}
	subject := profileSubjectFromVerified(VerifiedSubject{
		UserID: "700002", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: useridentity.DirectoryFacts{Source: useridentity.SourceProcessCredentials,
			HolderUnproven: true, Groups: []string{"staff"},
			Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()},
		Source: subjectSourceProcessOwner,
	}, true)
	if got := set.match(&subject, profileSubjectProcessOwner, "claudecode", ""); got.Refused == "" && got.Name == "base" {
		t.Errorf("uncertain approval profile silently fell to base without HILT: %+v", got)
	}
}
