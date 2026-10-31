// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"reflect"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// A Windows AD account's own UPN from the domain controller wins over a
// guardian record's identity store UPN, which a rename leaves stale; a
// record's translated UPN, and an own UPN that is only kept, still yield to
// the record (identity-round GAP-1238).
func TestMergeSpoolFactsKeepsTheDirectoryUPNOverAnIdentityStoreRecord(t *testing.T) {
	own := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		UPN: "new@corp.example", Principal: "new@corp.example", Source: useridentity.SourceWindowsLSA}
	stale := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		UPN: "old@corp.example", Principal: "old@corp.example", Source: useridentity.SourceWindowsIdentityStore}
	record := enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105", UPNSource: enterprisehooks.UPNSourceIdentityStore, Facts: stale}
	if merged := mergeSpoolFacts(own, record); merged.UPN != "new@corp.example" || merged.Principal != "new@corp.example" ||
		merged.Source != useridentity.SourceWindowsLSA {
		t.Fatalf("merged = %+v; want the domain controller UPN", merged)
	}
	kept := own
	kept.UPNKept = true
	if merged := mergeSpoolFacts(kept, record); merged.UPN != "old@corp.example" {
		t.Fatalf("merged with a kept own UPN = %+v; want the record's", merged)
	}
	translated := record
	translated.UPNSource = enterprisehooks.UPNSourceTranslateName
	if merged := mergeSpoolFacts(own, translated); merged.UPN != "old@corp.example" {
		t.Fatalf("merged with a translated record = %+v; want the record's", merged)
	}
}

// W19 review (loop round 1): the merge carries a guardian's kept mark with
// the spool's UPN for agent identity rows; every fact profile matching reads
// is what it was without the mark (GAP-0129, GAP-0284).
func TestMergeSpoolFactsCarriesTheKeptMarkOnly(t *testing.T) {
	at := time.Date(2026, 10, 23, 1, 0, 0, 0, time.UTC)
	own := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		UPN: "own@corp.example", Principal: "own@corp.example", Source: useridentity.SourceWindowsLSA}
	facts := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		UPN: "alice@corp.example", Principal: "alice@corp.example", Source: useridentity.SourceWindowsLSA}
	for _, tc := range []struct {
		name             string
		record, verified enterprisehooks.IdentitySpoolRecord
		own              useridentity.DirectoryFacts
		wantUPN          string
		wantKept         bool
	}{
		{"Windows kept",
			enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105", UPNSource: enterprisehooks.UPNSourceTranslateName, UPNKeptSince: at, Facts: facts},
			enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105", UPNSource: enterprisehooks.UPNSourceTranslateName, Facts: facts},
			own, "alice@corp.example", true},
		{"InfoPipe kept",
			enterprisehooks.IdentitySpoolRecord{Key: "70001", UPNSource: enterprisehooks.UPNSourceInfoPipeKept, UPNKeptSince: at, Facts: facts},
			enterprisehooks.IdentitySpoolRecord{Key: "70001", UPNSource: enterprisehooks.UPNSourceInfoPipe, Facts: facts},
			own, "alice@corp.example", true},
		{"verified",
			enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105", UPNSource: enterprisehooks.UPNSourceTranslateName, Facts: facts},
			enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105", UPNSource: enterprisehooks.UPNSourceTranslateName, Facts: facts},
			func() useridentity.DirectoryFacts { f := own; f.UPNKept = true; return f }(), "alice@corp.example", false},
		{"no spool UPN keeps the gateway's own answer and mark",
			enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105", UPNKeptSince: at},
			enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105"},
			func() useridentity.DirectoryFacts { f := own; f.UPNKept = true; return f }(), "own@corp.example", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			merged := mergeSpoolFacts(tc.own, tc.record)
			if merged.UPN != tc.wantUPN || merged.UPNKept != tc.wantKept {
				t.Fatalf("merged UPN %q, kept %t; want %q, kept %t", merged.UPN, merged.UPNKept, tc.wantUPN, tc.wantKept)
			}
			unmarkedOwn := tc.own
			unmarkedOwn.UPNKept = false
			unmarked := mergeSpoolFacts(unmarkedOwn, tc.verified)
			merged.UPNKept = false
			if !reflect.DeepEqual(merged, unmarked) {
				t.Fatalf("merged facts differ beyond the mark:\n%+v\n%+v", merged, unmarked)
			}
		})
	}
}

// A kept UPN still selects the profile its users assignment names, and a
// UPN-only assignment is decided as without the mark (GAP-0129, GAP-0284).
func TestKeptUPNSelectsTheAssignedProfile(t *testing.T) {
	for _, p := range []identityTestPlatform{identityTestPlatforms[0], identityTestPlatforms[2]} {
		t.Run(p.os, func(t *testing.T) {
			for _, kept := range []bool{false, true} {
				subject := profileSubjectFromVerified(VerifiedSubject{UserID: p.id, IDKind: p.kind, UserName: p.name,
					Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
						UPN: "alice@corp.example", Principal: "alice@corp.example", UPNKept: kept, Domain: "corp.example",
						GuardianRecord: true, Groups: []string{p.group}, ResolvedAt: time.Now(),
						Assurance: useridentity.AssuranceVerified},
					Source: subjectSourcePeerCredentials}, true)
				set := identityTestSet(t, p, "watch", config.ProfileAssignment{Profile: "strict",
					Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}})
				if got := set.match(&subject, profileSubjectVerified, "codex", ""); got.Refused != "" || got.Name != "strict" {
					t.Fatalf("kept %t: %+v; want the strict profile", kept, got)
				}
				other := identityTestSet(t, p, "watch", config.ProfileAssignment{Profile: "strict",
					Match: config.ProfileMatch{Users: []string{"bob@corp.example"}}})
				if got := other.match(&subject, profileSubjectVerified, "codex", ""); strings.Contains(got.Refused, "UPN") || got.Name != "watch" {
					t.Fatalf("kept %t, another user's assignment: %+v; want the default profile", kept, got)
				}
			}
		})
	}
}
