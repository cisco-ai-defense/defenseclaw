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

// A guardian record whose UPN an earlier build took from the identity store
// for an AD account gives no UPN: a rename of the AD UPN left it stale. The
// account keeps its own principal and its own domain controller UPN, kept
// or not; a record's translated UPN still wins (identity-round GAP-1238).
func TestMergeSpoolFactsDropsTheIdentityStoreUPNOfAnADAccount(t *testing.T) {
	own := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		Principal: "alice@corp.example", Source: useridentity.SourceWindowsLSA}
	stale := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory,
		UPN: "old@olddomain.example", Principal: "old@olddomain.example", Source: useridentity.SourceWindowsIdentityStore}
	record := enterprisehooks.IdentitySpoolRecord{Key: "S-1-5-21-1-2-3-1105", UPNSource: enterprisehooks.UPNSourceIdentityStore, Facts: stale}
	if merged := mergeSpoolFacts(own, record); merged.UPN != "" || merged.Principal != "alice@corp.example" ||
		merged.Source != useridentity.SourceWindowsLSA {
		t.Fatalf("merged = %+v; want no UPN and the account's own principal", merged)
	}
	answered := own
	answered.UPN, answered.Principal = "new@corp.example", "new@corp.example"
	for _, kept := range []bool{false, true} {
		answered.UPNKept = kept
		if merged := mergeSpoolFacts(answered, record); merged.UPN != "new@corp.example" || merged.Principal != "new@corp.example" {
			t.Fatalf("merged with the own UPN (kept %t) = %+v; want the domain controller UPN", kept, merged)
		}
	}
	translated := record
	translated.UPNSource = enterprisehooks.UPNSourceTranslateName
	translated.Facts.UPN, translated.Facts.Principal = "renamed@corp.example", "renamed@corp.example"
	if merged := mergeSpoolFacts(own, translated); merged.UPN != "renamed@corp.example" {
		t.Fatalf("merged with a translated record = %+v; want the record's", merged)
	}
	entra := enterprisehooks.IdentitySpoolRecord{Key: "S-1-12-1-1-2-3-4", UPNSource: enterprisehooks.UPNSourceIdentityStore,
		Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryEntraID, UPN: "carol@contoso.example",
			Principal: "carol@contoso.example", Source: useridentity.SourceWindowsIdentityStore}}
	if merged := mergeSpoolFacts(useridentity.DirectoryFacts{Directory: useridentity.DirectoryEntraID}, entra); merged.UPN != "carol@contoso.example" {
		t.Fatalf("merged Entra ID record = %+v; want its identity store UPN", merged)
	}
}

// identity-round GAP-1238, the failed managed Windows cell: the gateway's
// own facts of a hybrid AD account carry no UPN (its write-restricted
// service token gets no TranslateNameW answer), and the guardian record
// holds the identity store's stale cloud UPN. A users assignment naming that
// UPN selects nothing; one naming the account's current AD UPN selects its
// profile, through the account's principal and, once the enumerator records
// the domain controller's answer, through that UPN, also after a rename.
func TestStaleIdentityStoreUPNSelectsNoUsersAssignment(t *testing.T) {
	p := identityTestPlatforms[2]
	own := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example",
		Realm: "CORP.EXAMPLE", Principal: "alice@corp.example", AccountDomain: "CORP", Source: useridentity.SourceWindowsLSA,
		Assurance: useridentity.AssuranceVerified, ResolvedAt: time.Now()}
	record := func(source, upn string) enterprisehooks.IdentitySpoolRecord {
		return enterprisehooks.IdentitySpoolRecord{Key: p.id, User: p.name, UpdatedAt: time.Now(), UPNSource: source,
			Facts: useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example",
				UPN: upn, Principal: upn, Groups: []string{p.group}, ResolvedAt: time.Now()}}
	}
	subject := func(r enterprisehooks.IdentitySpoolRecord) profileSubject {
		return profileSubjectFromVerified(VerifiedSubject{UserID: p.id, IDKind: p.kind, UserName: p.name,
			Directory: mergeSpoolFacts(own, r), Source: subjectSourcePeerCredentials}, true)
	}
	users := func(entry string) *guardrailProfileSet {
		return identityTestSet(t, p, "watch", config.ProfileAssignment{Profile: "strict",
			Match: config.ProfileMatch{Users: []string{entry}}})
	}
	for _, tc := range []struct {
		name, entry string
		record      enterprisehooks.IdentitySpoolRecord
		want        string
	}{
		{"stale identity store UPN", "old.alice@olddomain.example", record(enterprisehooks.UPNSourceIdentityStore, "old.alice@olddomain.example"), "watch"},
		{"current AD UPN beside the stale record", "alice@corp.example", record(enterprisehooks.UPNSourceIdentityStore, "old.alice@olddomain.example"), "strict"},
		{"renamed AD UPN the enumerator translated", "new.alice@corp.example", record(enterprisehooks.UPNSourceTranslateName, "new.alice@corp.example"), "strict"},
		{"stale UPN after the enumerator translated", "old.alice@olddomain.example", record(enterprisehooks.UPNSourceTranslateName, "new.alice@corp.example"), "watch"},
	} {
		t.Run(tc.name, func(t *testing.T) {
			s := subject(tc.record)
			if got := users(tc.entry).match(&s, profileSubjectVerified, "codex", ""); got.Refused != "" || got.Name != tc.want {
				t.Fatalf("users %q with UPN %q principal %q: %+v; want %s", tc.entry, s.UPN, s.Principal, got, tc.want)
			}
		})
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
