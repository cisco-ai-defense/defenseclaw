// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"slices"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// Decision 3 of the 1.0.4 identity design (GAP-0503): the last proven
// profile is keyed by the whole account incarnation, so it never crosses
// incarnations: no macOS account deleted and created again, and no uid or
// name handed to another account, gets the former holder's profile.

// incarnationSubject is a verified subject of uid 501 with facts: a fully proven
// pass, or (upnPending) one whose UPN the guardian has not given yet.
func incarnationSubject(facts useridentity.DirectoryFacts, upnPending bool) profileSubject {
	facts.Assurance, facts.ResolvedAt = useridentity.AssuranceVerified, time.Now()
	subject := profileSubjectFromVerified(VerifiedSubject{UserID: "501", IDKind: useridentity.KindPOSIXUID, UserName: "alice",
		Directory: facts, Source: subjectSourcePeerCredentials}, true)
	subject.upnUnproven = upnPending
	return subject
}

// Review loop 3, finding 2. The last proven profile was kept under a token
// of the directory and domain for an account no SID names (macOS, local and
// LDAP Linux accounts), so an account deleted and created again under the
// same uid, name and domain, in other groups, took the former account's
// group profile and its block message while its UPN was not given yet. A
// token now names the incarnation only when it tells one account from
// another (a SID, a macOS local node record); any other account keeps
// nothing proven. The same incarnation keeps its profile.
func TestLastProvenProfileNeverCrossesAccountIncarnations(t *testing.T) {
	cfg := &config.Config{}
	cfg.Guardrail.Mode = "observe"
	cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
		"former-team": {Mode: "action", BlockAt: "LOW", BlockMessage: "blocked by the former team's policy"},
		"tooling":     {Mode: "action", BlockAt: "HIGH"},
		"watch":       {Mode: "observe"},
	}
	cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
		{Profile: "former-team", Match: config.ProfileMatch{Groups: []string{"former-team"}}},
		{Profile: "tooling", Match: config.ProfileMatch{Users: []string{"alice@corp.example"}}},
	}
	cfg.Guardrail.DefaultProfile = "watch"
	macDirectory := useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory, Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example"}
	macLocal := useridentity.DirectoryFacts{Source: useridentity.SourceMacOSOpenDirectory, Directory: useridentity.DirectoryLocal}
	linuxLocal := useridentity.DirectoryFacts{Source: useridentity.SourceNSSFiles, Directory: useridentity.DirectoryLocal}
	linuxLDAP := useridentity.DirectoryFacts{Source: useridentity.SourceNSSLDAP, Directory: useridentity.DirectoryLDAP, Domain: "corp.example"}
	sssd := useridentity.DirectoryFacts{Source: useridentity.SourceSSSD, Directory: useridentity.DirectoryActiveDirectory, Domain: "corp.example"}
	with := func(facts useridentity.DirectoryFacts, set func(*useridentity.DirectoryFacts)) useridentity.DirectoryFacts {
		set(&facts)
		return facts
	}
	for _, tc := range []struct {
		name              string
		former, recreated useridentity.DirectoryFacts
		sameIncarnation   bool
	}{
		{name: "macOS directory account with no local record", former: macDirectory, recreated: macDirectory},
		{name: "macOS mobile account recreated (another record)",
			former:    with(macDirectory, func(f *useridentity.DirectoryFacts) { f.AccountRecord = "record:aaaa" }),
			recreated: with(macDirectory, func(f *useridentity.DirectoryFacts) { f.AccountRecord = "record:bbbb" })},
		{name: "macOS local account recreated (another record)",
			former:    with(macLocal, func(f *useridentity.DirectoryFacts) { f.AccountRecord = "record:aaaa" }),
			recreated: with(macLocal, func(f *useridentity.DirectoryFacts) { f.AccountRecord = "record:bbbb" })},
		{name: "macOS record known before, none now",
			former: with(macDirectory, func(f *useridentity.DirectoryFacts) { f.AccountRecord = "record:aaaa" }), recreated: macDirectory},
		{name: "Linux local account", former: linuxLocal, recreated: linuxLocal},
		{name: "Linux LDAP account", former: linuxLDAP, recreated: linuxLDAP},
		{name: "SSSD account recreated (another SID)",
			former:    with(sssd, func(f *useridentity.DirectoryFacts) { f.AccountSID = "S-1-5-21-1-2-3-1601" }),
			recreated: with(sssd, func(f *useridentity.DirectoryFacts) { f.AccountSID = "S-1-5-21-1-2-3-1777" })},
		{name: "same macOS record", sameIncarnation: true,
			former:    with(macDirectory, func(f *useridentity.DirectoryFacts) { f.AccountRecord = "record:aaaa" }),
			recreated: with(macDirectory, func(f *useridentity.DirectoryFacts) { f.AccountRecord = "record:aaaa" })},
		{name: "same SSSD SID", sameIncarnation: true,
			former:    with(sssd, func(f *useridentity.DirectoryFacts) { f.AccountSID = "S-1-5-21-1-2-3-1601" }),
			recreated: with(sssd, func(f *useridentity.DirectoryFacts) { f.AccountSID = "S-1-5-21-1-2-3-1601" })},
	} {
		t.Run(tc.name, func(t *testing.T) {
			set, err := newGuardrailProfileSet(cfg, nil, true)
			if err != nil {
				t.Fatal(err)
			}
			former := tc.former
			former.Groups = []string{"former-team", "everyone"}
			before := incarnationSubject(former, false)
			if got := set.match(&before, profileSubjectVerified, "codex", ""); got.Name != "former-team" || got.Match != profileMatchGroup {
				t.Fatalf("former account: %+v; want former-team by group", got)
			}
			recreated := tc.recreated
			recreated.Groups = []string{"everyone"}
			after := incarnationSubject(recreated, true)
			got := set.match(&after, profileSubjectVerified, "codex", "")
			if tc.sameIncarnation {
				if got.Name != "former-team" || !slices.Contains(got.Candidates, "former-team") {
					t.Fatalf("the same incarnation: %+v; want its last proven former-team", got)
				}
				return
			}
			if got.Name != "tooling" || got.Match != profileMatchDefaultLookupFailed || slices.Contains(got.Candidates, "former-team") {
				t.Fatalf("recreated account: %+v; want tooling (the UPN entry that may apply) as default_lookup_failed, never the former account's profile", got)
			}
		})
	}
}

// Review loop 3, finding 2: the store keeps one incarnation per uid or
// SID. Once a pass proves another account holds it (another token, or an
// account no token names), the former one's profile is forgotten; a pass
// that cannot prove the account forgets nothing.
func TestProvenProfileStoreForgetsAFormerHolder(t *testing.T) {
	former := identityIncarnation{Kind: useridentity.KindPOSIXUID, ID: "501", Name: "alice", Token: "record:aaaa"}
	for _, tc := range []struct {
		name   string
		next   identityIncarnation
		proven bool
		kept   bool
	}{
		{"another record", identityIncarnation{Kind: useridentity.KindPOSIXUID, ID: "501", Name: "alice", Token: "record:bbbb"}, true, false},
		{"an account no token names", identityIncarnation{Kind: useridentity.KindPOSIXUID, ID: "501", Name: "alice"}, true, false},
		{"the account is not proven", identityIncarnation{Kind: useridentity.KindPOSIXUID, ID: "501"}, false, true},
		{"another uid", identityIncarnation{Kind: useridentity.KindPOSIXUID, ID: "502", Name: "bob", Token: "record:cccc"}, true, true},
		{"the same incarnation", former, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			var store provenProfileStore
			store.note(former, "former-team")
			if _, ok := store.get(tc.next, tc.proven); ok && tc.next.key() != former.key() {
				t.Fatalf("%+v got the former incarnation's profile", tc.next)
			}
			if _, ok := store.get(former, false); ok != tc.kept {
				t.Fatalf("former incarnation kept %v; want %v", ok, tc.kept)
			}
			// A new holder's own proven profile is kept for it.
			if tc.next.key() != "" {
				store.note(tc.next, "watch")
				if got, ok := store.get(tc.next, true); !ok || got != "watch" {
					t.Fatalf("new holder's profile %q %v; want watch", got, ok)
				}
			}
		})
	}
	var store provenProfileStore
	for i := 0; i < provenProfileStoreMax+10; i++ {
		store.note(identityIncarnation{Kind: useridentity.KindPOSIXUID, ID: strconv.Itoa(100000 + i), Name: "u", Token: "record:" + strconv.Itoa(i)}, "watch")
	}
	if len(store.byKey) > provenProfileStoreMax || len(store.holders) > provenProfileStoreMax || len(store.order) > provenProfileStoreMax {
		t.Fatalf("store holds %d profiles, %d holders, %d order entries; want at most %d", len(store.byKey), len(store.holders), len(store.order), provenProfileStoreMax)
	}
}
