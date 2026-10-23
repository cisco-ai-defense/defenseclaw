// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0494 (PM-34): enterprise.enrollment.exempt_users names a hook-socket
// caller in every spelling a users entry selects it by. The SSSD account
// ent-alice@dclab.test (Linux, fully qualified names) and the Open Directory
// AD account ent-alice (macOS) are exempted by the bare name, its case, the
// UPN, DCLAB\ent-alice and the uid; a local namesake only by its own name or
// uid; a name whose domain the facts do not confirm, and a caller whose facts
// are unknown, only by the exact name or uid.
func TestExemptUsersNameFormsPerPlatform(t *testing.T) {
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	now := time.Now()
	sssd := useridentity.DirectoryFacts{Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceSSSD,
		Assurance: useridentity.AssuranceVerified, Domain: "dclab.test", AccountDomain: "DCLAB",
		Realm: "DCLAB.TEST", Principal: "ent-alice@dclab.test", ResolvedAt: now}
	openDirectory := sssd
	openDirectory.Source = useridentity.SourceMacOSOpenDirectory
	facts := map[int]useridentity.DirectoryFacts{
		94404076:   sssd,
		2027364327: openDirectory,
		2500: {Directory: useridentity.DirectoryLocal, Source: useridentity.SourceNSSFiles,
			Assurance: useridentity.AssuranceVerified, ResolvedAt: now},
		// A plain LDAP domain naming an account by an e-mail address (GAP-0596).
		70004: {Directory: useridentity.DirectoryLDAP, Source: useridentity.SourceSSSD, Domain: "ldap.example.org",
			Assurance: useridentity.AssuranceVerified, ResolvedAt: now},
	}
	restore := managedHookExemptFacts
	managedHookExemptFacts = func(uid int, _ bool) (useridentity.DirectoryFacts, bool) { f, ok := facts[uid]; return f, ok }
	t.Cleanup(func() { managedHookExemptFacts = restore })

	linux := managedHookPeer{UID: 94404076, Name: "ent-alice@dclab.test"}
	macos := managedHookPeer{UID: 2027364327, Name: "ent-alice"}
	local := managedHookPeer{UID: 2500, Name: "ent-alice"}
	ldap := managedHookPeer{UID: 70004, Name: "ent-alice@dclab.test"}
	unknown := managedHookPeer{UID: 99999, Name: "ent-alice@dclab.test"}
	for _, tc := range []struct {
		entry                           string
		linux, macos, local, ldap, cold bool
	}{
		{"ent-alice", true, true, true, false, false},
		{"ENT-ALICE", true, true, false, false, false},
		{"ent-alice@dclab.test", true, true, false, true, true},
		{"ENT-ALICE@DCLAB.TEST", true, true, false, false, false},
		{`DCLAB\ent-alice`, true, true, false, false, false},
		{`dclab\ENT-ALICE`, true, true, false, false, false},
		{"94404076", true, false, false, false, false},
		{"2500", false, false, true, false, false},
		{`.\ent-alice`, false, false, true, false, false},
		{"ent-bob", false, false, false, false, false},
		{`OTHER\ent-alice`, false, false, false, false, false},
	} {
		z := &managedHookAuthorizer{enrollment: config.EnterpriseEnrollmentConfig{ExemptUsers: []string{tc.entry}}}
		for _, peer := range []struct {
			name string
			peer managedHookPeer
			want bool
		}{
			{"linux", linux, tc.linux}, {"macos", macos, tc.macos}, {"local namesake", local, tc.local},
			{"unconfirmed LDAP", ldap, tc.ldap}, {"unknown facts", unknown, tc.cold},
		} {
			if got := z.exempt(peer.peer); got != peer.want {
				t.Errorf("exempt_users [%q], %s caller: exempt = %t, want %t", tc.entry, peer.name, got, peer.want)
			}
		}
	}
}
