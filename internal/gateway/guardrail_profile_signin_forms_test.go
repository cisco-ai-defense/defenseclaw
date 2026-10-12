// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/useridentity"
)

// GAP-0533 (PM-04, PM-12, PM-34): one AD account selects one profile, and
// one exempt_users entry exempts it, whichever form its user signed in
// with. The Windows subject of a DCLAB\ent-bob and of an ENT-BOB@DCLAB.TEST
// sign-in (the account name useridentity.CanonicalNameForID gives each) is
// matched by every spelling of the account, and a local namesake by none of
// the domain spellings (GAP-0305).
func TestWindowsSignInFormsSelectOneProfile(t *testing.T) {
	previous := identityFactsEnabled.Load()
	setIdentityFactsEnabled(true)
	t.Cleanup(func() { setIdentityFactsEnabled(previous) })
	const (
		bobSID   = "S-1-5-21-602989718-809138714-1982218064-4077"
		devsSID  = "S-1-5-21-602989718-809138714-1982218064-4074"
		localSID = "S-1-5-21-9-9-9-1116"
	)
	now := time.Now()
	adFacts := useridentity.DirectoryFacts{
		Directory: useridentity.DirectoryActiveDirectory, Source: useridentity.SourceWindowsLSA,
		Assurance: useridentity.AssuranceVerified, Domain: "dclab.test", AccountDomain: "DCLAB",
		Realm: "DCLAB.TEST", Principal: "ent-bob@dclab.test", Groups: []string{devsSID}, ResolvedAt: now,
	}
	signIns := map[string]VerifiedSubject{
		"DCLAB sign-in": {UserID: bobSID, IDKind: useridentity.KindWindowsSID, UserName: "ent-bob", Directory: adFacts},
		"UPN sign-in":   {UserID: bobSID, IDKind: useridentity.KindWindowsSID, UserName: "ENT-BOB", Directory: adFacts},
	}
	local := profileSubjectFromVerified(VerifiedSubject{UserID: localSID, IDKind: useridentity.KindWindowsSID,
		UserName: "ent-bob", Directory: useridentity.DirectoryFacts{Directory: useridentity.DirectoryLocal,
			Source: useridentity.SourceWindowsLSA, AccountDomain: "WIN2-SBX", ResolvedAt: now}}, true)

	for _, tc := range []struct {
		entry      string
		bob, nsake bool
	}{
		{"ent-bob", true, false},
		{"ENT-BOB", true, false},
		{`DCLAB\ent-bob`, true, false},
		{`dclab\ENT-BOB`, true, false},
		{"ent-bob@dclab.test", true, false},
		{"ENT-BOB@DCLAB.TEST", true, false},
		{bobSID, true, false},
		{`OTHER\ent-bob`, false, false},
		{"ent-nobody", false, false},
		{`.\ent-bob`, false, true},
		{`WIN2-SBX\ent-bob`, false, true},
		{localSID, false, true},
	} {
		for form, verified := range signIns {
			subject := profileSubjectFromVerified(verified, true)
			if got := userEntryMatches(&subject, tc.entry); got != tc.bob {
				t.Errorf("%s: users entry %q selects ent-bob = %t, want %t", form, tc.entry, got, tc.bob)
			}
			if got := requireSandboxAccountListed([]string{tc.entry}, verified); got != tc.bob {
				t.Errorf("%s: exempt_users entry %q exempts ent-bob = %t, want %t", form, tc.entry, got, tc.bob)
			}
		}
		if got := userEntryMatches(&local, tc.entry); got != tc.nsake {
			t.Errorf("users entry %q selects the local namesake = %t, want %t", tc.entry, got, tc.nsake)
		}
	}

	// The NE09 policy: the strict first assignment (user AND group) selects
	// ent-bob on both sign-ins, so the required-agent gate applies to both.
	for _, entry := range []string{"ent-bob", `DCLAB\ent-bob`, "ENT-BOB@DCLAB.TEST"} {
		cfg := &config.Config{}
		cfg.Guardrail.Mode = "action"
		cfg.Guardrail.Profiles = map[string]config.GuardrailProfile{
			"contractors": {Mode: "action"}, "engineering": {Mode: "action"}, "floor": {Mode: "observe"},
		}
		cfg.Guardrail.ProfileAssignments = []config.ProfileAssignment{
			{Profile: "contractors", Match: config.ProfileMatch{Users: []string{entry}, Groups: []string{devsSID}}},
			{Profile: "engineering", Match: config.ProfileMatch{Groups: []string{devsSID}}},
		}
		cfg.Guardrail.DefaultProfile = "floor"
		set, err := newGuardrailProfileSet(cfg, nil, true)
		if err != nil {
			t.Fatal(err)
		}
		for form, verified := range signIns {
			subject := profileSubjectFromVerified(verified, true)
			if got := set.match(&subject, profileSubjectVerified, "claudecode", ""); got.Name != "contractors" || got.Match != profileMatchUser {
				t.Errorf("users %q, %s: %+v, want contractors by user", entry, form, got)
			}
		}
	}
}
