//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// GAP-0494: on a host whose SSSD requires fully qualified names, a bare
// exempt_users entry exempts the directory account it names, as the gateway
// exempts its hooks; a bare name NSS answers itself (a local account) keeps
// its exact meaning, and a lookup failure adds nothing.
func TestExemptBareNameSelectsQualifiedDirectoryAccount(t *testing.T) {
	previous := enrollmentQualifiedUserName
	t.Cleanup(func() { enrollmentQualifiedUserName = previous })
	enrollmentQualifiedUserName = func(_ context.Context, r unixidentity.Resolver, name string) string {
		if _, err := r.LookupUser(name + "@dclab.test"); err == nil {
			return name + "@dclab.test"
		}
		return ""
	}
	resolver := &fakeResolver{
		accounts: map[string]unixidentity.Account{
			"ent-alice@dclab.test": {Name: "ent-alice@dclab.test", UID: 94404076},
			"ent-bob@dclab.test":   {Name: "ent-bob@dclab.test", UID: 94404077},
			"ent-carol":            {Name: "ent-carol", UID: 2501}, // local, next to ent-carol@dclab.test
			"ent-carol@dclab.test": {Name: "ent-carol@dclab.test", UID: 94404078},
		},
		transient: map[string]bool{"ent-dave": true},
	}
	set := stringSet([]string{"ent-alice", "ent-carol", "ent-dave", "ent-nobody", "1201", "ent-bob@dclab.test"})
	addQualifiedSpellings(context.Background(), resolver, set)
	for key, want := range map[string]bool{
		"ent-alice@dclab.test": true, "94404076": true, // bare name of a directory-only account
		"ent-carol@dclab.test": false, "94404078": false, // a local account answers the bare name
		"ent-dave@dclab.test": false, "ent-nobody@dclab.test": false,
		"ent-bob@dclab.test": true, "94404077": false, // qualified entries keep their exact meaning
	} {
		if hasKey(set, key) != want {
			t.Errorf("exempt set holds %q = %t, want %t", key, !want, want)
		}
	}
}
