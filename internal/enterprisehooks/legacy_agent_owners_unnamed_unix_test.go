// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"strconv"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// Review of r104 Q-identity (continuation 2, loop round 3): at the
// upgrade's first pass the NSS lookups of a listed uid failed, both the one
// that names it for the listing and the one that collects its record, so
// the account had no name, the map left it out, and it was recorded closed
// because another account resolved. Once NSS answered again the map could
// not add it, and its 1.0.x agents entry stayed unbound for good; 1.0.3
// matched it. Now the map takes the name the guardian's recent record of the
// uid gives (the account that held it before the upgrade), or the name a
// last lookup gives, as pending; with neither it is not recorded until a
// pass names every listed account. A uid two successive passes find
// unresolved holds no account and is left out.
func TestUnnamedAccountAtUpgradeIsNotLeftOutOfTheMap(t *testing.T) {
	notAnswering := errors.New("sssd: the domain controller did not answer")
	for _, tc := range []struct {
		name string
		// recorded: the guardian holds a recent record of uid 501 naming
		// alice from before the upgrade.
		recorded bool
		// lookup is the last lookup of uid 501 at pass n.
		lookup func(pass int) (unixidentity.Account, error)
		// deferred: passes the map is not recorded at.
		deferred int
		// aliceBound: the map binds alice once NSS answers.
		aliceBound bool
	}{
		{name: "the guardian's record names the account", recorded: true,
			lookup:     func(int) (unixidentity.Account, error) { return unixidentity.Account{}, notAnswering },
			aliceBound: true},
		{name: "the last lookup names the account",
			lookup:     func(int) (unixidentity.Account, error) { return unixidentity.Account{UID: 501, Name: "alice"}, nil },
			aliceBound: true},
		{name: "nothing names the account until NSS answers",
			lookup:   func(int) (unixidentity.Account, error) { return unixidentity.Account{}, notAnswering },
			deferred: 2, aliceBound: true},
		{name: "one not-found answer is not proof",
			lookup: func(pass int) (unixidentity.Account, error) {
				if pass == 1 {
					return unixidentity.Account{}, unixidentity.ErrNotFound
				}
				return unixidentity.Account{}, notAnswering
			},
			deferred: 2, aliceBound: true},
		{name: "the uid holds no account",
			lookup:   func(int) (unixidentity.Account, error) { return unixidentity.Account{}, unixidentity.ErrNotFound },
			deferred: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			homes := map[int]string{501: t.TempDir(), 502: t.TempDir()}
			names := map[int]string{501: "alice", 502: "bob"}
			pass := 0
			nssDown := func() bool { return pass <= 2 } // NSS answers again from pass 3
			previousCollect, previousHome, previousLookup := identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID
			t.Cleanup(func() {
				identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID = previousCollect, previousHome, previousLookup
			})
			identitySpoolAccountHome = func(uid int) string { return homes[uid] }
			identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
				if account.UID == 501 && nssDown() {
					return IdentitySpoolRecord{}, notAnswering
				}
				return IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: names[account.UID], UpdatedAt: now, AccountIncarnation: "files"}, nil
			}
			identitySpoolLookupUID = func(_ context.Context, uid int) (unixidentity.Account, error) {
				if uid == 501 && nssDown() {
					return tc.lookup(pass)
				}
				return unixidentity.Account{UID: uid, Name: names[uid]}, nil
			}
			if tc.recorded {
				before := IdentitySpoolRecord{Key: "501", User: "alice", UpdatedAt: time.Now().UTC().Add(-10 * time.Minute), AccountIncarnation: "files"}
				if err := writeIdentitySpoolFile(dir, "501.json", before, nil); err != nil {
					t.Fatal(err)
				}
			}
			run := func() {
				t.Helper()
				pass++
				alice := IdentitySpoolAccount{UID: 501}
				if !nssDown() {
					alice.User = "alice"
				}
				_ = WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{alice, {UID: 502, User: "bob"}}, nil, nil, nil)
			}
			for range tc.deferred {
				run()
				if LegacyAgentOwnersRecorded(dir) {
					t.Fatalf("pass %d recorded the map while uid 501 had no name", pass)
				}
			}
			for pass < 4 {
				run()
			}
			got, open, ok := ReadLegacyAgentOwners(dir, nil)
			if !ok || got[502].Token != LegacyAgentOwnerToken("files", homes[502]) {
				t.Fatalf("map %+v ok=%t; want bob bound", got, ok)
			}
			if !tc.aliceBound {
				if _, bound := got[501]; bound || open {
					t.Fatalf("a uid that holds no account is in the map: %+v open=%t", got[501], open)
				}
				return
			}
			if got[501].User != "alice" || got[501].Token != LegacyAgentOwnerToken("files", homes[501]) || open {
				t.Fatalf("alice %+v open=%t; want her bound once NSS answers, and the map closed", got[501], open)
			}
		})
	}
}
