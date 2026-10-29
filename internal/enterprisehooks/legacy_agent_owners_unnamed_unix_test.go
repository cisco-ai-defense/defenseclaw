// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strconv"
	"strings"
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
// matched it. Now the map takes the name the guardian's record of the uid
// gives (the account that held it before the upgrade), or the name a last
// lookup gives, as pending.
//
// Continuation 3, loop round 1: only a record written within the last hour
// counted. Any record of the uid names it now.
//
// Continuation 3, loop round 2: a uid that two passes found not found was
// taken to hold no account, and the map was recorded closed without it, so
// an account SSSD missed twice (offline, or a false miss) lost its 1.0.x
// agents entry for good once SSSD answered again. A uid unnamed at two
// passes, whatever its lookups answer, is now recorded as pending without a
// name, and the map stays open for it. The account that holds it later is
// bound only when its home was created before the map was written: an
// account given the uid after the upgrade is not.
func TestUnnamedAccountAtUpgradeIsNotLeftOutOfTheMap(t *testing.T) {
	if token := LegacyAgentOwnerToken("", t.TempDir()); strings.Count(token, ":") < 3 {
		t.Skipf("the file system of the test directories keeps no creation time (token %q)", token)
	}
	notAnswering := errors.New("sssd: the domain controller did not answer")
	notFound := func(int) (unixidentity.Account, error) { return unixidentity.Account{}, unixidentity.ErrNotFound }
	for _, tc := range []struct {
		name string
		// recorded: the guardian holds a record of uid 501 naming alice
		// from before the upgrade, written recordAge ago (10 minutes when
		// unset).
		recorded  bool
		recordAge time.Duration
		// lookup is the last lookup of uid 501 while NSS does not answer
		// for it, at pass n.
		lookup func(pass int) (unixidentity.Account, error)
		// nssNever: NSS never answers for uid 501 (from pass 3 otherwise).
		nssNever bool
		// later, when set, is the account NSS gives uid 501 once it
		// answers: one created after the upgrade, with a new home.
		later string
		// deferred: passes the map is not recorded at.
		deferred int
		// aliceBound: the map binds alice once NSS answers. Otherwise uid
		// 501 stays pending without a name, and the map open.
		aliceBound bool
	}{
		{name: "the guardian's record names the account", recorded: true,
			lookup:     func(int) (unixidentity.Account, error) { return unixidentity.Account{}, notAnswering },
			aliceBound: true},
		{name: "an old guardian record names the account", recorded: true, recordAge: 3 * time.Hour,
			lookup: notFound, aliceBound: true},
		{name: "the last lookup names the account",
			lookup:     func(int) (unixidentity.Account, error) { return unixidentity.Account{UID: 501, Name: "alice"}, nil },
			aliceBound: true},
		{name: "nothing names the account until NSS answers",
			lookup:   func(int) (unixidentity.Account, error) { return unixidentity.Account{}, notAnswering },
			deferred: 1, aliceBound: true},
		{name: "one not-found answer is not proof",
			lookup: func(pass int) (unixidentity.Account, error) {
				if pass == 1 {
					return unixidentity.Account{}, unixidentity.ErrNotFound
				}
				return unixidentity.Account{}, notAnswering
			},
			deferred: 1, aliceBound: true},
		{name: "two not-found answers are not proof either", lookup: notFound, deferred: 1, aliceBound: true},
		{name: "the uid stays not found", lookup: notFound, nssNever: true, deferred: 1},
		{name: "the lookup never answers", nssNever: true, deferred: 1,
			lookup: func(int) (unixidentity.Account, error) { return unixidentity.Account{}, notAnswering }},
		{name: "the uid is given to an account created again after the upgrade", lookup: notFound, later: "alice", deferred: 1},
		{name: "the uid is given to another account after the upgrade", lookup: notFound, later: "mallory", deferred: 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			homes := map[int]string{501: t.TempDir(), 502: t.TempDir()}
			names := map[int]string{501: "alice", 502: "bob"}
			pass := 0
			nssDown := func() bool { return tc.nssNever || pass <= 2 } // NSS answers again from pass 3
			previousCollect, previousHome, previousLookup := identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID
			t.Cleanup(func() {
				identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID = previousCollect, previousHome, previousLookup
				legacyAgentOwnersUnresolved.set(dir, nil)
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
				age := 10 * time.Minute
				if tc.recordAge > 0 {
					age = tc.recordAge
				}
				before := IdentitySpoolRecord{Key: "501", User: "alice", UpdatedAt: time.Now().UTC().Add(-age), AccountIncarnation: "files"}
				if err := writeIdentitySpoolFile(dir, "501.json", before, nil); err != nil {
					t.Fatal(err)
				}
			}
			run := func() {
				t.Helper()
				pass++
				if pass == 3 && tc.later != "" {
					// The account given uid 501 after the upgrade has a home
					// created after the map.
					time.Sleep(50 * time.Millisecond)
					homes[501], names[501] = filepath.Join(t.TempDir(), tc.later), tc.later
					if err := os.Mkdir(homes[501], 0o700); err != nil {
						t.Fatal(err)
					}
				}
				alice := IdentitySpoolAccount{UID: 501}
				if !nssDown() {
					alice.User = names[501]
				}
				_ = WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{alice, {UID: 502, User: "bob"}}, nil, nil, nil)
			}
			for range tc.deferred {
				run()
				if LegacyAgentOwnersRecorded(dir) {
					t.Fatalf("pass %d recorded the map while uid 501 had no name", pass)
				}
			}
			run()
			if !LegacyAgentOwnersRecorded(dir) {
				t.Fatalf("pass %d did not record the map; an account unnamed at two passes must not hold it back", pass)
			}
			for pass < 4 {
				run()
			}
			got, open, _, ok := ReadLegacyAgentOwners(dir, nil)
			if !ok || got[502].Token != LegacyAgentOwnerToken("files", homes[502]) {
				t.Fatalf("map %+v ok=%t; want bob bound", got, ok)
			}
			if !tc.aliceBound {
				main, _, err := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), nil)
				if _, bound := got[501]; bound || !open || err != nil {
					t.Fatalf("uid 501 is bound: %+v open=%t err=%v; want it pending and the map open", got[501], open, err)
				}
				if user, pending := main.pending[501]; !pending || user != "" {
					t.Fatalf("pending %+v; want uid 501 pending without a name", main.pending)
				}
				return
			}
			if got[501].User != "alice" || got[501].Token != LegacyAgentOwnerToken("files", homes[501]) || open {
				t.Fatalf("alice %+v open=%t; want her bound once NSS answers, and the map closed", got[501], open)
			}
		})
	}
}

// Two listed accounts that no lookup names, one listed from the first pass
// and one from the second, do not hold the map back: each is pending
// without a name by the third pass. Each pass deferred the map for the one
// unnamed the first time, so they took turns holding it back for good.
func TestStaggeredUnnamedAccountsDoNotHoldBackTheMap(t *testing.T) {
	dir := t.TempDir()
	homes := map[int]string{501: t.TempDir(), 502: t.TempDir(), 503: t.TempDir()}
	pass := 0
	unnamed := func(uid int) bool { return uid == 501 || uid == 503 }
	previousCollect, previousHome, previousLookup := identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID
	t.Cleanup(func() {
		identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID = previousCollect, previousHome, previousLookup
		legacyAgentOwnersUnresolved.set(dir, nil)
	})
	identitySpoolAccountHome = func(uid int) string { return homes[uid] }
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
		if unnamed(account.UID) {
			return IdentitySpoolRecord{}, unixidentity.ErrNotFound
		}
		return IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: "user" + strconv.Itoa(account.UID), UpdatedAt: now,
			AccountIncarnation: "files"}, nil
	}
	identitySpoolLookupUID = func(_ context.Context, uid int) (unixidentity.Account, error) {
		if unnamed(uid) {
			return unixidentity.Account{}, unixidentity.ErrNotFound
		}
		return unixidentity.Account{UID: uid, Name: "user" + strconv.Itoa(uid)}, nil
	}
	for pass < 3 {
		pass++
		accounts := []IdentitySpoolAccount{{UID: 501}, {UID: 502, User: "user502"}}
		if pass >= 2 {
			// Listed from the second pass on, with no record and no name.
			accounts = append(accounts, IdentitySpoolAccount{UID: 503})
		}
		_ = WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, nil)
	}
	if !LegacyAgentOwnersRecorded(dir) {
		t.Fatal("three passes did not record the map")
	}
	got, open, _, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok || !open || got[502].User != "user502" {
		t.Fatalf("map %+v open=%t ok=%t; want user502 bound and the map open", got, open, ok)
	}
}
