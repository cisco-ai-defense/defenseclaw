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
)

// TestRollbackWindowAccountJoinsTheMigrationMap is GAP-0709: 1.0.4 wrote the
// migration map, the host was rolled back to 1.0.3 within the hour (its
// guardian keeps a young map and rewrites every identity record without the
// account incarnation and the record extension), an account was added there
// with a 1.0.3 agent and its agents entry, and the host was upgraded again.
// The first pass after the upgrade back adds that account to the map, and
// keeps every recorded entry. Without a rollback window, a later account is
// not added (GAP-0503). A macOS record carries no account incarnation, only
// the owner token of its extension (GAP-1787).
func TestRollbackWindowAccountJoinsTheMigrationMap(t *testing.T) {
	for _, tc := range []struct{ name, incarnation string }{
		{"linux record with an account incarnation", "files"},
		{"macOS record with the owner token only", ""},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			homes := map[int]string{501: t.TempDir(), 1006: t.TempDir(), 1007: t.TempDir()}
			stubIdentitySpoolAccounts(t, homes, tc.incarnation, nil)
			alice, bob, carol := IdentitySpoolAccount{UID: 501, User: "alice"}, IdentitySpoolAccount{UID: 1006, User: "bob"}, IdentitySpoolAccount{UID: 1007, User: "carol"}
			first := rollbackTestPass(t, dir, alice)
			if len(first) != 1 || first[501].User != "alice" {
				t.Fatalf("first upgrade map %+v", first)
			}
			writePreMapRecords(t, dir, alice, bob)
			again := rollbackTestPass(t, dir, alice, bob)
			if again[501] != first[501] || again[1006].User != "bob" || again[1006].Token != LegacyAgentOwnerToken(tc.incarnation, homes[1006]) {
				t.Fatalf("map after the upgrade back %+v; want alice kept and bob added", again)
			}
			later := rollbackTestPass(t, dir, alice, bob, carol)
			if _, added := later[1007]; added || len(later) != 2 {
				t.Fatalf("map after a pass with no rollback window %+v; want no later account", later)
			}
		})
	}
}

func stubIdentitySpoolAccounts(t *testing.T, homes map[int]string, incarnation string, failing map[int]bool) {
	t.Helper()
	previousCollect, previousHome := identitySpoolCollect, identitySpoolAccountHome
	t.Cleanup(func() { identitySpoolCollect, identitySpoolAccountHome = previousCollect, previousHome })
	identitySpoolAccountHome = func(uid int) string { return homes[uid] }
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
		if failing[account.UID] {
			return IdentitySpoolRecord{}, errors.New("directory lookup timed out")
		}
		return IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: account.User, UpdatedAt: now, AccountIncarnation: incarnation}, nil
	}
}

// writePreMapRecords writes the records a 1.0.3 guardian writes: no account
// incarnation and no extension.
func writePreMapRecords(t *testing.T, dir string, accounts ...IdentitySpoolAccount) {
	t.Helper()
	for _, account := range accounts {
		key := strconv.Itoa(account.UID)
		if err := writeIdentitySpoolFile(dir, key+".json", IdentitySpoolRecord{Key: key, User: account.User, UpdatedAt: time.Now().UTC()}, nil); err != nil {
			t.Fatal(err)
		}
	}
}

func rollbackTestPass(t *testing.T, dir string, accounts ...IdentitySpoolAccount) map[int]LegacyAgentOwner {
	t.Helper()
	// A failed account's error is the pass's; the map is what is checked.
	_ = WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, nil)
	owners, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok {
		t.Fatal("no migration map")
	}
	return owners
}
