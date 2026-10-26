// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"strconv"
	"testing"
	"time"
)

// TestRollbackWindowAccountJoinsTheMigrationMap is GAP-0709: 1.0.4 wrote the
// migration map, the host was rolled back to 1.0.3 within the hour (its
// guardian keeps a young map and rewrites every identity record without the
// account incarnation), an account was added there with a 1.0.3 agent and
// its agents entry, and the host was upgraded again. The first pass after
// the upgrade back adds that account to the map, and keeps every recorded
// entry. Without a rollback window, a later account is not added (GAP-0503).
func TestRollbackWindowAccountJoinsTheMigrationMap(t *testing.T) {
	dir := t.TempDir()
	homes := map[int]string{501: t.TempDir(), 1006: t.TempDir(), 1007: t.TempDir()}
	previousCollect, previousHome := identitySpoolCollect, identitySpoolAccountHome
	t.Cleanup(func() { identitySpoolCollect, identitySpoolAccountHome = previousCollect, previousHome })
	identitySpoolAccountHome = func(uid int) string { return homes[uid] }
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
		return IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: account.User, UpdatedAt: now, AccountIncarnation: "files"}, nil
	}
	pass := func(accounts ...IdentitySpoolAccount) map[int]LegacyAgentOwner {
		t.Helper()
		if err := WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, nil); err != nil {
			t.Fatal(err)
		}
		owners, ok := ReadLegacyAgentOwners(dir, nil)
		if !ok {
			t.Fatal("no migration map")
		}
		return owners
	}
	alice, bob, carol := IdentitySpoolAccount{UID: 501, User: "alice"}, IdentitySpoolAccount{UID: 1006, User: "bob"}, IdentitySpoolAccount{UID: 1007, User: "carol"}
	first := pass(alice)
	if len(first) != 1 || first[501].User != "alice" {
		t.Fatalf("first upgrade map %+v", first)
	}
	// The 1.0.3 guardian's passes: records without an account incarnation.
	for _, account := range []IdentitySpoolAccount{alice, bob} {
		key := strconv.Itoa(account.UID)
		if err := writeIdentitySpoolFile(dir, key+".json", IdentitySpoolRecord{Key: key, User: account.User, UpdatedAt: time.Now().UTC()}, nil); err != nil {
			t.Fatal(err)
		}
	}
	again := pass(alice, bob)
	if again[501] != first[501] || again[1006].User != "bob" || again[1006].Token != LegacyAgentOwnerToken("files", homes[1006]) {
		t.Fatalf("map after the upgrade back %+v; want alice kept and bob added", again)
	}
	later := pass(alice, bob, carol)
	if _, added := later[1007]; added || len(later) != 2 {
		t.Fatalf("map after a pass with no rollback window %+v; want no later account", later)
	}
}
