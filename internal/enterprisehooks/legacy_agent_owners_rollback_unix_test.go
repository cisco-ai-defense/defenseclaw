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

// TestRollbackWindowAccountWhoseLookupFailsJoinsLater is GAP-1788: dave was
// added in the rollback window, and his lookup fails at the first pass
// after the upgrade back, which finds the window. The next pass no longer
// finds it (alice and bob carry the map's facts again), but it still adds
// dave once his lookup answers. After a complete pass a later account is
// not added (GAP-0503).
func TestRollbackWindowAccountWhoseLookupFailsJoinsLater(t *testing.T) {
	dir := t.TempDir()
	homes := map[int]string{501: t.TempDir(), 1006: t.TempDir(), 1008: t.TempDir(), 1009: t.TempDir()}
	failing := map[int]bool{}
	stubIdentitySpoolAccounts(t, homes, "files", failing)
	alice, bob := IdentitySpoolAccount{UID: 501, User: "alice"}, IdentitySpoolAccount{UID: 1006, User: "bob"}
	dave, erin := IdentitySpoolAccount{UID: 1008, User: "dave"}, IdentitySpoolAccount{UID: 1009, User: "erin"}
	rollbackTestPass(t, dir, alice)
	writePreMapRecords(t, dir, alice, bob, dave)
	failing[1008] = true
	if owners := rollbackTestPass(t, dir, alice, bob, dave); owners[1006].User != "bob" {
		t.Fatalf("map after the upgrade back %+v; want bob added", owners)
	} else if _, added := owners[1008]; added {
		t.Fatalf("map after the upgrade back %+v; dave's lookup failed", owners)
	}
	failing[1008] = false
	if owners := rollbackTestPass(t, dir, alice, bob, dave); owners[1008].User != "dave" {
		t.Fatalf("map after the pass that collected dave %+v; want dave added", owners)
	}
	if owners := rollbackTestPass(t, dir, alice, bob, dave, erin); len(owners) != 3 {
		t.Fatalf("map after a complete pass %+v; want no later account", owners)
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

// GAP-1865: on a machine-policy host 1.0.4 wrote no records and so no
// migration map. The account listed only because the gateway served it (a
// peer) may have been created again while the host ran 1.0.4, so it does
// not write the first map at the upgrade to this release and is not bound
// to the uid's 1.0.3 agent identities. An enrolled account still writes it,
// and a peer then joins it only under the rollback rule.
func TestPeerOnlyAccountDoesNotWriteTheFirstMigrationMap(t *testing.T) {
	dir := t.TempDir()
	homes := map[int]string{52100: t.TempDir(), 501: t.TempDir()}
	stubIdentitySpoolAccounts(t, homes, "files", nil)
	peer := IdentitySpoolAccount{UID: 52100, User: "fcuid1", Peer: true}
	for pass := 0; pass < legacyAgentOwnersPassLimit+1; pass++ {
		_ = WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{peer}, nil, nil, nil)
		if LegacyAgentOwnersRecorded(dir) {
			t.Fatalf("pass %d: a peer-only account wrote the first migration map", pass+1)
		}
	}
	owners := rollbackTestPass(t, dir, peer, IdentitySpoolAccount{UID: 501, User: "alice"})
	if _, bound := owners[52100]; bound || owners[501].User != "alice" {
		t.Fatalf("first map %+v; want the enrolled account only", owners)
	}
}

// TestPreTokenHolderJoinsAnExistingMigrationMap is GAP-2085: a 1.0.4
// guardian wrote the migration map at its first pass with the accounts it
// enrolled only (alice). ali held her uid under 1.0.3 and no 1.0.4 gateway
// served it (the homes file marks her a pre-token holder), so she joins
// the existing map at a later pass, and recorded entries keep theirs. A
// served account the homes file does not mark (a Peer) and an account
// enrolled after the map (carol) still do not join it (GAP-1865, GAP-0503).
func TestPreTokenHolderJoinsAnExistingMigrationMap(t *testing.T) {
	dir := t.TempDir()
	homes := map[int]string{501: t.TempDir(), 2201: t.TempDir(), 2202: t.TempDir(), 1007: t.TempDir()}
	stubIdentitySpoolAccounts(t, homes, "files", nil)
	alice := IdentitySpoolAccount{UID: 501, User: "alice"}
	first := rollbackTestPass(t, dir, alice)
	if len(first) != 1 || first[501].User != "alice" {
		t.Fatalf("map the 1.0.4 guardian wrote %+v", first)
	}
	ali := IdentitySpoolAccount{UID: 2201, User: "ali", PreTokenHolder: true}
	peer := IdentitySpoolAccount{UID: 2202, User: "rec", Peer: true}
	carol := IdentitySpoolAccount{UID: 1007, User: "carol"}
	owners := rollbackTestPass(t, dir, alice, ali, peer, carol)
	if owners[501] != first[501] {
		t.Fatalf("map %+v; want alice's entry kept", owners)
	}
	if owners[2201].User != "ali" || owners[2201].Token != LegacyAgentOwnerToken("files", homes[2201]) {
		t.Fatalf("map %+v; want the 1.0.3 holder ali added", owners)
	}
	if _, bound := owners[2202]; bound {
		t.Fatalf("map %+v; a served account the homes file does not mark joined it", owners)
	}
	if _, bound := owners[1007]; bound {
		t.Fatalf("map %+v; an account enrolled after the map joined it", owners)
	}
}
