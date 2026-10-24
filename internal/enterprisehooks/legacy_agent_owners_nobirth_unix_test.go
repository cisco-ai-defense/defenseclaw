// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/unixidentity"
)

// Review of r104 Q-identity (continuation 4, loop round 2): an account no
// lookup and no record named at the upgrade was recorded as pending without
// a name, and a later pass bound the account then holding its uid only when
// its home was created before the map, so on a file system that keeps no
// creation time (NFS, tmpfs, ext3) it never bound, and its 1.0.x agents
// entry stayed unbound for good; 1.0.3 matched it after SSSD recovered. The
// map now records, for such an account, the directories its uid owns under
// the home roots when it is written, and binds the account whose home is
// one of them, the proof a home token gives on such a file system. An
// account given the uid after the upgrade, with another home, is not bound,
// and an account that cannot be bound is logged once, with what keeps its
// entries.
func TestUnnamedAccountBindsWithoutAHomeCreationTime(t *testing.T) {
	unnamedUID := os.Getuid() // the test directories' owner
	if unnamedUID <= 0 {
		t.Skip("needs a non-root test user, who owns the test directories")
	}
	notAnswering := errors.New("sssd: the domain controller did not answer")
	for _, tc := range []struct {
		name string
		// atUpgrade: the account's home is a directory under a home root
		// when the map is written. later: the account NSS gives the uid
		// once it answers was given it after the upgrade, with a new home.
		atUpgrade, later bool
		bound            bool
	}{
		{name: "the home was there at the upgrade", atUpgrade: true, bound: true},
		{name: "the home was not there at the upgrade (an automounted home)", atUpgrade: false},
		{name: "the uid is given to another account after the upgrade", atUpgrade: true, later: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir, root := t.TempDir(), t.TempDir()
			bobHome := t.TempDir() // outside the home root
			aliceHome := filepath.Join(root, "alice")
			if tc.atUpgrade {
				if err := os.Mkdir(aliceHome, 0o700); err != nil {
					t.Fatal(err)
				}
			}
			homes := map[int]string{unnamedUID: aliceHome, unnamedUID + 1: bobHome}
			names := map[int]string{unnamedUID: "alice", unnamedUID + 1: "bob"}
			pass := 0
			nssDown := func() bool { return pass <= 2 }
			var logged []string
			logf := func(format string, args ...any) { logged = append(logged, fmt.Sprintf(format, args...)) }
			previousCollect, previousHome, previousLookup := identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID
			previousRoots, previousIdentity := legacyAgentHomeRoots, homeIdentityOf
			t.Cleanup(func() {
				identitySpoolCollect, identitySpoolAccountHome, identitySpoolLookupUID = previousCollect, previousHome, previousLookup
				legacyAgentHomeRoots, homeIdentityOf = previousRoots, previousIdentity
				legacyAgentOwnersUnresolved.set(dir, nil)
				legacyAgentOwnersClosed.forget(dir)
			})
			// A file system that keeps no creation time.
			homeIdentityOf = func(home string) (homeProof, bool) {
				proof, ok := homeIdentity(home)
				proof.birth, proof.hasBirth = 0, false
				return proof, ok
			}
			legacyAgentHomeRoots = func([]int) []string { return []string{root, filepath.Join(root, "missing")} }
			identitySpoolAccountHome = func(uid int) string {
				if uid == unnamedUID && nssDown() {
					return ""
				}
				return homes[uid]
			}
			identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
				if account.UID == unnamedUID && nssDown() {
					return IdentitySpoolRecord{}, notAnswering
				}
				return IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: names[account.UID], UpdatedAt: now, AccountIncarnation: "files"}, nil
			}
			identitySpoolLookupUID = func(_ context.Context, uid int) (unixidentity.Account, error) {
				if uid == unnamedUID && nssDown() {
					return unixidentity.Account{}, notAnswering
				}
				return unixidentity.Account{UID: uid, Name: names[uid]}, nil
			}
			run := func() {
				t.Helper()
				pass++
				if pass == 3 {
					switch {
					case tc.later:
						// The account given the uid after the upgrade has a new
						// home, not the one the map recorded.
						homes[unnamedUID], names[unnamedUID] = filepath.Join(root, "mallory"), "mallory"
						if err := os.Mkdir(homes[unnamedUID], 0o700); err != nil {
							t.Fatal(err)
						}
					case !tc.atUpgrade:
						// The automounted home is there once the directory answers.
						if err := os.Mkdir(aliceHome, 0o700); err != nil {
							t.Fatal(err)
						}
					}
				}
				alice := IdentitySpoolAccount{UID: unnamedUID}
				if !nssDown() {
					alice.User = names[unnamedUID]
				}
				_ = WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{alice, {UID: unnamedUID + 1, User: "bob"}}, nil, logf, nil)
			}
			for pass < 5 {
				run()
			}
			main, ok, err := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), nil)
			if !ok || err != nil {
				t.Fatalf("map not read: %t %v", ok, err)
			}
			got, open, _, _ := ReadLegacyAgentOwners(dir, nil)
			if got[unnamedUID+1].User != "bob" {
				t.Fatalf("map %+v; want bob bound", got)
			}
			unbound := strings.Count(strings.Join(logged, "\n"), "uid "+strconv.Itoa(unnamedUID)+" had no name at the upgrade")
			if tc.bound {
				if got[unnamedUID].User != "alice" || got[unnamedUID].Token != LegacyAgentOwnerToken("files", aliceHome) || open {
					t.Fatalf("alice %+v open=%t pending %+v homes %+v; want her bound by the home the map recorded, and the map closed",
						got[unnamedUID], open, main.pending, main.pendingHomes)
				}
				if unbound != 0 || len(main.pendingHomes) != 0 {
					t.Fatalf("a bound account was logged unbindable (%d) or kept its recorded homes %+v", unbound, main.pendingHomes)
				}
				return
			}
			if _, bound := got[unnamedUID]; bound || !open {
				t.Fatalf("uid %d is bound: %+v open=%t; want it pending and the map open", unnamedUID, got[unnamedUID], open)
			}
			if user, pending := main.pending[unnamedUID]; !pending || user != "" {
				t.Fatalf("pending %+v; want the uid pending without a name", main.pending)
			}
			if unbound != 1 {
				t.Fatalf("the unbindable account was logged %d times over two passes; want once: %q", unbound, logged)
			}
		})
	}
}

// The homes the map records for an account pending without a name are the
// directories directly under the roots that its uid owns, at most
// maxLegacyAgentPendingHomes, and the reader keeps only well-formed ones
// of an account pending without a name.
func TestUnnamedAccountHomesAreTheDirectoriesItsUIDOwns(t *testing.T) {
	uid := os.Getuid()
	root := t.TempDir()
	for i := range maxLegacyAgentPendingHomes + 2 {
		if err := os.Mkdir(filepath.Join(root, "home"+strconv.Itoa(i)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(root, "file"), nil, 0o600); err != nil {
		t.Fatal(err)
	}
	homes := legacyAgentUnnamedHomes(map[int]bool{uid: true}, []string{root, filepath.Join(root, "missing")})
	if len(homes[uid]) != maxLegacyAgentPendingHomes {
		t.Fatalf("homes %+v; want %d directories of uid %d", homes, maxLegacyAgentPendingHomes, uid)
	}
	if other := legacyAgentUnnamedHomes(map[int]bool{uid + 1: true}, []string{root}); len(other) != 0 {
		t.Fatalf("homes %+v recorded for a uid that owns none", other)
	}
	dir := t.TempDir()
	doc := legacyAgentOwnersDoc{Version: legacyAgentOwnersVersion, WrittenAt: time.Now().UTC(), Owners: map[string]LegacyAgentOwner{},
		Pending: map[string]string{"501": "", "502": "bob"}, Open: true,
		PendingHomes: map[string][]string{"501": {"home:1:2", "sid:S-1-5", "home:1:3:4"}, "502": {"home:1:2"}, "503": {"home:1:2"}}}
	data, err := json.Marshal(doc)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, LegacyAgentOwnersFile), data, 0o600); err != nil {
		t.Fatal(err)
	}
	file, ok, err := readLegacyAgentOwnersFile(filepath.Join(dir, LegacyAgentOwnersFile), nil)
	if !ok || err != nil || len(file.pendingHomes) != 1 || strings.Join(file.pendingHomes[501], ",") != "home:1:2,home:1:3:4" {
		t.Fatalf("read %+v ok=%t err=%v; want only uid 501's home tokens", file.pendingHomes, ok, err)
	}
	if !sameHomeInode("home:1:2", "home:9:2") || !sameHomeInode("home:1:2:5", "home:9:2") || sameHomeInode("home:1:2:5", "home:1:2:6") ||
		sameHomeInode("home:1:2", "home:1:3") || sameHomeInode("sid:S-1", "sid:S-1") {
		t.Fatal("sameHomeInode compares the inode, and the creation time where both have one, on any device")
	}
}

// An account pending without a name, with the most homes the map records,
// each a home token of the longest form, takes less than an owner's entry,
// which bounds every entry of the map (maxLegacyAgentOwnersBytes).
func TestUnnamedAccountEntryIsWithinTheBound(t *testing.T) {
	worst := "home:18446744073709551615:18446744073709551615:" + strconv.FormatInt(math.MinInt64, 10)
	if len(worst) != legacyAgentHomeTokenBytes || len((homeProof{dev: math.MaxUint64, ino: math.MaxUint64, birth: math.MinInt64, hasBirth: true}).token()) != len(worst) {
		t.Fatalf("the longest home token is %d bytes; the bound takes %d", len(worst), legacyAgentHomeTokenBytes)
	}
	size := func(unnamed int) int {
		doc := legacyAgentOwnersDoc{Version: legacyAgentOwnersVersion, WrittenAt: time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC),
			Owners: map[string]LegacyAgentOwner{}, Pending: map[string]string{}, PendingHomes: map[string][]string{}, Open: true, Shards: maxLegacyAgentOwnerShards}
		for i := range unnamed {
			key := strconv.FormatInt(math.MaxInt64-int64(i), 10)
			doc.Pending[key] = ""
			for range maxLegacyAgentPendingHomes {
				doc.PendingHomes[key] = append(doc.PendingHomes[key], worst)
			}
		}
		data, err := json.Marshal(doc)
		if err != nil {
			t.Fatal(err)
		}
		return len(data)
	}
	if one := size(1); one > legacyAgentOwnersHeaderBytes+legacyAgentUnnamedEntryBytes {
		t.Fatalf("a map of one worst unnamed account is %d bytes; the bound allows %d", one, legacyAgentOwnersHeaderBytes+legacyAgentUnnamedEntryBytes)
	}
	if step := size(2) - size(1); step > legacyAgentUnnamedEntryBytes || legacyAgentUnnamedEntryBytes > legacyAgentOwnerEntryBytes {
		t.Fatalf("a worst unnamed account adds %d bytes; the bound allows %d, and an owner's entry %d", step, legacyAgentUnnamedEntryBytes, legacyAgentOwnerEntryBytes)
	}
}
