// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"bytes"
	"context"
	"encoding/json"
	"errors"
	"fmt"
	"math"
	"os"
	"path/filepath"
	"slices"
	"strconv"
	"strings"
	"syscall"
	"testing"
	"time"
)

func TestLegacyAgentOwnerToken(t *testing.T) {
	if got := LegacyAgentOwnerToken("sid:s-1-5-21-1-2-3-1601", "/nowhere"); got != "sid:S-1-5-21-1-2-3-1601" {
		t.Fatalf("SID token %q", got)
	}
	home := t.TempDir()
	a := LegacyAgentOwnerToken("files", home)
	if !strings.HasPrefix(a, "home:") || a != LegacyAgentOwnerToken("sss", home) {
		t.Fatalf("home token %q", a)
	}
	// An account created again gets another home directory.
	if err := os.Remove(home); err != nil {
		t.Fatal(err)
	}
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	if proof, ok := homeIdentity(home); !ok || !proof.hasBirth {
		t.Log("this file system keeps no creation time: a recreated home that takes the freed inode keeps its token")
	} else if b := LegacyAgentOwnerToken("files", home); b == "" || b == a {
		t.Fatalf("recreated home token %q, before %q; want another", b, a)
	}
	for _, home := range []string{"", "relative", filepath.Join(t.TempDir(), "missing")} {
		if got := LegacyAgentOwnerToken("files", home); got != "" {
			t.Fatalf("home %q token %q; want none", home, got)
		}
	}
}

// The migration map is written once and never changed; the gateway reads it
// only when the trust check accepts it.
func TestLegacyAgentOwnersAreWrittenOnce(t *testing.T) {
	dir := t.TempDir()
	first := map[int]LegacyAgentOwner{501: {User: "alice", Token: "home:1:2"}, 94401: {User: "dcad-bob@dclab.test", Token: "sid:S-1-5-21-1-2-3-1"}}
	if written, err := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{}, time.Now(), nil); err != nil || written {
		t.Fatalf("an empty map was written: %v %v", written, err)
	}
	if written, err := WriteLegacyAgentOwners(dir, first, time.Now(), nil); err != nil || !written {
		t.Fatalf("write: %v %v", written, err)
	}
	if written, _ := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{501: {User: "mallory", Token: "home:9:9"}}, time.Now(), nil); written {
		t.Fatal("the map was written twice")
	}
	got, _, _, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok || got[501] != first[501] || got[94401] != first[94401] || len(got) != 2 {
		t.Fatalf("read %+v, %v", got, ok)
	}
	if _, _, _, ok := ReadLegacyAgentOwners(dir, func(string, string) error { return errors.New("not root-owned") }); ok {
		t.Fatal("an untrusted map was read")
	}
}

// The 1.0.2 guardian treats every *.json in the identity spool as a uid.
// An upgrade map must survive 1.0.4 and be invisible after rollback.
func TestLegacyAgentOwnersSurviveRollbackWithoutAStaleIdentityRecord(t *testing.T) {
	dir := t.TempDir()
	owners := map[int]LegacyAgentOwner{501: {User: "alice", Token: "home:1:2"}}
	if written, err := WriteLegacyAgentOwners(dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("write migration map: written=%t err=%v", written, err)
	}
	if _, err := os.Stat(filepath.Join(dir, "legacy-agent-owners.json")); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("1.0.2 sees a non-uid JSON identity record: %v", err)
	}
	if got, _, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
		t.Fatalf("1.0.4 cannot read its migration map after rollback: %+v, %t", got, ok)
	}
	if err := os.Rename(filepath.Join(dir, LegacyAgentOwnersFile), filepath.Join(dir, oldLegacyAgentOwnersFile)); err != nil {
		t.Fatal(err)
	}
	if got, _, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
		t.Fatalf("the gateway lost the earlier map before guardian migration: %+v, %t", got, ok)
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil); err != nil {
		t.Fatalf("upgrade an earlier 1.0.4 spool: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, oldLegacyAgentOwnersFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old map remains visible on rollback: %v", err)
	}
	if got, _, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
		t.Fatalf("migration changed the account binding: %+v, %t", got, ok)
	}
}

func TestCorruptPre104AgentOwnersMapDoesNotStopIdentitySpool(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
		size int64 // a sparse file of this size when data is nil
	}{
		{name: "truncated", data: []byte(`{"v":1,"owners":`)},
		{name: "oversized", size: maxLegacyAgentOwnersBytes + 1},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			oldPath := filepath.Join(dir, oldLegacyAgentOwnersFile)
			if tc.data != nil {
				if err := os.WriteFile(oldPath, tc.data, 0o640); err != nil {
					t.Fatal(err)
				}
			} else if err := os.WriteFile(oldPath, nil, 0o640); err != nil {
				t.Fatal(err)
			} else if err := os.Truncate(oldPath, tc.size); err != nil {
				t.Fatal(err)
			}
			old := time.Now().Add(-2 * IdentitySpoolMaxAge)
			if err := os.Chtimes(oldPath, old, old); err != nil {
				t.Fatal(err)
			}
			previous := identitySpoolCollect
			t.Cleanup(func() { identitySpoolCollect = previous })
			identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
				return IdentitySpoolRecord{Key: "501", User: account.User, UpdatedAt: now}, nil
			}
			var logs []string
			if err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: 501, User: "alice"}}, nil,
				func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }, nil); err != nil {
				t.Fatalf("corrupt pre-1.0.4 map blocked the pass: %v", err)
			}
			if _, err := ReadIdentitySpoolRecord(dir, "501", nil); err != nil {
				t.Fatalf("account record was not refreshed: %v", err)
			}
			if _, err := os.Stat(filepath.Join(dir, oldLegacyAgentOwnersFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("bad map still visible to rollback readers: %v", err)
			}
			bad, err := filepath.Glob(filepath.Join(dir, "legacy-agent-owners-corrupt-*.bad"))
			if err != nil || len(bad) != 1 {
				t.Fatalf("quarantined map was removed during this pass: paths=%v err=%v", bad, err)
			}
			if tc.data == nil {
				if info, err := os.Stat(bad[0]); err != nil || info.Size() != tc.size {
					t.Fatalf("quarantine lost the original map: %v", err)
				}
			} else if contents, err := os.ReadFile(bad[0]); err != nil || !bytes.Equal(contents, tc.data) {
				t.Fatalf("quarantine lost the original map: size=%d err=%v", len(contents), err)
			}
			if len(logs) == 0 || !strings.Contains(strings.Join(logs, "\n"), "invalid previous agent identity migration map") {
				t.Fatalf("bad map not explained: %v", logs)
			}
		})
	}
}

func TestTransientLegacyAgentOwnersReadErrorKeepsValidMap(t *testing.T) {
	dir := t.TempDir()
	owners := map[int]LegacyAgentOwner{501: {User: "alice", Token: "home:1:2"}}
	if written, err := WriteLegacyAgentOwners(dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("write migration map: written=%t err=%v", written, err)
	}
	oldPath := filepath.Join(dir, oldLegacyAgentOwnersFile)
	if err := os.Rename(filepath.Join(dir, LegacyAgentOwnersFile), oldPath); err != nil {
		t.Fatal(err)
	}
	previousOpen := legacyAgentOwnersOpen
	t.Cleanup(func() { legacyAgentOwnersOpen = previousOpen })
	legacyAgentOwnersOpen = func(path string) (*os.File, error) {
		if path == oldPath {
			return nil, syscall.EMFILE
		}
		return previousOpen(path)
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil); !errors.Is(err, syscall.EMFILE) {
		t.Fatalf("transient open error did not stop migration: %v", err)
	}
	if _, err := os.Stat(oldPath); err != nil {
		t.Fatalf("valid map moved on an I/O error: %v", err)
	}
	if bad, _ := filepath.Glob(filepath.Join(dir, "legacy-agent-owners-corrupt-*.bad")); len(bad) != 0 {
		t.Fatalf("valid map was quarantined: %v", bad)
	}
	legacyAgentOwnersOpen = previousOpen
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil); err != nil {
		t.Fatalf("retry migration: %v", err)
	}
	if got, _, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
		t.Fatalf("retry changed the binding: %+v, ok=%t", got, ok)
	}
}

// The guardian records the map at its first pass that collected every
// account, from what it collected, and keeps it through every later pass's
// cleanup.
func TestIdentitySpoolPassRecordsTheMigrationMap(t *testing.T) {
	dir := t.TempDir()
	home := t.TempDir()
	previousCollect, previousHome := identitySpoolCollect, identitySpoolAccountHome
	t.Cleanup(func() { identitySpoolCollect, identitySpoolAccountHome = previousCollect, previousHome })
	identitySpoolAccountHome = func(int) string { return home }
	identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
		return IdentitySpoolRecord{Key: "501", User: account.User, UpdatedAt: now, AccountIncarnation: "files"}, nil
	}
	if err := WriteIdentitySpool(context.Background(), dir, []IdentitySpoolAccount{{UID: 501, User: "alice"}}, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	owners, _, _, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok || owners[501].User != "alice" || owners[501].Token != LegacyAgentOwnerToken("files", home) {
		t.Fatalf("map %+v, %v", owners, ok)
	}
	path := filepath.Join(dir, LegacyAgentOwnersFile)
	old := time.Now().Add(-2 * IdentitySpoolMaxAge)
	if err := os.Chtimes(path, old, old); err != nil {
		t.Fatal(err)
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Stat(path); err != nil {
		t.Fatalf("a later pass removed the migration map: %v", err)
	}
}

// largeLegacyAgentOwners is the migration map of a large directory-joined
// host: n accounts with qualified names and SIDs as SSSD gives them. At
// n = maxLegacyAgentOwners it serializes to well over 4 MiB.
func largeLegacyAgentOwners(n int) map[int]LegacyAgentOwner {
	owners := make(map[int]LegacyAgentOwner, n)
	for i := range n {
		owners[1_900_000_000+i] = LegacyAgentOwner{
			User:  fmt.Sprintf("dcad-user-%05d@corp.dclab.example.com", i),
			Token: fmt.Sprintf("sid:S-1-5-21-1004336348-1177238915-682003330-%d", 100000+i),
		}
	}
	return owners
}

func sameLegacyAgentOwners(t *testing.T, got, want map[int]LegacyAgentOwner) {
	t.Helper()
	if len(got) != len(want) {
		t.Fatalf("map holds %d owners; want %d", len(got), len(want))
	}
	for uid, owner := range want {
		if got[uid] != owner {
			t.Fatalf("uid %d: %+v; want %+v", uid, got[uid], owner)
		}
	}
}

// A large 1.0.x upgrade: the map of maxLegacyAgentOwners accounts that the
// guardian writes, over 4 MiB, is the map the gateway reads. The guardian
// writes the map once, so a map the reader refused would leave every legacy
// agents entry unbound for good.
func TestLegacyAgentOwnersMapOver4MiBIsRead(t *testing.T) {
	dir := t.TempDir()
	owners := largeLegacyAgentOwners(maxLegacyAgentOwners)
	if written, err := WriteLegacyAgentOwners(dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("write: written=%t err=%v", written, err)
	}
	info, err := os.Stat(filepath.Join(dir, LegacyAgentOwnersFile))
	if err != nil || info.Size() <= 4<<20 {
		t.Fatalf("map stat %v; want a map over 4 MiB", err)
	}
	got, _, _, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok {
		t.Fatalf("the reader refused the %d-byte map the guardian wrote", info.Size())
	}
	sameLegacyAgentOwners(t, got, owners)
}

// Maps over 4 MiB that an earlier 1.0.4 build already published, under the
// current name or the pre-1.0.4 one, keep their bindings: the guardian's
// next pass neither quarantines nor replaces them, and the gateway reads
// them.
func TestExistingLegacyAgentOwnersMapOver4MiBKeepsBindings(t *testing.T) {
	owners := largeLegacyAgentOwners(maxLegacyAgentOwners)
	doc := legacyAgentOwnersDoc{Version: legacyAgentOwnersVersion, WrittenAt: time.Now().UTC(), Owners: map[string]LegacyAgentOwner{}}
	for uid, owner := range owners {
		doc.Owners[strconv.Itoa(uid)] = owner
	}
	data, err := json.Marshal(doc)
	if err != nil || len(data) <= 4<<20 {
		t.Fatalf("map of %d bytes (%v); want over 4 MiB", len(data), err)
	}
	for _, name := range []string{LegacyAgentOwnersFile, oldLegacyAgentOwnersFile} {
		t.Run(name, func(t *testing.T) {
			dir := t.TempDir()
			if err := os.WriteFile(filepath.Join(dir, name), data, 0o640); err != nil {
				t.Fatal(err)
			}
			var logs []string
			if err := WriteIdentitySpool(context.Background(), dir, nil, nil,
				func(format string, args ...any) { logs = append(logs, fmt.Sprintf(format, args...)) }, nil); err != nil {
				t.Fatalf("pass: %v", err)
			}
			if bad, _ := filepath.Glob(filepath.Join(dir, "legacy-agent-owners-corrupt-*.bad")); len(bad) != 0 {
				t.Fatalf("a valid map was quarantined: %v (logs %v)", bad, logs)
			}
			if _, err := os.Stat(filepath.Join(dir, oldLegacyAgentOwnersFile)); !errors.Is(err, os.ErrNotExist) {
				t.Fatalf("map still under the rollback-unsafe name: %v", err)
			}
			if written, err := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{501: {User: "mallory", Token: "home:9:9"}}, time.Now(), nil); err != nil || written {
				t.Fatalf("existing map replaced: written=%t err=%v", written, err)
			}
			if contents, err := os.ReadFile(filepath.Join(dir, LegacyAgentOwnersFile)); err != nil || !bytes.Equal(contents, data) {
				t.Fatalf("published map changed: %d bytes, err %v", len(contents), err)
			}
			got, _, _, ok := ReadLegacyAgentOwners(dir, nil)
			if !ok {
				t.Fatal("the reader refused the published map")
			}
			sameLegacyAgentOwners(t, got, owners)
		})
	}
}

// The reader's bound is the largest file of the map WriteLegacyAgentOwners
// can write: the longest time, the open mark, the most shards, and entries
// with the longest uid, user and token, every byte of which json.Marshal
// spells in six. A pending entry is shorter than an owner's. Such a map,
// once written, is read.
func TestLegacyAgentOwnersBoundIsTheLargestWritableMap(t *testing.T) {
	for _, owner := range []LegacyAgentOwner{
		{User: strings.Repeat("<", maxLegacyAgentOwnerField), Token: strings.Repeat("&", maxLegacyAgentOwnerField)},
		{User: strings.Repeat(">", maxLegacyAgentOwnerField), Token: strings.Repeat("<", maxLegacyAgentOwnerField)},
	} {
		if !validLegacyAgentOwner(owner) {
			t.Fatalf("the writer refuses the worst-case owner %q", owner.User[:1])
		}
		at := time.Date(9999, 12, 31, 23, 59, 59, 999999999, time.UTC)
		size := func(n, pending int) int {
			t.Helper()
			doc := legacyAgentOwnersDoc{Version: legacyAgentOwnersVersion, WrittenAt: at, Owners: map[string]LegacyAgentOwner{},
				Pending: map[string]string{}, Open: true, Shards: maxLegacyAgentOwnerShards}
			for i := range n {
				doc.Owners[strconv.FormatInt(math.MaxInt64-int64(i), 10)] = owner
			}
			for i := range pending {
				doc.Pending[strconv.FormatInt(math.MaxInt64-int64(n+i), 10)] = owner.User
			}
			data, err := json.Marshal(doc)
			if err != nil {
				t.Fatal(err)
			}
			return len(data)
		}
		if one := size(1, 1); one != legacyAgentOwnersHeaderBytes+legacyAgentOwnerEntryBytes-1+legacyAgentPendingEntryBytes-1 {
			t.Fatalf("worst one-owner, one-pending map is %d bytes; the bound allows %d", one,
				legacyAgentOwnersHeaderBytes+legacyAgentOwnerEntryBytes-1+legacyAgentPendingEntryBytes-1)
		}
		if step := size(2, 1) - size(1, 1); step != legacyAgentOwnerEntryBytes {
			t.Fatalf("worst owner adds %d bytes; the bound allows %d", step, legacyAgentOwnerEntryBytes)
		}
		if step := size(1, 2) - size(1, 1); step != legacyAgentPendingEntryBytes || step > legacyAgentOwnerEntryBytes {
			t.Fatalf("worst pending account adds %d bytes; the bound allows %d", step, legacyAgentPendingEntryBytes)
		}
		dir := t.TempDir()
		if written, err := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{math.MaxInt: owner}, at, nil); err != nil || !written {
			t.Fatalf("write: written=%t err=%v", written, err)
		}
		if got, _, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[math.MaxInt] != owner {
			t.Fatalf("worst-case map not read back: %t", ok)
		}
	}
	if maxLegacyAgentOwnersBytes != int64(legacyAgentOwnersHeaderBytes+maxLegacyAgentOwners*legacyAgentOwnerEntryBytes) {
		t.Fatal("the reader's bound is not maxLegacyAgentOwners worst-case owners")
	}
}

// Review of r104 Q-identity (continuation 2, loop round 2): past
// maxLegacyAgentOwners accounts, Go's map order picked which owners the map
// dropped, and it was written once, so those accounts' 1.0.x agents entries
// were refused for good. Every owner is now written, the rest in shards the
// main file counts, and a map missing a shard binds nobody until it is whole.
func TestLegacyAgentOwnersMapKeepsEveryOwnerPastOneFile(t *testing.T) {
	dir := t.TempDir()
	owners := make(map[int]LegacyAgentOwner, 2*maxLegacyAgentOwners+5)
	for i := range 2*maxLegacyAgentOwners + 5 {
		owners[10_000+i] = LegacyAgentOwner{User: fmt.Sprintf("user%d", i), Token: fmt.Sprintf("home:1:%d", 10_000+i)}
	}
	if written, err := WriteLegacyAgentOwners(dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("write: written=%t err=%v", written, err)
	}
	got, open, _, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok || open {
		t.Fatalf("read: ok=%t open=%t", ok, open)
	}
	sameLegacyAgentOwners(t, got, owners)
	for _, name := range []string{LegacyAgentOwnersFile, legacyAgentOwnersShardFile(1), legacyAgentOwnersShardFile(2)} {
		info, err := os.Stat(filepath.Join(dir, name))
		if err != nil || info.Size() > maxLegacyAgentOwnersBytes {
			t.Fatalf("%s: %v; want a file within the reader's bound", name, err)
		}
	}
	// The spool's cleanup keeps the shards, also once they are old.
	old := time.Now().Add(-2 * IdentitySpoolMaxAge)
	for _, name := range []string{legacyAgentOwnersShardFile(1), legacyAgentOwnersShardFile(2)} {
		if err := os.Chtimes(filepath.Join(dir, name), old, old); err != nil {
			t.Fatal(err)
		}
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil); err != nil {
		t.Fatal(err)
	}
	if got, _, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || len(got) != len(owners) {
		t.Fatalf("after a pass: %d owners, ok=%t; want %d", len(got), ok, len(owners))
	}
	if err := os.Remove(filepath.Join(dir, legacyAgentOwnersShardFile(2))); err != nil {
		t.Fatal(err)
	}
	if _, _, _, ok := ReadLegacyAgentOwners(dir, nil); ok {
		t.Fatal("a map missing a shard was read")
	}
	for name, want := range map[string]bool{LegacyAgentOwnersFile: true, legacyAgentOwnersShardFile(1): true,
		"legacy-agent-owners-corrupt-1.bad": true, "legacy-agent-owners-0.map": false, "legacy-agent-owners-01.map": false,
		"legacy-agent-owners-x.map": false, "legacy-agent-owners.json": false, "501.json": false} {
		if got := isLegacyAgentOwnersFile(name); got != want {
			t.Errorf("isLegacyAgentOwnersFile(%q) = %t, want %t", name, got, want)
		}
	}
}

// Review of r104 Q-identity (continuation 2, loop round 2): at the upgrade's
// first pass alice's automounted home was not there (or her lookup failed,
// past the passes the guardian used to wait), so the map was published
// without her for good, and her 1.0.x agents entry was refused. The map now
// lists her as pending, and the pass that proves her adds her owner. Nothing
// else changes: another account's entry keeps its first token, a uid now
// held by another name stays pending, and an account the first pass did not
// list is never added.
func TestLegacyOwnerWithoutProofAtUpgradeIsAddedLater(t *testing.T) {
	for _, tc := range []struct {
		name    string
		missing func(pass int, uid int) (noHome, failed bool)
	}{
		{"automounted home absent at the first pass", func(pass, uid int) (bool, bool) { return (uid == 501 || uid == 504) && pass == 1, false }},
		{"lookup failing past the old pass limit", func(pass, uid int) (bool, bool) { return uid == 504 && pass == 1, uid == 501 && pass <= 4 }},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			homes := map[int]string{501: t.TempDir(), 502: t.TempDir(), 503: t.TempDir(), 504: t.TempDir()}
			pass := 0
			names := map[int]string{501: "alice", 502: "bob", 503: "carol", 504: "dave"}
			previousCollect, previousHome := identitySpoolCollect, identitySpoolAccountHome
			t.Cleanup(func() { identitySpoolCollect, identitySpoolAccountHome = previousCollect, previousHome })
			identitySpoolAccountHome = func(uid int) string {
				if noHome, _ := tc.missing(pass, uid); noHome {
					return filepath.Join(homes[uid], "not-mounted")
				}
				return homes[uid]
			}
			identitySpoolCollect = func(_ context.Context, account IdentitySpoolAccount, now time.Time) (IdentitySpoolRecord, error) {
				record := IdentitySpoolRecord{Key: strconv.Itoa(account.UID), User: names[account.UID], UpdatedAt: now, AccountIncarnation: "files"}
				if _, failed := tc.missing(pass, account.UID); failed {
					return record, errors.New("the directory did not answer")
				}
				return record, nil
			}
			listed := []IdentitySpoolAccount{{UID: 501, User: "alice"}, {UID: 502, User: "bob"}, {UID: 504, User: "dave"}}
			run := func(accounts []IdentitySpoolAccount) {
				t.Helper()
				pass++
				_ = WriteIdentitySpool(context.Background(), dir, accounts, nil, nil, nil)
			}
			bobToken := LegacyAgentOwnerToken("files", homes[502])
			run(listed)
			got, open, _, ok := ReadLegacyAgentOwners(dir, nil)
			if !ok || !open || got[502].Token != bobToken {
				t.Fatalf("first pass: %+v ok=%t open=%t; want bob proven and alice pending", got, ok, open)
			}
			if _, bound := got[501]; bound {
				t.Fatal("alice was bound without her proof")
			}
			// Later passes: dave's uid (pending: his home was not there either)
			// is now held by another name, carol is listed for the first
			// time, and bob's home was created again.
			names[504] = "mallory"
			if err := os.Remove(homes[502]); err != nil {
				t.Fatal(err)
			}
			if err := os.Mkdir(homes[502], 0o700); err != nil {
				t.Fatal(err)
			}
			for pass < 6 {
				run(append(slices.Clone(listed), IdentitySpoolAccount{UID: 503, User: "carol"}))
			}
			got, open, _, ok = ReadLegacyAgentOwners(dir, nil)
			if !ok || got[501].User != "alice" || got[501].Token != LegacyAgentOwnerToken("files", homes[501]) {
				t.Fatalf("alice was not added once proven: %+v ok=%t", got[501], ok)
			}
			if got[502].Token != bobToken {
				t.Fatalf("bob's entry changed to %q; want the token of the upgrade %q", got[502].Token, bobToken)
			}
			if _, added := got[503]; added {
				t.Fatal("an account the first pass did not list was added")
			}
			if owner, added := got[504]; added {
				t.Fatalf("uid 504, now another name's, was bound to %+v", owner)
			}
			if len(got) != 2 || !open {
				t.Fatalf("map %+v, open=%t; want alice and bob, with dave still pending", got, open)
			}
		})
	}
}

// A pending account is filled in whichever file holds it, the main file is
// rewritten last, and the open mark goes once nothing is pending.
func TestPendingLegacyOwnerInAShardIsFilled(t *testing.T) {
	dir := t.TempDir()
	owners := make(map[int]LegacyAgentOwner, maxLegacyAgentOwners+2)
	for i := range maxLegacyAgentOwners {
		owners[10_000+i] = LegacyAgentOwner{User: fmt.Sprintf("user%d", i), Token: fmt.Sprintf("home:1:%d", 10_000+i)}
	}
	owners[1_000_000] = LegacyAgentOwner{User: "alice"} // sorts into shard 1
	owners[1] = LegacyAgentOwner{User: "bob"}           // stays in the main file
	if written, err := WriteLegacyAgentOwners(dir, owners, time.Now(), nil); err != nil || !written {
		t.Fatalf("write: written=%t err=%v", written, err)
	}
	if got, open, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || !open || len(got) != maxLegacyAgentOwners {
		t.Fatalf("read: %d owners ok=%t open=%t", len(got), ok, open)
	}
	alice := LegacyAgentOwner{User: "ALICE", Token: "home:1:2:3"}
	if written, err := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{1_000_000: alice}, time.Now(), nil); err != nil || !written {
		t.Fatalf("fill alice: written=%t err=%v", written, err)
	}
	got, open, _, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok || !open || got[1_000_000] != (LegacyAgentOwner{User: "ALICE", Token: "home:1:2:3"}) {
		t.Fatalf("after alice: %+v ok=%t open=%t; want alice bound, bob still pending", got[1_000_000], ok, open)
	}
	if written, err := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{1: {User: "bob", Token: "sid:S-1-5-21-1-2-3-4"}}, time.Now(), nil); err != nil || !written {
		t.Fatalf("fill bob: written=%t err=%v", written, err)
	}
	if got, open, _, ok := ReadLegacyAgentOwners(dir, nil); !ok || open || len(got) != maxLegacyAgentOwners+2 {
		t.Fatalf("after bob: %d owners ok=%t open=%t; want all and closed", len(got), ok, open)
	}
	if written, err := WriteLegacyAgentOwners(dir, map[int]LegacyAgentOwner{1: {User: "bob", Token: "sid:S-1-5-21-9"}}, time.Now(), nil); err != nil || written {
		t.Fatalf("a closed map was rewritten: written=%t err=%v", written, err)
	}
}

// Every owner the guardian writes, the gateway reads back unchanged: the
// longest fields, JSON escapes, a DOMAIN\name account, separators JSON
// spells as escapes. An owner the map cannot carry unchanged (not UTF-8,
// too long, a control character) is not written at all.
func TestLegacyAgentOwnersRoundTripExactly(t *testing.T) {
	long := strings.Repeat("a", maxLegacyAgentOwnerField)
	carried := map[int]LegacyAgentOwner{
		0:           {User: "root", Token: "home:1:2"},
		501:         {User: long, Token: strings.Repeat("9", maxLegacyAgentOwnerField)},
		502:         {User: `CORP\alice`, Token: `sid:S-1-5-21-1-2-3-1601`},
		503:         {User: `"quoted"<&>`, Token: "home:3:4:5"},
		504:         {User: "na\u2028me\u2029", Token: "home:5:6"},
		505:         {User: "José@corp.example", Token: "home:7:8"},
		math.MaxInt: {User: "max", Token: "home:9:10"},
	}
	refused := map[int]LegacyAgentOwner{
		601: {User: "bad\xffname", Token: "home:1:1"},
		602: {User: "bob", Token: "home:\xfe"},
		603: {User: long + "a", Token: "home:1:1"},
		604: {User: "bob", Token: "home:" + long},
		605: {User: "tab\tname", Token: "home:1:1"},
		606: {User: "", Token: "home:1:1"},
		-1:  {User: "negative", Token: "home:1:1"},
	}
	all := map[int]LegacyAgentOwner{}
	for uid, owner := range carried {
		all[uid] = owner
	}
	for uid, owner := range refused {
		all[uid] = owner
	}
	dir := t.TempDir()
	if written, err := WriteLegacyAgentOwners(dir, all, time.Now(), nil); err != nil || !written {
		t.Fatalf("write: written=%t err=%v", written, err)
	}
	got, _, _, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok {
		t.Fatal("map not read")
	}
	sameLegacyAgentOwners(t, got, carried)
	dir = t.TempDir()
	if written, err := WriteLegacyAgentOwners(dir, refused, time.Now(), nil); err != nil || written {
		t.Fatalf("a map of owners it cannot carry was written: written=%t err=%v", written, err)
	}
}
