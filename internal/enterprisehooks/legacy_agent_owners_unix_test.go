// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"bytes"
	"context"
	"errors"
	"fmt"
	"os"
	"path/filepath"
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
	if _, ok := homeBirth(home); !ok {
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
	got, ok := ReadLegacyAgentOwners(dir, nil)
	if !ok || got[501] != first[501] || got[94401] != first[94401] || len(got) != 2 {
		t.Fatalf("read %+v, %v", got, ok)
	}
	if _, ok := ReadLegacyAgentOwners(dir, func(string, string) error { return errors.New("not root-owned") }); ok {
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
	if got, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
		t.Fatalf("1.0.4 cannot read its migration map after rollback: %+v, %t", got, ok)
	}
	if err := os.Rename(filepath.Join(dir, LegacyAgentOwnersFile), filepath.Join(dir, oldLegacyAgentOwnersFile)); err != nil {
		t.Fatal(err)
	}
	if got, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
		t.Fatalf("the gateway lost the earlier map before guardian migration: %+v, %t", got, ok)
	}
	if err := WriteIdentitySpool(context.Background(), dir, nil, nil, nil, nil); err != nil {
		t.Fatalf("upgrade an earlier 1.0.4 spool: %v", err)
	}
	if _, err := os.Stat(filepath.Join(dir, oldLegacyAgentOwnersFile)); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("old map remains visible on rollback: %v", err)
	}
	if got, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
		t.Fatalf("migration changed the account binding: %+v, %t", got, ok)
	}
}

func TestCorruptPre104AgentOwnersMapDoesNotStopIdentitySpool(t *testing.T) {
	for _, tc := range []struct {
		name string
		data []byte
	}{
		{"truncated", []byte(`{"v":1,"owners":`)},
		{"oversized", bytes.Repeat([]byte("x"), maxLegacyAgentOwnersBytes+1)},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := t.TempDir()
			oldPath := filepath.Join(dir, oldLegacyAgentOwnersFile)
			if err := os.WriteFile(oldPath, tc.data, 0o640); err != nil {
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
			if contents, err := os.ReadFile(bad[0]); err != nil || !bytes.Equal(contents, tc.data) {
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
	if got, ok := ReadLegacyAgentOwners(dir, nil); !ok || got[501] != owners[501] {
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
	owners, ok := ReadLegacyAgentOwners(dir, nil)
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
