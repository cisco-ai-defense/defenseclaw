// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"strings"
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
