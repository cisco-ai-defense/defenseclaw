// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"fmt"
	"os"
	"os/user"
	"path/filepath"
	"sync"
	"syscall"
	"testing"
	"time"
)

// privateGroupFixture makes a 0775 folder of this account's group and points
// the local proof at account files that show it as a private group.
func privateGroupFixture(t *testing.T) (string, os.FileInfo, string, string) {
	t.Helper()
	root := t.TempDir()
	dir := filepath.Join(root, ".config")
	if err := os.MkdirAll(filepath.Join(dir, "opencode", "plugins"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(dir, 0o775); err != nil {
		t.Fatal(err)
	}
	dropInheritedACLs(t, root)
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	uid := fmt.Sprint(os.Geteuid())
	gid := fmt.Sprint(info.Sys().(*syscall.Stat_t).Gid)
	oldUser, oldLookupGroup := privateGroupLookupUser, privateGroupLookupGroup
	privateGroupLookupUser = func(string) (*user.User, error) {
		return &user.User{Username: "me", Uid: uid, Gid: gid}, nil
	}
	privateGroupLookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: gid, Name: "me"}, nil }
	files := t.TempDir()
	passwd, groupFile := filepath.Join(files, "passwd"), filepath.Join(files, "group")
	if err := os.WriteFile(passwd, []byte(fmt.Sprintf("me:x:%s:%s::/home/x:/bin/sh\n", uid, gid)), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(groupFile, []byte(fmt.Sprintf("me:x:%s:\n", gid)), 0o600); err != nil {
		t.Fatal(err)
	}
	oldPasswd, oldGroup, oldGetent, oldNow := privateGroupPasswdFile, privateGroupGroupFile, privateGroupGetent, privateGroupNow
	privateGroupPasswdFile, privateGroupGroupFile = passwd, groupFile
	resetPrivateGroupCache()
	t.Cleanup(func() {
		privateGroupLookupUser, privateGroupLookupGroup = oldUser, oldLookupGroup
		privateGroupPasswdFile, privateGroupGroupFile, privateGroupGetent, privateGroupNow = oldPasswd, oldGroup, oldGetent, oldNow
		resetPrivateGroupCache()
	})
	return dir, info, uid, gid
}

func resetPrivateGroupCache() {
	privateGroupCache.Lock()
	defer privateGroupCache.Unlock()
	privateGroupCache.answers = map[[3]string]privateGroupAnswer{}
}

// GAP-0905 review 1 MF1: a directory service can add a member to the private
// group that the local files do not show; that member can write the folder, so
// the proof the watcher root check uses refuses it. The stock private group
// stays accepted.
func TestOwnerPrivateGroupCachedAsksTheNameService(t *testing.T) {
	dir, info, uid, gid := privateGroupFixture(t)
	for _, tc := range []struct {
		name, group string
		fail        bool
		want        bool
	}{
		{name: "stock private group", group: "me:x:%[2]s:\n", want: true},
		{name: "owner listed as its own member", group: "me:x:%[2]s:me\n", want: true},
		{name: "member added by the name service", group: "me:x:%[2]s:me,bob\n"},
		{name: "member only the name service lists", group: "me:x:%[2]s:bob\n"},
		{name: "group answered under another name", group: "devs:x:%[2]s:\n"},
		{name: "getent fails", group: "me:x:%[2]s:\n", fail: true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			resetPrivateGroupCache()
			privateGroupGetent = func(database, key string) (string, bool) {
				if tc.fail {
					return "", false
				}
				if database == "group" {
					return fmt.Sprintf(tc.group, "me", gid), true
				}
				return fmt.Sprintf("me:x:%s:%s::/home/x:/bin/sh\n", uid, gid), true
			}
			if got := ownerPrivateGroupCached(dir, info); got != tc.want {
				t.Fatalf("cached proof=%v, want %v", got, tc.want)
			}
			if !ownerPrivateGroup(dir, info) {
				t.Fatal("the local proof no longer sees the stock private group")
			}
		})
	}
}

// The name service half is asked once per account and minute, for either
// answer, and again after the minute; the local half is judged on each call.
func TestOwnerPrivateGroupCachedRemembersTheAnswerForAMinute(t *testing.T) {
	dir, info, uid, gid := privateGroupFixture(t)
	now := time.Unix(1_700_000_000, 0)
	var mu sync.Mutex
	privateGroupNow = func() time.Time { mu.Lock(); defer mu.Unlock(); return now }
	calls, members := 0, ""
	privateGroupGetent = func(database, key string) (string, bool) {
		calls++
		if database == "group" {
			return fmt.Sprintf("me:x:%s:%s\n", gid, members), true
		}
		return fmt.Sprintf("me:x:%s:%s::/home/x:/bin/sh\n", uid, gid), true
	}
	for i := 0; i < 5; i++ {
		if !ownerPrivateGroupCached(dir, info) {
			t.Fatal("stock private group refused")
		}
	}
	if calls != 2 {
		t.Fatalf("getent calls for five checks = %d, want 2", calls)
	}
	members = "bob"
	if !ownerPrivateGroupCached(dir, info) {
		t.Fatal("answer was not remembered inside the minute")
	}
	mu.Lock()
	now = now.Add(privateGroupNameServiceTTL + time.Second)
	mu.Unlock()
	if ownerPrivateGroupCached(dir, info) {
		t.Fatal("a member added by the name service was accepted after the answer expired")
	}
	calls = 0
	for i := 0; i < 3; i++ {
		if ownerPrivateGroupCached(dir, info) {
			t.Fatal("refused answer flipped")
		}
	}
	if calls != 0 {
		t.Fatalf("a refusal was not remembered: %d getent calls", calls)
	}
	// The local files are judged on every call, whatever the name service answer
	// was remembered as.
	privateGroupLookupGroup = func(string) (*user.Group, error) { return &user.Group{Gid: gid, Name: "other"}, nil }
	members = ""
	mu.Lock()
	now = now.Add(2 * privateGroupNameServiceTTL)
	mu.Unlock()
	if ownerPrivateGroupCached(dir, info) {
		t.Fatal("the local files disagreed and the folder was accepted")
	}
}
