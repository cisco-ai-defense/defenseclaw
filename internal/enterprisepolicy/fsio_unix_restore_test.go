// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import (
	"encoding/binary"
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"reflect"
	"runtime"
	"strings"
	"testing"

	"golang.org/x/sys/unix"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/posixacl"
)

// GAP-0924: the repair of a vendor directory users could not pass made it
// 0755, so an administrator's 0700 /etc/claude-code listed its unrelated
// files to every account. It adds only the bits users need: search on the
// directories above the drop-in directory, search and list on that one.
func TestRestorePublishedDirsAddsOnlyTheMissingModeBits(t *testing.T) {
	withHigherSources(t)
	opts := publishTestOptions(t)
	if _, err := Publish(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	dropIn := filepath.Join(opts.Root, "etc/claude-code/managed-settings.d")
	vendor := filepath.Dir(dropIn)
	for dir, mode := range map[string]os.FileMode{dropIn: 0o700, vendor: 0o750} {
		if err := os.Chmod(dir, mode); err != nil {
			t.Fatal(err)
		}
	}
	restored, err := RestorePublishedPolicyDirs(opts)
	if err != nil || !containsString(restored, dropIn) || !containsString(restored, vendor) {
		t.Fatalf("restore published dirs = %v, %v", restored, err)
	}
	for dir, want := range map[string]os.FileMode{dropIn: 0o755, vendor: 0o751} {
		if info, err := os.Stat(dir); err != nil || info.Mode().Perm() != want {
			t.Fatalf("%s: mode %v (%v) after the repair, want %04o", dir, info.Mode().Perm(), err, want)
		}
	}
	result, err := VerifyAll(opts, []string{"claudecode"})
	if err != nil || !containsString(result.MachinePolicyConnectors, "claudecode") {
		t.Fatalf("verify after the repair: %+v, %v", result, err)
	}
}

// GAP-0924: Codex opens /etc/codex/requirements.toml by name, so the repair
// of an administrator's 0700 /etc/codex adds search only: listing it showed
// its unrelated files to every account. Search alone lets any account open
// a file it can name, so while an unrelated file there grants other
// accounts access the repair leaves the directory as it is and names it.
func TestRestorePublishedDirsAddsOnlySearchAboveASingleFile(t *testing.T) {
	withHigherSources(t)
	opts := publishTestOptions(t)
	if _, err := Publish(opts, []string{"codex"}); err != nil {
		t.Fatal(err)
	}
	vendor := filepath.Join(opts.Root, "etc/codex")
	notes := filepath.Join(vendor, "admin-notes.toml")
	if err := os.WriteFile(notes, []byte("x = 1\n"), 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(notes, 0o644); err != nil {
		t.Fatal(err)
	}
	if err := os.Chmod(vendor, 0o700); err != nil {
		t.Fatal(err)
	}
	restored, err := RestorePublishedPolicyDirs(opts)
	if !errors.Is(err, errPublishedDirExposes) || !strings.Contains(err.Error(), notes) || len(restored) != 0 {
		t.Fatalf("restore with a readable unrelated file = %v, %v; want it refused, naming %s", restored, err, notes)
	}
	if info, err := os.Stat(vendor); err != nil || info.Mode().Perm() != 0o700 {
		t.Fatalf("%s: mode %v (%v) after the refused repair, want 0700", vendor, info.Mode().Perm(), err)
	}
	published, err := Publish(opts, []string{"codex"})
	if err != nil || published.Complete() {
		t.Fatalf("publish with a readable unrelated file = %+v, %v; want codex not covered", published, err)
	}
	for _, state := range published.States {
		if state.Connector == "codex" && !strings.Contains(strings.Join(state.Conflicts, "; "), notes) {
			t.Fatalf("the codex conflicts do not name %s: %v", notes, state.Conflicts)
		}
	}
	if err := os.Chmod(notes, 0o600); err != nil {
		t.Fatal(err)
	}
	restored, err = RestorePublishedPolicyDirs(opts)
	if err != nil || !containsString(restored, vendor) {
		t.Fatalf("restore published dirs = %v, %v", restored, err)
	}
	if info, err := os.Stat(vendor); err != nil || info.Mode().Perm() != 0o711 {
		t.Fatalf("%s: mode %v (%v) after the repair, want 0711", vendor, info.Mode().Perm(), err)
	}
	if problem := publishedDirProblem(opts, filepath.Join("/etc/codex", "requirements.toml")); problem != "" {
		t.Fatalf("a searchable /etc/codex is still reported: %s", problem)
	}
}

// GAP-1323: the macOS repair ran `chmod -N`, which removed every ACL entry
// of the vendor directory, an administrator's unrelated ones too. It
// removes only the entries that deny search or list, and the ones that
// grant write (user:admin could not use its write while everyone was denied
// search; with the deny gone it could add or replace machine policy),
// highest index first.
func TestRestorePublishedDirsRemovesOnlyTheDenyingMacOSACLEntries(t *testing.T) {
	withHigherSources(t)
	opts := publishTestOptions(t)
	opts.GOOS = "darwin"
	if _, err := Publish(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(opts.Root, "Library/Application Support/ClaudeCode/managed-settings.d")
	acl := []managed.DarwinACLEntry{
		{Index: 0, Text: "user:admin allow read,write", Allow: true, Rights: []string{"read", "write"}},
		{Index: 1, Text: "group:everyone deny list,search", Rights: []string{"list", "search"}},
		{Index: 2, Text: "user:bob deny write,delete", Rights: []string{"write", "delete"}},
		{Index: 3, Text: "group:staff deny search", Rights: []string{"search"}},
		{Index: 4, Text: "user:carol deny list,file_inherit,only_inherit", Rights: []string{"list", "file_inherit", "only_inherit"}},
		{Index: 5, Text: "user:dave allow read", Allow: true, Rights: []string{"read"}},
	}
	previousRead, previousRemove := publishedDirACLEntries, removeDarwinACLEntry
	t.Cleanup(func() { publishedDirACLEntries, removeDarwinACLEntry = previousRead, previousRemove })
	publishedDirACLEntries = func(path string) ([]managed.DarwinACLEntry, error) {
		if path != dir {
			return nil, nil
		}
		return append([]managed.DarwinACLEntry(nil), acl...), nil
	}
	var removed []int
	removeDarwinACLEntry = func(path string, index int) error {
		if path != dir {
			t.Fatalf("removed an ACL entry of %s", path)
		}
		removed = append(removed, index)
		// The entries after it move up one, as on macOS.
		kept := acl[:0:0]
		for _, entry := range acl {
			switch {
			case entry.Index < index:
				kept = append(kept, entry)
			case entry.Index > index:
				entry.Index--
				kept = append(kept, entry)
			}
		}
		acl = kept
		return nil
	}
	restored, err := RestorePublishedPolicyDirs(opts)
	if err != nil || !containsString(restored, dir) {
		t.Fatalf("restore published dirs = %v, %v", restored, err)
	}
	if !reflect.DeepEqual(removed, []int{3, 1, 0}) {
		t.Fatalf("removed ACL entries %v, want only the denying and the write ones, highest first: [3 1 0]", removed)
	}
	var left []string
	for _, entry := range acl {
		left = append(left, entry.Text)
	}
	want := []string{"user:bob deny write,delete", "user:carol deny list,file_inherit,only_inherit", "user:dave allow read"}
	if !reflect.DeepEqual(left, want) {
		t.Fatalf("ACL after the repair %q, want %q", left, want)
	}
	result, err := VerifyAll(opts, []string{"claudecode"})
	if err != nil || !containsString(result.MachinePolicyConnectors, "claudecode") {
		t.Fatalf("verify after the repair: %+v, %v", result, err)
	}
}

// GAP-1323 on Linux: the repair removed the whole access ACL of the
// drop-in directory. It gives the entries without access search and list,
// raises the mask, and keeps every other entry as it was.
func TestRestorePublishedDirsKeepsUnrelatedLinuxACLEntries(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX ACL xattrs are Linux-only")
	}
	withHigherSources(t)
	opts := publishTestOptions(t)
	if _, err := Publish(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(opts.Root, "etc/claude-code/managed-settings.d")
	start := posixacl.View{
		Present: true, Owner: 7, Group: 5, Mask: 1, Other: 5,
		Users:  []posixacl.Entry{{Kind: "user", ID: 54321, Perm: 0}, {Kind: "user", ID: 54322, Perm: 7}},
		Groups: []posixacl.Entry{{Kind: "group", ID: 54400, Perm: 4}},
	}
	if err := unix.Setxattr(dir, linuxAccessACLXattr, linuxAccessACLData(start), 0); errors.Is(err, unix.ENOTSUP) {
		t.Skipf("no POSIX ACLs on %s", dir)
	} else if err != nil {
		t.Fatal(err)
	}
	result, err := VerifyAll(opts, []string{"claudecode"})
	if err != nil {
		t.Fatal(err)
	}
	for _, state := range result.States {
		if state.Connector == "claudecode" && (state.Covered || !hasConflict(state, "user:54321:")) {
			t.Fatalf("a managed directory a named user cannot list was reported covered: %+v", state)
		}
	}
	restored, err := RestorePublishedPolicyDirs(opts)
	if err != nil || !containsString(restored, dir) {
		t.Fatalf("restore published dirs = %v, %v", restored, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := posixacl.System.Read(dir, info.Mode())
	if err != nil {
		t.Fatal(err)
	}
	want := posixacl.View{
		Present: true, Owner: 7, Group: 5, Mask: 5, Other: 5,
		Users:  []posixacl.Entry{{Kind: "user", ID: 54321, Perm: 5}, {Kind: "user", ID: 54322, Perm: 7}},
		Groups: []posixacl.Entry{{Kind: "group", ID: 54400, Perm: 5}},
	}
	if !reflect.DeepEqual(got, want) {
		t.Fatalf("ACL after the repair %+v, want %+v", got, want)
	}
	result, err = VerifyAll(opts, []string{"claudecode"})
	if err != nil || !containsString(result.MachinePolicyConnectors, "claudecode") {
		t.Fatalf("verify after the repair: %+v, %v", result, err)
	}
}

// groupClassPerms is the effective permission of the owning group and of
// each named entry: the entry and the mask, or the owning group entry alone
// when there are no named entries (no mask).
func groupClassPerms(acl posixacl.View) map[string]uint16 {
	if len(acl.Users)+len(acl.Groups) == 0 {
		return map[string]uint16{"group::": acl.Group}
	}
	perms := map[string]uint16{"group::": acl.Group & acl.Mask}
	for _, entry := range append(append([]posixacl.Entry(nil), acl.Users...), acl.Groups...) {
		perms[fmt.Sprintf("%s:%d:", entry.Kind, entry.ID)] = entry.Perm & acl.Mask
	}
	return perms
}

// GAP-1323 review: the Linux ACL repair raised search on every entry and the
// mask, so an entry with write but no search (user:x:rw-, group:g:-w-, and
// here the owning group -w-) under a mask rwx came out rwx: usable write on
// the root-owned drop-in folder, where that account can add or replace
// machine policy, while verify reported the connector covered. The repaired
// group class has search and list, and no write.
func TestRestorePublishedDirsGivesNoWriteThroughTheLinuxACL(t *testing.T) {
	if runtime.GOOS != "linux" {
		t.Skip("POSIX ACL xattrs are Linux-only")
	}
	withHigherSources(t)
	opts := publishTestOptions(t)
	if _, err := Publish(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	dir := filepath.Join(opts.Root, "etc/claude-code/managed-settings.d")
	start := posixacl.View{
		Present: true, Owner: 7, Group: 2, Mask: 7, Other: 5,
		Users:  []posixacl.Entry{{Kind: "user", ID: 54321, Perm: 6}},
		Groups: []posixacl.Entry{{Kind: "group", ID: 54400, Perm: 2}},
	}
	if err := unix.Setxattr(dir, linuxAccessACLXattr, linuxAccessACLData(start), 0); errors.Is(err, unix.ENOTSUP) {
		t.Skipf("no POSIX ACLs on %s", dir)
	} else if err != nil {
		t.Fatal(err)
	}
	restored, err := RestorePublishedPolicyDirs(opts)
	if err != nil || !containsString(restored, dir) {
		t.Fatalf("restore published dirs = %v, %v", restored, err)
	}
	info, err := os.Lstat(dir)
	if err != nil {
		t.Fatal(err)
	}
	got, err := posixacl.System.Read(dir, info.Mode())
	if err != nil {
		t.Fatal(err)
	}
	want := map[string]uint16{"group::": 5, "user:54321:": 5, "group:54400:": 5}
	if perms := groupClassPerms(got); !reflect.DeepEqual(perms, want) {
		t.Fatalf("effective ACL permissions after the repair %v (ACL %+v), want r-x and no write: %v", perms, got, want)
	}
	if perm := info.Mode().Perm(); perm != 0o755 {
		t.Fatalf("mode after the repair %04o, want 0755 (no group or other write)", perm)
	}
	result, err := VerifyAll(opts, []string{"claudecode"})
	if err != nil || !containsString(result.MachinePolicyConnectors, "claudecode") {
		t.Fatalf("verify after the repair: %+v, %v", result, err)
	}
}

// grantPublishedDirAccess leaves no group-class write, also where only the
// mask held it back from search (user rwx under mask -w-) and where no mask
// is written (the owning group entry is the group class).
func TestGrantPublishedDirAccessDropsGroupClassWrite(t *testing.T) {
	for name, acl := range map[string]posixacl.View{
		"mask -w- over user rwx":      {Present: true, Owner: 7, Mask: 2, Users: []posixacl.Entry{{Kind: "user", ID: 10, Perm: 7}}},
		"named group -w- under rwx":   {Present: true, Owner: 7, Group: 5, Mask: 7, Groups: []posixacl.Entry{{Kind: "group", ID: 20, Perm: 2}}},
		"no named entries, group -w-": {Present: true, Owner: 7, Group: 2, Mask: 7},
	} {
		for entry, perm := range groupClassPerms(grantPublishedDirAccess(acl, 5)) {
			if perm != 5 {
				t.Errorf("%s: %s is %03b after the grant, want r-x and no write", name, entry, perm)
			}
		}
	}
}

// linuxAccessACLData writes the entries in the kernel's order whatever the
// order of the view.
func TestLinuxAccessACLDataOrdersTheEntries(t *testing.T) {
	data := linuxAccessACLData(posixacl.View{
		Owner: 7, Group: 5, Mask: 5, Other: 1,
		Users: []posixacl.Entry{{Kind: "user", ID: 20, Perm: 5}, {Kind: "user", ID: 10, Perm: 4}},
	})
	var got [][3]uint32
	for off := 4; off < len(data); off += 8 {
		got = append(got, [3]uint32{uint32(binary.LittleEndian.Uint16(data[off:])), uint32(binary.LittleEndian.Uint16(data[off+2:])), binary.LittleEndian.Uint32(data[off+4:])})
	}
	want := [][3]uint32{{0x01, 7, 0xffffffff}, {0x02, 4, 10}, {0x02, 5, 20}, {0x04, 5, 0xffffffff}, {0x10, 5, 0xffffffff}, {0x20, 1, 0xffffffff}}
	if binary.LittleEndian.Uint32(data) != 2 || !reflect.DeepEqual(got, want) {
		t.Fatalf("encoded ACL %v, want %v", got, want)
	}
}
