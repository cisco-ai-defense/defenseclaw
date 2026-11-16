//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/managed"
)

func testFileOwner(t *testing.T, path string) *windows.SID {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		t.Fatalf("read the owner of %s: %v", path, err)
	}
	return owner
}

// setTestFileOwner gives path the owner want, with the repair privileges an
// elevated account holds. A fixture the account cannot build skips the test
// that needs it; the deterministic stampConfigSecurity tests below do not
// depend on it.
func setTestFileOwner(t *testing.T, path string, want *windows.SID) {
	t.Helper()
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, want, nil, nil, nil)
	}); err != nil {
		t.Skipf("this account cannot give %s an owner it does not hold: %v", path, err)
	}
	if got := testFileOwner(t, path); !windows.EqualSid(got, want) {
		t.Skipf("this account cannot give %s the owner %s (it is %s)", path, want, got)
	}
}

// testWriterOwner is the owner a file created by the test account gets.
func testWriterOwner(t *testing.T, dir string) *windows.SID {
	t.Helper()
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	defer os.Remove(probe)
	return testFileOwner(t, probe)
}

func testWellKnownSID(t *testing.T, kind windows.WELL_KNOWN_SID_TYPE) *windows.SID {
	t.Helper()
	sid, err := windows.CreateWellKnownSid(kind)
	if err != nil {
		t.Fatal(err)
	}
	return sid
}

// A record Setup rewrites after its lifecycle run (the deployment record that
// carries the approved config digest) is published with the owner of the
// record it replaces, which is the canonical owner of a managed record
// (Administrators), not the account that wrote it. The hook guardian keeps
// those records at the canonical owner and logged a repair seconds later, and
// the next ensure reported guardian_repaired_drift and was not a no-op.
func TestWriteFileKeepingDACLPublishesWithTheCanonicalOwner(t *testing.T) {
	dir := t.TempDir()
	creator := testWriterOwner(t, dir)
	want := testWellKnownSID(t, windows.WinBuiltinAdministratorsSid)
	sibling := filepath.Join(dir, "deployment.json")
	if err := os.WriteFile(sibling, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !windows.EqualSid(creator, want) {
		setTestFileOwner(t, sibling, want)
	}
	setTestFileDACL(t, sibling, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")

	for _, tc := range []struct{ name, path string }{
		{"a record that is new", filepath.Join(dir, "approved-config.yaml")},
		{"a record that replaces the sibling", sibling},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if err := writeFileKeepingDACL(tc.path, []byte("{\"a\": 1}\n"), sibling); err != nil {
				t.Fatal(err)
			}
			if got := testFileOwner(t, tc.path); !windows.EqualSid(got, want) {
				t.Fatalf("owner of %s = %s, want the canonical owner %s (the writer is %s)", tc.path, got, want, creator)
			}
			if raw, err := os.ReadFile(tc.path); err != nil || string(raw) != "{\"a\": 1}\n" {
				t.Fatalf("content of %s = %q, %v", tc.path, raw, err)
			}
		})
	}
}

// With the owner stamp denied (a token without the restore and take-ownership
// privileges) the DACL can still be stamped, but the staged record has the
// writing account as owner. Nothing is published: the record that is there
// stays, and no staging file is left.
func TestWriteFileKeepingDACLPublishesNothingWhenTheOwnerStampIsDenied(t *testing.T) {
	dir := t.TempDir()
	creator := testWriterOwner(t, dir)
	var other windows.WELL_KNOWN_SID_TYPE = windows.WinBuiltinAdministratorsSid
	if creator.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
		other = windows.WinLocalSystemSid
	}
	want := testWellKnownSID(t, other)
	sibling := filepath.Join(dir, "deployment.json")
	if err := os.WriteFile(sibling, []byte("{\"kept\": true}\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setTestFileOwner(t, sibling, want)
	setTestFileDACL(t, sibling, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	denyTestOwnerStamp(t)

	if err := writeFileKeepingDACL(sibling, []byte("{\"a\": 1}\n"), sibling); err == nil {
		t.Fatal("a record whose owner could not be stamped was published")
	}
	if raw, err := os.ReadFile(sibling); err != nil || string(raw) != "{\"kept\": true}\n" {
		t.Fatalf("the record that was there = %q, %v; want it unchanged", raw, err)
	}
	if got := testFileOwner(t, sibling); !windows.EqualSid(got, want) {
		t.Fatalf("owner of the record that was there = %s, want %s", got, want)
	}
	if left, _ := filepath.Glob(filepath.Join(dir, "*.tmp")); len(left) != 0 {
		t.Fatalf("staging files left behind: %v", left)
	}
}

// denyTestOwnerStamp makes every stamp that sets an owner or a group fail, as
// it does for a token that holds no right to give a file another owner; the
// DACL stamp is the real call.
func denyTestOwnerStamp(t *testing.T) {
	t.Helper()
	call := setNamedSecurityInfo
	setNamedSecurityInfo = func(name string, kind windows.SE_OBJECT_TYPE, information windows.SECURITY_INFORMATION,
		owner, group *windows.SID, dacl, sacl *windows.ACL) error {
		if information&(windows.OWNER_SECURITY_INFORMATION|windows.GROUP_SECURITY_INFORMATION) != 0 {
			return windows.ERROR_PRIVILEGE_NOT_HELD
		}
		return call(name, kind, information, owner, group, dacl, sacl)
	}
	t.Cleanup(func() { setNamedSecurityInfo = call })
}

// The DACL alone is not a published record when the owner is wrong, whatever
// the file system said about the DACL; it is when the file already has the
// owner. This needs no privilege and no foreign owner.
func TestStampConfigSecurityAcceptsTheDACLAloneOnlyForTheRightOwner(t *testing.T) {
	dir := t.TempDir()
	target := filepath.Join(dir, "staged")
	if err := os.WriteFile(target, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	current := testFileOwner(t, target)
	foreign := testWellKnownSID(t, windows.WinBuiltinGuestsSid)
	sd, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	denyTestOwnerStamp(t)

	if err := stampConfigSecurity(target, foreign, nil, dacl); err == nil {
		t.Fatal("the DACL stamp stood in for an owner stamp that was denied")
	}
	if got := testFileOwner(t, target); !windows.EqualSid(got, current) {
		t.Fatalf("owner changed to %s", got)
	}
	// The benign twin: the file has the owner already.
	if err := stampConfigSecurity(target, current, nil, dacl); err != nil {
		t.Fatalf("a file that has the owner was refused: %v", err)
	}
}

// The benign twin: a sibling the writer owns is a plain write, and the DACL
// still comes from the sibling.
func TestWriteFileKeepingDACLKeepsTheWritersOwnOwnerWhenTheSiblingHasIt(t *testing.T) {
	dir := t.TempDir()
	sibling := filepath.Join(dir, "config.yaml")
	if err := os.WriteFile(sibling, []byte("a: 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	setTestFileDACL(t, sibling, "D:P(A;;FA;;;SY)(A;;FA;;;BA)")
	next := filepath.Join(dir, "rejected-config.yaml")
	if err := writeFileKeepingDACL(next, []byte("a: 2\n"), sibling); err != nil {
		t.Fatal(err)
	}
	if got, want := testFileOwner(t, next), testFileOwner(t, sibling); !windows.EqualSid(got, want) {
		t.Fatalf("owner = %s, want %s", got, want)
	}
	read := func(path string) string {
		sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
		if err != nil {
			t.Fatal(err)
		}
		return sd.String()
	}
	if got, want := read(next), read(sibling); got != want {
		t.Fatalf("DACL = %s, want the sibling DACL %s", got, want)
	}
}
