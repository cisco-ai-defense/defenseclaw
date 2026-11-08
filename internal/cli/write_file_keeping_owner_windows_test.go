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

// A record Setup rewrites after its lifecycle run (the deployment record that
// carries the approved config digest) is published with the owner of the
// record it replaces, not the account that wrote it. The hook guardian keeps
// those records at the canonical owner and logged a repair seconds later, and
// the next ensure reported guardian_repaired_drift and was not a no-op.
func TestWriteFileKeepingDACLPublishesWithTheSiblingOwner(t *testing.T) {
	dir := t.TempDir()
	probe := filepath.Join(dir, "probe")
	if err := os.WriteFile(probe, nil, 0o600); err != nil {
		t.Fatal(err)
	}
	creator := testFileOwner(t, probe)
	// An owner the writing account does not give a new file by itself.
	var other windows.WELL_KNOWN_SID_TYPE = windows.WinLocalSystemSid
	if creator.IsWellKnown(windows.WinLocalSystemSid) {
		other = windows.WinBuiltinAdministratorsSid
	}
	want, err := windows.CreateWellKnownSid(other)
	if err != nil {
		t.Fatal(err)
	}
	sibling := filepath.Join(dir, "deployment.json")
	if err := os.WriteFile(sibling, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := managed.RunWithWindowsRepairPrivileges(func() error {
		return windows.SetNamedSecurityInfo(sibling, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION, want, nil, nil, nil)
	}); err != nil {
		t.Skipf("this account cannot give %s an owner it does not hold: %v", sibling, err)
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
				t.Fatalf("owner of %s = %s, want the sibling owner %s (the writer is %s)", tc.path, got, want, creator)
			}
			if raw, err := os.ReadFile(tc.path); err != nil || string(raw) != "{\"a\": 1}\n" {
				t.Fatalf("content of %s = %q, %v", tc.path, raw, err)
			}
		})
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
