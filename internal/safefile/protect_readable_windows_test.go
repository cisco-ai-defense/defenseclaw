// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func setAccessListForTest(t *testing.T, path, sddl string) {
	t.Helper()
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION, nil, nil, dacl, nil); err != nil {
		t.Fatal(err)
	}
}

// currentUserAccessEntry is a full-access entry for the user the test runs
// as. The access lists below name only administrators, and a Limited token is
// in none of those groups: a file's owner has READ_CONTROL and WRITE_DAC
// without an entry but not the read of attributes that ReadPathMetadata asks
// for, so without this entry the test itself was refused the file it had just
// created ("Access is denied" on the replaced file) before it reached the
// product. The entry names no ordinary-users group, so it grants none of the
// read these tests check for.
func currentUserAccessEntry(t *testing.T) string {
	t.Helper()
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		t.Fatalf("current token user: %v", err)
	}
	return "(A;;FA;;;" + user.User.Sid.String() + ")"
}

// ProtectReadableByUsers keeps the replaced file's access list and adds only
// the Users read to it, falls back to the protection when a deny entry still
// refuses the read, protects a new file, and fails when even the protection
// leaves ordinary users without the read.
func TestProtectReadableByUsers(t *testing.T) {
	adminOnly := "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BO)" + currentUserAccessEntry(t)
	const protection = "D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"
	for _, test := range []struct {
		name string
		// keep is the access list of the file the publication replaces;
		// empty for a new file.
		keep string
		// protection is what the protect callback sets.
		protection string
		wantErr    bool
		protected  bool
		kept       []string
	}{
		{name: "kept access list without the read", keep: adminOnly, protection: protection,
			kept: []string{"D:P", ";;;BO)", ";;;BU)"}},
		{name: "kept access list that already grants the read", keep: adminOnly + "(A;;FR;;;AU)", protection: protection,
			kept: []string{";;;BO)", ";;;AU)"}},
		{name: "kept access list that denies a user the read", keep: adminOnly + "(D;;FR;;;S-1-5-21-111-222-333-1001)",
			protection: protection, protected: true},
		{name: "new file", protection: protection, protected: true},
		{name: "protection without the read", keep: adminOnly + "(D;;FR;;;S-1-5-21-111-222-333-1001)",
			protection: adminOnly, wantErr: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			dir := t.TempDir()
			replaced := filepath.Join(dir, "hooks.json")
			temp := filepath.Join(dir, "hooks.json.tmp")
			for _, path := range []string{replaced, temp} {
				if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
					t.Fatal(err)
				}
			}
			var keep *FileMetadata
			if test.keep != "" {
				setAccessListForTest(t, replaced, test.keep)
				metadata, err := ReadPathMetadata(replaced)
				if err != nil {
					t.Fatal(err)
				}
				keep = &metadata
			}
			protected := false
			err := ProtectReadableByUsers(temp, keep, func(path string) error {
				protected = true
				setAccessListForTest(t, path, test.protection)
				return nil
			})
			if test.wantErr {
				if err == nil {
					t.Fatal("a protection that leaves ordinary users without the read was accepted")
				}
				// The refusal must come from the check that ordinary users
				// can read the protected file, not from the test token
				// being denied it.
				if !strings.Contains(err.Error(), "ordinary users cannot read") {
					t.Fatalf("refused for another reason: %v", err)
				}
				return
			}
			if err != nil {
				t.Fatal(err)
			}
			if protected != test.protected {
				t.Fatalf("protection applied = %t, want %t", protected, test.protected)
			}
			if err := PathUsersCanRead(temp); err != nil {
				t.Fatalf("ordinary users cannot read the published file: %v", err)
			}
			metadata, err := ReadPathMetadata(temp)
			if err != nil {
				t.Fatal(err)
			}
			for _, entry := range test.kept {
				if !strings.Contains(metadata.SecurityDescriptor, entry) {
					t.Fatalf("access list %s lacks %q", metadata.SecurityDescriptor, entry)
				}
			}
		})
	}
}

// A writer's Stale file is written again even when the edit leaves its bytes
// as they are; without Stale such an edit writes nothing.
func TestSharedFileWriterUpdateWritesAStaleFile(t *testing.T) {
	for _, stale := range []bool{false, true} {
		t.Run(map[bool]string{false: "current", true: "stale"}[stale], func(t *testing.T) {
			path := filepath.Join(t.TempDir(), "hooks.json")
			if err := os.WriteFile(path, []byte("admin\n"), 0o600); err != nil {
				t.Fatal(err)
			}
			base, err := readSharedFileForTest(path)
			if err != nil {
				t.Fatal(err)
			}
			writes := 0
			writer := sharedWriterForTest(func(string) { writes++ })
			writer.Stale = func(file SharedFile) bool { return stale && file.Exists }
			write, err := writer.Update(base, func(current SharedFile) (SharedEdit, error) {
				return SharedEdit{Data: current.Data}, nil
			})
			if err != nil {
				t.Fatal(err)
			}
			if write.Written != stale || writes != map[bool]int{false: 0, true: 1}[stale] {
				t.Fatalf("written=%t swaps=%d, want written=%t", write.Written, writes, stale)
			}
		})
	}
}
