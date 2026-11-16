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

func TestUsersCanRead(t *testing.T) {
	const admins = "O:BAG:SYD:P(A;;FA;;;SY)(A;;FA;;;BA)"
	for _, test := range []struct {
		name     string
		sddl     string
		readable bool
	}{
		{name: "Administrators and SYSTEM only", sddl: admins},
		{name: "Users read", sddl: admins + "(A;;FR;;;BU)", readable: true},
		{name: "Users read and execute", sddl: admins + "(A;;0x1200a9;;;BU)", readable: true},
		{name: "Everyone generic read", sddl: admins + "(A;;GR;;;WD)", readable: true},
		{name: "Authenticated Users read", sddl: admins + "(A;;FR;;;AU)", readable: true},
		{name: "read split over two groups", sddl: admins + "(A;;0x1;;;BU)(A;;0x120088;;;AU)", readable: true},
		{name: "Users read attributes only", sddl: admins + "(A;;0x80;;;BU)"},
		{name: "Users read data without synchronize", sddl: admins + "(A;;0x20089;;;BU)"},
		{name: "Backup Operators read only", sddl: admins + "(A;;FR;;;BO)"},
		{name: "INTERACTIVE read only", sddl: admins + "(A;;FR;;;IU)"},
		{name: "one user's read", sddl: admins + "(A;;FR;;;S-1-5-21-111-222-333-1001)"},
		{name: "inherit-only Users read", sddl: admins + "(A;OIIO;FR;;;BU)"},
		{name: "Users denied read", sddl: "O:BAG:SYD:P(D;;FR;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"},
		{name: "a user denied read", sddl: "O:BAG:SYD:P(D;;0x1;;;S-1-5-21-111-222-333-1001)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"},
		{name: "Everyone denied synchronize", sddl: "O:BAG:SYD:P(D;;0x100000;;;WD)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)"},
		{name: "Users denied the write rights only", sddl: "O:BAG:SYD:P(D;;0x116;;;BU)(A;;FA;;;SY)(A;;FA;;;BA)(A;;FR;;;BU)", readable: true},
		{name: "Administrators denied read", sddl: "O:BAG:SYD:P(D;;FR;;;BA)(A;;FA;;;SY)(A;;FR;;;BU)", readable: true},
		{name: "inherited Users read", sddl: "O:BAG:SYD:AI(A;ID;FA;;;SY)(A;ID;FA;;;BA)(A;ID;0x1200a9;;;BU)", readable: true},
		{name: "no access list entries", sddl: "O:BAG:SYD:P"},
		{name: "NULL access list", sddl: "O:BAG:SYD:NO_ACCESS_CONTROL", readable: true},
	} {
		t.Run(test.name, func(t *testing.T) {
			err := UsersCanRead(FileMetadata{SecurityDescriptor: test.sddl})
			if test.readable && err != nil {
				t.Fatalf("UsersCanRead(%s) = %v, want readable", test.sddl, err)
			}
			if !test.readable && err == nil {
				t.Fatalf("UsersCanRead(%s) accepted an access list ordinary users cannot read through", test.sddl)
			}
		})
	}
	if err := UsersCanRead(FileMetadata{}); err == nil {
		t.Fatal("UsersCanRead accepted metadata without a security descriptor")
	}
}

// GrantUsersRead adds the Users read entry and keeps every other entry and
// the protection from inheritance.
func TestGrantUsersReadKeepsTheOtherEntries(t *testing.T) {
	path := filepath.Join(t.TempDir(), "requirements.toml")
	if err := os.WriteFile(path, []byte("x = 1\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	descriptor, err := windows.SecurityDescriptorFromString("D:P(A;;FA;;;SY)(A;;FA;;;BA)(A;;FA;;;OW)(A;;FR;;;BO)")
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
	before, err := ReadPathMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if UsersCanRead(before) == nil {
		t.Fatalf("fixture: ordinary users can already read %s", before.SecurityDescriptor)
	}
	if err := GrantUsersRead(path); err != nil {
		t.Fatal(err)
	}
	after, err := ReadPathMetadata(path)
	if err != nil {
		t.Fatal(err)
	}
	if err := UsersCanRead(after); err != nil {
		t.Fatalf("after GrantUsersRead: %v (%s)", err, after.SecurityDescriptor)
	}
	for _, kept := range []string{"D:P", ";;;SY)", ";;;BA)", ";;;BO)", ";;;BU)"} {
		if !strings.Contains(after.SecurityDescriptor, kept) {
			t.Fatalf("access list %s lacks %q", after.SecurityDescriptor, kept)
		}
	}
	if after.Attributes != before.Attributes {
		t.Fatalf("attributes changed: %#x -> %#x", before.Attributes, after.Attributes)
	}
}
