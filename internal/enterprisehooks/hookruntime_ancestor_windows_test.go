// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"os"
	"path/filepath"
	"reflect"
	"testing"
	"unsafe"

	"golang.org/x/sys/windows"
)

// The explicit Users entries on dir, in DACL order, as mask/flags pairs.
func windowsTestUsersEntries(t *testing.T, dir string) (string, [][2]uint32) {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		t.Fatal(err)
	}
	var entries [][2]uint32
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			t.Fatal(err)
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).IsWellKnown(windows.WinBuiltinUsersSid) {
			entries = append(entries, [2]uint32{uint32(ace.Mask), uint32(ace.Header.AceFlags)})
		}
	}
	return sd.String(), entries
}

// GAP-0578 adds the Users check rights to an Administrators-only vendor
// directory; GAP-0867 never widens a Users entry it finds there.
func TestEnsureWindowsDirectoryUsersReadable(t *testing.T) {
	administrators, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	for _, tc := range []struct {
		name, sddl string
		want       [][2]uint32 // nil: DACL must stay byte-identical
	}{
		{"admin-only", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)", [][2]uint32{{0x1200a0, 0}}},
		{"users-fx-as-found", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;FX;;;BU)", nil},
		{"users-0x1200a8-as-found", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x1200a8;;;BU)", nil},
		{"users-narrow", "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;0x120000;;;BU)", [][2]uint32{{0x120000, 0}, {0xa0, 0}}},
	} {
		t.Run(tc.name, func(t *testing.T) {
			dir := filepath.Join(t.TempDir(), "Cisco")
			if err := os.Mkdir(dir, 0o700); err != nil {
				t.Fatal(err)
			}
			sd, err := windows.SecurityDescriptorFromString(tc.sddl)
			if err != nil {
				t.Fatal(err)
			}
			dacl, _, _ := sd.DACL()
			if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
				windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
				administrators, nil, dacl, nil); err != nil {
				t.Skipf("cannot set an Administrators owner in this test context: %v", err)
			}
			before, _ := windowsTestUsersEntries(t, dir)
			for pass := 0; pass < 2; pass++ {
				if err := ensureWindowsDirectoryUsersReadable(dir); err != nil {
					t.Fatalf("pass %d: %v", pass, err)
				}
			}
			after, entries := windowsTestUsersEntries(t, dir)
			if tc.want == nil {
				if after != before {
					t.Fatalf("a Users entry that already grants the rights changed:\n before %s\n after  %s", before, after)
				}
				return
			}
			if !reflect.DeepEqual(entries, tc.want) {
				t.Fatalf("Users entries = %#x, want %#x (DACL %s)", entries, tc.want, after)
			}
		})
	}
}
