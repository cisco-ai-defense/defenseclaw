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
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestEnsureWindowsDirectoryUsersReadableAddsOnlyUsersRead(t *testing.T) {
	dir := filepath.Join(t.TempDir(), "Cisco")
	if err := os.Mkdir(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	administrators, _ := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	adminOnly, err := windows.SecurityDescriptorFromString("D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)")
	if err != nil {
		t.Fatal(err)
	}
	dacl, _, _ := adminOnly.DACL()
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		administrators, nil, dacl, nil); err != nil {
		t.Skipf("cannot set an Administrators owner in this test context: %v", err)
	}
	if err := ensureWindowsDirectoryUsersReadable(dir); err != nil {
		t.Fatalf("grant users read: %v", err)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	got := after.String()
	if !strings.HasPrefix(got, "D:P") || !strings.Contains(got, "(A;OICI;FA;;;SY)") ||
		!strings.Contains(got, "(A;OICI;FA;;;BA)") || !strings.Contains(got, ";;;BU)") {
		t.Fatalf("DACL after grant = %s, want protected SY/BA plus a Users entry", got)
	}
	if strings.Contains(got, "CI;0x1200a9;;;BU)") || strings.Contains(got, "OI;0x1200a9;;;BU)") {
		t.Fatalf("users entry must not be inheritable: %s", got)
	}
	if err := ensureWindowsDirectoryUsersReadable(dir); err != nil {
		t.Fatalf("second grant: %v", err)
	}
	again, _ := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if strings.Count(again.String(), ";;;BU)") != 1 {
		t.Fatalf("grant is not idempotent: %s", again.String())
	}
}
