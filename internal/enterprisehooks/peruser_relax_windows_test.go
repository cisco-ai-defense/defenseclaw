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

func TestRelaxStandalonePerUserDirectoryRestoresOwnerPrivateShape(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, ".defenseclaw", "connector_backups", "amp")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	ownerDescriptor, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	owner, _, err := ownerDescriptor.Owner()
	if err != nil {
		t.Fatal(err)
	}
	// The guardian's hardened shape: machine principals full, the owner's
	// implicit WRITE_DAC removed through a read-only OWNER RIGHTS entry.
	hardened, err := windows.SecurityDescriptorFromString(
		"D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)(A;;RC;;;OW)(A;OICI;0x1301bf;;;" + owner.String() + ")",
	)
	if err != nil {
		t.Fatal(err)
	}
	hardenedDACL, _, err := hardened.DACL()
	if err != nil {
		t.Fatal(err)
	}
	if err := windows.SetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, hardenedDACL, nil); err != nil {
		t.Fatal(err)
	}

	target := windowsGenericManagedTarget{home: home, sid: owner}
	if err := relaxWindowsStandalonePerUserDirectory(target, dir); err != nil {
		t.Fatalf("relax hardened directory: %v", err)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.String(); !strings.HasPrefix(got, "D:P") || !strings.HasSuffix(got, "(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)") {
		t.Fatalf("relaxed DACL = %s, want the owner-private shape", got)
	}

	// Missing directories are a no-op; paths outside the home are refused.
	if err := relaxWindowsStandalonePerUserDirectory(target, filepath.Join(home, "absent")); err != nil {
		t.Fatalf("missing directory: %v", err)
	}
	outside := t.TempDir()
	if err := relaxWindowsStandalonePerUserDirectory(target, outside); err == nil {
		t.Fatal("directory outside the user home was relaxed")
	}
}

func TestRelaxStandalonePerUserDirectoryLeavesForeignOwnedDirectories(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "foreign")
	if err := os.MkdirAll(dir, 0o700); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	// LocalSystem never owns a test temp directory, so it stands in for a
	// target whose SID does not own this path.
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		t.Fatal(err)
	}
	if err := relaxWindowsStandalonePerUserDirectory(windowsGenericManagedTarget{home: home, sid: system}, dir); err != nil {
		t.Fatalf("foreign-owned directory: %v", err)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("foreign-owned directory DACL changed: %s -> %s", before, after)
	}
}
