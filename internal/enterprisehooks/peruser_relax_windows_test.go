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
	if changed, err := relaxWindowsStandalonePerUserDirectory(target, dir); err != nil || !changed {
		t.Fatalf("relax hardened directory: changed=%v err=%v", changed, err)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if got := after.String(); !strings.HasPrefix(got, "D:P") || !strings.HasSuffix(got, "(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)") {
		t.Fatalf("relaxed DACL = %s, want the owner-private shape", got)
	}

	// Missing directories are a no-op; paths outside the home are refused.
	if changed, err := relaxWindowsStandalonePerUserDirectory(target, filepath.Join(home, "absent")); err != nil || changed {
		t.Fatalf("missing directory: changed=%v err=%v", changed, err)
	}
	outside := t.TempDir()
	if _, err := relaxWindowsStandalonePerUserDirectory(target, outside); err == nil {
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
	if changed, err := relaxWindowsStandalonePerUserDirectory(windowsGenericManagedTarget{home: home, sid: system}, dir); err != nil || changed {
		t.Fatalf("foreign-owned directory: changed=%v err=%v", changed, err)
	}
	after, err := windows.GetNamedSecurityInfo(dir, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	if before.String() != after.String() {
		t.Fatalf("foreign-owned directory DACL changed: %s -> %s", before, after)
	}
}

// A connector home can hold the agent's whole install (Hermes keeps about
// 130,000 objects under %LOCALAPPDATA%\hermes). The relax step must set the
// directory's own DACL only: rewriting every descendant made one guardian
// reconcile take minutes, so a lifecycle stopped the guardian halfway and left
// the user's hooks directory owner-private.
func TestRelaxStandalonePerUserDirectoryLeavesDescendantACLs(t *testing.T) {
	home := t.TempDir()
	dir := filepath.Join(home, "AppData", "Local", "hermes")
	nested := filepath.Join(dir, "hermes-agent", "venv")
	if err := os.MkdirAll(nested, 0o700); err != nil {
		t.Fatal(err)
	}
	file := filepath.Join(nested, "python.exe")
	if err := os.WriteFile(file, []byte("MZ"), 0o600); err != nil {
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
	// Harden the directory the way an earlier reconcile left it; this test
	// setup propagates the hardened inheritance to the descendants.
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
	beforeNested := windowsRelaxTestDACL(t, nested)
	beforeFile := windowsRelaxTestDACL(t, file)

	changed, err := relaxWindowsStandalonePerUserDirectory(windowsGenericManagedTarget{home: home, sid: owner}, dir)
	if err != nil || !changed {
		t.Fatalf("relax hardened connector home: changed=%v err=%v", changed, err)
	}
	if got := windowsRelaxTestDACL(t, dir); !strings.HasPrefix(got, "D:P") ||
		!strings.HasSuffix(got, "(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)") {
		t.Fatalf("relaxed DACL = %s, want the owner-private shape", got)
	}
	if got := windowsRelaxTestDACL(t, nested); got != beforeNested {
		t.Fatalf("relax rewrote a descendant directory ACL: %s -> %s", beforeNested, got)
	}
	if got := windowsRelaxTestDACL(t, file); got != beforeFile {
		t.Fatalf("relax rewrote a descendant file ACL: %s -> %s", beforeFile, got)
	}
}

func windowsRelaxTestDACL(t *testing.T, path string) string {
	t.Helper()
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatalf("read DACL of %s: %v", path, err)
	}
	return sd.String()
}

func TestTeardownKeepsAgentFoldersOwnerPrivate(t *testing.T) {
	// GAP-1243: a completed teardown hardened %APPDATA%\devin again, so the
	// account could not protect it after the uninstall.
	dataDir := `C:\Users\u\.defenseclaw`
	agent := `C:\Users\u\AppData\Roaming\devin`
	backups := filepath.Join(dataDir, "connector_backups", "devin")
	relaxed := []string{backups, agent, dataDir}

	got := windowsRelaxedPathsToRestoreAfterTeardown(dataDir, relaxed, true)
	if len(got) != 2 || got[0] != backups || got[1] != dataDir {
		t.Fatalf("after a completed teardown restore = %v, want only the data directory paths", got)
	}
	if got := windowsRelaxedPathsToRestoreAfterTeardown(dataDir, relaxed, false); len(got) != len(relaxed) {
		t.Fatalf("after a failed teardown restore = %v, want every relaxed path", got)
	}
}
