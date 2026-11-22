// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package cli

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

// An owner-less SDDL (windowsInstallFileSDDL, D:P(...)) applies to a real
// file: the owner is left as it is and the protected DACL is set. Asking
// Windows to set the owner from that SDDL failed with "The parameter is
// incorrect", so the hook-image retire marker never got its protection and
// Setup 1.0.9 /upgrade ended 1603 with every service disabled
// (rel-1-0-10:GAP-0840).
func TestApplyWindowsSDDLWithoutAnOwnerSetsTheProtectedDACL(t *testing.T) {
	path := filepath.Join(t.TempDir(), ".retired")
	if err := os.WriteFile(path, []byte("{}"), 0o600); err != nil {
		t.Fatal(err)
	}
	before, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ownerBefore, _, err := before.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if err := applyWindowsSDDL(path, windowsInstallFileSDDL); err != nil {
		t.Fatalf("apply %s: %v", windowsInstallFileSDDL, err)
	}
	after, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		t.Fatal(err)
	}
	ownerAfter, _, err := after.Owner()
	if err != nil {
		t.Fatal(err)
	}
	if !ownerAfter.Equals(ownerBefore) {
		t.Fatalf("owner changed from %s to %s for an owner-less SDDL", ownerBefore, ownerAfter)
	}
	control, _, err := after.Control()
	if err != nil {
		t.Fatal(err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		t.Fatal("the DACL is not protected")
	}
	if text := after.String(); !strings.Contains(text, "(A;;FA;;;SY)") || !strings.Contains(text, "(A;;FA;;;BA)") {
		t.Fatalf("DACL = %s, want the install-file entries", text)
	}
}

// The retire marker fails closed: a protection that cannot be set leaves no
// marker, and a marker whose protection is set is kept (rel-1-0-10:GAP-0840).
func TestRetiredMarkerWriteLeavesNoMarkerWhenProtectionFails(t *testing.T) {
	dir := t.TempDir()
	failing := filepath.Join(dir, "failing.retired")
	err := writeWindowsHookImageRetiredMarker(failing, []byte("{}"), func(string, string) error {
		return errors.New("The parameter is incorrect.")
	})
	if err == nil {
		t.Fatal("a failed protection was reported as written")
	}
	if _, statErr := os.Stat(failing); !errors.Is(statErr, os.ErrNotExist) {
		t.Fatalf("an unprotected marker was left behind: %v", statErr)
	}
	ok := filepath.Join(dir, "ok.retired")
	if err := writeWindowsHookImageRetiredMarker(ok, []byte("{}"), applyWindowsSDDL); err != nil {
		t.Fatalf("real marker write: %v", err)
	}
	if _, err := os.Stat(ok); err != nil {
		t.Fatalf("the protected marker is missing: %v", err)
	}
}
