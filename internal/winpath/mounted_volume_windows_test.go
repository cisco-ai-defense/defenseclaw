// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"golang.org/x/sys/windows"
)

func TestValidateFixedNTFSMountedPathAcceptsCurrentMountedDrive(t *testing.T) {
	identity, err := ValidateFixedNTFSMountedPath(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	if identity.DriveRoot == "" || identity.VolumeName == "" ||
		identity.DeviceTarget == "" || !strings.EqualFold(identity.FileSystem, "NTFS") {
		t.Fatalf("incomplete mounted-volume identity: %+v", identity)
	}
}

func TestValidateFixedNTFSMountedPathRejectsRawPerLogonDriveAlias(t *testing.T) {
	target := t.TempDir()
	volume := filepath.VolumeName(target)
	if len(volume) != 2 {
		t.Skipf("test temp path has no drive letter: %s", target)
	}
	rootTarget, err := globalDOSDeviceTarget(volume)
	if err != nil {
		t.Fatal(err)
	}
	rawTarget := rootTarget + strings.TrimPrefix(filepath.Clean(target), volume)

	alias, ok := unusedDriveLetter('Q')
	if !ok {
		t.Skip("no unused drive letter available for raw-alias regression")
	}
	aliasPtr, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		t.Fatal(err)
	}
	targetPtr, err := windows.UTF16PtrFromString(rawTarget)
	if err != nil {
		t.Fatal(err)
	}
	const noBroadcast = 0x00000008
	if err := windows.DefineDosDevice(
		windows.DDD_RAW_TARGET_PATH|noBroadcast,
		aliasPtr,
		targetPtr,
	); err != nil {
		t.Skipf("cannot create a per-logon raw DOS alias: %v", err)
	}
	t.Cleanup(func() {
		err := windows.DefineDosDevice(
			windows.DDD_REMOVE_DEFINITION|
				windows.DDD_EXACT_MATCH_ON_REMOVE|
				windows.DDD_RAW_TARGET_PATH|
				noBroadcast,
			aliasPtr,
			targetPtr,
		)
		if err != nil {
			t.Errorf("remove raw DOS alias %s: %v", alias, err)
		}
	})

	aliasRoot := alias + `\`
	if _, err := os.Stat(aliasRoot); err != nil {
		t.Fatalf("raw DOS alias is not accessible: %v", err)
	}
	rootPtr, err := windows.UTF16PtrFromString(aliasRoot)
	if err != nil {
		t.Fatal(err)
	}
	if got := windows.GetDriveType(rootPtr); got != windows.DRIVE_FIXED {
		t.Fatalf("raw alias drive type = %d, want DRIVE_FIXED", got)
	}
	if _, err := ValidateFixedNTFSMountedPath(filepath.Join(aliasRoot, "probe")); err == nil {
		t.Fatal("raw per-logon DOS alias passed mount-manager validation")
	}
}

func TestValidateFixedNTFSMountedPathRejectsWholeVolumePerLogonAlias(t *testing.T) {
	target := t.TempDir()
	volume := filepath.VolumeName(target)
	if len(volume) != 2 {
		t.Skipf("test temp path has no drive letter: %s", target)
	}
	rootTarget, err := globalDOSDeviceTarget(volume)
	if err != nil {
		t.Fatal(err)
	}
	alias, ok := unusedDriveLetter('P')
	if !ok {
		t.Skip("P: is unavailable for whole-volume raw-alias regression")
	}
	aliasPtr, err := windows.UTF16PtrFromString(alias)
	if err != nil {
		t.Fatal(err)
	}
	targetPtr, err := windows.UTF16PtrFromString(rootTarget)
	if err != nil {
		t.Fatal(err)
	}
	const noBroadcast = 0x00000008
	if err := windows.DefineDosDevice(
		windows.DDD_RAW_TARGET_PATH|noBroadcast,
		aliasPtr,
		targetPtr,
	); err != nil {
		t.Skipf("cannot create whole-volume per-logon DOS alias: %v", err)
	}
	t.Cleanup(func() {
		if err := windows.DefineDosDevice(
			windows.DDD_REMOVE_DEFINITION|
				windows.DDD_EXACT_MATCH_ON_REMOVE|
				windows.DDD_RAW_TARGET_PATH|
				noBroadcast,
			aliasPtr,
			targetPtr,
		); err != nil {
			t.Errorf("remove whole-volume raw DOS alias %s: %v", alias, err)
		}
	})

	aliasRoot := alias + `\`
	if _, err := os.Stat(aliasRoot); err != nil {
		t.Fatalf("whole-volume raw DOS alias is not accessible: %v", err)
	}
	if _, err := ValidateFixedNTFSMountedPath(
		filepath.Join(aliasRoot, "Windows"),
	); err == nil {
		t.Fatal("whole-volume per-logon DOS alias passed mount-manager validation")
	}
}

func TestValidateFixedNTFSMountedPathRejectsDriveRelativeAndDeviceSyntax(t *testing.T) {
	for _, path := range []string{
		`C:`,
		`C:relative`,
		`relative`,
		`\\server\share\file`,
		`\\?\C:\file`,
		`\\.\C:\file`,
		`C:\file:stream`,
	} {
		if _, err := ValidateFixedNTFSMountedPath(path); err == nil {
			t.Fatalf("ValidateFixedNTFSMountedPath(%q) succeeded", path)
		}
	}
}

func TestParseMultiSZ(t *testing.T) {
	input := []uint16{'a', 0, 'b', 'c', 0, 0, 'x'}
	got := parseMultiSZ(input)
	if len(got) != 2 || got[0] != "a" || got[1] != "bc" {
		t.Fatalf("parseMultiSZ = %#v", got)
	}
}

func unusedDriveLetter(letter byte) (string, bool) {
	mask, err := windows.GetLogicalDrives()
	if err != nil {
		return "", false
	}
	if mask&(uint32(1)<<(letter-'A')) != 0 {
		return "", false
	}
	return string([]byte{letter, ':'}), true
}

// TestEffectiveDriveTargetByHandleMatchesTheDOSDevice pins the fallback of a
// token that cannot query its DOS-device directory (GAP-0052) to what
// QueryDosDevice answers for a token that can: the system drive resolves to
// the same kernel device both ways, and to the global one.
func TestEffectiveDriveTargetByHandleMatchesTheDOSDevice(t *testing.T) {
	root := strings.ToUpper(os.Getenv("SystemDrive")) + `\`
	if len(root) != 3 {
		t.Skip("no SystemDrive")
	}
	byHandle, err := effectiveDriveTargetByHandle(root)
	if err != nil {
		t.Fatal(err)
	}
	global, err := globalDOSDeviceTarget(strings.TrimSuffix(root, `\`))
	if err != nil {
		t.Fatal(err)
	}
	nt, err := globalSymbolicLinkTarget(strings.TrimSuffix(root, `\`))
	if err != nil || !strings.EqualFold(nt, global) {
		t.Fatalf("\\GLOBAL?? link %q (%v), global %q", nt, err, global)
	}
	if !strings.EqualFold(byHandle, global) {
		t.Fatalf("by handle %q, global %q", byHandle, global)
	}
	effective, err := singleDOSDeviceTarget(strings.TrimSuffix(root, `\`))
	switch {
	case errors.Is(err, windows.ERROR_ACCESS_DENIED):
		t.Logf("this token cannot query %s (deny-only Administrators); by handle %s", root, byHandle)
	case err != nil:
		t.Fatal(err)
	case !strings.EqualFold(effective, byHandle):
		t.Fatalf("QueryDosDevice %q, by handle %q", effective, byHandle)
	default:
		t.Logf("QueryDosDevice and by handle agree: %s", byHandle)
	}
	if _, err := ValidateFixedNTFSMountedPath(root + "Windows"); err != nil {
		t.Fatalf("system drive refused: %v", err)
	}
	if _, err := ValidateTrustedMachineRoot(os.Getenv("ProgramFiles"), "Program Files"); err != nil {
		t.Fatalf("Program Files refused: %v", err)
	}
	if _, err := LocalPathIdentity(os.Args[0]); err != nil {
		t.Fatalf("the test binary is not a local path: %v", err)
	}
}
