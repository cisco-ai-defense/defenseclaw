// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
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
	rootTarget, err := singleDOSDeviceTarget(volume)
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
	rootTarget, err := singleDOSDeviceTarget(volume)
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
