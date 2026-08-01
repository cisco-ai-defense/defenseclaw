// Copyright 2026 Cisco Systems, Inc. and its affiliates
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

func TestValidateWindowsEnterpriseProfileVolumeRejectsRawPerLogonAlias(t *testing.T) {
	target := t.TempDir()
	volume := filepath.VolumeName(target)
	if len(volume) != 2 {
		t.Skipf("test temp path has no drive letter: %s", target)
	}
	volumePtr, err := windows.UTF16PtrFromString(volume)
	if err != nil {
		t.Fatal(err)
	}
	targetBuffer := make([]uint16, 1024)
	n, err := windows.QueryDosDevice(volumePtr, &targetBuffer[0], uint32(len(targetBuffer)))
	if err != nil || n == 0 {
		t.Fatalf("resolve test volume device target: %v", err)
	}
	rawTarget := windows.UTF16ToString(targetBuffer[:n]) +
		strings.TrimPrefix(filepath.Clean(target), volume)

	const alias = `M:`
	if mask, err := windows.GetLogicalDrives(); err != nil ||
		mask&(uint32(1)<<('M'-'A')) != 0 {
		t.Skip("M: is unavailable for raw-alias regression")
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
		t.Skipf("cannot create per-logon raw DOS alias: %v", err)
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
			t.Errorf("remove raw DOS alias %s: %v", alias, err)
		}
	})

	aliasRoot := alias + `\`
	if _, err := os.Stat(aliasRoot); err != nil {
		t.Fatalf("raw alias is not accessible: %v", err)
	}
	if err := validateWindowsEnterpriseProfileVolume(aliasRoot); err == nil ||
		!strings.Contains(strings.ToLower(err.Error()), "mount-manager") {
		t.Fatalf("raw per-logon alias error = %v, want mount-manager refusal", err)
	}
}
