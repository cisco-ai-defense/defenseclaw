//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func ValidateTrustedConfigPath(path string) error {
	return ValidateTrustedFilePath(path, "managed config")
}

func ValidateTrustedFilePath(path, label string) error {
	if label == "" {
		label = "managed file"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if err := validateTrustedWindowsPathElement(clean, false, label); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElement(dir, true, label); err != nil {
			return err
		}
	}
	return validateTrustedWindowsPathElement(filepath.VolumeName(clean)+string(filepath.Separator), true, label)
}

func ValidateTrustedRuntimeDir(path, label string) error {
	if label == "" {
		label = "managed runtime dir"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	for cur := clean; ; cur = filepath.Dir(cur) {
		if err := validateTrustedWindowsPathElement(cur, true, label); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

func validateTrustedWindowsPathElement(path string, wantDir bool, label string) error {
	info, err := os.Lstat(path)
	if err != nil {
		return fmt.Errorf("%s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 {
		return fmt.Errorf("%s: symlinks are not allowed in %s path", path, label)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("%s: expected directory in %s path", path, label)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("%s: expected regular %s file", path, label)
	}
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("%s: inspect Windows security descriptor: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("%s: missing Windows security descriptor", path)
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows owner: %w", path, err)
	}
	if !windowsTrustedOwner(owner) {
		return fmt.Errorf("%s: owner %s is not trusted for %s; expected Administrators, LocalSystem, or TrustedInstaller", path, sidString(owner), label)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows DACL: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s: null Windows DACL is not trusted", path)
	}
	if err := rejectUntrustedWindowsWriteACEs(path, dacl); err != nil {
		return err
	}
	return nil
}

func rejectUntrustedWindowsWriteACEs(path string, dacl *windows.ACL) error {
	const (
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("%s: inspect Windows ACE %d: %w", path, i, err)
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("%s: unsupported allow ACE type 0x%x; refusing managed trust", path, ace.Header.AceType)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		if !windowsWriteLikeAccess(ace.Mask) {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !windowsTrustedOwner(sid) {
			return fmt.Errorf("%s: untrusted Windows principal %s has write-like access mask 0x%x", path, sidString(sid), uint32(ace.Mask))
		}
	}
	return nil
}

func windowsWriteLikeAccess(mask windows.ACCESS_MASK) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	writeLike := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.GENERIC_WRITE |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES,
	)
	return mask&(writeLike|fileDeleteChild) != 0
}

func windowsTrustedOwner(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	if err != nil {
		return false
	}
	return sid.Equals(trustedInstaller)
}

func sidString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}
