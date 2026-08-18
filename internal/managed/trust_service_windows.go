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
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// ValidateTrustedServiceRuntimeDir permits the exact NT SERVICE virtual
// account installed for the gateway to write the managed runtime tree. That
// exception is deliberately opt-in and is never used for config, binaries,
// guardian manifests, or the protected authorization ledger.
func ValidateTrustedServiceRuntimeDir(path, label, serviceAccount string) error {
	if label == "" {
		label = "managed runtime dir"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	for cur := clean; ; cur = filepath.Dir(cur) {
		ancestor := cur != clean
		if err := validateTrustedWindowsServicePathElement(cur, true, label, serviceSID, ancestor); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

// ValidateTrustedServiceRuntimeFilePath applies the same narrow service-SID
// writer exception to a regular runtime file such as a scoped token.
func ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount string) error {
	if label == "" {
		label = "managed runtime file"
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if err := validateTrustedWindowsServicePathElement(clean, false, label, serviceSID, false); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsServicePathElement(dir, true, label, serviceSID, true); err != nil {
			return err
		}
	}
	return validateTrustedWindowsServicePathElement(
		filepath.VolumeName(clean)+string(filepath.Separator),
		true,
		label,
		serviceSID,
		true,
	)
}

// WindowsServiceAccountSID resolves a narrowly validated NT SERVICE virtual
// account for Windows-only ACL construction. Callers must still choose the
// service-runtime versus strict administrator trust API for each path.
func WindowsServiceAccountSID(account string) (*windows.SID, error) {
	return windowsVirtualServiceSID(account)
}

func windowsVirtualServiceSID(account string) (*windows.SID, error) {
	account = strings.TrimSpace(account)
	if account == "" {
		return nil, nil
	}
	const prefix = `NT SERVICE\`
	if len(account) <= len(prefix) || !strings.EqualFold(account[:len(prefix)], prefix) {
		return nil, fmt.Errorf(
			"%s must identify an NT SERVICE virtual account, got %q",
			WindowsServiceAccountEnv,
			account,
		)
	}
	name := account[len(prefix):]
	for _, char := range name {
		if (char >= 'a' && char <= 'z') ||
			(char >= 'A' && char <= 'Z') ||
			(char >= '0' && char <= '9') ||
			char == '_' || char == '.' || char == '-' {
			continue
		}
		return nil, fmt.Errorf("%s contains an invalid service name: %q", WindowsServiceAccountEnv, account)
	}
	if len(name) > 128 {
		return nil, fmt.Errorf("%s service name is too long", WindowsServiceAccountEnv)
	}
	sid, _, _, err := windows.LookupSID("", account)
	if err != nil {
		return nil, fmt.Errorf("resolve Windows virtual service account %q: %w", account, err)
	}
	return sid, nil
}

func validateTrustedWindowsServicePathElement(
	path string,
	wantDir bool,
	label string,
	allowedWriter *windows.SID,
	ancestor bool,
) error {
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
	extendedPath, err := winpath.Extended(path)
	if err != nil {
		return fmt.Errorf("%s: encode extended Windows path: %w", path, err)
	}
	sd, err := windows.GetNamedSecurityInfo(
		extendedPath,
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
	if !windowsTrustedServicePathOwner(owner, allowedWriter) {
		return fmt.Errorf("%s: owner %s is not trusted for %s; expected Administrators, LocalSystem, or TrustedInstaller", path, sidString(owner), label)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows DACL: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s: null Windows DACL is not trusted", path)
	}
	return rejectUntrustedWindowsServiceWriteACEs(path, dacl, allowedWriter, ancestor)
}

func rejectUntrustedWindowsServiceWriteACEs(
	path string,
	dacl *windows.ACL,
	allowedWriter *windows.SID,
	ancestor bool,
) error {
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
		if ace == nil {
			continue
		}
		// OBJECT_INHERIT_ACE on a directory propagates the ACE to newly
		// created child files as an EFFECTIVE ACE. When we are validating
		// an ancestor of a not-yet-created runtime file, an INHERIT_ONLY
		// allow ACE with OBJECT_INHERIT_ACE still lets a caller grant the
		// child write access via inheritance, so it must be evaluated.
		inheritsToChildFile := ancestor && ace.Header.AceFlags&windows.OBJECT_INHERIT_ACE != 0
		isInheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		if isInheritOnly && !inheritsToChildFile {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("%s: unsupported allow ACE type 0x%x; refusing managed trust", path, ace.Header.AceType)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		// CREATOR OWNER / CREATOR GROUP resolve to the file's own owner at
		// creation time. The child's actual owner is verified independently
		// by validateTrustedWindowsServicePathElement, so an inheritable
		// placeholder ACE on the parent is not itself a trust breach.
		if inheritsToChildFile && windowsServicePlaceholderSID(sid) {
			continue
		}
		var writeLike bool
		switch {
		case inheritsToChildFile:
			// The ACE will land on the child file with its full mask. Use
			// the file-level write rule so a granted FILE_WRITE_DATA (which
			// WindowsAncestorReplaceAccess excludes) is caught.
			writeLike = windowsWriteLikeAccess(ace.Mask)
		case ancestor && !windowsServiceWorldSID(sid):
			writeLike = WindowsAncestorReplaceAccess(ace.Mask)
		default:
			writeLike = windowsWriteLikeAccess(ace.Mask)
		}
		if !writeLike {
			continue
		}
		if !windowsTrustedOwner(sid) && !sameWindowsServiceSID(sid, allowedWriter) {
			return fmt.Errorf("%s: untrusted Windows principal %s has write-like access mask 0x%x", path, sidString(sid), uint32(ace.Mask))
		}
	}
	return nil
}

func windowsServicePlaceholderSID(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	return sid.IsWellKnown(windows.WinCreatorOwnerSid) ||
		sid.IsWellKnown(windows.WinCreatorGroupSid)
}

// WindowsAncestorReplaceAccess reports whether mask lets a principal replace a
// protected child. Narrower than the leaf rule: stock Windows grants Users
// add-file and write-EA/attributes on roots like C:\ProgramData, none of which
// can replace an existing child.
func WindowsAncestorReplaceAccess(mask windows.ACCESS_MASK) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	dangerous := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.GENERIC_WRITE |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)
	return mask&(dangerous|fileDeleteChild) != 0
}

func windowsServiceWorldSID(sid *windows.SID) bool {
	return sid != nil && sid.IsWellKnown(windows.WinWorldSid)
}

func windowsTrustedServicePathOwner(owner, allowedServiceOwner *windows.SID) bool {
	return windowsTrustedOwner(owner) || sameWindowsServiceSID(owner, allowedServiceOwner)
}

func sameWindowsServiceSID(left, right *windows.SID) bool {
	return left != nil && right != nil && left.Equals(right)
}
