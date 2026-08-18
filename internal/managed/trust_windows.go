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
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, nil, false); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, nil, true); err != nil {
			return err
		}
	}
	return validateTrustedWindowsPathElementWithWriter(
		filepath.VolumeName(clean)+string(filepath.Separator),
		true,
		label,
		nil,
		true,
	)
}

func ValidateTrustedRuntimeDir(path, label string) error {
	return validateTrustedWindowsRuntimeDir(path, label, nil)
}

// ValidateTrustedServiceRuntimeDir permits the exact NT SERVICE virtual
// account installed for the gateway to write the managed runtime tree. That
// exception is deliberately opt-in and is never used for config, binaries,
// guardian manifests, or the protected authorization ledger.
func ValidateTrustedServiceRuntimeDir(path, label, serviceAccount string) error {
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	return validateTrustedWindowsRuntimeDir(path, label, serviceSID)
}

// ValidateTrustedServiceRuntimeFilePath applies the same narrow service-SID
// writer exception to a regular runtime file such as a scoped token.
func ValidateTrustedServiceRuntimeFilePath(path, label, serviceAccount string) error {
	if label == "" {
		label = "managed runtime file"
	}
	serviceSID, err := windowsVirtualServiceSID(serviceAccount)
	if err != nil {
		return err
	}
	if path == "" {
		return fmt.Errorf("%s path is empty", label)
	}
	clean, err := filepath.Abs(path)
	if err != nil {
		return fmt.Errorf("resolve %s path: %w", label, err)
	}
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	if err := validateTrustedWindowsPathElementWithWriter(clean, false, label, serviceSID, false); err != nil {
		return err
	}
	for dir := filepath.Dir(clean); dir != filepath.Dir(dir); dir = filepath.Dir(dir) {
		if err := validateTrustedWindowsPathElementWithWriter(dir, true, label, serviceSID, true); err != nil {
			return err
		}
	}
	return validateTrustedWindowsPathElementWithWriter(
		filepath.VolumeName(clean)+string(filepath.Separator),
		true,
		label,
		serviceSID,
		true,
	)
}

func validateTrustedWindowsRuntimeDir(path, label string, allowedWriter *windows.SID) error {
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
	if _, err := winpath.ValidateFixedNTFSMountedPath(clean); err != nil {
		return fmt.Errorf("%s is not on a trusted mount-manager NTFS drive: %w", label, err)
	}
	for cur := clean; ; cur = filepath.Dir(cur) {
		ancestor := cur != clean
		if err := validateTrustedWindowsPathElementWithWriter(cur, true, label, allowedWriter, ancestor); err != nil {
			return err
		}
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

func validateTrustedWindowsPathElement(path string, wantDir bool, label string) error {
	return validateTrustedWindowsPathElementWithWriter(path, wantDir, label, nil, false)
}

func validateTrustedWindowsPathElementWithWriter(
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
	if err := rejectWindowsReparsePoint(path, label); err != nil {
		return err
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
	if !windowsTrustedPathOwner(owner, allowedWriter) {
		return fmt.Errorf("%s: owner %s is not trusted for %s; expected Administrators, LocalSystem, or TrustedInstaller", path, sidString(owner), label)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("%s: inspect Windows DACL: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("%s: null Windows DACL is not trusted", path)
	}
	if err := rejectUntrustedWindowsWriteACEsWithWriter(path, dacl, allowedWriter, ancestor); err != nil {
		return err
	}
	return nil
}

func rejectUntrustedWindowsWriteACEs(path string, dacl *windows.ACL) error {
	return rejectUntrustedWindowsWriteACEsWithWriter(path, dacl, nil, false)
}

func rejectUntrustedWindowsWriteACEsWithWriter(
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
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		writeLike := windowsWriteLikeAccess(ace.Mask)
		if ancestor && !windowsWorldSID(sid) {
			writeLike = WindowsAncestorReplaceAccess(ace.Mask)
		}
		if !writeLike {
			continue
		}
		if !windowsTrustedOwner(sid) && !sameWindowsSID(sid, allowedWriter) {
			return fmt.Errorf("%s: untrusted Windows principal %s has write-like access mask 0x%x", path, sidString(sid), uint32(ace.Mask))
		}
	}
	return nil
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

func rejectWindowsReparsePoint(path, label string) error {
	extendedPath, err := winpath.Extended(path)
	if err != nil {
		return fmt.Errorf("%s: encode extended Windows path: %w", path, err)
	}
	pathPtr, err := windows.UTF16PtrFromString(extendedPath)
	if err != nil {
		return fmt.Errorf("%s: encode Windows path: %w", path, err)
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("%s: inspect Windows file attributes: %w", path, err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("%s: reparse points are not allowed in %s path", path, label)
	}
	return nil
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
	// LookupSID resolved the `NT SERVICE\<name>` string, but a compromised
	// registrar could point the lookup at any SID. Bind trust to the NT
	// SERVICE authority (S-1-5-80-...) before returning: reject any SID
	// that is not under NT AUTHORITY (Value 5) with SubAuthority(0) == 80.
	if !sidIsNTService(sid) {
		return nil, fmt.Errorf(
			"resolved Windows virtual service account %q is not under NT SERVICE (S-1-5-80): %s",
			account, sidString(sid),
		)
	}
	return sid, nil
}

func sidIsNTService(sid *windows.SID) bool {
	if sid == nil || !sid.IsValid() {
		return false
	}
	authority := sid.IdentifierAuthority()
	// NT authority: {0, 0, 0, 0, 0, 5}. Only the last byte varies for known
	// authorities on modern Windows, so a byte-exact comparison is safe.
	if authority.Value != [6]byte{0, 0, 0, 0, 0, 5} {
		return false
	}
	if sid.SubAuthorityCount() < 1 {
		return false
	}
	const ntServiceSubAuthority uint32 = 80
	return sid.SubAuthority(0) == ntServiceSubAuthority
}

// WindowsServiceAccountSID resolves a narrowly validated NT SERVICE virtual
// account for Windows-only ACL construction. Callers must still choose the
// service-runtime versus strict administrator trust API for each path.
func WindowsServiceAccountSID(account string) (*windows.SID, error) {
	return windowsVirtualServiceSID(account)
}

func sameWindowsSID(left, right *windows.SID) bool {
	return left != nil && right != nil && left.Equals(right)
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

// windowsWorldSID reports whether sid is Everyone. The relaxed ancestor rule
// covers what stock Windows grants on roots like C:\ProgramData, which goes to
// BUILTIN\Users and Authenticated Users. Everyone gets nothing there, so a write
// right for it is deliberate and answers to the leaf rule.
func windowsWorldSID(sid *windows.SID) bool {
	return sid != nil && sid.IsWellKnown(windows.WinWorldSid)
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

func windowsTrustedPathOwner(owner, allowedServiceOwner *windows.SID) bool {
	return windowsTrustedOwner(owner) || sameWindowsSID(owner, allowedServiceOwner)
}

func sidString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}
