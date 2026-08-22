// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"fmt"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/safefile"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

var (
	windowsTargetsManifestAncestorTrust = func(path string) error {
		return managed.ValidateTrustedDirectoryAncestor(path, "hook guardian manifest parent")
	}
	windowsTargetsManifestProtect = protectWindowsTargetsManifestObject
	windowsTargetsManifestReplace = safefile.ReplaceFile
)

// protectWindowsTargetsManifestObject applies the installer AdminDirectory or
// AdminFile contract: Administrators owns the object and is its primary group,
// while only SYSTEM and Administrators receive FullControl through a protected
// DACL. The object-shape preflight runs before SetNamedSecurityInfo so a
// reparse point or multiply-linked regular file is never adopted.
func protectWindowsTargetsManifestObject(path string, directory bool) error {
	if err := validateWindowsTargetsManifestObjectShape(path, directory); err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve Administrators SID: %w", err)
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve LocalSystem SID: %w", err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 2)
	for _, sid := range []*windows.SID{system, administrators} {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: windows.GENERIC_ALL,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       inheritance,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return fmt.Errorf("enterprise hooks: build hook guardian manifest DACL: %w", err)
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	securityInformation := windows.SECURITY_INFORMATION(
		windows.OWNER_SECURITY_INFORMATION |
			windows.GROUP_SECURITY_INFORMATION |
			windows.DACL_SECURITY_INFORMATION |
			windows.PROTECTED_DACL_SECURITY_INFORMATION,
	)
	if err := windows.SetNamedSecurityInfo(
		extended,
		windows.SE_FILE_OBJECT,
		securityInformation,
		administrators,
		administrators,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("enterprise hooks: protect hook guardian manifest object %s: %w", path, err)
	}
	return validateWindowsTargetsManifestObject(path, directory)
}

func validateWindowsTargetsManifestObject(path string, directory bool) error {
	handle, err := openWindowsTargetsManifestObject(path, directory, windows.READ_CONTROL|windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	defer windows.CloseHandle(handle)
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|
			windows.GROUP_SECURITY_INFORMATION|
			windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect hook guardian manifest security for %s: %w", path, err)
	}
	if descriptor == nil {
		return fmt.Errorf("enterprise hooks: hook guardian manifest security descriptor is missing: %s", path)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || !owner.Equals(administrators) {
		return fmt.Errorf("enterprise hooks: hook guardian manifest object has noncanonical owner: %s", path)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil || !group.Equals(administrators) {
		return fmt.Errorf("enterprise hooks: hook guardian manifest object has noncanonical group: %s", path)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect hook guardian manifest DACL control for %s: %w", path, err)
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("enterprise hooks: hook guardian manifest DACL is not protected: %s", path)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("enterprise hooks: hook guardian manifest has no canonical DACL: %s", path)
	}
	if dacl.AceCount != 2 {
		return fmt.Errorf("enterprise hooks: hook guardian manifest DACL has %d ACEs, want 2: %s", dacl.AceCount, path)
	}
	wantFlags := uint8(0)
	if directory {
		wantFlags = uint8(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	}
	coverage := map[string]bool{
		system.String():         false,
		administrators.String(): false,
	}
	fullAccess := map[windows.ACCESS_MASK]bool{
		windows.GENERIC_ALL:                                true,
		windows.ACCESS_MASK(0x001f01ff):                    true, // FILE_ALL_ACCESS
		mapWindowsUserPathGenericMask(windows.GENERIC_ALL): true,
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("enterprise hooks: inspect hook guardian manifest ACE %d for %s: %w", index, path, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != wantFlags || !fullAccess[ace.Mask] {
			return fmt.Errorf("enterprise hooks: hook guardian manifest has a noncanonical access rule: %s", path)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid == nil || !sid.IsValid() {
			return fmt.Errorf("enterprise hooks: hook guardian manifest has an invalid access principal: %s", path)
		}
		seen, ok := coverage[sid.String()]
		if !ok || seen {
			return fmt.Errorf("enterprise hooks: hook guardian manifest grants an unexpected or duplicate principal: %s", path)
		}
		coverage[sid.String()] = true
	}
	for sid, seen := range coverage {
		if !seen {
			return fmt.Errorf("enterprise hooks: hook guardian manifest DACL omits %s: %s", sid, path)
		}
	}
	return nil
}

func validateWindowsTargetsManifestObjectShape(path string, directory bool) error {
	handle, err := openWindowsTargetsManifestObject(path, directory, windows.FILE_READ_ATTRIBUTES)
	if err != nil {
		return err
	}
	return windows.CloseHandle(handle)
}

func openWindowsTargetsManifestObject(path string, directory bool, access uint32) (windows.Handle, error) {
	if err := winpath.RejectReparseChain(path); err != nil {
		return 0, fmt.Errorf("enterprise hooks: hook guardian manifest path contains a reparse point: %w", err)
	}
	info, err := os.Lstat(path)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: inspect hook guardian manifest object %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || info.IsDir() != directory || (!directory && !info.Mode().IsRegular()) {
		return 0, fmt.Errorf("enterprise hooks: hook guardian manifest object has an unexpected type: %s", path)
	}
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return 0, err
	}
	flags := uint32(windows.FILE_FLAG_OPEN_REPARSE_POINT)
	if directory {
		flags |= windows.FILE_FLAG_BACKUP_SEMANTICS
	}
	handle, err := windows.CreateFile(
		pointer,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		flags,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: open hook guardian manifest object without following %s: %w", path, err)
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		windows.CloseHandle(handle)
		return 0, fmt.Errorf("enterprise hooks: inspect hook guardian manifest object %s: %w", path, err)
	}
	if handleInfo.FileAttributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DEVICE) != 0 ||
		(handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0) != directory {
		windows.CloseHandle(handle)
		return 0, fmt.Errorf("enterprise hooks: refusing unsafe hook guardian manifest object: %s", path)
	}
	if !directory && handleInfo.NumberOfLinks != 1 {
		windows.CloseHandle(handle)
		return 0, fmt.Errorf("enterprise hooks: refusing hook guardian manifest with %d hard links: %s", handleInfo.NumberOfLinks, path)
	}
	return handle, nil
}
