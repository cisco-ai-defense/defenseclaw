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

const (
	windowsTargetsManifestAdminDirectorySDDL = "O:BAG:BAD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;BA)"
	windowsTargetsManifestAdminFileSDDL      = "O:BAG:BAD:P(A;;FA;;;SY)(A;;FA;;;BA)"
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
	descriptor, err := windowsTargetsManifestCanonicalDescriptor(directory)
	if err != nil {
		return err
	}
	administrators, _, err := descriptor.Owner()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve hook guardian manifest owner: %w", err)
	}
	group, _, err := descriptor.Group()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve hook guardian manifest group: %w", err)
	}
	acl, _, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve hook guardian manifest DACL: %w", err)
	}
	if acl == nil {
		return fmt.Errorf("enterprise hooks: canonical hook guardian manifest DACL is missing")
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
		group,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("enterprise hooks: protect hook guardian manifest object %s: %w", path, err)
	}
	return validateWindowsTargetsManifestObject(path, directory)
}

// windowsTargetsManifestCanonicalDescriptor is deliberately derived from the
// same SDDL contract as the installer's AdminDirectory/AdminFile ACLs. In
// particular, FA is the concrete FILE_ALL_ACCESS mask: using inheritable
// GENERIC_ALL here makes NTFS split each rule into an effective mapped ACE and
// a generic inherit-only ACE, publishing a different four-ACE DACL.
func windowsTargetsManifestCanonicalDescriptor(directory bool) (*windows.SECURITY_DESCRIPTOR, error) {
	sddl := windowsTargetsManifestAdminFileSDDL
	if directory {
		sddl = windowsTargetsManifestAdminDirectorySDDL
	}
	descriptor, err := windows.SecurityDescriptorFromString(sddl)
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: build canonical hook guardian manifest descriptor: %w", err)
	}
	return descriptor, nil
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
	expected, err := windowsTargetsManifestCanonicalDescriptor(directory)
	if err != nil {
		return err
	}
	expectedOwner, _, err := expected.Owner()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect canonical hook guardian manifest owner: %w", err)
	}
	expectedGroup, _, err := expected.Group()
	if err != nil {
		return fmt.Errorf("enterprise hooks: inspect canonical hook guardian manifest group: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil || expectedOwner == nil || !owner.Equals(expectedOwner) {
		return fmt.Errorf("enterprise hooks: hook guardian manifest object has noncanonical owner: %s", path)
	}
	group, _, err := descriptor.Group()
	if err != nil || group == nil || expectedGroup == nil || !group.Equals(expectedGroup) {
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
	expectedDACL, _, err := expected.DACL()
	if err != nil {
		return fmt.Errorf("enterprise hooks: canonical hook guardian manifest DACL is unavailable: %w", err)
	}
	if expectedDACL == nil {
		return fmt.Errorf("enterprise hooks: canonical hook guardian manifest DACL is missing")
	}
	if dacl.AceCount != expectedDACL.AceCount {
		return fmt.Errorf(
			"enterprise hooks: hook guardian manifest DACL has %d ACEs, want %d: %s",
			dacl.AceCount,
			expectedDACL.AceCount,
			path,
		)
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var actualACE *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &actualACE); err != nil {
			return fmt.Errorf("enterprise hooks: inspect hook guardian manifest ACE %d for %s: %w", index, path, err)
		}
		var expectedACE *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(expectedDACL, uint32(index), &expectedACE); err != nil {
			return fmt.Errorf("enterprise hooks: inspect canonical hook guardian manifest ACE %d: %w", index, err)
		}
		if actualACE == nil || expectedACE == nil ||
			actualACE.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			actualACE.Header.AceType != expectedACE.Header.AceType ||
			actualACE.Header.AceFlags != expectedACE.Header.AceFlags ||
			actualACE.Header.AceSize != expectedACE.Header.AceSize ||
			actualACE.Mask != expectedACE.Mask {
			return fmt.Errorf("enterprise hooks: hook guardian manifest has a noncanonical access rule at index %d: %s", index, path)
		}
		actualSID := (*windows.SID)(unsafe.Pointer(&actualACE.SidStart))
		expectedSID := (*windows.SID)(unsafe.Pointer(&expectedACE.SidStart))
		if actualSID == nil || expectedSID == nil || !actualSID.IsValid() || !expectedSID.IsValid() {
			return fmt.Errorf("enterprise hooks: hook guardian manifest has an invalid access principal: %s", path)
		}
		if !actualSID.Equals(expectedSID) {
			return fmt.Errorf("enterprise hooks: hook guardian manifest has a noncanonical principal at index %d: %s", index, path)
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
