//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// ensureWindowsTargetOwnedDirectoryTree creates only missing descendants of
// the authenticated target profile. Each directory receives its target owner
// and exact protected canonical DACL in the native create call, so an elevated
// target token's Administrators default owner cannot leak into the managed
// runtime and no weaker staging descriptor is ever published. The still-bound
// no-follow handle verifies that exact contract before it is released.
//
// Existing descendants are never adopted or repaired here: every one must
// already have the exact target-owner/DACL contract. All traversal is relative
// to no-follow directory handles, which prevents a concurrent reparse-point
// swap from redirecting creation outside the profile.
type windowsTargetOwnedDirectoryCreation struct {
	createdDataDir bool
	createdHookDir bool
}

func ensureWindowsTargetOwnedDirectoryTree(
	home string,
	path string,
	target *windows.SID,
) (windowsTargetOwnedDirectoryCreation, error) {
	var creation windowsTargetOwnedDirectoryCreation
	err := ensureWindowsTargetOwnedDirectoryTreeInto(home, path, target, &creation)
	return creation, err
}

func ensureWindowsTargetOwnedDirectoryTreeInto(
	home string,
	path string,
	target *windows.SID,
	creation *windowsTargetOwnedDirectoryCreation,
) (retErr error) {
	if target == nil || windowsEnterpriseSystemIdentity(target) {
		return fmt.Errorf("enterprise hooks: invalid target SID for managed directory creation")
	}
	if err := windowsEnterpriseEffectiveTokenCheck(target); err != nil {
		return fmt.Errorf("enterprise hooks: managed directory creation requires the exact target token: %w", err)
	}
	if err := validateWindowsEnterpriseHomeAnchor(home, target); err != nil {
		return err
	}
	homeAbs, err := filepath.Abs(home)
	if err != nil {
		return err
	}
	pathAbs, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	homeAbs = filepath.Clean(homeAbs)
	pathAbs = filepath.Clean(pathAbs)
	canonicalHookDir := filepath.Join(homeAbs, ".defenseclaw", "hooks")
	if !sameWindowsEnterprisePath(pathAbs, canonicalHookDir) {
		return fmt.Errorf(
			"enterprise hooks: managed directory creation requires canonical hook path %s, got %s",
			canonicalHookDir,
			pathAbs,
		)
	}
	rel, err := filepath.Rel(homeAbs, pathAbs)
	if err != nil {
		return err
	}
	parts := strings.Split(rel, string(filepath.Separator))
	if len(parts) == 0 || len(parts) > windowsGuardianACLMaxPathElements {
		return fmt.Errorf(
			"enterprise hooks: managed directory path must contain 1-%d bounded elements",
			windowsGuardianACLMaxPathElements,
		)
	}
	for _, part := range parts {
		if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\/\x00") {
			return fmt.Errorf("enterprise hooks: invalid managed directory path element %q", part)
		}
	}

	descriptor, err := windowsTargetOwnedDirectorySecurityDescriptor(target)
	if err != nil {
		return fmt.Errorf("enterprise hooks: build target-owned directory security descriptor: %w", err)
	}
	created := make([]string, 0, len(parts))
	defer func() {
		if retErr == nil {
			return
		}
		for index := len(created) - 1; index >= 0; index-- {
			if removeErr := os.Remove(created[index]); removeErr != nil && !errors.Is(removeErr, os.ErrNotExist) {
				retErr = errors.Join(retErr, fmt.Errorf(
					"enterprise hooks: remove incomplete managed directory %s: %w",
					created[index],
					removeErr,
				))
			}
		}
	}()
	currentHandle, err := openWindowsTargetDirectoryRoot(homeAbs)
	if err != nil {
		return err
	}
	defer func() {
		if currentHandle != 0 {
			if closeErr := windows.CloseHandle(currentHandle); closeErr != nil {
				retErr = errors.Join(retErr, fmt.Errorf("enterprise hooks: close managed directory handle: %w", closeErr))
			}
		}
	}()
	if err := validateWindowsGuardianACLHandle(currentHandle, target, true, false, true); err != nil {
		return fmt.Errorf("enterprise hooks: reject managed directory profile root: %w", err)
	}

	currentPath := homeAbs
	for _, part := range parts {
		currentPath = filepath.Join(currentPath, part)
		child, wasCreated, err := openOrCreateWindowsTargetDirectory(
			currentHandle,
			part,
			descriptor,
		)
		if err != nil {
			return fmt.Errorf("enterprise hooks: create managed directory %s: %w", currentPath, err)
		}
		if wasCreated {
			created = append(created, currentPath)
			switch {
			case sameWindowsEnterprisePath(currentPath, filepath.Dir(canonicalHookDir)):
				creation.createdDataDir = true
			case sameWindowsEnterprisePath(currentPath, canonicalHookDir):
				creation.createdHookDir = true
			default:
				_ = windows.CloseHandle(child)
				return fmt.Errorf(
					"enterprise hooks: created unexpected managed directory %s",
					currentPath,
				)
			}
			if err := validateWindowsTargetOwnedDirectoryHandle(child, currentPath, target); err != nil {
				_ = windows.CloseHandle(child)
				return fmt.Errorf("enterprise hooks: verify newly created managed directory %s: %w", currentPath, err)
			}
		} else if err := validateWindowsTargetOwnedDirectoryHandle(child, currentPath, target); err != nil {
			_ = windows.CloseHandle(child)
			return fmt.Errorf("enterprise hooks: reject managed directory %s: %w", currentPath, err)
		}
		if err := windows.CloseHandle(currentHandle); err != nil {
			_ = windows.CloseHandle(child)
			currentHandle = 0
			return fmt.Errorf("enterprise hooks: close managed directory parent: %w", err)
		}
		currentHandle = child
	}
	return nil
}

func windowsTargetOwnedDirectorySecurityDescriptor(target *windows.SID) (*windows.SECURITY_DESCRIPTOR, error) {
	applied, err := windowsUserPathAppliedCanonicalACEs(target, true)
	if err != nil {
		return nil, err
	}
	// Supply the exact seven-ACE applied representation in the create security
	// descriptor. In particular, the effective OWNER RIGHTS ACE suppresses the
	// target owner's implicit WRITE_DAC from the instant the name is published.
	// The target/owner entries grant no WRITE_DAC capability; SYSTEM and enabled
	// Administrators remain trusted by the canonical contract.
	entries := make([]windows.EXPLICIT_ACCESS, 0, len(applied))
	for _, item := range applied {
		entries = append(entries, windows.EXPLICIT_ACCESS{
			AccessPermissions: item.mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       uint32(item.flags),
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(item.sid),
			},
		})
	}
	acl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, err
	}
	descriptor, err := windows.NewSecurityDescriptor()
	if err != nil {
		return nil, err
	}
	if err := descriptor.SetOwner(target, false); err != nil {
		return nil, err
	}
	if err := descriptor.SetDACL(acl, true, false); err != nil {
		return nil, err
	}
	if err := descriptor.SetControl(windows.SE_DACL_PROTECTED, windows.SE_DACL_PROTECTED); err != nil {
		return nil, err
	}
	selfRelative, err := descriptor.ToSelfRelative()
	if err != nil {
		return nil, err
	}
	dacl, _, err := selfRelative.DACL()
	if err != nil {
		return nil, fmt.Errorf("enterprise hooks: inspect target-owned directory create descriptor DACL: %w", err)
	}
	if dacl == nil {
		return nil, fmt.Errorf("enterprise hooks: target-owned directory create descriptor has no DACL")
	}
	if err := validateWindowsUserPathProtectionACL(
		"target-owned directory create descriptor",
		selfRelative,
		dacl,
		target,
		true,
	); err != nil {
		return nil, fmt.Errorf("enterprise hooks: reject noncanonical target-owned directory create descriptor: %w", err)
	}
	return selfRelative, nil
}

func openWindowsTargetDirectoryRoot(path string) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	access := uint32(
		windows.READ_CONTROL |
			windows.FILE_READ_ATTRIBUTES |
			windows.FILE_LIST_DIRECTORY |
			windows.FILE_APPEND_DATA |
			windows.SYNCHRONIZE,
	)
	handle, err := windows.CreateFile(
		ptr,
		access,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: open target profile for managed directory creation: %w", err)
	}
	return handle, nil
}

func openOrCreateWindowsTargetDirectory(
	parent windows.Handle,
	name string,
	descriptor *windows.SECURITY_DESCRIPTOR,
) (windows.Handle, bool, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, false, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:             uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory:      parent,
		ObjectName:         objectName,
		Attributes:         windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
		SecurityDescriptor: descriptor,
	}
	access := uint32(
		windows.READ_CONTROL |
			windows.FILE_READ_ATTRIBUTES |
			windows.FILE_LIST_DIRECTORY |
			windows.FILE_APPEND_DATA |
			windows.SYNCHRONIZE,
	)
	options := uint32(
		windows.FILE_DIRECTORY_FILE |
			windows.FILE_OPEN_REPARSE_POINT |
			windows.FILE_SYNCHRONOUS_IO_NONALERT,
	)
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		access,
		&attributes,
		&status,
		nil,
		0,
		// Deny data/delete sharing while the creator validates the atomically
		// published final descriptor. Windows sharing does not cover metadata or
		// security-only opens; safety therefore comes from the final DACL above,
		// not from treating this share mode as a security-control mutex.
		0,
		windows.FILE_CREATE,
		options,
		0,
		0,
	)
	if err == nil {
		return handle, true, nil
	}
	if !errors.Is(err, windows.STATUS_OBJECT_NAME_COLLISION) {
		return 0, false, err
	}
	attributes.SecurityDescriptor = nil
	err = windows.NtCreateFile(
		&handle,
		access,
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		options,
		0,
		0,
	)
	if err != nil {
		return 0, false, err
	}
	return handle, false, nil
}

func validateWindowsTargetOwnedDirectoryHandle(
	handle windows.Handle,
	path string,
	target *windows.SID,
) error {
	if err := validateWindowsGuardianACLHandle(handle, target, true, true, false); err != nil {
		return err
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return err
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("enterprise hooks: target-owned directory has a null or unreadable DACL")
	}
	return validateWindowsUserPathProtectionACL(path, descriptor, dacl, target, true)
}
