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
	"syscall"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// ensureWindowsTargetOwnedDirectoryTree creates only missing descendants of
// the authenticated target profile: %USERPROFILE%\.defenseclaw, and its hooks
// folder when path names that. Each directory receives its target owner
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
	canonicalDataDir := filepath.Join(homeAbs, ".defenseclaw")
	canonicalHookDir := filepath.Join(canonicalDataDir, "hooks")
	if !sameWindowsEnterprisePath(pathAbs, canonicalHookDir) && !sameWindowsEnterprisePath(pathAbs, canonicalDataDir) {
		return fmt.Errorf(
			"enterprise hooks: managed directory creation requires canonical data path %s or hook path %s, got %s",
			canonicalDataDir,
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
			case sameWindowsEnterprisePath(currentPath, canonicalDataDir):
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
			adopted, adoptErr := adoptWindowsAccountCreatedDataDir(
				currentHandle, child, part, currentPath,
				sameWindowsEnterprisePath(currentPath, canonicalDataDir), target,
			)
			_ = windows.CloseHandle(child)
			if adoptErr != nil || adopted == 0 {
				return fmt.Errorf("enterprise hooks: reject managed directory %s: %w", currentPath, errors.Join(err, adoptErr))
			}
			child = adopted
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

// Bounds for a pre-existing data directory the account created itself.
const (
	windowsAccountCreatedDataDirMaxEntries = 256
	windowsAccountCreatedDataDirMaxDepth   = 8
)

// adoptWindowsAccountCreatedDataDir takes over, in the standalone profile
// only, a %USERPROFILE%\.defenseclaw the account created before it was
// enrolled (for example the hook's hook-failures.jsonl from an agent run
// that was refused as unregistered): it runs on the impersonated target
// thread, and when windowsAccountCreatedDataDir accepts the tree it reopens
// the same name without following reparse points and applies the protected
// canonical DACL to that directory. It returns the validated handle, or 0
// when the directory is not an account-created data directory.
func adoptWindowsAccountCreatedDataDir(
	parent windows.Handle,
	child windows.Handle,
	name string,
	path string,
	dataDir bool,
	target *windows.SID,
) (windows.Handle, error) {
	if !dataDir || !windowsEnterpriseStandaloneProcess() {
		return 0, nil
	}
	descriptor, err := windows.GetSecurityInfo(child, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return 0, err
	}
	if ok, err := windowsAccountCreatedDataDir(path, descriptor, target); err != nil || !ok {
		return 0, err
	}
	handle, err := openWindowsTargetDirectoryForDACL(parent, name)
	if err != nil {
		return 0, fmt.Errorf("enterprise hooks: reopen account-created data directory %s: %w", path, err)
	}
	reopened, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err == nil {
		// The reopened object must still be a plain directory the target
		// owns before its DACL changes: never a junction put in its place.
		err = validateWindowsGuardianACLHandle(handle, target, true, true, false)
	}
	if err == nil {
		var ok bool
		ok, err = windowsAccountCreatedDataDirDescriptor(reopened, target)
		if err == nil && !ok {
			err = fmt.Errorf("enterprise hooks: %s changed while it was adopted", path)
		}
	}
	if err == nil {
		var acl *windows.ACL
		if acl, err = windowsUserPathProtectionACL(target, true); err == nil {
			err = setWindowsObjectDACLNoPropagation(handle, acl, true)
		}
	}
	if err == nil {
		err = validateWindowsTargetOwnedDirectoryHandle(handle, path, target)
	}
	if err != nil {
		_ = windows.CloseHandle(handle)
		return 0, fmt.Errorf("enterprise hooks: adopt account-created data directory %s: %w", path, err)
	}
	return handle, nil
}

// windowsAccountCreatedDataDir reports whether path, with descriptor, is a
// data directory the target account created with an ordinary create call:
// owned by the target, an unprotected DACL made only of entries inherited
// from the profile for the target, LocalSystem and Administrators, no
// hooks child (the managed runtime is never adopted), and a bounded tree of
// plain files and directories all owned by the target.
func windowsAccountCreatedDataDir(path string, descriptor *windows.SECURITY_DESCRIPTOR, target *windows.SID) (bool, error) {
	if ok, err := windowsAccountCreatedDataDirDescriptor(descriptor, target); err != nil || !ok {
		return false, err
	}
	// The folder itself must be plain: a junction there would have the
	// checks below read, and the pending proof accept, another folder.
	root, err := os.Lstat(path)
	if err != nil {
		return false, err
	}
	if attrs, _ := root.Sys().(*syscall.Win32FileAttributeData); attrs == nil || !root.IsDir() ||
		attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false, nil
	}
	if _, err := os.Lstat(filepath.Join(path, "hooks")); !errors.Is(err, os.ErrNotExist) {
		return false, err
	}
	entries := 0
	var walk func(dir string, depth int) (bool, error)
	walk = func(dir string, depth int) (bool, error) {
		if depth > windowsAccountCreatedDataDirMaxDepth {
			return false, nil
		}
		items, err := os.ReadDir(dir)
		if err != nil {
			return false, err
		}
		for _, item := range items {
			entries++
			if entries > windowsAccountCreatedDataDirMaxEntries {
				return false, nil
			}
			full := filepath.Join(dir, item.Name())
			info, err := item.Info()
			if err != nil {
				return false, err
			}
			attrs, _ := info.Sys().(*syscall.Win32FileAttributeData)
			if attrs == nil || attrs.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 ||
				!(info.IsDir() || info.Mode().IsRegular()) {
				return false, nil
			}
			owner, err := windowsPathOwnerNoFollow(full)
			if err != nil {
				return false, err
			}
			if owner == nil || !owner.Equals(target) {
				return false, nil
			}
			if info.IsDir() {
				if ok, err := walk(full, depth+1); err != nil || !ok {
					return false, err
				}
			}
		}
		return true, nil
	}
	return walk(path, 1)
}

// windowsAccountCreatedDataDirDescriptor is the descriptor half of
// windowsAccountCreatedDataDir.
func windowsAccountCreatedDataDirDescriptor(descriptor *windows.SECURITY_DESCRIPTOR, target *windows.SID) (bool, error) {
	if descriptor == nil || target == nil {
		return false, nil
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil || !owner.Equals(target) {
		return false, nil
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return false, err
	}
	if control&windows.SE_DACL_PROTECTED != 0 {
		return false, nil
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil || dacl.AceCount == 0 {
		return false, err
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERITED_ACE == 0 {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(target) && !sid.IsWellKnown(windows.WinLocalSystemSid) &&
			!sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) {
			return false, nil
		}
	}
	return true, nil
}

// openWindowsTargetDirectoryForDACL opens an existing child directory of
// parent for a DACL change, never following a reparse point.
func openWindowsTargetDirectoryForDACL(parent windows.Handle, name string) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE | windows.OBJ_DONT_REPARSE,
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES|
			windows.FILE_LIST_DIRECTORY|windows.FILE_APPEND_DATA|windows.SYNCHRONIZE,
		&attributes,
		&status,
		nil,
		0,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		windows.FILE_OPEN,
		windows.FILE_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		return 0, err
	}
	return handle, nil
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
