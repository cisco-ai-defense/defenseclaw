//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"errors"
	"fmt"
	"path/filepath"
	"runtime"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

const windowsGuardianACLMaxPathElements = 64

var windowsEnterpriseGuardianDACLRepair = runWindowsEnterpriseGuardianDACLRepair

// repairWindowsTargetOwnedPathDACL authorizes a narrowly bounded process-token
// operation from inside the exact target-token callback. The actual content
// mutation remains on the impersonated thread; this escape is only for
// restoring the canonical DACL when the user has denied their own token.
//
// OWNER RIGHTS (S-1-3-4) can suppress an owner's implicit READ_CONTROL and
// WRITE_DAC rights. Consequently, owner-only repair is not sufficient for an
// enterprise guardian. The LocalSystem helper below uses a separate locked OS
// thread and enables backup/restore privileges only on that thread.
func repairWindowsTargetOwnedPathDACL(
	home string,
	path string,
	target *windows.SID,
	directory bool,
) error {
	if target == nil {
		return fmt.Errorf("enterprise hooks: target SID is unavailable for DACL repair")
	}
	if sameWindowsEnterprisePath(home, path) {
		return fmt.Errorf("enterprise hooks: refusing to rewrite the target profile root DACL")
	}
	if err := windowsEnterpriseEffectiveTokenCheck(target); err != nil {
		return fmt.Errorf("enterprise hooks: DACL repair requires exact target-token authorization: %w", err)
	}
	if !pathInside(home, path) && !sameWindowsEnterprisePath(home, path) {
		return fmt.Errorf("enterprise hooks: refusing DACL repair outside target home: %s", path)
	}
	return windowsEnterpriseGuardianDACLRepair(home, path, target, directory)
}

func runWindowsEnterpriseGuardianDACLRepair(
	home string,
	path string,
	target *windows.SID,
	directory bool,
) error {
	result := make(chan error, 1)
	go func() {
		runtime.LockOSThread()
		if err := windowsEnterpriseMutationIdentityCheck(); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: guardian DACL repair requires LocalSystem: %w", err)
			return
		}
		if err := windows.ImpersonateSelf(windows.SecurityImpersonation); err != nil {
			runtime.UnlockOSThread()
			result <- fmt.Errorf("enterprise hooks: create dedicated guardian privilege token: %w", err)
			return
		}

		var token windows.Token
		if err := windows.OpenThreadToken(
			windows.CurrentThread(),
			windows.TOKEN_ADJUST_PRIVILEGES|windows.TOKEN_QUERY,
			false,
			&token,
		); err != nil {
			revertErr := windows.RevertToSelf()
			if revertErr == nil {
				runtime.UnlockOSThread()
				result <- fmt.Errorf("enterprise hooks: open guardian privilege token: %w", err)
				return
			}
			result <- fmt.Errorf(
				"enterprise hooks: open guardian privilege token: %v (revert failed: %v)",
				err,
				revertErr,
			)
			return
		}

		privilegeErr := enableWindowsThreadPrivilege(token, "SeBackupPrivilege")
		if privilegeErr == nil {
			privilegeErr = enableWindowsThreadPrivilege(token, "SeRestorePrivilege")
		}
		repairErr := privilegeErr
		if repairErr == nil {
			repairErr = repairWindowsTargetOwnedPathDACLNoFollow(home, path, target, directory)
		}
		token.Close()

		if revertErr := windows.RevertToSelf(); revertErr != nil {
			// Do not return a still-privileged thread to the runtime pool.
			if repairErr == nil {
				result <- fmt.Errorf("enterprise hooks: revert guardian DACL privilege token: %w", revertErr)
			} else {
				result <- fmt.Errorf("%v (revert guardian DACL privilege token failed: %v)", repairErr, revertErr)
			}
			return
		}
		runtime.UnlockOSThread()
		result <- repairErr
	}()
	return <-result
}

func enableWindowsThreadPrivilege(token windows.Token, name string) error {
	namePtr, err := windows.UTF16PtrFromString(name)
	if err != nil {
		return err
	}
	var luid windows.LUID
	if err := windows.LookupPrivilegeValue(nil, namePtr, &luid); err != nil {
		return fmt.Errorf("enterprise hooks: look up %s: %w", name, err)
	}
	state := windows.Tokenprivileges{
		PrivilegeCount: 1,
		Privileges: [1]windows.LUIDAndAttributes{{
			Luid:       luid,
			Attributes: windows.SE_PRIVILEGE_ENABLED,
		}},
	}
	if err := windows.AdjustTokenPrivileges(token, false, &state, 0, nil, nil); err != nil {
		return fmt.Errorf("enterprise hooks: enable %s: %w", name, err)
	}
	if err := windows.GetLastError(); errors.Is(err, windows.ERROR_NOT_ALL_ASSIGNED) {
		return fmt.Errorf("enterprise hooks: guardian token does not hold %s", name)
	}
	return nil
}

// repairWindowsTargetOwnedPathDACLNoFollow walks from the already authorized
// profile root with handle-relative NtCreateFile calls. Every component is
// opened with FILE_OPEN_REPARSE_POINT and must be owned by the manifest SID.
// An attacker therefore cannot redirect LocalSystem DACL repair through a
// junction to an object outside the profile.
func repairWindowsTargetOwnedPathDACLNoFollow(
	home string,
	path string,
	target *windows.SID,
	directory bool,
) error {
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
	if err := validateWindowsEnterpriseProfileVolume(homeAbs); err != nil {
		return err
	}
	if sameWindowsEnterprisePath(homeAbs, pathAbs) {
		return fmt.Errorf("enterprise hooks: refusing no-follow rewrite of the target profile root DACL")
	}
	if !pathInside(homeAbs, pathAbs) && !sameWindowsEnterprisePath(homeAbs, pathAbs) {
		return fmt.Errorf("enterprise hooks: refusing no-follow DACL repair outside target home: %s", pathAbs)
	}
	rel, err := filepath.Rel(homeAbs, pathAbs)
	if err != nil {
		return err
	}
	parts := make([]string, 0, 8)
	if rel != "." {
		for _, part := range strings.Split(rel, string(filepath.Separator)) {
			if part == "" || part == "." || part == ".." || strings.ContainsAny(part, "\\/\x00") {
				return fmt.Errorf("enterprise hooks: invalid DACL repair path element %q", part)
			}
			parts = append(parts, part)
		}
	}
	if len(parts) > windowsGuardianACLMaxPathElements {
		return fmt.Errorf(
			"enterprise hooks: DACL repair path exceeds %d elements",
			windowsGuardianACLMaxPathElements,
		)
	}

	handle, err := openWindowsGuardianACLRoot(homeAbs, false)
	if err != nil {
		return err
	}
	defer func() {
		if handle != 0 {
			_ = windows.CloseHandle(handle)
		}
	}()
	if err := validateWindowsGuardianACLHandle(handle, target, true, false, true); err != nil {
		return fmt.Errorf("enterprise hooks: reject DACL repair profile root: %w", err)
	}

	for index, part := range parts {
		final := index == len(parts)-1
		child, err := openWindowsGuardianACLChild(handle, part, final, directory)
		if err != nil {
			return fmt.Errorf("enterprise hooks: open DACL repair path element %q: %w", part, err)
		}
		if err := validateWindowsGuardianACLHandle(child, target, !final || directory, final, false); err != nil {
			_ = windows.CloseHandle(child)
			return fmt.Errorf("enterprise hooks: reject DACL repair path element %q: %w", part, err)
		}
		if err := windows.CloseHandle(handle); err != nil {
			_ = windows.CloseHandle(child)
			handle = 0
			return fmt.Errorf("enterprise hooks: close DACL repair parent handle: %w", err)
		}
		handle = child
	}

	acl, err := windowsUserPathProtectionACL(target, directory)
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	); err != nil {
		return fmt.Errorf("enterprise hooks: restore canonical target DACL by handle: %w", err)
	}
	return nil
}

func openWindowsGuardianACLRoot(path string, final bool) (windows.Handle, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return 0, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return 0, err
	}
	access := uint32(windows.READ_CONTROL | windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY | windows.SYNCHRONIZE)
	if final {
		access |= windows.WRITE_DAC
	}
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
		return 0, fmt.Errorf("enterprise hooks: open target profile root without following: %w", err)
	}
	return handle, nil
}

func openWindowsGuardianACLChild(
	parent windows.Handle,
	name string,
	final bool,
	directory bool,
) (windows.Handle, error) {
	objectName, err := windows.NewNTUnicodeString(name)
	if err != nil {
		return 0, err
	}
	attributes := windows.OBJECT_ATTRIBUTES{
		Length:        uint32(unsafe.Sizeof(windows.OBJECT_ATTRIBUTES{})),
		RootDirectory: parent,
		ObjectName:    objectName,
		Attributes:    windows.OBJ_CASE_INSENSITIVE,
	}
	access := uint32(windows.READ_CONTROL)
	options := uint32(
		windows.FILE_OPEN_REPARSE_POINT |
			windows.FILE_OPEN_FOR_BACKUP_INTENT,
	)
	if final {
		access |= windows.WRITE_DAC | windows.FILE_READ_ATTRIBUTES
	} else {
		access |= windows.FILE_READ_ATTRIBUTES | windows.FILE_LIST_DIRECTORY | windows.SYNCHRONIZE
		options |= windows.FILE_DIRECTORY_FILE | windows.FILE_SYNCHRONOUS_IO_NONALERT
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	if err := windows.NtCreateFile(
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
	); err != nil {
		return 0, err
	}
	return handle, nil
}

func validateWindowsGuardianACLHandle(
	handle windows.Handle,
	target *windows.SID,
	wantDirectory bool,
	final bool,
	profileRoot bool,
) error {
	owner, err := windowsHandleOwner(handle)
	if err != nil {
		return err
	}
	ownerOK := owner != nil && owner.Equals(target)
	if profileRoot {
		ownerOK = windowsEnterpriseProfileAnchorOwner(owner, target)
	}
	if !ownerOK {
		return fmt.Errorf(
			"owner SID %s is not trusted for target SID %s",
			windowsSIDString(owner),
			windowsSIDString(target),
		)
	}
	if final {
		// This query is bound to the exact no-follow handle that will receive
		// SetSecurityInfo. SeBackupPrivilege plus FILE_OPEN_FOR_BACKUP_INTENT
		// permits the metadata read even when a hostile target DACL denies
		// FILE_READ_ATTRIBUTES. Never rewrite the shared security descriptor
		// of an attacker-created hard link.
		var info windows.ByHandleFileInformation
		if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
			return fmt.Errorf("inspect final DACL repair handle: %w", err)
		}
		if info.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
			return fmt.Errorf("final path element is a reparse point")
		}
		isDirectory := info.FileAttributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
		if isDirectory != wantDirectory {
			if wantDirectory {
				return fmt.Errorf("expected directory")
			}
			return fmt.Errorf("expected regular file")
		}
		if !isDirectory && info.NumberOfLinks != 1 {
			return fmt.Errorf(
				"%w (final DACL repair handle has %d links)",
				errWindowsManagedHardlink,
				info.NumberOfLinks,
			)
		}
		return nil
	}
	attributes, err := windowsQuarantineHandleAttributes(handle)
	if err != nil {
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("intermediate path element is a reparse point")
	}
	isDirectory := attributes&windows.FILE_ATTRIBUTE_DIRECTORY != 0
	if isDirectory != wantDirectory {
		if wantDirectory {
			return fmt.Errorf("expected directory")
		}
		return fmt.Errorf("expected regular file")
	}
	return nil
}
