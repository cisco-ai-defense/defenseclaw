// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"
	"fmt"
	"os"
	"path/filepath"
	"time"
	"unsafe"

	"golang.org/x/sys/windows"
)

var (
	windowsManagedFileLockTimeout = 2 * time.Second
	windowsManagedFileLockRetry   = 25 * time.Millisecond
)

// withFileLock acquires an exclusive, blocking lock on path+".lock" before
// running fn, and releases it when fn returns.
//
// It uses Windows LockFileEx (exclusive, without LOCKFILE_FAIL_IMMEDIATELY),
// which blocks until the lock is available and is released automatically by
// the OS when the holding process exits or the handle is closed. That gives
// the same mutual-exclusion and crash-safety guarantees as flock(LOCK_EX) on
// Unix. The earlier O_CREATE|O_EXCL sentinel-file approach was non-blocking
// (it returned an error on contention instead of waiting) and left a stale
// lock file that hard-failed all callers for up to a minute after a crash.
func withFileLock(path string, fn func() error) error {
	return withFileLockMode(path, false, fn)
}

// withFileLockMode preserves ordinary Windows connector behavior while giving
// the LocalSystem guardian a hard acquisition deadline. A target user can hold
// a per-user .lock indefinitely; managed reconciliation must report that row
// and continue to later targets/ticks instead of blocking the service thread.
func withFileLockMode(path string, managedEnterprise bool, fn func() error) error {
	lockPath := path + ".lock"

	// O_RDWR (not O_EXCL): every caller opens the shared lock file; mutual
	// exclusion is enforced by the byte-range lock below, not by file
	// existence. Managed creation must not inherit an elevated administrator
	// token's BUILTIN\Administrators default owner. Open or create the leaf
	// relative to an authenticated no-follow parent handle and stamp the exact
	// effective user as owner in the initial native create instead.
	var lockFile *os.File
	var lockParent *os.File
	var err error
	if managedEnterprise {
		lockFile, lockParent, err = openWindowsManagedFileLock(lockPath)
	} else {
		lockFile, err = os.OpenFile(lockPath, os.O_CREATE|os.O_RDWR, 0o600)
	}
	if err != nil {
		return fmt.Errorf("open lock file %s: %w", lockPath, err)
	}
	defer lockFile.Close()
	if lockParent != nil {
		// The parent handle excludes delete sharing, so the target-controlled
		// directory cannot be renamed away and replaced while the callback uses
		// paths adjacent to the held lock.
		defer lockParent.Close()
	}

	handle := windows.Handle(lockFile.Fd())
	overlapped := new(windows.Overlapped)
	flags := uint32(windows.LOCKFILE_EXCLUSIVE_LOCK)
	if managedEnterprise {
		flags |= windows.LOCKFILE_FAIL_IMMEDIATELY
	}
	deadline := time.Now().Add(windowsManagedFileLockTimeout)
	for {
		err = windows.LockFileEx(handle, flags, 0, 1, 0, overlapped)
		if err == nil {
			break
		}
		if !managedEnterprise || !errors.Is(err, windows.ERROR_LOCK_VIOLATION) {
			return fmt.Errorf("acquire lock %s: %w", lockPath, err)
		}
		if !time.Now().Before(deadline) {
			return fmt.Errorf(
				"acquire managed lock %s: timed out after %s: %w",
				lockPath,
				windowsManagedFileLockTimeout,
				err,
			)
		}
		delay := windowsManagedFileLockRetry
		if remaining := time.Until(deadline); delay > remaining {
			delay = remaining
		}
		if delay > 0 {
			time.Sleep(delay)
		}
	}
	defer func() {
		_ = windows.UnlockFileEx(handle, 0, 1, 0, overlapped)
	}()
	if managedEnterprise {
		if err := validateWindowsManagedFileLockName(
			lockParent,
			filepath.Base(lockPath),
			lockFile,
		); err != nil {
			return fmt.Errorf("validate held managed lock %s: %w", lockPath, err)
		}
	}

	return fn()
}

// openWindowsManagedFileLock opens or creates a target-owned lock leaf without
// trusting a path-based create. FILE_OPEN_IF preserves the shared persistent
// lock-file protocol, while FILE_SHARE_READ|FILE_SHARE_WRITE matches Go's
// ordinary Windows os.OpenFile sharing and deliberately excludes delete/rename
// sharing for the lifetime of the mutex handle.
func openWindowsManagedFileLock(path string) (*os.File, *os.File, error) {
	parent, err := openAtomicTransformBoundDirectoryPlatform(filepath.Dir(path))
	if err != nil {
		return nil, nil, fmt.Errorf("open managed lock parent: %w", err)
	}
	if err := validateAtomicTransformBoundDirectoryPlatform(parent, false); err != nil {
		_ = parent.Close()
		return nil, nil, fmt.Errorf("validate managed lock parent: %w", err)
	}

	descriptor, err := windowsManagedFileLockSecurityDescriptor()
	if err != nil {
		_ = parent.Close()
		return nil, nil, err
	}
	attributes, err := atomicTransformBoundObjectAttributes(
		parent,
		filepath.Base(path),
		descriptor,
	)
	if err != nil {
		_ = parent.Close()
		return nil, nil, err
	}
	var handle windows.Handle
	var status windows.IO_STATUS_BLOCK
	err = windows.NtCreateFile(
		&handle,
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.READ_CONTROL|windows.SYNCHRONIZE,
		attributes,
		&status,
		nil,
		windows.FILE_ATTRIBUTE_NORMAL,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		windows.FILE_OPEN_IF,
		windows.FILE_NON_DIRECTORY_FILE|windows.FILE_OPEN_REPARSE_POINT|
			windows.FILE_SYNCHRONOUS_IO_NONALERT,
		0,
		0,
	)
	if err != nil {
		_ = parent.Close()
		return nil, nil, err
	}
	if err := validateWindowsManagedFileLockHandle(handle); err != nil {
		_ = windows.CloseHandle(handle)
		_ = parent.Close()
		return nil, nil, err
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		_ = parent.Close()
		return nil, nil, fmt.Errorf("wrap managed lock handle")
	}
	return file, parent, nil
}

func validateWindowsManagedFileLockName(
	parent *os.File,
	name string,
	held *os.File,
) error {
	if parent == nil || held == nil {
		return fmt.Errorf("managed lock has no bound parent or held file")
	}
	named, err := openAtomicTransformBoundFilePlatform(parent, name, false)
	if err != nil {
		return fmt.Errorf("open managed lock name relative to held parent: %w", err)
	}
	defer named.Close()
	if err := validateWindowsManagedFileLockHandle(windows.Handle(named.Fd())); err != nil {
		return err
	}
	heldIdentity, err := atomicTransformOpenFileIdentity(held)
	if err != nil {
		return fmt.Errorf("read held managed lock identity: %w", err)
	}
	namedIdentity, err := atomicTransformOpenFileIdentity(named)
	if err != nil {
		return fmt.Errorf("read named managed lock identity: %w", err)
	}
	if heldIdentity != namedIdentity {
		return fmt.Errorf("managed lock path does not name the held lock file")
	}
	return nil
}

// windowsManagedFileLockSecurityDescriptor is the file form of the managed
// per-user runtime contract: exact target ownership, a protected DACL, OWNER
// RIGHTS limited to READ_CONTROL, target read/write/execute/delete, and full
// access only for LocalSystem and Administrators. Supplying it to NtCreateFile
// avoids a visible wrong-owner or inheritable staging interval.
func windowsManagedFileLockSecurityDescriptor() (*windows.SECURITY_DESCRIPTOR, error) {
	target, err := windowsEffectiveUserSID()
	if err != nil || target == nil {
		return nil, fmt.Errorf("resolve effective Windows user for managed lock: %w", err)
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return nil, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, err
	}
	entry := func(sid *windows.SID, mask windows.ACCESS_MASK) windows.EXPLICIT_ACCESS {
		return windows.EXPLICIT_ACCESS{
			AccessPermissions: mask,
			AccessMode:        windows.GRANT_ACCESS,
			Inheritance:       windows.NO_INHERITANCE,
			Trustee: windows.TRUSTEE{
				TrusteeForm:  windows.TRUSTEE_IS_SID,
				TrusteeType:  windows.TRUSTEE_IS_USER,
				TrusteeValue: windows.TrusteeValueFromSID(sid),
			},
		}
	}
	targetMask := windows.ACCESS_MASK(
		windows.GENERIC_READ |
			windows.GENERIC_WRITE |
			windows.GENERIC_EXECUTE |
			windows.DELETE,
	)
	acl, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{
		entry(ownerRights, windows.READ_CONTROL),
		entry(target, targetMask),
		entry(system, windows.GENERIC_ALL),
		entry(administrators, windows.GENERIC_ALL),
	}, nil)
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
	if err := descriptor.SetControl(
		windows.SE_DACL_PROTECTED,
		windows.SE_DACL_PROTECTED,
	); err != nil {
		return nil, err
	}
	return descriptor.ToSelfRelative()
}

func validateWindowsManagedFileLockHandle(handle windows.Handle) error {
	if err := validateAtomicTransformWindowsHandleType(handle, false); err != nil {
		return fmt.Errorf("managed lock type: %w", err)
	}
	var fileInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &fileInfo); err != nil {
		return fmt.Errorf("inspect managed lock identity: %w", err)
	}
	if fileInfo.NumberOfLinks != 1 {
		return fmt.Errorf("managed lock has %d hard links, want exactly 1", fileInfo.NumberOfLinks)
	}
	if fileInfo.FileSizeHigh != 0 || fileInfo.FileSizeLow != 0 {
		return fmt.Errorf("managed lock is not empty")
	}
	descriptor, err := windows.GetSecurityInfo(
		handle,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect managed lock protection: %w", err)
	}
	target, err := windowsEffectiveUserSID()
	if err != nil || target == nil {
		return fmt.Errorf("resolve effective Windows user for managed lock validation: %w", err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil {
		return err
	}
	if owner == nil || !owner.Equals(target) {
		return fmt.Errorf("managed lock owner does not match effective target user")
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	if control&windows.SE_DACL_PROTECTED == 0 {
		return fmt.Errorf("managed lock DACL is not protected")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("managed lock has a null or unreadable DACL")
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	const fileAllAccess windows.ACCESS_MASK = 0x001f01ff
	expected := []struct {
		sid  *windows.SID
		mask windows.ACCESS_MASK
	}{
		{sid: ownerRights, mask: windows.READ_CONTROL},
		{sid: target, mask: windows.FILE_GENERIC_READ | windows.FILE_GENERIC_WRITE | windows.FILE_GENERIC_EXECUTE | windows.DELETE},
		{sid: system, mask: fileAllAccess},
		{sid: administrators, mask: fileAllAccess},
	}
	if int(dacl.AceCount) != len(expected) {
		return fmt.Errorf("managed lock DACL has %d ACEs, want %d", dacl.AceCount, len(expected))
	}
	seen := make([]bool, len(expected))
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return fmt.Errorf("inspect managed lock ACE %d: %w", index, err)
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != 0 {
			return fmt.Errorf("managed lock DACL contains a noncanonical ACE at index %d", index)
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		match := -1
		for candidate, want := range expected {
			if !seen[candidate] && sid.Equals(want.sid) && ace.Mask == want.mask {
				match = candidate
				break
			}
		}
		if match < 0 {
			return fmt.Errorf("managed lock DACL contains an unexpected or duplicate ACE")
		}
		seen[match] = true
	}
	return nil
}
