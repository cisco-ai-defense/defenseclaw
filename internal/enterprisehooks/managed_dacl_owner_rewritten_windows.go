// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisehooks

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsDACLEntriesOf reads every ACE of dacl. An ACE that is neither an
// access-allowed nor an access-denied ACE keeps an empty SID.
func windowsDACLEntriesOf(dacl *windows.ACL) ([]windowsDACLEntry, error) {
	if dacl == nil {
		return nil, errors.New("enterprise hooks: null Windows DACL")
	}
	entries := make([]windowsDACLEntry, 0, dacl.AceCount)
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return nil, err
		}
		if ace == nil {
			return nil, fmt.Errorf("enterprise hooks: unreadable Windows ACE %d", index)
		}
		entry := windowsDACLEntry{aceType: ace.Header.AceType, flags: ace.Header.AceFlags, mask: uint32(ace.Mask)}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, windows.ACCESS_DENIED_ACE_TYPE:
			entry.sid = (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
		}
		entries = append(entries, entry)
	}
	return entries, nil
}

// windowsManagedFileOwnerRewrittenDescriptor reports whether sd is owned by
// target and carries exactly the protected canonical managed file DACL of
// target with its OWNER RIGHTS entry removed (windowsManagedFileOwnerRewrittenDACL).
func windowsManagedFileOwnerRewrittenDescriptor(sd *windows.SECURITY_DESCRIPTOR, target *windows.SID) bool {
	if sd == nil || target == nil {
		return false
	}
	owner, ownerDefaulted, err := sd.Owner()
	if err != nil || ownerDefaulted || owner == nil || !owner.Equals(target) {
		return false
	}
	control, _, err := sd.Control()
	if err != nil || control&windows.SE_DACL_PROTECTED == 0 {
		return false
	}
	dacl, daclDefaulted, err := sd.DACL()
	if err != nil || daclDefaulted || dacl == nil {
		return false
	}
	entries, err := windowsDACLEntriesOf(dacl)
	if err != nil {
		return false
	}
	return windowsManagedFileOwnerRewrittenDACL(entries, target.String())
}

// windowsManagedRuntimeBundleOwnerRewritten reports whether path is a
// regular, single-link file reached without a reparse point whose security
// is the owner-rewritten managed file shape.
func windowsManagedRuntimeBundleOwnerRewritten(path string, target *windows.SID) bool {
	info, err := os.Lstat(path)
	if err != nil || !info.Mode().IsRegular() {
		return false
	}
	ptr, err := winpath.UTF16Ptr(path)
	if err != nil {
		return false
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return false
	}
	if validateWindowsRegularFileSingleLink(path) != nil {
		return false
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return false
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	return windowsManagedFileOwnerRewrittenDescriptor(sd, target)
}

// validateWindowsManagedRuntimeBundleElement is the trust check of an
// immutable managed runtime generation bundle: the canonical managed file
// check, or exactly the canonical DACL an owner write left without its
// OWNER RIGHTS entry (rel-1-0-6:GAP-0303). The digest the protected selector
// pins still authenticates a selected bundle's bytes.
func validateWindowsManagedRuntimeBundleElement(path string, target *windows.SID) error {
	err := validateWindowsUserPathElement(path, target, false, false, true)
	if err == nil || errors.Is(err, os.ErrNotExist) {
		return err
	}
	if windowsManagedRuntimeBundleOwnerRewritten(path, target) {
		return nil
	}
	return err
}

// windowsManagedRuntimeBundleRestoreOwnerRights is a seam for tests.
var windowsManagedRuntimeBundleRestoreOwnerRights = restoreWindowsManagedFileOwnerRights

// restoreWindowsManagedFileOwnerRights gives a managed per-user file in the
// exact owner-rewritten shape its canonical DACL back, OWNER RIGHTS entry
// included, and reports whether it changed it. Any other shape, a directory,
// a link, a file with another name and a file the caller cannot open for
// WRITE_DAC are left as they are for the trust check to judge. LocalSystem
// holds full control in that shape; the owner holds WRITE_DAC there too,
// since no OWNER RIGHTS entry withholds it.
func restoreWindowsManagedFileOwnerRights(path string, target *windows.SID) (bool, error) {
	if target == nil {
		return false, errors.New("enterprise hooks: target SID is unavailable for the OWNER RIGHTS restore")
	}
	extended, err := winpath.Extended(path)
	if err != nil {
		return false, err
	}
	ptr, err := windows.UTF16PtrFromString(extended)
	if err != nil {
		return false, err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.READ_CONTROL|windows.WRITE_DAC|windows.FILE_READ_ATTRIBUTES|windows.SYNCHRONIZE,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	switch {
	case errors.Is(err, windows.ERROR_FILE_NOT_FOUND), errors.Is(err, windows.ERROR_PATH_NOT_FOUND),
		errors.Is(err, windows.ERROR_ACCESS_DENIED):
		return false, nil
	case err != nil:
		return false, fmt.Errorf("enterprise hooks: open %s for the OWNER RIGHTS restore: %w", path, err)
	}
	defer windows.CloseHandle(handle)
	var info windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &info); err != nil {
		return false, err
	}
	if info.FileAttributes&(windows.FILE_ATTRIBUTE_DIRECTORY|windows.FILE_ATTRIBUTE_REPARSE_POINT) != 0 ||
		info.NumberOfLinks != 1 {
		return false, nil
	}
	current, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, fmt.Errorf("enterprise hooks: read the security of %s: %w", path, err)
	}
	if !windowsManagedFileOwnerRewrittenDescriptor(current, target) {
		return false, nil
	}
	acl, err := windowsUserPathProtectionACL(target, false)
	if err != nil {
		return false, err
	}
	if err := setWindowsObjectDACLNoPropagation(handle, acl, false); err != nil {
		return false, fmt.Errorf("enterprise hooks: restore the OWNER RIGHTS entry on %s: %w", path, err)
	}
	after, err := windows.GetSecurityInfo(handle, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return true, fmt.Errorf("enterprise hooks: reread the security of %s: %w", path, err)
	}
	owner, _, err := after.Owner()
	if err != nil || owner == nil || !owner.Equals(target) {
		return true, fmt.Errorf("enterprise hooks: owner of %s changed during the OWNER RIGHTS restore", path)
	}
	dacl, _, err := after.DACL()
	if err != nil || dacl == nil {
		return true, fmt.Errorf("enterprise hooks: DACL of %s is unreadable after the OWNER RIGHTS restore", path)
	}
	if err := validateWindowsUserPathProtectionACL(path, after, dacl, target, false); err != nil {
		return true, err
	}
	return true, nil
}
