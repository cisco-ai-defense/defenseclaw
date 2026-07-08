// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func protectFile(path string, _ *os.File) error { return setPrivateDACL(path, false) }

func protectDirectory(path string) error {
	if err := rejectReparsePath(path); err != nil {
		return err
	}
	owned, err := windowsPathOwnedByCurrentUser(path)
	if err != nil {
		return err
	}
	if !owned {
		return fmt.Errorf("safefile: refusing foreign-owned directory: %s", path)
	}
	safe, err := privateDACLIsSafe(path)
	if err != nil {
		return err
	}
	if safe {
		return preserveExistingProtection(path, path)
	}
	return setPrivateDACL(path, true)
}

func withLockedDirectory(path string, write func() error) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	handle, err := windows.CreateFile(
		ptr,
		windows.FILE_LIST_DIRECTORY|windows.FILE_READ_ATTRIBUTES,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE,
		nil,
		windows.OPEN_EXISTING,
		windows.FILE_FLAG_BACKUP_SEMANTICS|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return fmt.Errorf("safefile: lock private directory %s: %w", path, err)
	}
	defer windows.CloseHandle(handle)
	if err := rejectReparsePath(path); err != nil {
		return err
	}
	return write()
}

func windowsPathOwnedByCurrentUser(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false, err
	}
	return owner != nil && owner.Equals(user.User.Sid), nil
}

func preserveExistingProtection(source, destination string) error {
	if _, err := os.Lstat(source); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	safe, err := privateDACLIsSafe(source)
	if err != nil || !safe {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(source, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		destination, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

func rejectReparsePath(path string) error {
	ptr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return err
	}
	attributes, err := windows.GetFileAttributes(ptr)
	if err != nil {
		if err == windows.ERROR_FILE_NOT_FOUND || err == windows.ERROR_PATH_NOT_FOUND {
			return nil
		}
		return err
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("safefile: refusing reparse point: %s", path)
	}
	return nil
}

func rejectReparseChain(path string) error {
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		if err := rejectReparsePath(current); err != nil {
			return err
		}
		parent := filepath.Dir(current)
		if parent == current {
			return nil
		}
		current = parent
	}
}

func makePrivateDirectories(path string) error {
	missing := make([]string, 0, 2)
	current, err := filepath.Abs(path)
	if err != nil {
		return err
	}
	for {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			break
		}
		if !os.IsNotExist(statErr) {
			return statErr
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	if len(missing) == 0 {
		return nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return fmt.Errorf("safefile: current token user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return fmt.Errorf("safefile: current token user is unavailable")
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", user.User.Sid),
	)
	if err != nil {
		return err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		ptr, err := windows.UTF16PtrFromString(directory)
		if err != nil {
			return err
		}
		if err := windows.CreateDirectory(ptr, &attributes); err != nil && err != windows.ERROR_ALREADY_EXISTS {
			return err
		}
		if err := rejectReparsePath(directory); err != nil {
			return err
		}
		if err := protectDirectory(directory); err != nil {
			return err
		}
	}
	return nil
}

func setPrivateDACL(path string, inherit bool) error {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if inherit {
		inheritance = uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 2)
	for _, sid := range []*windows.SID{user.User.Sid, system} {
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
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION,
		user.User.Sid,
		nil,
		nil,
		nil,
	); err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func privateDACLIsSafe(path string) (bool, error) {
	sd, err := windows.GetNamedSecurityInfo(
		path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil {
		return false, err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, err
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false, err
	}
	if owner == nil || !owner.Equals(user.User.Sid) {
		return false, nil
	}
	const writeLike = windows.GENERIC_ALL | windows.GENERIC_WRITE | windows.DELETE | windows.WRITE_DAC | windows.WRITE_OWNER | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA | windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES | 0x40
	foundOwner := false
	foundSystem := false
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(index), &ace); err != nil {
			return false, err
		}
		if ace == nil {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if ace.Header.AceType == windows.ACCESS_DENIED_ACE_TYPE &&
			(sid.Equals(user.User.Sid) || sid.Equals(system) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)) &&
			ace.Mask != 0 {
			return false, nil
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Mask != 0 && (sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)) {
			foundOwner = true
		}
		if ace.Mask != 0 && sid.Equals(system) {
			foundSystem = true
		}
		if ace.Mask&writeLike == 0 {
			continue
		}
		if sid.Equals(user.User.Sid) || sid.Equals(system) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) {
			continue
		}
		return false, nil
	}
	return foundOwner && foundSystem, nil
}
