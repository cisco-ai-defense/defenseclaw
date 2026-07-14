// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
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

func validatePrivateProtection(path string, wantDirectory bool) error {
	if err := rejectReparseChain(path); err != nil {
		return err
	}
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	if info.Mode()&os.ModeSymlink != 0 || (wantDirectory && !info.IsDir()) ||
		(!wantDirectory && !info.Mode().IsRegular()) {
		return fmt.Errorf("safefile: private path has an unexpected type: %s", path)
	}
	owned, err := windowsPathOwnedByCurrentUser(path)
	if err != nil {
		return err
	}
	if !owned {
		return fmt.Errorf("safefile: private path is not owned by the current user: %s", path)
	}
	safe, err := privateDACLIsSafe(path)
	if err != nil {
		return err
	}
	if !safe {
		return fmt.Errorf("safefile: private path has an unsafe DACL: %s", path)
	}
	return nil
}

func withLockedDirectory(path string, write func() error) error {
	ptr, err := winpath.UTF16Ptr(path)
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
	extended, err := winpath.Extended(path)
	if err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
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
	if err != nil {
		return err
	}
	if !safe {
		// ReplaceFileW deliberately preserves the replaced file's DACL. Tighten
		// an unsafe DefenseClaw-owned destination before publication so the
		// metadata-preserving replace cannot retain a foreign read/write ACE.
		if err := setPrivateDACL(source, false); err != nil {
			return err
		}
	}
	extendedSource, err := winpath.Extended(source)
	if err != nil {
		return err
	}
	extendedDestination, err := winpath.Extended(destination)
	if err != nil {
		return err
	}
	sd, err := windows.GetNamedSecurityInfo(extendedSource, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return err
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return err
	}
	return windows.SetNamedSecurityInfo(
		extendedDestination, windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil, nil, dacl, nil,
	)
}

func rejectReparsePath(path string) error {
	ptr, err := winpath.UTF16Ptr(path)
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

// CreatePrivateDirectory creates path and any missing parents with the private
// Windows DACL, returning true only when this call created path itself. If path
// already exists (including a concurrent creator winning the race), its ACL is
// left untouched so callers can validate rather than rewrite operator state.
func CreatePrivateDirectory(path string) (bool, error) {
	if path == "" {
		return false, fmt.Errorf("safefile: empty directory path")
	}
	if err := rejectReparseChain(path); err != nil {
		return false, err
	}
	created, err := makePrivateDirectoriesCreationAware(path, false)
	if err != nil {
		return false, fmt.Errorf("safefile: mkdir %s: %w", path, err)
	}
	return created, nil
}

func makePrivateDirectories(path string) error {
	_, err := makePrivateDirectoriesCreationAware(path, true)
	return err
}

func makePrivateDirectoriesCreationAware(path string, protectConcurrentExisting bool) (bool, error) {
	missing := make([]string, 0, 2)
	current, err := filepath.Abs(path)
	if err != nil {
		return false, err
	}
	for {
		_, statErr := os.Lstat(current)
		if statErr == nil {
			break
		}
		if !os.IsNotExist(statErr) {
			return false, statErr
		}
		missing = append(missing, current)
		parent := filepath.Dir(current)
		if parent == current {
			break
		}
		current = parent
	}
	if len(missing) == 0 {
		return false, nil
	}
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil {
		return false, fmt.Errorf("safefile: current token user: %w", err)
	}
	if user == nil || user.User.Sid == nil {
		return false, fmt.Errorf("safefile: current token user is unavailable")
	}
	descriptor, err := windows.SecurityDescriptorFromString(
		fmt.Sprintf("O:%sD:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)", user.User.Sid),
	)
	if err != nil {
		return false, err
	}
	attributes := windows.SecurityAttributes{
		Length:             uint32(unsafe.Sizeof(windows.SecurityAttributes{})),
		SecurityDescriptor: descriptor,
	}
	targetCreated := false
	for index := len(missing) - 1; index >= 0; index-- {
		directory := missing[index]
		ptr, err := winpath.UTF16Ptr(directory)
		if err != nil {
			return false, err
		}
		createErr := windows.CreateDirectory(ptr, &attributes)
		created := createErr == nil
		if createErr != nil && createErr != windows.ERROR_ALREADY_EXISTS {
			return false, createErr
		}
		if index == 0 {
			targetCreated = created
		}
		if !created && !protectConcurrentExisting {
			// A concurrent creator changed the path topology after the
			// initial walk. Leave its ACL untouched and stop before using
			// that directory as an ancestor for any further creation.
			return false, nil
		}
		if err := rejectReparsePath(directory); err != nil {
			return false, err
		}
		if err := protectDirectory(directory); err != nil {
			return false, err
		}
	}
	return targetCreated, nil
}

func setPrivateDACL(path string, inherit bool) error {
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
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
		extended,
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
		extended,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		acl,
		nil,
	)
}

func privateDACLIsSafe(path string) (bool, error) {
	extended, err := winpath.Extended(path)
	if err != nil {
		return false, err
	}
	sd, err := windows.GetNamedSecurityInfo(
		extended, windows.SE_FILE_OBJECT,
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
		// Object, callback, conditional, and other extended ACE layouts do not
		// share ACCESS_ALLOWED_ACE's SID offset. Treat them as unsafe instead of
		// mis-parsing or silently skipping a potentially writable principal.
		if !isSimpleDiscretionaryACE(ace.Header.AceType) {
			return false, nil
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
		if ace.Mask == 0 {
			continue
		}
		if sid.Equals(user.User.Sid) || sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) {
			foundOwner = true
			continue
		}
		if sid.Equals(system) {
			foundSystem = true
			continue
		}
		return false, nil
	}
	return foundOwner && foundSystem, nil
}

// isSimpleDiscretionaryACE deliberately recognizes only the two ACE layouts
// whose SID offset privateDACLIsSafe parses. Object, callback, conditional, and
// callback-object ACEs carry additional fields or application data; accepting
// one as a basic ACCESS_ALLOWED_ACE can validate the wrong SID. Unknown future
// ACE types are therefore unsafe by default.
func isSimpleDiscretionaryACE(aceType byte) bool {
	return aceType == windows.ACCESS_ALLOWED_ACE_TYPE ||
		aceType == windows.ACCESS_DENIED_ACE_TYPE
}
