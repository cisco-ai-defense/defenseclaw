//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package audit

import (
	"errors"
	"fmt"
	"os"
	"unsafe"

	"golang.org/x/sys/windows"
)

func openAuditDBFileNoFollow(path string, create bool) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("audit: encode Windows database path: %w", err)
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.CREATE_NEW
	}
	handle, err := windows.CreateFile(
		pathPtr,
		// secureAuditDBPlatformFile applies the protected DACL through this
		// pinned handle after the identity checks. SetSecurityInfo requires
		// WRITE_DAC; GENERIC_WRITE alone does not grant it on hosted Windows.
		windows.GENERIC_READ|windows.GENERIC_WRITE|windows.WRITE_DAC,
		windows.FILE_SHARE_READ|windows.FILE_SHARE_WRITE|windows.FILE_SHARE_DELETE,
		nil,
		disposition,
		windows.FILE_ATTRIBUTE_NORMAL|windows.FILE_FLAG_OPEN_REPARSE_POINT,
		0,
	)
	if err != nil {
		return nil, err
	}
	var handleInfo windows.ByHandleFileInformation
	if err := windows.GetFileInformationByHandle(handle, &handleInfo); err != nil {
		_ = windows.CloseHandle(handle)
		return nil, fmt.Errorf("audit: inspect Windows database handle: %w", err)
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("audit: database file must not be a reparse point")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("audit: create Windows database file handle")
	}
	return file, nil
}

func validateAuditDBPlatformTrust(path string, _ os.FileInfo, directory, protectChildren bool) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("audit: encode Windows path: %w", err)
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("audit: inspect Windows path attributes: %w", err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("audit: database path contains a Windows reparse point")
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("audit: inspect Windows security descriptor: %w", err)
	}
	if sd == nil {
		return errors.New("audit: missing Windows security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("audit: inspect Windows owner: %w", err)
	}
	if !auditDBWindowsTrustedPrincipal(owner) {
		return fmt.Errorf("audit: Windows owner %s is not trusted", auditDBWindowsSID(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("audit: inspect Windows DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("audit: null Windows DACL is not trusted")
	}
	return rejectUntrustedAuditDBWindowsACEs(path, dacl, directory, protectChildren)
}

func secureAuditDBPlatformPath(path string, directory bool) error {
	dacl, err := auditDBWindowsProtectedDACL(directory)
	if err != nil {
		return err
	}
	if err := windows.SetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("audit: apply protected Windows DACL: %w", err)
	}
	return nil
}

func secureAuditDBPlatformFile(file *os.File, directory bool) error {
	if file == nil {
		return errors.New("audit: secure Windows file ACL: file handle is unavailable")
	}
	dacl, err := auditDBWindowsProtectedDACL(directory)
	if err != nil {
		return err
	}
	if err := windows.SetSecurityInfo(
		windows.Handle(file.Fd()),
		windows.SE_FILE_OBJECT,
		windows.DACL_SECURITY_INFORMATION|windows.PROTECTED_DACL_SECURITY_INFORMATION,
		nil,
		nil,
		dacl,
		nil,
	); err != nil {
		return fmt.Errorf("audit: apply protected Windows DACL by handle: %w", err)
	}
	return nil
}

func auditDBWindowsProtectedDACL(directory bool) (*windows.ACL, error) {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		return nil, fmt.Errorf("audit: resolve current Windows user: %w", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve Windows Administrators SID: %w", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, fmt.Errorf("audit: resolve Windows LocalSystem SID: %w", err)
	}
	inheritance := uint32(windows.NO_INHERITANCE)
	if directory {
		inheritance = uint32(windows.SUB_CONTAINERS_AND_OBJECTS_INHERIT)
	}
	entries := make([]windows.EXPLICIT_ACCESS, 0, 3)
	for _, sid := range []*windows.SID{currentUser.User.Sid, administrators, localSystem} {
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
	dacl, err := windows.ACLFromEntries(entries, nil)
	if err != nil {
		return nil, fmt.Errorf("audit: build protected Windows DACL: %w", err)
	}
	return dacl, nil
}

func rejectUntrustedAuditDBWindowsACEs(path string, dacl *windows.ACL, directory, protectChildren bool) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("audit: inspect Windows ACE %d for %s: %w", i, path, err)
		}
		if ace == nil {
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		inheritsToChildren := ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
		if inheritOnly && (!directory || !protectChildren || !inheritsToChildren) {
			continue
		}
		readExposesSidecars := protectChildren && (!directory || inheritsToChildren) &&
			auditDBWindowsReadLikeAccess(ace.Mask)
		if !auditDBWindowsWriteLikeAccess(ace.Mask, protectChildren) && !readExposesSidecars {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedCompoundACEType, accessAllowedObjectACEType,
			accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("audit: unsupported Windows allow ACE type 0x%x on %s", ace.Header.AceType, path)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) ||
			inheritOnly && sid.IsWellKnown(windows.WinCreatorOwnerSid) {
			continue
		}
		if !auditDBWindowsTrustedPrincipal(sid) {
			return fmt.Errorf(
				"audit: untrusted Windows principal %s has access mask 0x%x that can expose or modify audit storage on %s",
				auditDBWindowsSID(sid), uint32(ace.Mask), path,
			)
		}
	}
	return nil
}

func auditDBWindowsReadLikeAccess(mask windows.ACCESS_MASK) bool {
	readLike := windows.ACCESS_MASK(
		windows.GENERIC_READ |
			windows.FILE_READ_DATA |
			windows.FILE_READ_EA |
			windows.FILE_READ_ATTRIBUTES |
			windows.FILE_EXECUTE,
	)
	return mask&readLike != 0
}

func auditDBWindowsWriteLikeAccess(mask windows.ACCESS_MASK, protectChildren bool) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	unsafeMask := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER |
			fileDeleteChild,
	)
	if protectChildren {
		unsafeMask |= windows.GENERIC_WRITE | windows.FILE_WRITE_DATA | windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA | windows.FILE_WRITE_ATTRIBUTES
	}
	return mask&unsafeMask != 0
}

func auditDBWindowsTrustedPrincipal(sid *windows.SID) bool {
	if sid == nil {
		return false
	}
	if sid.IsWellKnown(windows.WinBuiltinAdministratorsSid) || sid.IsWellKnown(windows.WinLocalSystemSid) {
		return true
	}
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err == nil && currentUser != nil && currentUser.User.Sid != nil && sid.Equals(currentUser.User.Sid) {
		return true
	}
	trustedInstaller, err := windows.StringToSid("S-1-5-80-956008885-3418522649-1831038044-1853292631-2271478464")
	return err == nil && sid.Equals(trustedInstaller)
}

func auditDBWindowsSID(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

func trustedAuditDBSystemDirectoryAlias(string, os.FileInfo) bool { return false }

// Windows mode bits are synthesized; the protected DACL is authoritative.
func auditDBModeMatches(os.FileInfo, os.FileMode) bool { return true }

// Windows FileInfo permissions are synthesized POSIX bits and do not express
// who can mutate the directory. validateAuditDBPlatformTrust already proves
// owner, protected DACL, inheritance, and every write-capable ACE.
func auditDBImmediateDirectoryModeTrusted(os.FileInfo) bool { return true }
