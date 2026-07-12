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

func openJudgeBodyFileNoFollow(path string, create bool) (*os.File, error) {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return nil, fmt.Errorf("judge_body: encode Windows database path: %w", err)
	}
	disposition := uint32(windows.OPEN_EXISTING)
	if create {
		disposition = windows.CREATE_NEW
	}
	handle, err := windows.CreateFile(
		pathPtr,
		windows.GENERIC_READ|windows.GENERIC_WRITE,
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
		return nil, fmt.Errorf("judge_body: inspect Windows database handle: %w", err)
	}
	if handleInfo.FileAttributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("judge_body: database file must not be a reparse point")
	}
	file := os.NewFile(uintptr(handle), path)
	if file == nil {
		_ = windows.CloseHandle(handle)
		return nil, errors.New("judge_body: create Windows database file handle")
	}
	return file, nil
}

func validateJudgeBodyPlatformTrust(path string, _ os.FileInfo, directory, protectChildren bool) error {
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("judge_body: encode Windows path: %w", err)
	}
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("judge_body: inspect Windows path attributes: %w", err)
	}
	if attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return errors.New("judge_body: database path contains a Windows reparse point")
	}

	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("judge_body: inspect Windows security descriptor: %w", err)
	}
	if sd == nil {
		return errors.New("judge_body: missing Windows security descriptor")
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("judge_body: inspect Windows owner: %w", err)
	}
	if !judgeBodyWindowsTrustedPrincipal(owner) {
		return fmt.Errorf("judge_body: Windows owner %s is not trusted", judgeBodyWindowsSID(owner))
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("judge_body: inspect Windows DACL: %w", err)
	}
	if dacl == nil {
		return errors.New("judge_body: null Windows DACL is not trusted")
	}
	return rejectUntrustedJudgeBodyWindowsWriteACEs(path, dacl, directory, protectChildren)
}

func secureJudgeBodyPlatformPath(path string, directory bool) error {
	currentUser, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || currentUser == nil || currentUser.User.Sid == nil {
		return fmt.Errorf("judge_body: resolve current Windows user: %w", err)
	}
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return fmt.Errorf("judge_body: resolve Windows Administrators SID: %w", err)
	}
	localSystem, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return fmt.Errorf("judge_body: resolve Windows LocalSystem SID: %w", err)
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
		return fmt.Errorf("judge_body: build protected Windows DACL: %w", err)
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
		return fmt.Errorf("judge_body: apply protected Windows DACL: %w", err)
	}
	return nil
}

func rejectUntrustedJudgeBodyWindowsWriteACEs(path string, dacl *windows.ACL, directory, protectChildren bool) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("judge_body: inspect Windows ACE %d for %s: %w", i, path, err)
		}
		if ace == nil {
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		inheritsToChildren := ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
		if inheritOnly && (!directory || !protectChildren || !inheritsToChildren) {
			continue
		}
		readExposesDatabase := protectChildren && (!directory || inheritsToChildren) &&
			judgeBodyWindowsReadLikeAccess(ace.Mask)
		if !judgeBodyWindowsWriteLikeAccess(ace.Mask, protectChildren) && !readExposesDatabase {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedCompoundACEType, accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("judge_body: unsupported Windows allow ACE type 0x%x on %s", ace.Header.AceType, path)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if sid.IsWellKnown(windows.WinCreatorOwnerRightsSid) ||
			inheritOnly && sid.IsWellKnown(windows.WinCreatorOwnerSid) {
			continue
		}
		if !judgeBodyWindowsTrustedPrincipal(sid) {
			return fmt.Errorf(
				"judge_body: untrusted Windows principal %s has access mask 0x%x that can expose or modify judge-body storage on %s",
				judgeBodyWindowsSID(sid), uint32(ace.Mask), path,
			)
		}
	}
	return nil
}

func judgeBodyWindowsReadLikeAccess(mask windows.ACCESS_MASK) bool {
	readLike := windows.ACCESS_MASK(
		windows.GENERIC_READ |
			windows.FILE_READ_DATA |
			windows.FILE_READ_EA |
			windows.FILE_READ_ATTRIBUTES |
			windows.FILE_EXECUTE,
	)
	return mask&readLike != 0
}

func judgeBodyWindowsWriteLikeAccess(mask windows.ACCESS_MASK, protectChildren bool) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	// Every directory component rejects FILE_DELETE_CHILD: it lets an attacker
	// remove/rename an already validated lower component. Merely creating an
	// unrelated child can be legitimate on Windows volume/profile ancestors, so
	// the broader add/write mask is required only on the immediate DB parent.
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

func judgeBodyWindowsTrustedPrincipal(sid *windows.SID) bool {
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

func judgeBodyWindowsSID(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}

func trustedJudgeBodySystemDirectoryAlias(string, os.FileInfo) bool { return false }

// Windows reports synthesized POSIX mode bits. The protected DACL is the
// authoritative access check, so chmod's synthetic mode is not compared.
func judgeBodyModeMatches(os.FileInfo, os.FileMode) bool { return true }

// Windows FileInfo permissions are synthesized POSIX bits; the protected-DACL
// validation above is the authoritative directory mutation boundary.
func judgeBodyImmediateDirectoryModeTrusted(os.FileInfo) bool { return true }
