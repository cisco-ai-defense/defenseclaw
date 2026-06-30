// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"fmt"
	"os"
	"path/filepath"
	"unsafe"

	"golang.org/x/sys/windows"
)

func hookAPIValidateOwner(path string, _ os.FileInfo) error {
	return hookAPIValidateWindowsPathElement(path, false, true)
}

func hookAPIValidateDirectory(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	clean := filepath.Clean(path)
	protectChildren := true
	for cur := clean; ; cur = filepath.Dir(cur) {
		if err := hookAPIValidateWindowsPathElement(cur, true, protectChildren); err != nil {
			return err
		}
		protectChildren = false
		if cur == filepath.Dir(cur) {
			break
		}
	}
	return nil
}

func hookAPIValidateDirectoryElement(path string) error {
	if !filepath.IsAbs(path) {
		return fmt.Errorf("hook API token directory must be absolute: %q", path)
	}
	return hookAPIValidateWindowsPathElement(filepath.Clean(path), true, true)
}

func hookAPIValidateWindowsPathElement(path string, wantDir, protectChildren bool) error {
	hookAPIWindowsPathStage(path, "lstat")
	info, err := os.Lstat(path)
	if err != nil {
		return err
	}
	pathPtr, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return fmt.Errorf("encode Windows path %s: %w", path, err)
	}
	hookAPIWindowsPathStage(path, "attributes")
	attributes, err := windows.GetFileAttributes(pathPtr)
	if err != nil {
		return fmt.Errorf("inspect Windows attributes for %s: %w", path, err)
	}
	if info.Mode()&os.ModeSymlink != 0 || attributes&windows.FILE_ATTRIBUTE_REPARSE_POINT != 0 {
		return fmt.Errorf("symlinks, junctions, and reparse points are not allowed: %s", path)
	}
	if wantDir && !info.IsDir() {
		return fmt.Errorf("expected directory: %s", path)
	}
	if !wantDir && !info.Mode().IsRegular() {
		return fmt.Errorf("expected regular file: %s", path)
	}
	hookAPIWindowsPathStage(path, "security-info")
	sd, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("inspect Windows security descriptor for %s: %w", path, err)
	}
	if sd == nil {
		return fmt.Errorf("missing Windows security descriptor: %s", path)
	}
	defer func() { _, _ = windows.LocalFree(windows.Handle(unsafe.Pointer(sd))) }()
	hookAPIWindowsPathStage(path, "owner")
	owner, _, err := sd.Owner()
	if err != nil {
		return fmt.Errorf("inspect Windows owner for %s: %w", path, err)
	}
	if !hookAPIWindowsTrustedPrincipal(owner) {
		return fmt.Errorf("owner %s is not trusted for hook API token path %s", hookAPIWindowsSIDString(owner), path)
	}
	hookAPIWindowsPathStage(path, "dacl")
	dacl, _, err := sd.DACL()
	if err != nil {
		return fmt.Errorf("inspect Windows DACL for %s: %w", path, err)
	}
	if dacl == nil {
		return fmt.Errorf("null Windows DACL is not trusted: %s", path)
	}
	hookAPIWindowsPathStage(path, "aces")
	if err := hookAPIRejectUntrustedWindowsWriteACEs(path, dacl, wantDir, protectChildren); err != nil {
		return err
	}
	hookAPIWindowsPathStage(path, "ready")
	return nil
}

func hookAPIWindowsPathStage(path, stage string) {
	fmt.Fprintf(os.Stderr, "[hook-token] path=%s stage=%s\n", path, stage)
}

func hookAPIRejectUntrustedWindowsWriteACEs(path string, dacl *windows.ACL, wantDir, protectChildren bool) error {
	const (
		accessAllowedCompoundACEType       = 0x4
		accessAllowedObjectACEType         = 0x5
		accessAllowedCallbackACEType       = 0x9
		accessAllowedCallbackObjectACEType = 0xB
	)
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return fmt.Errorf("inspect Windows ACE %d for %s: %w", i, path, err)
		}
		if ace == nil {
			continue
		}
		inheritOnly := ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0
		inheritsToChildren := ace.Header.AceFlags&(windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE) != 0
		if inheritOnly && (!protectChildren || !wantDir || !inheritsToChildren) {
			continue
		}
		if !hookAPIWindowsWriteLikeAccess(ace.Mask, protectChildren) {
			continue
		}
		switch ace.Header.AceType {
		case accessAllowedCompoundACEType, accessAllowedObjectACEType, accessAllowedCallbackACEType, accessAllowedCallbackObjectACEType:
			return fmt.Errorf("unsupported Windows allow ACE type 0x%x on %s", ace.Header.AceType, path)
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		default:
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if hookAPIWindowsOwnerRightsPrincipal(sid) {
			continue
		}
		if inheritOnly && hookAPIWindowsCreatorOwnerTemplate(sid) {
			continue
		}
		if !hookAPIWindowsTrustedPrincipal(sid) {
			return fmt.Errorf("untrusted Windows principal %s has write-like access mask 0x%x on %s", hookAPIWindowsSIDString(sid), uint32(ace.Mask), path)
		}
	}
	return nil
}

func hookAPIWindowsCreatorOwnerTemplate(sid *windows.SID) bool {
	return sid != nil && sid.IsWellKnown(windows.WinCreatorOwnerSid)
}

func hookAPIWindowsOwnerRightsPrincipal(sid *windows.SID) bool {
	return sid != nil && sid.IsWellKnown(windows.WinCreatorOwnerRightsSid)
}

func hookAPIWindowsWriteLikeAccess(mask windows.ACCESS_MASK, protectChildren bool) bool {
	const fileDeleteChild windows.ACCESS_MASK = 0x00000040
	unsafe := windows.ACCESS_MASK(
		windows.GENERIC_ALL |
			windows.DELETE |
			windows.WRITE_DAC |
			windows.WRITE_OWNER,
	)
	if protectChildren {
		unsafe |= windows.GENERIC_WRITE |
			windows.FILE_WRITE_DATA |
			windows.FILE_APPEND_DATA |
			windows.FILE_WRITE_EA |
			windows.FILE_WRITE_ATTRIBUTES
	}
	return mask&(unsafe|fileDeleteChild) != 0
}

func hookAPIWindowsTrustedPrincipal(sid *windows.SID) bool {
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

func hookAPIWindowsSIDString(sid *windows.SID) string {
	if sid == nil {
		return "<nil>"
	}
	return sid.String()
}
