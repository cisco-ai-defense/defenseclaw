// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"fmt"
	"path/filepath"
	"strings"
	"unsafe"

	"golang.org/x/sys/windows"
)

const projectSkillWriteMask uint32 = 0x00000002 | 0x00000004 | 0x00000010 |
	0x00000040 | 0x00000100 | 0x00010000 | 0x00040000 | 0x00080000 |
	0x10000000 | 0x40000000

// projectSkillRootSharedWritable checks the root and every folder through
// the caller's profile. A different owner can replace a folder by changing
// its access list even when its current allow entries are read-only.
func projectSkillRootSharedWritable(home, root string) (bool, error) {
	user, err := windows.GetCurrentProcessToken().GetTokenUser()
	if err != nil || user == nil || user.User.Sid == nil {
		return false, fmt.Errorf("caller SID is unavailable: %w", err)
	}
	caller := user.User.Sid.String()
	for dir := filepath.Clean(root); ; dir = filepath.Dir(dir) {
		shared, err := projectSkillFolderSharedWritable(dir, caller)
		if shared || err != nil {
			return shared, err
		}
		if strings.EqualFold(dir, filepath.Clean(home)) {
			return false, nil
		}
		if filepath.Dir(dir) == dir {
			return false, fmt.Errorf("project skill root left the caller profile")
		}
	}
}

func projectSkillFolderSharedWritable(path, caller string) (bool, error) {
	// The security descriptor is read only below a share that has answered.
	if networkPathUnanswered(path) {
		return false, networkShareError("security", path)
	}
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil || owner == nil {
		return false, fmt.Errorf("project skill folder owner is unavailable: %w", err)
	}
	if !projectSkillTrustedWriter(owner.String(), caller) {
		return true, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return true, nil
	}
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE, 0x09:
			if uint32(ace.Mask)&projectSkillWriteMask != 0 &&
				!projectSkillTrustedWriter((*windows.SID)(unsafe.Pointer(&ace.SidStart)).String(), caller) {
				return true, nil
			}
		case 0x05, 0x0b:
			return false, fmt.Errorf("project skill folder has an unsupported allow entry")
		}
	}
	return false, nil
}

func projectSkillTrustedWriter(sid, caller string) bool {
	return strings.EqualFold(sid, caller) || sid == "S-1-5-18" ||
		sid == "S-1-5-32-544" || sid == "S-1-3-0" || sid == "S-1-3-4"
}
