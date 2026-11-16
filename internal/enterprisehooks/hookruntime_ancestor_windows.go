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

package enterprisehooks

import (
	"encoding/binary"
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsVendorDirectoryUsersRights is what a standard user's hook needs on
// the vendor directory to check it as an ancestor: READ_CONTROL, SYNCHRONIZE,
// FILE_TRAVERSE and FILE_READ_ATTRIBUTES (FILE_GENERIC_EXECUTE), on that
// directory alone. It matches $script:VendorDirectoryUsersRights in
// DefenseClawEnterprise.psm1: Setup grants those rights, records what it
// added and gives exactly that back on uninstall (GAP-0578, GAP-0867).
const windowsVendorDirectoryUsersRights windows.ACCESS_MASK = 0x1200a0

var windowsStandaloneHookRuntimeAncestor = func() (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", err
	}
	return filepath.Dir(layout.HookRuntimeDir), nil
}

// ensureWindowsStandaloneHookRuntimeAncestorReadable makes sure standard users
// can check the vendor directory above the per-user hook runtime
// (C:\ProgramData\Cisco). Per-user runtime generations are prepared and
// resolved with the target user's token, which validates every ancestor's
// security descriptor. Setup normally granted the rights already, so this is
// a no-op. The directory is shared with other Cisco software: an existing
// Users entry is never changed. It used to be merged up to read and execute
// (0x1200a9) here, which Setup recorded nothing for, so an uninstall left an
// administrator's 0x1200a0 entry widened (GAP-0867). Only when users lack the
// rights is a separate, non-inheritable entry with the missing rights alone
// added, to an Administrators- or LocalSystem-owned, non-reparse directory.
func ensureWindowsStandaloneHookRuntimeAncestorReadable() error {
	vendor, err := windowsStandaloneHookRuntimeAncestor()
	if err != nil {
		return fmt.Errorf("enterprise hooks: resolve hook runtime ancestor: %w", err)
	}
	return ensureWindowsDirectoryUsersReadable(vendor)
}

func ensureWindowsDirectoryUsersReadable(path string) error {
	if err := winpath.RejectReparseChain(path); err != nil {
		return fmt.Errorf("enterprise hooks: hook runtime ancestor %s: %w", path, err)
	}
	descriptor, err := windows.GetNamedSecurityInfo(
		path,
		windows.SE_FILE_OBJECT,
		windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION,
	)
	if err != nil {
		return fmt.Errorf("enterprise hooks: read hook runtime ancestor %s: %w", path, err)
	}
	owner, _, err := descriptor.Owner()
	if err != nil || owner == nil {
		return fmt.Errorf("enterprise hooks: hook runtime ancestor %s has no owner", path)
	}
	if !owner.IsWellKnown(windows.WinBuiltinAdministratorsSid) && !owner.IsWellKnown(windows.WinLocalSystemSid) {
		return fmt.Errorf("enterprise hooks: hook runtime ancestor %s is not owned by Administrators or LocalSystem", path)
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	dacl, defaulted, err := descriptor.DACL()
	if err != nil {
		return fmt.Errorf("enterprise hooks: read hook runtime ancestor DACL %s: %w", path, err)
	}
	if dacl == nil || defaulted {
		return fmt.Errorf("enterprise hooks: hook runtime ancestor %s has no explicit DACL", path)
	}
	missing := windowsVendorDirectoryUsersRights &^ windowsEveryUserAllowedMask(dacl)
	if missing == 0 {
		return nil
	}
	updated, err := windowsACLWithAllowACE(dacl, users, missing)
	if err != nil {
		return fmt.Errorf("enterprise hooks: extend hook runtime ancestor DACL %s: %w", path, err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, nil, nil, updated, nil); err != nil {
		return fmt.Errorf("enterprise hooks: grant users read on hook runtime ancestor %s: %w", path, err)
	}
	return nil
}

// windowsEveryUserAllowedMask is the union of the rights the allow entries
// for Users, Authenticated Users and Everyone give on this object itself.
// GENERIC_ALL, GENERIC_READ and GENERIC_EXECUTE cover the vendor rights, as
// Test-DefenseClawStandaloneVendorUsersRead counts them.
func windowsEveryUserAllowedMask(dacl *windows.ACL) windows.ACCESS_MASK {
	var granted windows.ACCESS_MASK
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.IsWellKnown(windows.WinBuiltinUsersSid) &&
			!sid.IsWellKnown(windows.WinAuthenticatedUserSid) &&
			!sid.IsWellKnown(windows.WinWorldSid) {
			continue
		}
		mask := ace.Mask
		if mask&(windows.GENERIC_ALL|windows.GENERIC_READ|windows.GENERIC_EXECUTE) != 0 {
			mask |= windowsVendorDirectoryUsersRights
		}
		granted |= mask
	}
	return granted
}

// windowsACLWithAllowACE copies dacl byte for byte and inserts one
// non-inheritable allow entry for sid with mask after the explicit entries,
// so no existing entry changes (SetEntriesInAcl merges into an existing entry
// for the same trustee instead).
func windowsACLWithAllowACE(dacl *windows.ACL, sid *windows.SID, mask windows.ACCESS_MASK) (*windows.ACL, error) {
	const aclHeaderSize, aceHeaderSize = 8, 8
	header := unsafe.Slice((*byte)(unsafe.Pointer(dacl)), aclHeaderSize)
	source := unsafe.Slice((*byte)(unsafe.Pointer(dacl)), int(binary.LittleEndian.Uint16(header[2:4])))
	count := int(binary.LittleEndian.Uint16(header[4:6]))
	used, insert := aclHeaderSize, -1
	for index := 0; index < count; index++ {
		if used+4 > len(source) {
			return nil, fmt.Errorf("DACL entry %d is truncated", index)
		}
		size := int(binary.LittleEndian.Uint16(source[used+2 : used+4]))
		if size < 4 || used+size > len(source) {
			return nil, fmt.Errorf("DACL entry %d is truncated", index)
		}
		if insert < 0 && source[used+1]&windows.INHERITED_ACE != 0 {
			insert = used
		}
		used += size
	}
	if insert < 0 {
		insert = used
	}
	aceSize := aceHeaderSize + int(sid.Len())
	total := used + aceSize
	if total > 0xffff || count+1 > 0xffff {
		return nil, fmt.Errorf("DACL is too large to extend")
	}
	words := make([]uint32, (total+3)/4)
	out := unsafe.Slice((*byte)(unsafe.Pointer(&words[0])), total)
	copy(out, source[:insert])
	ace := out[insert : insert+aceSize]
	ace[0] = windows.ACCESS_ALLOWED_ACE_TYPE
	ace[1] = 0
	binary.LittleEndian.PutUint16(ace[2:4], uint16(aceSize))
	binary.LittleEndian.PutUint32(ace[4:8], uint32(mask))
	copy(ace[8:], unsafe.Slice((*byte)(unsafe.Pointer(sid)), sid.Len()))
	copy(out[insert+aceSize:], source[insert:used])
	binary.LittleEndian.PutUint16(out[2:4], uint16(total))
	binary.LittleEndian.PutUint16(out[4:6], uint16(count+1))
	return (*windows.ACL)(unsafe.Pointer(&words[0])), nil
}
