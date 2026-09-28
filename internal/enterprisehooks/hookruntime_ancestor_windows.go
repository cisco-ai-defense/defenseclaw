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
	"fmt"
	"path/filepath"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/managed"
	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// windowsUsersReadExecute is FILE_GENERIC_READ | FILE_GENERIC_EXECUTE, the
// right ProgramData children normally grant BUILTIN\Users.
const windowsUsersReadExecute windows.ACCESS_MASK = 0x1200a9

var windowsStandaloneHookRuntimeAncestor = func() (string, error) {
	layout, err := managed.StandaloneWindowsLayout()
	if err != nil {
		return "", err
	}
	return filepath.Dir(layout.HookRuntimeDir), nil
}

// ensureWindowsStandaloneHookRuntimeAncestorReadable makes the vendor
// directory above the per-user hook runtime (C:\ProgramData\Cisco) readable
// by standard users. Per-user runtime generations are prepared and resolved
// with the target user's token, which validates every ancestor's security
// descriptor; a standalone install that created the vendor directory
// Administrators-only (there is no Secure Client to create it with the usual
// ProgramData inheritance) left users unable to read it. Only a
// non-inheritable read/execute entry for BUILTIN\Users is added, and only to
// an Administrators- or LocalSystem-owned, non-reparse directory; all other
// entries are preserved.
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
	administrators, err := windows.CreateWellKnownSid(windows.WinBuiltinAdministratorsSid)
	if err != nil {
		return err
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return err
	}
	if !owner.Equals(administrators) && !owner.Equals(system) {
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
	if windowsDACLGrants(dacl, users, windowsUsersReadExecute) {
		return nil
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: windowsUsersReadExecute,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(users),
		},
	}}, dacl)
	if err != nil {
		return fmt.Errorf("enterprise hooks: merge hook runtime ancestor DACL %s: %w", path, err)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, information, nil, nil, merged, nil); err != nil {
		return fmt.Errorf("enterprise hooks: grant users read on hook runtime ancestor %s: %w", path, err)
	}
	return nil
}

// windowsDACLGrants reports whether an allow entry for sid already carries at
// least mask on this object.
func windowsDACLGrants(dacl *windows.ACL, sid *windows.SID, mask windows.ACCESS_MASK) bool {
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		aceSID := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if aceSID.Equals(sid) && ace.Mask&mask == mask {
			return true
		}
	}
	return false
}
