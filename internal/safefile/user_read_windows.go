// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package safefile

import (
	"errors"
	"fmt"
	"strings"
	"unsafe"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// Access-entry types that x/sys/windows does not name.
const (
	accessDeniedObjectACEType         = 0x6
	accessDeniedCallbackACEType       = 0xA
	accessDeniedCallbackObjectACEType = 0xC
	fileAllAccess                     = windows.ACCESS_MASK(0x1F01FF)
)

// UsersRead is the access an ordinary user's agent needs to open and read a
// machine policy file, the access an open for GENERIC_READ asks for.
const UsersRead = windows.ACCESS_MASK(windows.FILE_GENERIC_READ)

// UsersCanRead reports, as an error, when the access list in metadata does
// not let every ordinary user read the file. A machine policy that its
// agent reads with the user's own token, Codex's requirements.toml for
// example, does nothing for a user who cannot open it.
//
// Every ordinary account carries Everyone, Users and Authenticated Users, so
// only an allow entry for one of them grants the read. A deny entry that
// takes part of the read from any principal other than LocalSystem,
// Administrators, the service accounts and the owner refuses it: it applies
// to the users it names, and an ordinary user may be among them.
func UsersCanRead(metadata FileMetadata) error {
	descriptor, err := windows.SecurityDescriptorFromString(metadata.SecurityDescriptor)
	if err != nil || descriptor == nil || !descriptor.IsValid() {
		return errors.New("safefile: the file has no valid security descriptor")
	}
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return errors.New("safefile: the file has no access list")
	}
	if dacl == nil {
		return nil // a NULL access list grants everyone every access
	}
	var granted windows.ACCESS_MASK
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return fmt.Errorf("safefile: read access entry %d: %v", index, err)
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
			if ordinaryUsersSID((*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()) {
				granted |= fileAccessMask(ace.Mask)
			}
		case windows.ACCESS_DENIED_ACE_TYPE, accessDeniedCallbackACEType:
			sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String()
			if fileAccessMask(ace.Mask)&UsersRead != 0 && !privilegedSID(sid) {
				return fmt.Errorf("safefile: an access entry denies %s read access", sid)
			}
		case accessDeniedObjectACEType, accessDeniedCallbackObjectACEType:
			return errors.New("safefile: an object access entry denies access")
		}
	}
	if missing := UsersRead &^ granted; missing != 0 {
		return fmt.Errorf("safefile: ordinary users lack read access %#x", uint32(missing))
	}
	return nil
}

// GrantUsersRead adds an allow entry for BUILTIN\Users with UsersRead to the
// access list of the file at path and keeps every other entry, its
// protection from inheritance included.
func GrantUsersRead(path string) error {
	extended, err := winpath.Extended(path)
	if err != nil {
		return err
	}
	descriptor, err := windows.GetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return fmt.Errorf("safefile: read the access list of %s: %w", path, err)
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return fmt.Errorf("safefile: %s has no access list to add to", path)
	}
	control, _, err := descriptor.Control()
	if err != nil {
		return err
	}
	users, err := windows.CreateWellKnownSid(windows.WinBuiltinUsersSid)
	if err != nil {
		return err
	}
	merged, err := windows.ACLFromEntries([]windows.EXPLICIT_ACCESS{{
		AccessPermissions: UsersRead,
		AccessMode:        windows.GRANT_ACCESS,
		Inheritance:       windows.NO_INHERITANCE,
		Trustee: windows.TRUSTEE{
			TrusteeForm:  windows.TRUSTEE_IS_SID,
			TrusteeType:  windows.TRUSTEE_IS_WELL_KNOWN_GROUP,
			TrusteeValue: windows.TrusteeValueFromSID(users),
		},
	}}, dacl)
	if err != nil {
		return fmt.Errorf("safefile: add the Users read entry for %s: %w", path, err)
	}
	information := windows.SECURITY_INFORMATION(windows.DACL_SECURITY_INFORMATION)
	if control&windows.SE_DACL_PROTECTED != 0 {
		information |= windows.PROTECTED_DACL_SECURITY_INFORMATION
	}
	if err := windows.SetNamedSecurityInfo(extended, windows.SE_FILE_OBJECT, information, nil, nil, merged, nil); err != nil {
		return fmt.Errorf("safefile: grant Users read on %s: %w", path, err)
	}
	return nil
}

// fileAccessMask maps the generic rights in mask to the file rights they
// stand for.
func fileAccessMask(mask windows.ACCESS_MASK) windows.ACCESS_MASK {
	mapped := mask &^ (windows.GENERIC_READ | windows.GENERIC_WRITE | windows.GENERIC_EXECUTE | windows.GENERIC_ALL)
	if mask&windows.GENERIC_READ != 0 {
		mapped |= windows.FILE_GENERIC_READ
	}
	if mask&windows.GENERIC_WRITE != 0 {
		mapped |= windows.FILE_GENERIC_WRITE
	}
	if mask&windows.GENERIC_EXECUTE != 0 {
		mapped |= windows.FILE_GENERIC_EXECUTE
	}
	if mask&windows.GENERIC_ALL != 0 {
		mapped |= fileAllAccess
	}
	return mapped
}

// ordinaryUsersSID reports a group every ordinary account is in: Everyone,
// Users or Authenticated Users.
func ordinaryUsersSID(sid string) bool {
	switch sid {
	case "S-1-1-0", "S-1-5-32-545", "S-1-5-11":
		return true
	}
	return false
}

// privilegedSID reports a principal no ordinary user holds: LocalSystem,
// LocalService, NetworkService, Administrators, OWNER RIGHTS (the owner of a
// machine policy file is Administrators or LocalSystem) and service SIDs.
func privilegedSID(sid string) bool {
	switch sid {
	case "S-1-5-18", "S-1-5-19", "S-1-5-20", "S-1-5-32-544", "S-1-3-4":
		return true
	}
	return strings.HasPrefix(sid, "S-1-5-80-")
}
