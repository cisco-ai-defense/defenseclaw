// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import (
	"os"
	"unsafe"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// Deny access-entry types that x/sys/windows does not name.
const (
	accessDeniedObjectACEType         = 0x6
	accessDeniedCallbackACEType       = 0xA
	accessDeniedCallbackObjectACEType = 0xC
)

// skillHomeTrust is the trust for a skill folder in home: that of the account
// the discovery profile list names for home when it names one (the folder of
// a profile may be owned by SYSTEM), else skillHomeOwnerTrust.
func (s *ContinuousDiscoveryService) skillHomeTrust(home string) func(*os.File, string) bool {
	if home != "" {
		if owner, ok := s.homeOwnerForPath(home); ok {
			if sid, err := windows.StringToSid(owner.UserID); err == nil {
				return skillAccountTrust(sid)
			}
		}
	}
	return skillHomeOwnerTrust(home)
}

// skillHomeOwnerTrust is skillAccountTrust for the owner of home (the
// scanning account when home is "").
func skillHomeOwnerTrust(home string) func(*os.File, string) bool {
	var owner *windows.SID
	if home != "" {
		owner = skillPathOwner(home)
	} else if user, err := windows.GetCurrentProcessToken().GetTokenUser(); err == nil {
		owner = user.User.Sid
	}
	return skillAccountTrust(owner)
}

// skillAccountTrust approves a folder a resolved skill path goes through, and
// every folder and file the walk below a linked skill folder opens (GAP-2008),
// when account owns it, or SYSTEM, Administrators or TrustedInstaller owns it
// and its access list lets account list the folder or read the file. A
// junction in a home therefore cannot lead a SYSTEM scan into a folder only
// administrators may read, such as systemprofile.
func skillAccountTrust(account *windows.SID) func(*os.File, string) bool {
	if account == nil {
		return func(*os.File, string) bool { return false }
	}
	return func(opened *os.File, path string) bool {
		descriptor, directory, err := skillSecurity(opened, path)
		if err != nil {
			return false
		}
		owner, _, err := descriptor.Owner()
		if err != nil || owner == nil {
			return false
		}
		if owner.Equals(account) {
			return true
		}
		need := windows.ACCESS_MASK(windows.FILE_READ_DATA)
		if directory {
			need = windows.FILE_LIST_DIRECTORY | windows.FILE_TRAVERSE
		}
		// The entries that name the account or every account first; then
		// Windows decides with the account's groups, where a deny entry for a
		// group the account is in takes the right away (GAP-2146).
		return skillAdminSID(owner) && skillAccessGranted(descriptor, account, need) &&
			skillAuthzGranted(descriptor, account, need)
	}
}

// skillSecurity reads the owner and access list of opened, or of the folder
// at path when opened is nil: a folder above the resolved one, read by name
// after the open pinned a chain with no reparse point. directory reports a
// folder.
func skillSecurity(opened *os.File, path string) (*windows.SECURITY_DESCRIPTOR, bool, error) {
	const info = windows.OWNER_SECURITY_INFORMATION | windows.DACL_SECURITY_INFORMATION
	if opened == nil {
		descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, info)
		return descriptor, true, err
	}
	stat, err := opened.Stat()
	if err != nil {
		return nil, false, err
	}
	descriptor, err := windows.GetSecurityInfo(windows.Handle(opened.Fd()), windows.SE_FILE_OBJECT, info)
	return descriptor, stat.IsDir(), err
}

// skillAccessGranted reports whether the access list in descriptor gives
// account, or a group every account is in, every right in need, and no deny
// entry for them takes one of those rights. Groups the account may also be
// in are not looked up here: skillAuthzGranted does that.
func skillAccessGranted(descriptor *windows.SECURITY_DESCRIPTOR, account *windows.SID, need windows.ACCESS_MASK) bool {
	dacl, _, err := descriptor.DACL()
	if err != nil {
		return false
	}
	if dacl == nil {
		return true // a NULL access list grants everyone every access
	}
	var granted windows.ACCESS_MASK
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil || ace == nil {
			return false
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		deny := false
		switch ace.Header.AceType {
		case windows.ACCESS_ALLOWED_ACE_TYPE:
		case windows.ACCESS_DENIED_ACE_TYPE:
			deny = true
		case accessDeniedObjectACEType, accessDeniedCallbackACEType, accessDeniedCallbackObjectACEType:
			return false // a deny entry whose account is not read here
		default:
			continue // other allow entries are not counted
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if !sid.Equals(account) && !skillEveryAccountSID(sid) {
			continue
		}
		mask := safefile.FileAccessMask(ace.Mask)
		if deny {
			if mask&need != 0 {
				return false
			}
			continue
		}
		granted |= mask
	}
	return granted&need == need
}

// skillEveryAccountSID reports a group every signed-in account is in:
// Everyone, Users, Authenticated Users or INTERACTIVE.
func skillEveryAccountSID(sid *windows.SID) bool {
	switch sid.String() {
	case "S-1-1-0", "S-1-5-32-545", "S-1-5-11", "S-1-5-4":
		return true
	}
	return false
}

// skillPathOwner is the owner of the file or folder at path, nil when it
// cannot be read.
func skillPathOwner(path string) *windows.SID {
	sd, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION)
	if err != nil {
		return nil
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return nil
	}
	return owner
}
