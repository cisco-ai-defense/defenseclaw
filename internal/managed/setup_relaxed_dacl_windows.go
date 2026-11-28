// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package managed

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// WindowsSetupRelaxedDirectorySDDL is the owner-private DACL a connector
// setup needs on a guardian-hardened per-user agent directory: LocalSystem
// and OWNER RIGHTS full control, inherited by new children.
const WindowsSetupRelaxedDirectorySDDL = "D:P(A;OICI;FA;;;SY)(A;OICI;FA;;;OW)"

// windowsRelaxedFullAccess is FILE_ALL_ACCESS.
const windowsRelaxedFullAccess windows.ACCESS_MASK = 0x001f01ff

// windowsServiceReadMask is GENERIC_READ|GENERIC_EXECUTE mapped to file
// rights (FILE_GENERIC_READ|FILE_GENERIC_EXECUTE, icacls RX): read, list,
// traverse and read attributes, with no write, delete, WRITE_DAC or
// WRITE_OWNER right.
const windowsServiceReadMask windows.ACCESS_MASK = 0x001200a9

// windowsRelaxedACE is one ACCESS_ALLOWED entry a relaxed shape requires.
type windowsRelaxedACE struct {
	sid   *windows.SID
	flags uint8
	mask  windows.ACCESS_MASK
}

// IsWindowsSetupRelaxedDirectoryDACL reports whether sd carries exactly the
// protected WindowsSetupRelaxedDirectorySDDL DACL, in either ACE order.
func IsWindowsSetupRelaxedDirectoryDACL(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	base, err := windowsSetupRelaxedBaseACEs(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	if err != nil {
		return false, err
	}
	return windowsSetupRelaxedShape(sd, true, base)
}

// IsWindowsSetupRelaxedChildFileDACL reports whether sd is the DACL a file
// gets when it is created in a WindowsSetupRelaxedDirectorySDDL folder: not
// protected, and only the two ACEs inherited from that folder. A file moved
// in from another folder keeps its own DACL (a protected one, explicit ACEs
// or ACEs inherited elsewhere), and its owner cannot re-propagate inheritance
// onto a file it has no WRITE_DAC on, so this shape shows the file was made
// in the folder (GAP-1672).
func IsWindowsSetupRelaxedChildFileDACL(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	base, err := windowsSetupRelaxedBaseACEs(windows.INHERITED_ACE)
	if err != nil {
		return false, err
	}
	return windowsSetupRelaxedShape(sd, false, base)
}

// IsWindowsSetupRelaxedAgentDirectoryDACL reports whether sd is the DACL a
// guardian-relaxed per-user agent folder really carries: the protected
// WindowsSetupRelaxedDirectorySDDL DACL, alone or with the read grant the
// hook enumerator gives the gateway service on every agent folder it
// inventories (the read rights on the folder itself and an inherit-only
// GENERIC_READ|GENERIC_EXECUTE entry for its children, the two ACEs Windows
// stores for that grant). service is the gateway service SID; serviceRead
// reports whether the grant is there. Any other entry, another SID, or more
// rights than read for the service is not the shape (GAP-1827: a live
// dcw-std1 .codex folder carries the grant, so the exact two-entry match
// never recognised it).
func IsWindowsSetupRelaxedAgentDirectoryDACL(sd *windows.SECURITY_DESCRIPTOR, service *windows.SID) (relaxed, serviceRead bool, err error) {
	if relaxed, err := IsWindowsSetupRelaxedDirectoryDACL(sd); err != nil || relaxed {
		return relaxed, false, err
	}
	if service == nil {
		return false, false, nil
	}
	aces, err := windowsSetupRelaxedBaseACEs(windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE)
	if err != nil {
		return false, false, err
	}
	aces = append(aces,
		windowsRelaxedACE{sid: service, mask: windowsServiceReadMask},
		windowsRelaxedACE{
			sid:   service,
			flags: windows.OBJECT_INHERIT_ACE | windows.CONTAINER_INHERIT_ACE | windows.INHERIT_ONLY_ACE,
			mask:  windows.GENERIC_READ | windows.GENERIC_EXECUTE,
		})
	relaxed, err = windowsSetupRelaxedShape(sd, true, aces)
	return relaxed, relaxed, err
}

// IsWindowsSetupRelaxedAgentChildFileDACL reports whether sd is the DACL a
// file gets when it is created in an IsWindowsSetupRelaxedAgentDirectoryDACL
// folder: not protected, and exactly the entries inherited from that folder,
// which with serviceRead include the gateway service's inherited read entry.
// As with IsWindowsSetupRelaxedChildFileDACL, a file moved in from elsewhere
// keeps its own DACL and does not match (GAP-1672, GAP-1827).
func IsWindowsSetupRelaxedAgentChildFileDACL(sd *windows.SECURITY_DESCRIPTOR, service *windows.SID, serviceRead bool) (bool, error) {
	if !serviceRead {
		return IsWindowsSetupRelaxedChildFileDACL(sd)
	}
	if service == nil {
		return false, nil
	}
	aces, err := windowsSetupRelaxedBaseACEs(windows.INHERITED_ACE)
	if err != nil {
		return false, err
	}
	aces = append(aces, windowsRelaxedACE{sid: service, flags: windows.INHERITED_ACE, mask: windowsServiceReadMask})
	return windowsSetupRelaxedShape(sd, false, aces)
}

// windowsSetupRelaxedBaseACEs is the LocalSystem and OWNER RIGHTS full
// control pair, with flags.
func windowsSetupRelaxedBaseACEs(flags uint8) ([]windowsRelaxedACE, error) {
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return nil, err
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return nil, err
	}
	return []windowsRelaxedACE{
		{sid: system, flags: flags, mask: windowsRelaxedFullAccess},
		{sid: ownerRights, flags: flags, mask: windowsRelaxedFullAccess},
	}, nil
}

// windowsSetupRelaxedShape reports whether sd's DACL has the protection
// state protected and holds exactly the ACCESS_ALLOWED entries in want, each
// once, in any order.
func windowsSetupRelaxedShape(sd *windows.SECURITY_DESCRIPTOR, protected bool, want []windowsRelaxedACE) (bool, error) {
	if sd == nil {
		return false, nil
	}
	control, _, err := sd.Control()
	if err != nil {
		return false, err
	}
	if (control&windows.SE_DACL_PROTECTED != 0) != protected {
		return false, nil
	}
	dacl, _, err := sd.DACL()
	if err != nil || dacl == nil || int(dacl.AceCount) != len(want) {
		return false, nil
	}
	seen := make([]bool, len(want))
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		matched := false
		for i, entry := range want {
			if !seen[i] && ace.Header.AceFlags == entry.flags && ace.Mask == entry.mask && sid.Equals(entry.sid) {
				seen[i], matched = true, true
				break
			}
		}
		if !matched {
			return false, nil
		}
	}
	return true, nil
}
