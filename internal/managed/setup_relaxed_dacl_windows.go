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

// IsWindowsSetupRelaxedDirectoryDACL reports whether sd carries exactly the
// protected WindowsSetupRelaxedDirectorySDDL DACL, in either ACE order.
func IsWindowsSetupRelaxedDirectoryDACL(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	return windowsSetupRelaxedShape(sd, true, windows.OBJECT_INHERIT_ACE|windows.CONTAINER_INHERIT_ACE)
}

// IsWindowsSetupRelaxedChildFileDACL reports whether sd is the DACL a file
// gets when it is created in a WindowsSetupRelaxedDirectorySDDL folder: not
// protected, and only the two ACEs inherited from that folder. A file moved
// in from another folder keeps its own DACL (a protected one, explicit ACEs
// or ACEs inherited elsewhere), and its owner cannot re-propagate inheritance
// onto a file it has no WRITE_DAC on, so this shape shows the file was made
// in the folder (GAP-1672).
func IsWindowsSetupRelaxedChildFileDACL(sd *windows.SECURITY_DESCRIPTOR) (bool, error) {
	return windowsSetupRelaxedShape(sd, false, windows.INHERITED_ACE)
}

func windowsSetupRelaxedShape(sd *windows.SECURITY_DESCRIPTOR, protected bool, aceFlags uint8) (bool, error) {
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
	if err != nil || dacl == nil || dacl.AceCount != 2 {
		return false, nil
	}
	system, err := windows.CreateWellKnownSid(windows.WinLocalSystemSid)
	if err != nil {
		return false, err
	}
	ownerRights, err := windows.CreateWellKnownSid(windows.WinCreatorOwnerRightsSid)
	if err != nil {
		return false, err
	}
	const fullAccess windows.ACCESS_MASK = 0x001f01ff
	sawSystem, sawOwnerRights := false, false
	for index := uint32(0); index < uint32(dacl.AceCount); index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, index, &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE ||
			ace.Header.AceFlags != aceFlags || ace.Mask != fullAccess {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		switch {
		case sid.Equals(system) && !sawSystem:
			sawSystem = true
		case sid.Equals(ownerRights) && !sawOwnerRights:
			sawOwnerRights = true
		default:
			return false, nil
		}
	}
	return sawSystem && sawOwnerRights, nil
}
