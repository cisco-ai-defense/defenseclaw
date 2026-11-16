// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enterprisepolicy

import (
	"fmt"
	"unsafe"

	"golang.org/x/sys/windows"
)

// CoworkPublicFileReady inspects the same no-follow handle it opened. Every
// ordinary user must be able to read the package, signature and arguments;
// no ordinary principal may modify them. Unlike the Bun-specific OpenCode
// contract, Cowork requires no FILE_WRITE_ATTRIBUTES permission.
func CoworkPublicFileReady(path string) (bool, error) {
	file, err := openNoFollow(path)
	if err != nil {
		return false, err
	}
	defer file.Close()
	info, err := file.Stat()
	if err != nil {
		return false, err
	}
	if !info.Mode().IsRegular() {
		return false, fmt.Errorf("%s is not a regular file", path)
	}
	sd, err := windows.GetSecurityInfo(windows.Handle(file.Fd()), windows.SE_FILE_OBJECT, windows.OWNER_SECURITY_INFORMATION|windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false, err
	}
	owner, _, err := sd.Owner()
	if err != nil {
		return false, err
	}
	if owner == nil || !trustedWindowsPublicDirPrincipal(owner) {
		return false, fmt.Errorf("%s is not administrator-owned", path)
	}
	dacl, _, err := sd.DACL()
	if err != nil {
		return false, err
	}
	if dacl == nil {
		return false, fmt.Errorf("%s has no DACL", path)
	}
	const readExecute uint32 = 0x1200a9
	var users uint32
	for i := uint16(0); i < dacl.AceCount; i++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if err := windows.GetAce(dacl, uint32(i), &ace); err != nil {
			return false, err
		}
		if ace == nil || ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 {
			continue
		}
		if ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			return false, nil
		}
		sid := (*windows.SID)(unsafe.Pointer(&ace.SidStart))
		if trustedWindowsPublicDirPrincipal(sid) {
			continue
		}
		if uint32(ace.Mask)&^readExecute != 0 {
			return false, nil
		}
		if sid.IsWellKnown(windows.WinBuiltinUsersSid) {
			users |= uint32(ace.Mask)
		}
	}
	return users&readExecute == readExecute, nil
}
