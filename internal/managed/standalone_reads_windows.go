//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

// principalReadsPath reports whether sid holds an allow entry on path that
// applies to path itself and lets it read data.
func principalReadsPath(path, sid string) bool {
	descriptor, err := windows.GetNamedSecurityInfo(path, windows.SE_FILE_OBJECT, windows.DACL_SECURITY_INFORMATION)
	if err != nil {
		return false
	}
	dacl, _, err := descriptor.DACL()
	if err != nil || dacl == nil {
		return false
	}
	for index := uint16(0); index < dacl.AceCount; index++ {
		var ace *windows.ACCESS_ALLOWED_ACE
		if windows.GetAce(dacl, uint32(index), &ace) != nil || ace == nil || ace.Header.AceType != windows.ACCESS_ALLOWED_ACE_TYPE {
			continue
		}
		if ace.Header.AceFlags&windows.INHERIT_ONLY_ACE != 0 || uint32(ace.Mask)&0x1 == 0 {
			continue
		}
		if (*windows.SID)(unsafe.Pointer(&ace.SidStart)).String() == sid {
			return true
		}
	}
	return false
}
