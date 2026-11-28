// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package winpath

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var procCompareStringOrdinal = windows.NewLazySystemDLL("kernel32.dll").NewProc("CompareStringOrdinal")

// equalNames is CompareStringOrdinal with bIgnoreCase: the operating
// system's uppercase table, as the file system compares names.
func equalNames(a, b string) bool {
	if a == b {
		return true
	}
	left, leftErr := windows.UTF16FromString(a)
	right, rightErr := windows.UTF16FromString(b)
	if leftErr != nil || rightErr != nil {
		return false
	}
	if len(left) != len(right) {
		return false
	}
	if len(left) == 1 {
		return true
	}
	result, _, _ := procCompareStringOrdinal.Call(
		uintptr(unsafe.Pointer(&left[0])), uintptr(len(left)-1),
		uintptr(unsafe.Pointer(&right[0])), uintptr(len(right)-1),
		1,
	)
	return result == 2 // CSTR_EQUAL
}
