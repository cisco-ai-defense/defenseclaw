// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package pathidentity

import (
	"unsafe"

	"golang.org/x/sys/windows"
)

var compareStringOrdinal = windows.NewLazySystemDLL("kernel32.dll").NewProc("CompareStringOrdinal")

func sameMissingPath(left, right string) bool {
	leftUTF16, leftErr := windows.UTF16FromString(left)
	rightUTF16, rightErr := windows.UTF16FromString(right)
	if leftErr != nil || rightErr != nil {
		return false
	}
	result, _, _ := compareStringOrdinal.Call(
		uintptr(unsafe.Pointer(&leftUTF16[0])), uintptr(len(leftUTF16)-1),
		uintptr(unsafe.Pointer(&rightUTF16[0])), uintptr(len(rightUTF16)-1),
		1,
	)
	return result == 2 // CSTR_EQUAL
}
