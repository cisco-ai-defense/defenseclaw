//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package managed

import (
	"fmt"

	"golang.org/x/sys/windows"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
)

const managedFileRestrictiveAttributes = windows.FILE_ATTRIBUTE_READONLY |
	windows.FILE_ATTRIBUTE_HIDDEN | windows.FILE_ATTRIBUTE_SYSTEM

// clearManagedFileRestrictiveAttributes clears ReadOnly, Hidden and System
// from an existing managed regular file and logs the repair. A missing file,
// a reparse point or a directory is left alone; a failure is logged as
// accepted drift.
func clearManagedFileRestrictiveAttributes(path string) {
	pointer, err := winpath.UTF16Ptr(path)
	if err != nil {
		return
	}
	attributes, err := windows.GetFileAttributes(pointer)
	if err != nil || attributes&managedFileRestrictiveAttributes == 0 ||
		attributes&(windows.FILE_ATTRIBUTE_REPARSE_POINT|windows.FILE_ATTRIBUTE_DIRECTORY) != 0 {
		return
	}
	cleared := attributes & managedFileRestrictiveAttributes
	remaining := attributes &^ managedFileRestrictiveAttributes
	if remaining == 0 {
		remaining = windows.FILE_ATTRIBUTE_NORMAL
	}
	if err := windows.SetFileAttributes(pointer, remaining); err != nil {
		EmitResilienceEvent(MarkerAccept, map[string]string{
			"path":   path,
			"reason": fmt.Sprintf("could not clear file attributes 0x%x: %v", cleared, err),
		})
		return
	}
	EmitResilienceEvent(MarkerRepair, map[string]string{
		"path":   path,
		"reason": fmt.Sprintf("cleared file attributes 0x%x on a managed file", cleared),
	})
}
