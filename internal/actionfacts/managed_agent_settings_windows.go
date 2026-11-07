// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package actionfacts

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// osWindowsLongPath returns the long form of a drive path ("C:/dir/file"):
// the long form of the deepest part that exists (GetLongPathName), followed
// by the names below it as written, which then name no file yet.
func osWindowsLongPath(drive string) (string, bool) {
	current := filepath.Clean(filepath.FromSlash(drive))
	var below []string
	for {
		if long, ok := longPathName(current); ok {
			for i := len(below) - 1; i >= 0; i-- {
				long += `\` + below[i]
			}
			return filepath.ToSlash(long), true
		}
		parent := filepath.Dir(current)
		if parent == current {
			return "", false
		}
		below = append(below, filepath.Base(current))
		current = parent
	}
}

func longPathName(path string) (string, bool) {
	from, err := windows.UTF16PtrFromString(path)
	if err != nil {
		return "", false
	}
	buffer := make([]uint16, windows.MAX_PATH)
	for range 2 {
		n, err := windows.GetLongPathName(from, &buffer[0], uint32(len(buffer)))
		if err != nil || n == 0 {
			return "", false
		}
		if int(n) <= len(buffer) {
			return strings.TrimRight(windows.UTF16ToString(buffer[:n]), `\`), true
		}
		buffer = make([]uint16, n)
	}
	return "", false
}
