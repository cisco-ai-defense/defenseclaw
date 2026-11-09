// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import (
	"path/filepath"
	"strings"

	"golang.org/x/sys/windows"
)

// osExpandWindowsShortNames asks the file system for the long form of a
// drive-letter path. When the whole path does not exist (a file about to be
// created), its longest existing folder is expanded and the rest is kept.
func osExpandWindowsShortNames(path string) string {
	rest := ""
	for current := path; ; {
		if long, ok := longPathName(current); ok {
			return long + rest
		}
		parent := current[:strings.LastIndexByte(current, '/')+1]
		if len(parent) <= 3 || len(parent) >= len(current) {
			return path
		}
		rest = current[len(parent)-1:] + rest
		current = parent[:len(parent)-1]
	}
}

func longPathName(path string) (string, bool) {
	native, err := windows.UTF16PtrFromString(filepath.FromSlash(path))
	if err != nil {
		return "", false
	}
	buffer := make([]uint16, windows.MAX_LONG_PATH)
	length, err := windows.GetLongPathName(native, &buffer[0], uint32(len(buffer)))
	if err != nil || length == 0 || int(length) > len(buffer) {
		return "", false
	}
	return filepath.ToSlash(windows.UTF16ToString(buffer[:length])), true
}
