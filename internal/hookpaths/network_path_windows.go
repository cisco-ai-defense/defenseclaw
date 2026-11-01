// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"path/filepath"
	"strings"
)

// networkShareRoot is the \\server\share volume of a UNC path, also spelled
// with forward slashes or in the \\?\UNC\ and \\.\UNC\ forms, as the path
// spells it; "" for a drive path, a relative path and every other device
// path (\\?\C:\..., \\.\pipe\...).
func networkShareRoot(path string) string {
	// VolumeName answers with backslashes and ends a \\?\UNC\ path at
	// \\?\UNC, so only its length is used and the share is read here.
	n := len(filepath.VolumeName(path))
	if n < 3 || !windowsSlash(path[0]) || !windowsSlash(path[1]) {
		return ""
	}
	if (path[2] == '?' || path[2] == '.') && (n == 3 || windowsSlash(path[3])) {
		if len(path) <= 8 || !strings.EqualFold(path[4:7], "UNC") || !windowsSlash(path[7]) {
			return ""
		}
		return path[:8+uncShareLength(path[8:])]
	}
	return path[:n]
}

// uncShareLength is the length of the server and share names that begin rest.
func uncShareLength(rest string) int {
	separators := 0
	for i := 0; i < len(rest); i++ {
		if windowsSlash(rest[i]) {
			if separators++; separators == 2 {
				return i
			}
		}
	}
	return len(rest)
}

func windowsSlash(c byte) bool { return c == '\\' || c == '/' }
