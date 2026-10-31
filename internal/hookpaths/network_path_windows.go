// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"path/filepath"
	"strings"
)

// networkShareRoot is the \\server\share volume of a UNC path, also spelled
// with forward slashes or in the \\?\UNC\ and \\.\UNC\ forms; "" for a drive
// path, a relative path and every other device path (\\?\C:\..., \\.\pipe\...).
func networkShareRoot(path string) string {
	volume := filepath.VolumeName(path)
	if len(volume) < 3 || !windowsSlash(volume[0]) || !windowsSlash(volume[1]) {
		return ""
	}
	if (volume[2] == '?' || volume[2] == '.') && (len(volume) == 3 || windowsSlash(volume[3])) {
		inner := filepath.ToSlash(volume[min(4, len(volume)):])
		if len(inner) > 4 && strings.EqualFold(inner[:4], "UNC/") {
			return volume
		}
		return ""
	}
	return volume
}

func windowsSlash(c byte) bool { return c == '\\' || c == '/' }
