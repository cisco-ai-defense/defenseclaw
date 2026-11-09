// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package assetfacts

import "strings"

// onNetworkShare reports whether path is on a network share: a UNC path
// (\\server\share, also spelled with forward slashes) or its \\?\UNC\ and
// \\.\UNC\ forms. A drive path, a relative path and every other device path
// are local.
func onNetworkShare(path string) bool {
	if len(path) < 3 || !isWindowsSlash(path[0]) || !isWindowsSlash(path[1]) {
		return false
	}
	if path[2] == 0x3f || path[2] == 0x2e { // ? or .
		return len(path) > 8 && isWindowsSlash(path[3]) && strings.EqualFold(path[4:7], "UNC") && isWindowsSlash(path[7])
	}
	return !isWindowsSlash(path[2])
}

func isWindowsSlash(c byte) bool { return c == 0x5c || c == 0x2f }
