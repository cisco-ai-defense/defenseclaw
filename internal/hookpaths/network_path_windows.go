// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

// networkShareRoot is the \\server\share volume of a path on a network share,
// in every spelling Windows opens one by (windowsShareRoot), as the path
// spells it; "" for a drive path, a relative path and every other device
// path (\\?\C:\..., \\.\pipe\...).
func networkShareRoot(path string) string {
	root, _ := windowsShareRoot(path)
	return root
}
