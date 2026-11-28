// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"os"
)

// pathOpenDirectory is pathOpen on Windows: directory, junction, share and
// MSYS path handling stay as pathOpen reads them (#1486).
func pathOpenDirectory(name string) (*os.File, error) {
	return pathOpen(name)
}

// networkShareRoot is the \\server\share volume of a path on a network share,
// in every spelling Windows opens one by (windowsShareRoot), as the path
// spells it; "" for a drive path, a relative path and every other device
// path (\\?\C:\..., \\.\pipe\...).
func networkShareRoot(path string) string {
	root, _ := windowsShareRoot(path)
	return root
}

// readGatedValue is the gate of a read network_path.go does not make itself
// (a Windows API call on the path: file identity, link count, DACL, a
// traverse open, a long name): readGated without the cut. The call gets the
// path the share gate read, its last component held, and its answer is
// discarded when the hold saw that component change; a hold that cannot be
// taken is that error, and the call is not made. gatedPath, which handed
// the path out and dropped the hold's answer, is gone (rel-1-0-10:GAP-1264).
func readGatedValue[T any](op, name string, call func(path string) (T, error)) (T, error) {
	value, _, err := readGated(op, name, call, nil)
	return value, err
}
