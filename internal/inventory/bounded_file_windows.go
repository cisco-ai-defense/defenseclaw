// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package inventory

import "os"

// openReadOnlyNonblocking opens path read-only. Unless follow is set, a path
// that is a link or another reparse point is refused before the open; the
// caller checks the opened object is a regular file.
func openReadOnlyNonblocking(path string, follow bool) (*boundedReadFile, error) {
	if !follow {
		info, err := os.Lstat(path)
		if err != nil {
			return nil, err
		}
		if !info.Mode().IsRegular() {
			return nil, errBoundedFileNotRegular
		}
	}
	return os.Open(path)
}
