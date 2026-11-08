// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package hookpaths

import (
	"strings"

	"golang.org/x/sys/windows"
)

// followMountPoints is the final path of the file or folder at path, which
// the system reaches through every junction and symbolic link on the way. A
// share that has not answered is asked first, as for any read of a path a
// hook call names.
func followMountPoints(path string) (string, error) {
	file, err := pathOpen(path)
	if err != nil {
		return "", err
	}
	defer file.Close()
	handle := windows.Handle(file.Fd())
	size := uint32(windows.MAX_PATH)
	for {
		buffer := make([]uint16, size)
		n, err := windows.GetFinalPathNameByHandle(handle, &buffer[0], size, 0)
		if err != nil {
			return "", err
		}
		if n >= size {
			size = n + 1
			continue
		}
		final := windows.UTF16ToString(buffer[:n])
		switch {
		case strings.HasPrefix(final, `\\?\UNC\`):
			return `\\` + final[len(`\\?\UNC\`):], nil
		case strings.HasPrefix(final, `\\?\`):
			return final[len(`\\?\`):], nil
		}
		return final, nil
	}
}
