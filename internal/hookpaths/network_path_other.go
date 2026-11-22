// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"syscall"
)

// networkShareRoot is "" off Windows: every path is a local file system
// path (an NFS or SMB mount reads like any mounted volume).
func networkShareRoot(string) string { return "" }

// pathOpenDirectory reads name through the share gate of pathOpen and asks the kernel
// to open a directory. A glob can match a FIFO or device; opening that as a
// plain file may block before Readdirnames can reject it. O_DIRECTORY also
// closes the gap between a type check and the open. Directory aliases remain
// followed, as the shell's glob expansion follows them.
func pathOpenDirectory(name string) (*os.File, error) {
	file, _, err := readGated("open", name, openDirectory, closeFile)
	return file, err
}

func openDirectory(path string) (*os.File, error) {
	return os.OpenFile(path, os.O_RDONLY|syscall.O_DIRECTORY|syscall.O_NONBLOCK, 0)
}
