// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package enforce

import (
	"io/fs"
	"os"
	"syscall"
)

const windowsFileAttributeReparsePoint = 0x400

func fileInfoIsLinkOrReparse(info fs.FileInfo) bool {
	if info.Mode()&os.ModeSymlink != 0 {
		return true
	}
	data, ok := info.Sys().(*syscall.Win32FileAttributeData)
	return ok && data.FileAttributes&windowsFileAttributeReparsePoint != 0
}
