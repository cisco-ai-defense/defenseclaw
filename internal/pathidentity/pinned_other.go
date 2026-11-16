// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package pathidentity

import "os"

// os.Lstat and os.Stat read the device and inode at once here.
func lstatPinned(path string) (os.FileInfo, error) { return os.Lstat(path) }

func statPinned(path string) (os.FileInfo, error) { return os.Stat(path) }
