// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package pathidentity

import "os"

// os.Lstat and os.Stat read the device and inode at once here.
func lstatPinned(path string) (os.FileInfo, error) { return os.Lstat(path) }

func statPinned(path string) (os.FileInfo, error) { return os.Stat(path) }

func holdUnlinked(path string) (func() bool, error) {
	info, err := os.Lstat(path)
	if err != nil && os.IsNotExist(err) {
		return nil, err
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return nil, ErrLinked
	}
	return func() bool {
		info, err := os.Lstat(path)
		return err != nil || info.Mode()&os.ModeSymlink == 0
	}, nil
}
