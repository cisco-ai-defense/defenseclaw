// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package scanner

import "syscall"

// rawOpenDirOnce is one open(2) of dir: syscall.Open does not retry EINTR,
// unlike os.Open and os.ReadDir.
func rawOpenDirOnce(dir string) error {
	fd, err := syscall.Open(dir, syscall.O_RDONLY|syscall.O_DIRECTORY|syscall.O_CLOEXEC, 0)
	if err != nil {
		return err
	}
	_ = syscall.Close(fd)
	return nil
}
