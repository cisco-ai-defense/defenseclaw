// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package safefile

import "os"

func protectFile(_ string, file *os.File) error { return file.Chmod(0o600) }

func protectDirectory(path string) error {
	info, err := os.Stat(path)
	if err != nil {
		return err
	}
	if info.Mode().Perm()&0o077 == 0 {
		return nil
	}
	return os.Chmod(path, 0o700)
}

func rejectReparsePath(_ string) error { return nil }

func rejectReparseChain(path string) error {
	info, err := os.Lstat(path)
	if os.IsNotExist(err) {
		return nil
	}
	if err == nil && info.Mode()&os.ModeSymlink != 0 {
		return ErrSymlinkRefused
	}
	return err
}

func preserveExistingProtection(_, _ string) error { return nil }

func withLockedDirectory(_ string, write func() error) error { return write() }

func makePrivateDirectories(path string) error { return os.MkdirAll(path, 0o700) }
