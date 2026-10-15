// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package sqliteperms

import "os"

func protectParent(string) error { return nil }

func secureFile(path string, info os.FileInfo) error {
	if info.Mode().Perm() != 0o600 {
		return os.Chmod(path, 0o600)
	}
	return nil
}
