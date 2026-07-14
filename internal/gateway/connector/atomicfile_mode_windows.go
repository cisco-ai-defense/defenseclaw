// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

func atomicFileProtectionMatches(path string, info os.FileInfo, perm os.FileMode) bool {
	if perm.Perm()&0o077 == 0 {
		return safefile.ValidatePrivateFile(path) == nil
	}
	return info.Mode().Perm() == perm.Perm()
}

func atomicFilePrepareDestination(path string, perm os.FileMode) error {
	if perm.Perm()&0o077 != 0 {
		return nil
	}
	if _, err := os.Lstat(path); os.IsNotExist(err) {
		return nil
	} else if err != nil {
		return err
	}
	if safefile.ValidatePrivateFile(path) == nil {
		return nil
	}
	return safefile.ProtectFile(path)
}
