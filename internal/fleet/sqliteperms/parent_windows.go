// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package sqliteperms

import (
	"os"
	"path/filepath"

	"github.com/defenseclaw/defenseclaw/internal/safefile"
)

// SQLite creates WAL and shared-memory files after the database is opened.
// Protect their parent first so newly created journals cannot inherit a
// readable DACL, even briefly before Secure sees them.
func protectParent(dbPath string) error {
	return safefile.ProtectDirectory(filepath.Dir(dbPath))
}

// Windows mode bits do not describe the DACL and os.Chmod cannot remove
// inherited Users/Everyone access. Protect the already-open SQLite files
// through a share-compatible handle and verify the native ACL afterward.
func secureFile(path string, _ os.FileInfo) error {
	if err := safefile.ProtectFileWhileInUse(path); err != nil {
		return err
	}
	return safefile.ValidatePrivateFile(path)
}
