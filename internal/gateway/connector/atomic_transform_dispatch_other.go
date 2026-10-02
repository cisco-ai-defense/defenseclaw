// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"os"
	"path/filepath"
	"syscall"
)

func atomicTransformFileWithStateDir(
	path string,
	transactionDir string,
	perm os.FileMode,
	transform func(current []byte, exists bool) (atomicTransformResult, error),
) error {
	return atomicTransformFileLegacyWithStateDir(path, atomicTransformRenameableStateDir(path, transactionDir), perm, transform)
}

// atomicTransformRenameableStateDir keeps the supplied transaction directory
// unless it is on another filesystem than the target. The completion receipt
// is renamed between the two directories, and rename(2) cannot cross
// filesystems, so a data dir on its own mount failed every config transform
// with "invalid cross-device link" (GAP-1447). Then the receipts stay next to
// the target, as atomicTransformFileLegacy already does.
func atomicTransformRenameableStateDir(path, transactionDir string) string {
	physical, err := canonicalAtomicTransformTargetPath(path)
	if err != nil {
		return transactionDir
	}
	targetDir := filepath.Dir(physical)
	if atomicTransformSameFilesystem(targetDir, transactionDir) {
		return transactionDir
	}
	return filepath.Join(targetDir, ".defenseclaw-cas-state")
}

// atomicTransformSameFilesystem reports whether two existing directories are
// on the same device. Unknown (a directory missing) counts as the same, which
// keeps the supplied directory.
var atomicTransformSameFilesystem = func(a, b string) bool {
	var left, right syscall.Stat_t
	if syscall.Stat(a, &left) != nil || syscall.Stat(b, &right) != nil {
		return true
	}
	return left.Dev == right.Dev
}
