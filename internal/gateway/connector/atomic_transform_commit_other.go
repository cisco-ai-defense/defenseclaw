// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import (
	"errors"
	"os"
)

// A same-directory hard link is an atomic create-if-absent operation. Removing
// the staging name after the link succeeds leaves the target with the staged
// inode and prevents POSIX rename's overwrite behavior from losing a file an
// external editor created after our comparison.
func installAtomicTransformFile(staged, target string) error {
	if err := os.Link(staged, target); err != nil {
		if errors.Is(err, os.ErrExist) {
			return errAtomicTransformConflict
		}
		return err
	}
	// The target is now committed. A staging-name cleanup failure must not be
	// reported as a failed config publication; the caller's deferred/best-effort
	// cleanup can remove the extra link without affecting target.
	_ = os.Remove(staged)
	return nil
}
