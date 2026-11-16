// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package audit

import (
	"errors"
	"fmt"
	"io/fs"
	"os"
)

// errNoReplaceMoveUnsupported marks a file system that has no rename that
// refuses an existing destination.
var errNoReplaceMoveUnsupported = errors.New("no atomic non-replacing rename on this file system")

// linkAuditStoreFile and renameAuditStoreExclusive are the two atomic moves
// renameNoReplace tries; tests make one of them fail.
var (
	linkAuditStoreFile        = os.Link
	renameAuditStoreExclusive = renameExclusive
)

// renameNoReplace moves from to to and fails with fs.ErrExist when to exists.
// os.Rename replaces an existing file, so a name checked free a moment before
// could still be overwritten by a second start moving a store at the same
// time (rel-1-0-2:GAP-0614). A hard link claims the name atomically; the old
// name is then removed. On a file system without hard links the move is the
// kernel's non-replacing rename (renameat2 RENAME_NOREPLACE on Linux,
// renamex_np RENAME_EXCL on macOS). When neither exists the move fails
// closed: the set stays where it is and the start reports the error.
func renameNoReplace(from, to string) error {
	linkErr := linkAuditStoreFile(from, to)
	if linkErr == nil {
		if removeErr := os.Remove(from); removeErr != nil {
			_ = os.Remove(to)
			return removeErr
		}
		return nil
	}
	if errors.Is(linkErr, fs.ErrExist) || errors.Is(linkErr, fs.ErrNotExist) {
		return linkErr
	}
	err := renameAuditStoreExclusive(from, to)
	if err == nil {
		return nil
	}
	if errors.Is(err, errNoReplaceMoveUnsupported) {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: fmt.Errorf(
			"the file system allows neither a hard link (%v) nor a rename that refuses an existing file, so the file is not moved: %w",
			linkErr, err)}
	}
	return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
}
