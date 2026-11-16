// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package audit

import (
	"os"

	"golang.org/x/sys/windows"
)

// renameNoReplace moves from to to and fails with fs.ErrExist when to exists.
// os.Rename passes MOVEFILE_REPLACE_EXISTING, so a name checked free a moment
// before could still be overwritten by a second start moving a store at the
// same time (rel-1-0-2:GAP-0614). MoveFileEx without that flag refuses an
// existing destination atomically.
func renameNoReplace(from, to string) error {
	fromPtr, err := windows.UTF16PtrFromString(from)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	toPtr, err := windows.UTF16PtrFromString(to)
	if err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	if err := windows.MoveFileEx(fromPtr, toPtr, 0); err != nil {
		return &os.LinkError{Op: "rename", Old: from, New: to, Err: err}
	}
	return nil
}
