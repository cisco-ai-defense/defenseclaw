// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"errors"

	"github.com/defenseclaw/defenseclaw/internal/winpath"
	"golang.org/x/sys/windows"
)

// installAtomicTransformFile publishes a staged file only while target is
// still absent. MOVEFILE_REPLACE_EXISTING is intentionally omitted: if an
// editor creates the config after our final comparison, the move fails and the
// caller re-reads/merges that new file instead of overwriting it.
func installAtomicTransformFile(staged, target string) error {
	from, err := winpath.UTF16Ptr(staged)
	if err != nil {
		return err
	}
	to, err := winpath.UTF16Ptr(target)
	if err != nil {
		return err
	}
	err = windows.MoveFileEx(from, to, windows.MOVEFILE_WRITE_THROUGH)
	if errors.Is(err, windows.ERROR_ALREADY_EXISTS) || errors.Is(err, windows.ERROR_FILE_EXISTS) {
		return errAtomicTransformConflict
	}
	return err
}
