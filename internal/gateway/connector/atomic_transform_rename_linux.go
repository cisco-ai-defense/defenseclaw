// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build linux

package connector

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func moveAtomicTransformPathNoReplace(source, target string) error {
	err := unix.Renameat2(unix.AT_FDCWD, source, unix.AT_FDCWD, target, unix.RENAME_NOREPLACE)
	if errors.Is(err, os.ErrExist) {
		return errAtomicTransformConflict
	}
	return err
}

func moveAtomicTransformPathNoReplaceAt(parentFD int, source, target string) error {
	err := unix.Renameat2(parentFD, source, parentFD, target, unix.RENAME_NOREPLACE)
	if errors.Is(err, os.ErrExist) {
		return errAtomicTransformConflict
	}
	return err
}
