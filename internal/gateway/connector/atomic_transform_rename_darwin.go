// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"errors"
	"os"

	"golang.org/x/sys/unix"
)

func moveAtomicTransformPathNoReplace(source, target string) error {
	err := unix.RenamexNp(source, target, unix.RENAME_EXCL)
	if errors.Is(err, os.ErrExist) {
		return errAtomicTransformConflict
	}
	return err
}

func moveAtomicTransformPathNoReplaceAt(parentFD int, source, target string) error {
	err := unix.RenameatxNp(parentFD, source, parentFD, target, unix.RENAME_EXCL)
	if errors.Is(err, os.ErrExist) {
		return errAtomicTransformConflict
	}
	return err
}
