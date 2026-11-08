// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package connector

import (
	"errors"

	"golang.org/x/sys/unix"
)

// exchangeAtomicFiles swaps the two names in one step, so each now leads to the
// file the other led to.
func exchangeAtomicFiles(a, b string) error {
	return unix.RenamexNp(a, b, unix.RENAME_SWAP)
}

// atomicExchangeUnsupported reports a file system that has no exchange; the
// caller then publishes with a plain replacement.
func atomicExchangeUnsupported(err error) bool {
	return errors.Is(err, unix.ENOSYS) || errors.Is(err, unix.EINVAL) ||
		errors.Is(err, unix.ENOTSUP) || errors.Is(err, unix.EOPNOTSUPP)
}

// moveAtomicFileNoReplace renames a to b and fails with errAtomicTransformConflict when b exists.
func moveAtomicFileNoReplace(a, b string) error { return moveAtomicTransformPathNoReplace(a, b) }
