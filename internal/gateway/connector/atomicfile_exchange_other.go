// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !linux && !darwin

package connector

import "errors"

// Windows has no exchange of two files: the project replaces by rename only,
// because a move-aside leaves the name missing for a concurrent reader
// (GAP-2644, GAP-0546; safefile.ReplaceFileAtomically).
func exchangeAtomicFiles(_, _ string) error {
	return errors.New("exchanging two files is unsupported on this platform")
}

func atomicExchangeUnsupported(error) bool { return true }

func moveAtomicFileNoReplace(_, _ string) error {
	return errors.New("exchanging two files is unsupported on this platform")
}
