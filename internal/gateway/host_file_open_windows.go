// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package gateway

import "os"

// openHostFileForInspection opens a hook-named host file for reading. Windows
// has no POSIX FIFOs to block on; the caller still checks that the opened
// file is the regular file it expected.
func openHostFileForInspection(path string) (*os.File, error) {
	return os.Open(path) // #nosec G304 -- callers pass a validated, hook-derived path.
}
