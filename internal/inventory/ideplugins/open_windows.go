// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package ideplugins

import "os"

// openNonblocking opens path read-only. The caller has already checked with
// Lstat that path is a regular file when links must not be followed.
func openNonblocking(path string, _ bool) (*os.File, error) {
	return os.Open(path)
}
