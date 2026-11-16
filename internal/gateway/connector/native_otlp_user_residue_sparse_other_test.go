// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package connector

import "os"

// makeSparseFile sets path's size; Unix file systems leave the hole
// unallocated.
func makeSparseFile(path string, size int64) error {
	return os.Truncate(path, size)
}
