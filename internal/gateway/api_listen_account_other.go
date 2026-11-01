// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"syscall"
)

// isAPIPortHeldByAnotherAccount is Windows-only: elsewhere another account's
// wildcard listener makes the bind fail with "address already in use".
func isAPIPortHeldByAnotherAccount(error) bool { return false }

// fileOwnedByRoot reports a file owned by uid 0.
func fileOwnedByRoot(info os.FileInfo) bool {
	st, ok := info.Sys().(*syscall.Stat_t)
	return ok && st.Uid == 0
}
