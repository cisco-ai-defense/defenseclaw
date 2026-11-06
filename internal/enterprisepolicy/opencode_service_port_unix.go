// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisepolicy

import "golang.org/x/sys/unix"

// writableDir reports whether this process may create entries in dir.
func writableDir(dir string) bool {
	return unix.Access(dir, unix.W_OK) == nil
}
