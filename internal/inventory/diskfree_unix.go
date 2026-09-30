// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import "golang.org/x/sys/unix"

// diskFreeBytes returns the bytes available to unprivileged users on the
// file system holding dir.
func diskFreeBytes(dir string) (uint64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true //nolint:gosec,unconvert // Bsize is positive; field widths differ by OS
}
