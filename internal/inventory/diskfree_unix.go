// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package inventory

import (
	"os"

	"golang.org/x/sys/unix"
)

// diskFreeBytes returns the bytes available to unprivileged users on the
// file system holding dir.
func diskFreeBytes(dir string) (uint64, bool) {
	var st unix.Statfs_t
	if err := unix.Statfs(dir, &st); err != nil {
		return 0, false
	}
	return uint64(st.Bavail) * uint64(st.Bsize), true //nolint:gosec,unconvert // Bsize is positive; field widths differ by OS
}

// sqliteTempDir mirrors SQLite's unix temp-file directory search
// (SQLITE_TMPDIR, TMPDIR, /var/tmp, /usr/tmp, /tmp): VACUUM writes its
// temporary copy there, which can be a different, smaller volume than the
// database (often a RAM-backed tmpfs in containers).
func sqliteTempDir() string {
	for _, dir := range []string{os.Getenv("SQLITE_TMPDIR"), os.Getenv("TMPDIR"), "/var/tmp", "/usr/tmp", "/tmp"} {
		if dir == "" {
			continue
		}
		if info, err := os.Stat(dir); err == nil && info.IsDir() && unix.Access(dir, unix.W_OK|unix.X_OK) == nil {
			return dir
		}
	}
	return ""
}
