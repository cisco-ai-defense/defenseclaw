// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package audit

import (
	"os"

	"golang.org/x/sys/unix"
)

// databaseFileFsync is fsync(2); replaceable by tests.
var databaseFileFsync = unix.Fsync

// syncDatabaseFileData writes the database file's dirty pages to the disk
// with fsync(2), the sync SQLite itself uses with fullfsync off. On macOS
// (*os.File).Sync is F_FULLFSYNC, which also flushes the disk's whole write
// cache: under a burst of hooks on a managed Mac it took up to 5.6 s, and
// the hooks' reads of audit.db waited for it, so calls that the gateway
// evaluated in 50 ms were answered after 5 to 8 s (rel-1-0-4 GAP-0367). The
// WAL guard's sync only moves work off the writer; durability stays
// SQLite's.
func syncDatabaseFileData(f *os.File) error {
	raw, err := f.SyscallConn()
	if err != nil {
		return err
	}
	var syncErr error
	if err := raw.Control(func(fd uintptr) { syncErr = databaseFileFsync(int(fd)) }); err != nil {
		return err
	}
	if syncErr != nil {
		return &os.PathError{Op: "fsync", Path: f.Name(), Err: syncErr}
	}
	return nil
}
