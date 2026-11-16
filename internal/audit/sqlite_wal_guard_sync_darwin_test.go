// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build darwin

package audit

import "testing"

// GAP-0367: the WAL guard's sync of the database file was F_FULLFSYNC on
// macOS, which took up to 5.6 s during a hook burst while the hooks waited
// for it. It is fsync(2) of the pinned database file, as SQLite syncs.
func TestWALGuardDatabaseSyncIsFsyncOnMacOS(t *testing.T) {
	store, cleanup := newTestStore(t)
	defer cleanup()
	if store.dbPathGuard == nil || store.dbPathGuard.pinned == nil {
		t.Fatal("the test store has no pinned database file")
	}
	want := int(store.dbPathGuard.pinned.Fd())
	var synced []int
	saved := databaseFileFsync
	t.Cleanup(func() { databaseFileFsync = saved })
	databaseFileFsync = func(fd int) error {
		synced = append(synced, fd)
		return saved(fd)
	}
	if err := store.syncDatabaseFile(); err != nil {
		t.Fatal(err)
	}
	if len(synced) != 1 || synced[0] != want {
		t.Fatalf("database file syncs by fsync(2) = %v, want one of fd %d", synced, want)
	}
}
