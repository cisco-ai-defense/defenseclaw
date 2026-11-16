// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package connector

import (
	"errors"
	"io/fs"
	"os"
	"path/filepath"
	"slices"
	"testing"
)

// rel-1-0-6 GAP-0207: when an administrator removes Amp, the folders the
// install recorded as created for it (~/.config/amp/plugins and
// ~/.config/amp) go once empty, and so does its empty connector_backups
// folder; another connector's recorded folder, and a folder with content,
// stay.
func TestRemoveCreatedDirsOfRemovesOnlyTheConnectorsEmptyFolders(t *testing.T) {
	home := t.TempDir()
	dataDir := filepath.Join(home, ".defenseclaw")
	amp := filepath.Join(home, ".config", "amp")
	plugins := filepath.Join(amp, "plugins")
	other := filepath.Join(home, ".copilot", "hooks")
	backups := filepath.Join(dataDir, "connector_backups", "amp")
	for _, dir := range []string{plugins, other, backups} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := recordCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile), []string{plugins, amp, other}); err != nil {
		t.Fatal(err)
	}
	conn, ok := NewDefaultRegistry().Get("amp")
	if !ok {
		t.Fatal("no amp connector")
	}
	if err := WithUserHomeDir(home, func() error {
		RemoveCreatedDirsOf(conn, SetupOpts{DataDir: dataDir})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	for _, gone := range []string{plugins, amp, backups} {
		if _, err := os.Lstat(gone); !errors.Is(err, fs.ErrNotExist) {
			t.Fatalf("%s stays after Amp was removed: %v", gone, err)
		}
	}
	if _, err := os.Lstat(other); err != nil {
		t.Fatalf("another connector's folder went: %v", err)
	}
	if got := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile)).Dirs; !slices.Equal(got, []string{other}) {
		t.Fatalf("created-folder list = %v, want only %s", got, other)
	}

	// A folder with content stays, and stays listed.
	if err := os.MkdirAll(plugins, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(plugins, "own.ts"), []byte("// own\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := recordCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile), []string{plugins, amp}); err != nil {
		t.Fatal(err)
	}
	if err := WithUserHomeDir(home, func() error {
		RemoveCreatedDirsOf(conn, SetupOpts{DataDir: dataDir})
		return nil
	}); err != nil {
		t.Fatal(err)
	}
	if _, err := os.Lstat(filepath.Join(plugins, "own.ts")); err != nil {
		t.Fatalf("a folder with the account's file was changed: %v", err)
	}
	if got := readWatcherCreatedDirs(filepath.Join(dataDir, watcherCreatedDirsFile)).Dirs; !slices.Contains(got, plugins) || !slices.Contains(got, amp) {
		t.Fatalf("kept folders left the list: %v", got)
	}
}
