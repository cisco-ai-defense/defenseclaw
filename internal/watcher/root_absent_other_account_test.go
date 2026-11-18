// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/testenv"
	"github.com/fsnotify/fsnotify"
)

// GAP-1251: the watcher never creates a root in a folder another account
// owns, even one the gateway account could write (a shared group): the root
// is watched once that account makes it. A root in the gateway's own tree is
// still created, as before.
func TestWatcherCreatesNoRootInAnotherAccountsFolder(t *testing.T) {
	home := filepath.Join(testenv.PrivateTempDir(t), "openclaw-home")
	if err := os.Mkdir(home, 0o700); err != nil {
		t.Fatal(err)
	}
	absHome, err := filepath.Abs(home)
	if err != nil {
		t.Fatal(err)
	}
	previous := anotherAccountOwns
	anotherAccountOwns = func(path string) bool { return filepath.Clean(path) == absHome }
	t.Cleanup(func() { anotherAccountOwns = previous })
	missing := filepath.Join(home, "workspace", "skills")

	w, published, wait := absentRootRun(t, missing, "late")
	if _, err := os.Lstat(filepath.Join(home, "workspace")); !os.IsNotExist(err) {
		t.Fatalf("watcher created a folder in another account's home: %v", err)
	}
	requireNoCoverageIssue(t, w, published())

	if err := os.MkdirAll(filepath.Join(missing, "late"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(missing, "late", "SKILL.md"), []byte("# late\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	wait("late")
	requireNoCoverageIssue(t, w, published())
}

func TestWatcherStillCreatesARootInItsOwnFolder(t *testing.T) {
	own := filepath.Join(testenv.PrivateTempDir(t), "own-home")
	if err := os.Mkdir(own, 0o700); err != nil {
		t.Fatal(err)
	}
	missing := filepath.Join(own, "skills")
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fsw.Close()
	created, err := ensureAndWatch(fsw, missing)
	if err != nil {
		t.Fatalf("watch a root in the gateway's own folder: %v", err)
	}
	if info, statErr := os.Stat(missing); statErr != nil || !info.IsDir() {
		t.Fatalf("root in the gateway's own folder was not created: %v", statErr)
	}
	if len(created) != 1 {
		t.Fatalf("created = %v, want the one root folder", created)
	}
}
