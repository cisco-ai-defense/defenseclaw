// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package watcher

import (
	"os"
	"os/exec"
	"path/filepath"
	"testing"

	"github.com/fsnotify/fsnotify"
)

func TestCleanupOwnedWatchDirsPreservesJunctionReplacement(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "plugins")
	created, err := createWatchDir(target)
	if err != nil {
		t.Fatalf("create watch directory: %v", err)
	}

	outside := filepath.Join(base, "outside")
	if err := os.Mkdir(outside, 0o700); err != nil {
		t.Fatal(err)
	}
	sentinel := filepath.Join(outside, "keep.txt")
	if err := os.WriteFile(sentinel, []byte("keep"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", target, outside).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(target); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove junction: %v", err)
		}
	})

	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean watch directories: %v", err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("junction replacement was removed: %v", err)
	}
	if !watchDirIsLinkOrReparse(target, info) {
		t.Fatal("junction replacement was not recognized as a reparse point")
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("outside content changed: %q, %v", got, err)
	}
}

func TestEnsureAndWatchAcceptsPreexistingJunctionDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "shared-skills")
	linked := filepath.Join(base, "skills")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	output, err := exec.Command("cmd.exe", "/d", "/c", "mklink", "/J", linked, target).CombinedOutput()
	if err != nil {
		t.Skipf("junction creation unavailable: %v: %s", err, output)
	}
	t.Cleanup(func() {
		if err := os.Remove(linked); err != nil && !os.IsNotExist(err) {
			t.Errorf("remove junction: %v", err)
		}
	})
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fsw.Close()

	created, err := ensureAndWatch(fsw, linked)
	if err != nil {
		t.Fatalf("watch junction directory: %v", err)
	}
	if len(created) != 0 {
		t.Fatalf("claimed %d pre-existing junction directories", len(created))
	}
	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean linked watch directory: %v", err)
	}
	info, err := os.Lstat(linked)
	if err != nil || !watchDirIsLinkOrReparse(linked, info) {
		t.Fatalf("pre-existing junction was not preserved: %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("junction target was not preserved: %v", err)
	}
}
