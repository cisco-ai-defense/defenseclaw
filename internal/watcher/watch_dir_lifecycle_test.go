// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"errors"
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/sandbox"
	"github.com/fsnotify/fsnotify"
)

func TestInstallWatcherRunCleansCreatedDirectoriesOnEachRun(t *testing.T) {
	cfg, store, logger, _ := setupTestEnv(t)
	base := t.TempDir()
	target := filepath.Join(base, "codex", "skills")
	shell := sandbox.New(cfg.OpenShell.Binary, cfg.OpenShell.PolicyDir)
	w := New(cfg, []string{target}, nil, store, logger, shell, nil, nil)

	for run := 1; run <= 2; run++ {
		ctx, cancel := context.WithCancel(context.Background())
		cancel()
		if err := w.Run(ctx); !errors.Is(err, context.Canceled) {
			t.Fatalf("run %d returned %v, want context cancellation", run, err)
		}
		if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("run %d left created target behind: %v", run, err)
		}
		if _, err := os.Lstat(filepath.Dir(target)); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("run %d left created parent behind: %v", run, err)
		}
	}
}

func TestCleanupOwnedWatchDirsRemovesOnlyCreatedEmptyDirectories(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "codex", "skills")

	created, err := createWatchDir(target)
	if err != nil {
		t.Fatalf("create watch directory: %v", err)
	}
	if len(created) != 2 {
		t.Fatalf("created %d directories, want 2", len(created))
	}
	if runtime.GOOS != "windows" {
		for _, dir := range created {
			if got := dir.identity.Mode().Perm(); got != 0o700 {
				t.Fatalf("mode for %s = %o, want 700", dir.path, got)
			}
		}
	}

	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean created directories: %v", err)
	}
	for _, path := range []string{target, filepath.Dir(target)} {
		if _, err := os.Lstat(path); !errors.Is(err, os.ErrNotExist) {
			t.Fatalf("created directory still exists at %s: %v", path, err)
		}
	}
	if _, err := os.Stat(base); err != nil {
		t.Fatalf("pre-existing parent was removed: %v", err)
	}
	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("repeated cleanup: %v", err)
	}
}

func TestCleanupOwnedWatchDirsPreservesPreexistingEmptyDirectory(t *testing.T) {
	target := filepath.Join(t.TempDir(), "skills")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}

	created, err := createWatchDir(target)
	if err != nil {
		t.Fatalf("open existing watch directory: %v", err)
	}
	if len(created) != 0 {
		t.Fatalf("claimed %d pre-existing directories", len(created))
	}
	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean watch directories: %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("pre-existing directory was not preserved: %v", err)
	}
}

func TestCleanupOwnedWatchDirsPreservesDirectoryThatGainsContent(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "codex", "plugins")
	created, err := createWatchDir(target)
	if err != nil {
		t.Fatalf("create watch directory: %v", err)
	}

	sentinel := filepath.Join(target, "keep.txt")
	want := []byte("user content\n")
	if err := os.WriteFile(sentinel, want, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean watch directories: %v", err)
	}
	got, err := os.ReadFile(sentinel)
	if err != nil {
		t.Fatalf("read preserved content: %v", err)
	}
	if string(got) != string(want) {
		t.Fatalf("preserved content = %q, want %q", got, want)
	}
	if info, err := os.Stat(filepath.Dir(target)); err != nil || !info.IsDir() {
		t.Fatalf("created parent containing user data was not preserved: %v", err)
	}
}

func TestCleanupOwnedWatchDirsPreservesRecreatedDirectory(t *testing.T) {
	base := t.TempDir()
	target := filepath.Join(base, "skills")
	created, err := createWatchDir(target)
	if err != nil {
		t.Fatalf("create watch directory: %v", err)
	}

	replacement := filepath.Join(base, "replacement")
	if err := os.Mkdir(replacement, 0o750); err != nil {
		t.Fatal(err)
	}
	replacementInfo, err := snapshotWatchDirIdentity(replacement)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.Remove(target); err != nil {
		t.Fatal(err)
	}
	if err := os.Rename(replacement, target); err != nil {
		t.Fatal(err)
	}

	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean watch directories: %v", err)
	}
	current, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("recreated directory was removed: %v", err)
	}
	if !os.SameFile(replacementInfo, current) {
		t.Fatal("recreated directory identity changed")
	}
}

func TestCleanupOwnedWatchDirsPreservesSymlinkReplacement(t *testing.T) {
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
	if err := os.Symlink(outside, target); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}

	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean watch directories: %v", err)
	}
	info, err := os.Lstat(target)
	if err != nil {
		t.Fatalf("symlink replacement was removed: %v", err)
	}
	if info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("replacement mode = %s, want symlink", info.Mode())
	}
	if got, err := os.ReadFile(sentinel); err != nil || string(got) != "keep" {
		t.Fatalf("outside content changed: %q, %v", got, err)
	}
}

func TestEnsureAndWatchDoesNotClaimDuplicateTarget(t *testing.T) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "skills")
	first, err := ensureAndWatch(fsw, target)
	if err != nil {
		_ = fsw.Close()
		t.Fatalf("first watch: %v", err)
	}
	second, err := ensureAndWatch(fsw, target)
	if err != nil {
		_ = fsw.Close()
		t.Fatalf("duplicate watch: %v", err)
	}
	if len(first) != 1 {
		t.Fatalf("first watch claimed %d directories, want 1", len(first))
	}
	if len(second) != 0 {
		t.Fatalf("duplicate watch claimed %d directories", len(second))
	}
	if err := fsw.Close(); err != nil {
		t.Fatalf("close watcher: %v", err)
	}
	if err := cleanupOwnedWatchDirs(append(first, second...)); err != nil {
		t.Fatalf("clean watch directories: %v", err)
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("owned duplicate target still exists: %v", err)
	}
}

func TestEnsureAndWatchAcceptsPreexistingSymlinkDirectory(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("junction coverage is Windows-specific")
	}
	base := t.TempDir()
	target := filepath.Join(base, "shared-skills")
	linked := filepath.Join(base, "skills")
	if err := os.Mkdir(target, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(target, linked); err != nil {
		t.Skipf("symlink creation unavailable: %v", err)
	}
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	defer fsw.Close()

	created, err := ensureAndWatch(fsw, linked)
	if err != nil {
		t.Fatalf("watch linked directory: %v", err)
	}
	if len(created) != 0 {
		t.Fatalf("claimed %d pre-existing linked directories", len(created))
	}
	if err := cleanupOwnedWatchDirs(created); err != nil {
		t.Fatalf("clean linked watch directory: %v", err)
	}
	if info, err := os.Lstat(linked); err != nil || info.Mode()&os.ModeSymlink == 0 {
		t.Fatalf("pre-existing symlink was not preserved: %v", err)
	}
	if info, err := os.Stat(target); err != nil || !info.IsDir() {
		t.Fatalf("linked target was not preserved: %v", err)
	}
}

func TestEnsureAndWatchCleansCreatedDirectoryWhenWatchFails(t *testing.T) {
	fsw, err := fsnotify.NewWatcher()
	if err != nil {
		t.Fatal(err)
	}
	if err := fsw.Close(); err != nil {
		t.Fatal(err)
	}
	target := filepath.Join(t.TempDir(), "plugins")

	if _, err := ensureAndWatch(fsw, target); err == nil {
		t.Fatal("watch unexpectedly succeeded after close")
	}
	if _, err := os.Lstat(target); !errors.Is(err, os.ErrNotExist) {
		t.Fatalf("failed watch left created directory behind: %v", err)
	}
}

func TestCreateWatchDirRejectsEmptyPath(t *testing.T) {
	if _, err := createWatchDir(""); err == nil {
		t.Fatal("empty watch path unexpectedly succeeded")
	}
}
