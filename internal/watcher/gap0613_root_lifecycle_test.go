// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package watcher

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"

	"github.com/fsnotify/fsnotify"
)

func TestGAP0613RelativeConfiguredRootIsAccepted(t *testing.T) {
	cwd, err := os.Getwd()
	if err != nil {
		t.Fatal(err)
	}
	// A root below the working folder is named relative to it on every
	// platform and volume.
	below, err := os.MkdirTemp(cwd, "relative-root-")
	if err != nil {
		t.Fatal(err)
	}
	t.Cleanup(func() { _ = os.RemoveAll(below) })
	belowRoot := filepath.Join(below, ".claude", "skills")
	if err := os.MkdirAll(belowRoot, 0o700); err != nil {
		t.Fatal(err)
	}
	relative, err := filepath.Rel(cwd, belowRoot)
	if err != nil {
		t.Fatal(err)
	}
	if err := unlinkedSkillTreePath(relative, relative); err != nil {
		t.Fatalf("relative configured root below the working folder: %v", err)
	}
	// A root elsewhere is named through parent elements, which needs both
	// folders on one volume.
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := unlinkedSkillTreePath(root, root); err != nil {
		t.Fatalf("absolute plain root: %v", err)
	}
	outside, err := filepath.Rel(cwd, root)
	if err != nil {
		if filepath.VolumeName(cwd) == filepath.VolumeName(root) {
			t.Fatal(err)
		}
		t.Logf("working folder and temp folder are on different volumes: %v", err)
		return
	}
	if err := unlinkedSkillTreePath(outside, outside); err != nil {
		t.Fatalf("relative configured root outside the working folder: %v", err)
	}
}

func TestGAP0613PluginCacheRootVersionsAndSubdirectories(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	for _, linked := range []bool{false, true} {
		name := "plain"
		if linked {
			name = "linked"
		}
		t.Run(name, func(t *testing.T) {
			home := t.TempDir()
			root := filepath.Join(home, "plugins", "cache")
			version := filepath.Join(root, "market", "plugin", "1.0")
			if linked {
				realRoot := filepath.Join(home, "dotfiles", "cache")
				if err := os.MkdirAll(filepath.Join(realRoot, "market", "plugin", "1.0"), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.MkdirAll(filepath.Dir(root), 0o700); err != nil {
					t.Fatal(err)
				}
				if err := os.Symlink(realRoot, root); err != nil {
					t.Skipf("symlink unavailable: %v", err)
				}
			} else if err := os.MkdirAll(version, 0o700); err != nil {
				t.Fatal(err)
			}
			fsw, err := fsnotify.NewWatcher()
			if err != nil {
				t.Fatal(err)
			}
			t.Cleanup(func() { _ = fsw.Close() })
			if _, err := ensureAndWatch(fsw, root); err != nil {
				t.Fatalf("watch cache root: %v", err)
			}
			plugins := enumerateClaudeWatcherPlugins(root)
			if len(plugins) != 1 || plugins[0] != version {
				t.Fatalf("cache versions: %v", plugins)
			}
			watched := map[string]struct{}{}
			addDirWatches(fsw, root, 2, watched)
			for _, want := range []string{filepath.Join(root, "market"), filepath.Join(root, "market", "plugin")} {
				found := false
				for _, got := range fsw.WatchList() {
					if sameWatcherPath(got, want) {
						found = true
						break
					}
				}
				if !found {
					t.Fatalf("missing subdirectory watch %s: %v", want, fsw.WatchList())
				}
			}
		})
	}
}

func TestGAP0613RemovedWatchedRootReportsCoverage(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "claudecode"
	cfg.Watch.RescanEnabled = true
	root := filepath.Join(t.TempDir(), ".claude", "skills")
	if err := os.MkdirAll(root, 0o700); err != nil {
		t.Fatal(err)
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	w.SetRootConnectors(map[string]string{root: "claudecode"})
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan error, 1)
	go func() { done <- w.Run(ctx) }()
	defer func() { cancel(); <-done }()
	deadline := time.After(10 * time.Second)
	for !w.firstCycleDone.Load() {
		select {
		case <-deadline:
			t.Fatal("watcher first cycle did not finish")
		case <-time.After(10 * time.Millisecond):
		}
	}
	if err := os.Rename(root, root+"-away"); err != nil {
		t.Fatal(err)
	}
	deadline = time.After(5 * time.Second)
	for len(w.RootCoverageIssues()) == 0 {
		select {
		case <-deadline:
			t.Fatal("removed root left no admission coverage issue")
		case <-time.After(20 * time.Millisecond):
		}
	}
}

func TestGAP0613LinkedHermesPinnedSkillStaysOutOfPeriodicRescan(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("Unix ownership checks")
	}
	cfg, store, logger, _ := setupTestEnv(t)
	cfg.Guardrail.Connector = "hermes"
	home := t.TempDir()
	root := filepath.Join(home, ".hermes", "skills")
	physical := filepath.Join(home, "dotfiles", "hermes", "skills")
	pinned := filepath.Join(physical, "media", "songsee")
	ordinary := filepath.Join(physical, "ordinary")
	for _, dir := range []string{pinned, ordinary} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	marker, err := os.ReadFile(filepath.Join("..", "hermesskills", "testdata", "vendor", "media", "songsee", "SKILL.md"))
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(pinned, "SKILL.md"), marker, 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(ordinary, "SKILL.md"), []byte("# ordinary\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(filepath.Dir(physical), filepath.Dir(root)); err != nil {
		t.Skipf("symlink unavailable: %v", err)
	}
	w := New(cfg, []string{root}, nil, store, logger, nil, nil)
	foundOrdinary := false
	for _, evt := range w.enumerateTargets() {
		switch evt.Name {
		case "songsee":
			t.Fatalf("pinned vendor skill entered periodic rescan: %+v", evt)
		case "ordinary":
			foundOrdinary = true
		}
	}
	if !foundOrdinary {
		t.Fatal("ordinary Hermes skill absent from periodic rescan")
	}
}
