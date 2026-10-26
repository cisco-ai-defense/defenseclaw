// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"os"
	"path/filepath"
	"runtime"
	"strings"
	"testing"
	"time"
)

// GAP-1413: one folder whose open() never returns (macOS waits for a privacy
// decision on ~/Desktop for a background worker) held the whole home walk, so
// every discovery worker timed out. The walk now gives up on that folder, says
// the scan is incomplete, and still finds the private copy in the rest of the
// home.
func TestUnixPrivateWalkDoesNotHangOnAFolderThatNeverOpens(t *testing.T) {
	home := t.TempDir()
	blocked := filepath.Join(home, "Blocked")
	if err := os.MkdirAll(blocked, 0o700); err != nil {
		t.Fatal(err)
	}
	pkg := filepath.Join(home, "work", "proj", "node_modules", "@openai", "codex")
	npmCopy(t, pkg, "@openai/codex", "0.0.1", "bin/codex.js")
	previousOpen, previousTimeout := unixPrivateWalkOpenFile, unixPrivateWalkOpenTimeout
	t.Cleanup(func() { unixPrivateWalkOpenFile, unixPrivateWalkOpenTimeout = previousOpen, previousTimeout })
	never := make(chan struct{})
	t.Cleanup(func() { close(never) })
	unixPrivateWalkOpenFile = func(dir string) (*os.File, error) {
		if filepath.Clean(dir) == blocked {
			<-never
		}
		return os.Open(dir)
	}
	unixPrivateWalkOpenTimeout = 200 * time.Millisecond
	done := make(chan []PrivateAgentInstall, 1)
	go func() { done <- DiscoverUnixPrivateAgentInstalls(context.Background(), home, []string{"codex"}) }()
	var installs []PrivateAgentInstall
	select {
	case installs = <-done:
	case <-time.After(20 * time.Second):
		t.Fatal("the home walk hung on a folder whose open never returns")
	}
	var copyFound, incomplete bool
	for _, install := range installs {
		switch {
		case install.Incomplete && install.Skipped == PrivateInstallSkippedHome:
			incomplete = true
		case strings.HasSuffix(install.Path, filepath.Join("work", "proj", "node_modules", "@openai", "codex")):
			copyFound = true
		}
	}
	if !incomplete || !copyFound {
		t.Fatalf("installs = %+v, want the private copy and a home_unreadable row", installs)
	}
}

// The macOS privacy-protected folders are never opened; elsewhere none is
// skipped.
func TestUnixPrivateWalkSkipsPrivacyProtectedFolders(t *testing.T) {
	home := filepath.Clean(t.TempDir())
	previousOpen := unixPrivateWalkOpenFile
	t.Cleanup(func() { unixPrivateWalkOpenFile = previousOpen })
	opened := map[string]bool{}
	unixPrivateWalkOpenFile = func(dir string) (*os.File, error) {
		opened[filepath.Base(dir)] = true
		return nil, os.ErrNotExist
	}
	// The opener reads the open it makes when it is made.
	opener := unixPrivateWalkOpener(home)
	for _, dir := range []string{"Desktop", "documents", filepath.Join("Library", "Containers"), "Projects"} {
		_, _ = opener(filepath.Join(home, dir))
	}
	if runtime.GOOS == "darwin" {
		if opened["Desktop"] || opened["documents"] || opened["Containers"] || !opened["Projects"] {
			t.Fatalf("opened = %v, want only Projects", opened)
		}
		return
	}
	if !opened["Desktop"] || !opened["Projects"] {
		t.Fatalf("opened = %v, want every folder opened off macOS", opened)
	}
}

// The release upgrade gate found the 1.0.4 walk incomplete for the macOS
// runner account: a developer home is mostly toolchains, package stores and
// caches, which the walk listed against its bound. It now leaves those trees
// unlisted, and still enters pnpm's dlx cache and npx's folder, which hold
// runnable npm installs.
func TestUnixPrivateWalkPrunesToolOwnedTrees(t *testing.T) {
	home := filepath.Clean(t.TempDir())
	cases := map[string]bool{
		".cache":                        false,
		".cache/uv":                     true,
		".cache/pnpm":                   false,
		".cache/pnpm/dlx/abc":           false,
		".npm/_cacache":                 true,
		".npm/_npx":                     false,
		"go/pkg/mod":                    true,
		"go/src":                        false,
		".rustup":                       true,
		".local/share/uv":               true,
		".local/share/pnpm/store":       true,
		".local/share/pnpm/global":      false,
		"src/proj/.git":                 true,
		"src/proj/node_modules":         false,
		"src/.cache":                    false,
		"src/.cache/uv":                 false,
		"Library/Caches/Homebrew":       runtime.GOOS == "darwin",
		"Library/Caches/pnpm":           false,
		"Library/Developer":             runtime.GOOS == "darwin",
		"Library/pnpm/store":            runtime.GOOS == "darwin",
		"Library/pnpm/global":           false,
		"Android/Sdk":                   runtime.GOOS != "darwin",
		"GO/PKG/MOD":                    runtime.GOOS == "darwin",
		"Library/Application Support/x": false,
	}
	for rel, want := range cases {
		if got := unixPrivateWalkPruned(home, filepath.Join(home, filepath.FromSlash(rel))); got != want {
			t.Errorf("unixPrivateWalkPruned(%q) = %v, want %v", rel, got, want)
		}
	}
	if unixPrivateWalkPruned(home, home) || unixPrivateWalkPruned(home, filepath.Dir(home)) {
		t.Fatal("the home and its parent are never pruned")
	}
	// A pruned tree is not opened, and its open hides nothing from the walk.
	previousOpen := unixPrivateWalkOpenFile
	t.Cleanup(func() { unixPrivateWalkOpenFile = previousOpen })
	opened := false
	unixPrivateWalkOpenFile = func(dir string) (*os.File, error) { opened = true; return os.Open(dir) }
	_, err := unixPrivateWalkOpener(home)(filepath.Join(home, ".cache", "uv"))
	if opened || err == nil || !unixPrivateWalkUnreachable(filepath.Join(home, ".cache", "uv"), err) {
		t.Fatalf("pruned open: opened=%v err=%v", opened, err)
	}
}
