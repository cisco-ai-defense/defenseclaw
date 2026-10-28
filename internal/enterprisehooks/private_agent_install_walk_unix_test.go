// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"errors"
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
		"Library/Application Support/x": false,
		// A folder of home whose name starts with ".." is below home.
		"..workspace/.git":   true,
		"..cache":            false,
		"..cache/uv":         false,
		"..workspace/go/src": false,
	}
	for _, fold := range []bool{false, true} {
		for rel, want := range cases {
			if got := unixPrivateWalkPruned(home, filepath.Join(home, filepath.FromSlash(rel)), fold); got != want {
				t.Errorf("unixPrivateWalkPruned(%q, fold=%v) = %v, want %v", rel, fold, got, want)
			}
		}
		// Case-distinct names are the same tree only on a volume that
		// compares names without case.
		for _, rel := range []string{"GO/PKG/MOD", ".CACHE/uv", "src/proj/.GIT", ".Cache/Homebrew"} {
			if got := unixPrivateWalkPruned(home, filepath.Join(home, filepath.FromSlash(rel)), fold); got != fold {
				t.Errorf("unixPrivateWalkPruned(%q, fold=%v) = %v, want %v", rel, fold, got, fold)
			}
		}
		for _, outside := range []string{home, filepath.Dir(home), filepath.Join(filepath.Dir(home), ".git"),
			filepath.Join(filepath.Dir(home), ".cache", "uv")} {
			if unixPrivateWalkPruned(home, outside, fold) {
				t.Fatalf("%s is not below the home and is never pruned (fold=%v)", outside, fold)
			}
		}
	}
	if got := unixPrivateWalkPrivacyProtected(home, filepath.Join(home, "Desktop")); got != (runtime.GOOS == "darwin") {
		t.Fatalf("Desktop privacy-protected = %v on %s", got, runtime.GOOS)
	}
	if unixPrivateWalkPrivacyProtected(home, filepath.Join(home, "..Desktop")) ||
		unixPrivateWalkPrivacyProtected(home, filepath.Join(filepath.Dir(home), "Desktop")) {
		t.Fatal("..Desktop below the home and Desktop beside it are not the protected folder")
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

// The walk prunes case-distinct trees only when the home's volume compares
// names without case (the default APFS volume does; a case-sensitive one and
// every Linux file system do not), measured on a real mixed-case home.
func TestUnixPrivateWalkPruneFollowsTheHomeVolumeCase(t *testing.T) {
	home := filepath.Join(t.TempDir(), "Mixed Case Home")
	for _, rel := range []string{".CACHE/uv", "Go/Pkg/Mod", "src/proj/.Git", "..cache/uv"} {
		if err := os.MkdirAll(filepath.Join(home, filepath.FromSlash(rel)), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	// What the volume actually does: does a case-flipped name reach the
	// same folder?
	_, err := os.Lstat(filepath.Join(filepath.Dir(home), "mIXED cASE hOME"))
	volumeFolds := err == nil
	if got := unixHomeCaseInsensitive(home); got != volumeFolds {
		t.Fatalf("unixHomeCaseInsensitive(%s) = %v; the volume folds case: %v", home, got, volumeFolds)
	}
	if runtime.GOOS != "darwin" && unixHomeCaseInsensitive(home) {
		t.Fatal("only macOS folds case")
	}
	if missing := filepath.Join(home, "missing"); unixHomeCaseInsensitive(missing) {
		t.Fatal("an unknown volume must compare names with case")
	}
	open := unixPrivateWalkOpener(home)
	for rel, want := range map[string]bool{".CACHE/uv": volumeFolds, "Go/Pkg/Mod": volumeFolds,
		"src/proj/.Git": volumeFolds, "..cache/uv": false} {
		dir := filepath.Join(home, filepath.FromSlash(rel))
		f, err := open(dir)
		if f != nil {
			_ = f.Close()
		}
		if pruned := errors.Is(err, errPrivateWalkPruned); pruned != want || (!pruned && err != nil) {
			t.Errorf("open %s: err=%v, want pruned=%v", rel, err, want)
		}
	}
	// A case-sensitive answer prunes the exact names only.
	previous := unixHomeCaseInsensitive
	t.Cleanup(func() { unixHomeCaseInsensitive = previous })
	unixHomeCaseInsensitive = func(string) bool { return false }
	if f, err := unixPrivateWalkOpener(home)(filepath.Join(home, ".CACHE", "uv")); err != nil {
		t.Fatalf("case-sensitive volume: .CACHE/uv must be listed: %v", err)
	} else {
		_ = f.Close()
	}
	unixHomeCaseInsensitive = func(string) bool { return true }
	if _, err := unixPrivateWalkOpener(home)(filepath.Join(home, ".CACHE", "uv")); !errors.Is(err, errPrivateWalkPruned) {
		t.Fatalf("case-insensitive volume: .CACHE/uv must be pruned: %v", err)
	}
}
