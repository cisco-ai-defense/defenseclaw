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
