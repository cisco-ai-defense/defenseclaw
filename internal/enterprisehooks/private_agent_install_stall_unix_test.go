// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterprisehooks

import (
	"context"
	"io/fs"
	"os"
	"path/filepath"
	"testing"
	"time"
)

// GAP-1468: a folder listing that never returns (a stalled automount or
// network home) held the private-home scan, so the discovery worker was
// killed and published nothing. The whole scan is bounded: it answers
// shortly after its context ends and reports every wanted connector
// incomplete, never a silently clean home.
func TestDiscoverUnixPrivateInstallsAnswersWhenAListingStalls(t *testing.T) {
	home := t.TempDir()
	stuck := filepath.Join(home, "automount")
	if err := os.MkdirAll(stuck, 0o700); err != nil {
		t.Fatal(err)
	}
	entered, release, returned := make(chan struct{}, 1), make(chan struct{}), make(chan struct{}, 1)
	previous := privateInstallWalkReadDir
	privateInstallWalkReadDir = func(f *os.File, n int) ([]fs.DirEntry, error) {
		if filepath.Clean(f.Name()) == stuck {
			entered <- struct{}{}
			<-release
			defer func() { returned <- struct{}{} }()
		}
		return f.ReadDir(n)
	}
	t.Cleanup(func() {
		close(release)
		select {
		case <-returned:
		case <-time.After(10 * time.Second):
		}
		privateInstallWalkReadDir = previous
	})
	ctx, cancel := context.WithTimeout(context.Background(), 300*time.Millisecond)
	defer cancel()
	done := make(chan []PrivateAgentInstall, 1)
	go func() { done <- DiscoverUnixPrivateAgentInstalls(ctx, home, []string{"claudecode", "codex"}) }()
	select {
	case found := <-done:
		select {
		case <-entered:
		case <-time.After(5 * time.Second):
		}
		got := map[string]string{}
		for _, install := range found {
			if install.Incomplete {
				got[install.Connector] = install.Skipped
			}
		}
		if got["claudecode"] != PrivateInstallSkippedHome || got["codex"] != PrivateInstallSkippedHome {
			t.Fatalf("a stalled listing must leave each connector incomplete (%s): %+v", PrivateInstallSkippedHome, found)
		}
	case <-time.After(10 * time.Second):
		t.Fatal("the private install scan did not answer 10s after its 300ms context ended")
	}
}
