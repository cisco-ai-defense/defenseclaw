//go:build !windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package enterprisehooks

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-10 GAP-0802: a scan gap names the folder the walk could not list
// (here the one where its entry bound ran out), so status can say which part
// of the home was not inspected; a scan stopped by its deadline names the
// home.
func TestUnixPrivateInstallScanNamesTheFolderItCouldNotList(t *testing.T) {
	home := t.TempDir()
	huge := filepath.Join(home, "work", "huge")
	for i := 0; i < 40; i++ {
		if err := os.MkdirAll(filepath.Join(huge, fmt.Sprintf("d%02d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	previous := privateInstallWalkMaxEntries
	t.Cleanup(func() { privateInstallWalkMaxEntries = previous })
	privateInstallWalkMaxEntries = 20

	_, complete, unlisted := walkPrivateNPMPrefixes(context.Background(), home, privateInstallWalk{open: os.Open, unreachable: unixPrivateWalkUnreachable})
	if complete || unlisted != huge {
		t.Fatalf("walk over its entry bound: complete=%t unlisted=%q, want %q", complete, unlisted, huge)
	}
	installs := DiscoverUnixPrivateAgentInstalls(context.Background(), home, []string{"claudecode", "codex"})
	if len(installs) != 2 {
		t.Fatalf("scan over its entry bound = %+v, want one gap per connector", installs)
	}
	for _, install := range installs {
		agent, ok := privateInstallUnprotected(install)
		if !install.Incomplete || install.Skipped != PrivateInstallSkippedHome || install.Folder != huge ||
			!ok || agent.Folder != huge || agent.Skipped != PrivateInstallSkippedHome {
			t.Fatalf("scan gap = %+v (entry %+v), want the folder %q", install, agent, huge)
		}
	}

	privateInstallWalkMaxEntries = previous
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	for _, install := range DiscoverUnixPrivateAgentInstalls(ctx, home, []string{"claudecode"}) {
		if !install.Incomplete || install.Folder != home {
			t.Fatalf("expired scan gap = %+v, want the home %q", install, home)
		}
	}
}
