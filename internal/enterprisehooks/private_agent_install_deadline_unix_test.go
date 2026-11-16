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

func TestUnixPrivateInstallDeadlineAndDepthAreIncomplete(t *testing.T) {
	home := t.TempDir()
	for i := 0; i < 40; i++ {
		if err := os.Mkdir(filepath.Join(home, fmt.Sprintf("d%02d", i)), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	cancel()
	expired := DiscoverUnixPrivateAgentInstalls(ctx, home, []string{"claudecode", "codex"})
	if len(expired) != 2 {
		t.Fatalf("expired scan = %+v, want one incomplete entry per connector", expired)
	}
	for _, install := range expired {
		if !install.Incomplete || install.Skipped != PrivateInstallSkippedHome {
			t.Fatalf("expired scan silently completed: %+v", install)
		}
	}
	deep := t.TempDir()
	for i := 0; i <= privateInstallWalkMaxDepth; i++ {
		deep = filepath.Join(deep, "a")
		if err := os.Mkdir(deep, 0o755); err != nil {
			t.Fatal(err)
		}
	}
	root := deep
	for i := 0; i <= privateInstallWalkMaxDepth; i++ {
		root = filepath.Dir(root)
	}
	_, complete := walkPrivateNPMPrefixes(context.Background(), root, privateInstallWalk{open: os.Open, unreachable: unixPrivateWalkUnreachable})
	if complete {
		t.Fatal("a directory beyond the depth cap was silently omitted")
	}
}

func TestUnixPrivateWalkStopsDuringAProfileWithoutClaimingCompletion(t *testing.T) {
	home := t.TempDir()
	for _, name := range []string{"a", "b", "c"} {
		if err := os.Mkdir(filepath.Join(home, name), 0o755); err != nil {
			t.Fatal(err)
		}
	}
	ctx, cancel := context.WithCancel(context.Background())
	defer cancel()
	opened := 0
	_, complete := walkPrivateNPMPrefixes(ctx, home, privateInstallWalk{
		open: func(dir string) (*os.File, error) {
			opened++
			if opened == 2 {
				cancel()
			}
			return os.Open(dir)
		},
		unreachable: unixPrivateWalkUnreachable,
	})
	if opened != 2 || complete {
		t.Fatalf("canceled walk opened %d directories, complete=%v", opened, complete)
	}
}
