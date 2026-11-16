//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/enterprisehooks"
	"github.com/fsnotify/fsnotify"
)

// A Copilot row's VS Code Local hook file was in no watch list, so its
// removal waited for the interval pass (GAP-0664).
func TestEnterpriseHookPlatformWatchFilesNamesTheCopilotVSCodeHookFile(t *testing.T) {
	home := t.TempDir()
	want := filepath.Join(home, ".copilot", "hooks", "defenseclaw-vscode.json")
	dirs, files := enterpriseHookPlatformWatchFiles("copilot", home)
	if len(dirs) != 0 || len(files) != 1 || files[0] != want {
		t.Fatalf("without the hooks folder: dirs %q files %q, want no folder and %s", dirs, files, want)
	}
	if err := os.MkdirAll(filepath.Dir(want), 0o700); err != nil {
		t.Fatal(err)
	}
	dirs, files = enterpriseHookPlatformWatchFiles("Copilot", home)
	if len(dirs) != 1 || dirs[0] != filepath.Dir(want) || len(files) != 1 || files[0] != want {
		t.Fatalf("with the hooks folder: dirs %q files %q", dirs, files)
	}
	for _, other := range []string{"codex", "claudecode", "cursor", "hermes"} {
		if dirs, files := enterpriseHookPlatformWatchFiles(other, home); len(dirs)+len(files) != 0 {
			t.Fatalf("%s: dirs %q files %q, want none", other, dirs, files)
		}
	}
}

func TestEnterpriseHookPlatformWatchFileHasFailedTargetOwner(t *testing.T) {
	home := t.TempDir()
	_, files := enterpriseHookPlatformWatchFiles("copilot", home)
	if len(files) != 1 {
		t.Fatalf("Copilot platform files: %v", files)
	}
	row := enterpriseHookReconcileRow{User: "alice", Connector: "copilot", Error: "repair pending"}
	exclusive := map[string]struct{}{}
	owners := map[string][]string{}
	enterpriseHookWatchAddExclusiveOwnedFiles(exclusive, owners, files, enterpriseHookProtectedTargetKey(row))
	failed := enterpriseHookWatchFailedOwnedPaths(enterpriseHookReconcileRun{
		Rows: []enterpriseHookReconcileRow{row}, WatchPathOwners: owners,
	})
	path := files[0]
	if _, watched := exclusive[path]; !watched || !failed[path] {
		t.Fatalf("platform path %q has no failed owner: watched=%v failed=%v", path, watched, failed[path])
	}
	// The watch loop judges an event against the snapshots its last pass took
	// of every owned path (takeEnterpriseHookOwnedSnapshot); an owned path
	// with no snapshot entry counts as changed, never as the pass's tail.
	found, left := map[string]string{}, map[string]string{}
	takeEnterpriseHookOwnedSnapshot(found, exclusive, nil, enterprisehooks.OwnedFileFingerprint)
	takeEnterpriseHookOwnedSnapshot(left, exclusive, nil, enterprisehooks.OwnedFileFingerprint)
	now := time.Now()
	if drop, settling := enterpriseHookWatchEventDropped(now, now.Add(time.Second),
		fsnotify.Event{Name: path, Op: fsnotify.Create | fsnotify.Remove}, failed[path], exclusive, nil,
		found, left, enterprisehooks.OwnedFileFingerprint, true); !drop || !settling {
		t.Fatalf("failed repair tail: drop=%v settling=%v", drop, settling)
	}
}
