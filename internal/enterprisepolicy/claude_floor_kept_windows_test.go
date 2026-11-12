//go:build windows

// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package enterprisepolicy

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0758: a link kept at the Claude Code managed-settings folder is not
// followed by the uninstall's floor removal or the purge pass. Only
// DefenseClaw's own record of the floor goes; nothing behind the link is read,
// changed or removed, and neither pass takes the policy lock.
func TestWindowsClaudeVersionFloorRemovalKeepsALinkedFolder(t *testing.T) {
	opts, locked := windowsFloorOptions(t)
	if _, err := PublishWindowsClaudeVersionFloor(opts, []string{"claudecode"}); err != nil {
		t.Fatal(err)
	}
	path := filepath.Join(opts.WindowsProgramFiles, "ClaudeCode", "managed-settings.d", "00-defenseclaw-version-floor.json")
	before := readFile(t, path)
	recorded, err := ClaudeVersionFloorRecorded(opts)
	if err != nil || !recorded {
		t.Fatalf("the published floor must be recorded: %v %v", recorded, err)
	}
	lockedBefore := *locked

	previous := windowsClaudeFloorFolderKept
	windowsClaudeFloorFolderKept = func() (bool, error) { return true, nil }
	t.Cleanup(func() { windowsClaudeFloorFolderKept = previous })

	if removed, err := PurgeWindowsUnrecordedClaudeVersionFloor(opts); err != nil || removed {
		t.Fatalf("purge pass behind a link: removed %v, err %v; want neither", removed, err)
	}
	if _, err := RemoveWindowsClaudeVersionFloor(opts); err != nil {
		t.Fatalf("floor removal behind a link must not fail the uninstall: %v", err)
	}
	if recorded, err := ClaudeVersionFloorRecorded(opts); err != nil || recorded {
		t.Fatalf("DefenseClaw's own record must go: recorded %v, err %v", recorded, err)
	}
	if *locked != lockedBefore {
		t.Errorf("the policy lock was taken %d more times behind a link", *locked-lockedBefore)
	}
	if got, err := os.ReadFile(path); err != nil || string(got) != before {
		t.Errorf("the file behind the link changed: %q, %v", got, err)
	}
}
