// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build windows

package connector

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-2284: on Windows a POSIX script word (/dir/copilot-hook.sh) names the
// file Copilot's bash resolves under its own root, not the drive-root file a
// native Lstat reaches. Setup read the deleted-copy rule from the drive-root
// file, so the same entry was claimed when that unrelated file was absent and
// refused (the GAP-2234 symptom) when an unmarked file of that name happened
// to sit there. The text decides now, as the doctor reads it. Fails at
// r111/rf-ent-win2 877b81e4de on the "drive-root file present" case.
func TestGAP2284CopilotPOSIXCopyClaimDoesNotDependOnTheDriveRootFile(t *testing.T) {
	dir := t.TempDir()
	t.Chdir(dir) // a POSIX word resolves against the current drive
	volume := filepath.VolumeName(dir)
	if volume == "" || strings.HasPrefix(volume, `\\`) {
		t.Skipf("temp dir %q is not on a drive letter", dir)
	}
	native := filepath.Join(dir, "lane", copilotHookScriptName)
	if err := os.MkdirAll(filepath.Dir(native), 0o700); err != nil {
		t.Fatal(err)
	}
	posix := filepath.ToSlash(strings.TrimPrefix(native, volume))
	command := "'" + posix + "' --event 'preToolUse'"
	hookScript := filepath.Join(dir, ".defenseclaw", "hooks", copilotHookScriptName)

	if !copilotBoundEventOwnsCommand("bash", command, hookScript) {
		t.Fatalf("drive-root file absent: Setup does not claim %s", command)
	}
	// An unmarked same-named file at the drive-root reading is not the file
	// bash runs; it must not change the claim.
	if err := os.WriteFile(native, []byte("#!/bin/sh\nexit 0\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if !copilotBoundEventOwnsCommand("bash", command, hookScript) {
		t.Fatalf("GAP-2284: drive-root file present: Setup does not claim %s", command)
	}
	// Twins: the text rule is only the exact script name with Copilot's
	// event binding.
	for _, other := range []string{
		"'" + filepath.ToSlash(filepath.Dir(posix)) + "/other-hook.sh' --event 'preToolUse'",
		"'" + posix + "' --event 'preToolUse' --debug",
		"'" + posix + "' --event 'notAnEvent'",
	} {
		if copilotBoundEventOwnsCommand("bash", other, hookScript) {
			t.Errorf("Setup claims %s", other)
		}
	}
}
