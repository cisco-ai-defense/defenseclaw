// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A typed patch that steps up from a directory that does not exist
// (proj/../x from the project, which has no proj inside it) is listed twice:
// by the clean spelling the gateway judges, and by the raw spelling, which the
// operating system cannot open and the hook could not place. The raw spelling
// still leading nowhere is not a change of the patch; the clean spelling is
// the one that decides, so an ordinary file stays allowed and a protected one
// stays refused. A raw spelling that leads somewhere after the reading is a
// change.
func TestPatchTargetWatchUnplacedStepUpSpellingIsNotAChange(t *testing.T) {
	for _, tc := range []struct {
		name, target string
		changed      bool
	}{
		{"step up to an ordinary file", "proj/../.ssh/authorized_keys", false},
		{"step up to an ordinary config", "proj/../.ssh/config", false},
		{"step up to a project file", "proj/../notes.txt", false},
		{"step up from a missing sub directory", "sub/../notes.txt", false},
		{"plain project file", "notes.txt", false},
		{"step up out of the project to the keys file", "../.ssh/authorized_keys", true},
		{"absolute keys file", "@HOME@/.ssh/authorized_keys", true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			home, project := stepUpFixture(t)
			target := tc.target
			if len(target) > 6 && target[:6] == "@HOME@" {
				target = home + target[6:]
			}
			for _, form := range []string{"typed", "heredoc"} {
				watch := stepUpWatch(t, form, target, project)
				if watch == nil {
					t.Fatalf("%s: the patch is not attested complete", form)
				}
				if got := watch.Changed(); got != tc.changed {
					t.Errorf("%s: changed = %v, want %v", form, got, tc.changed)
				}
			}
		})
	}
}

// The raw spelling is read again: a link made since at the missing directory
// that leads it to the keys file reads as a change.
func TestPatchTargetWatchUnplacedStepUpSpellingLinkedLaterIsAChange(t *testing.T) {
	home, project := stepUpFixture(t)
	watch := stepUpWatch(t, "typed", "proj/../.ssh/authorized_keys", project)
	if watch.Changed() {
		t.Fatal("the unchanged patch reads as changed")
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "proj")); err != nil {
		t.Fatal(err)
	}
	if !watch.Changed() {
		t.Error("a link made since at the missing directory, leading to the keys file, reads as unchanged")
	}
}

func stepUpFixture(t *testing.T) (home, project string) {
	t.Helper()
	home, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project = filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	mustWrite(t, filepath.Join(home, ".ssh", "authorized_keys"), "k\n")
	mustWrite(t, filepath.Join(project, "notes.txt"), "n\n")
	t.Setenv("HOME", home)
	return home, project
}

func stepUpWatch(t *testing.T, form, target, project string) *PatchTargetWatch {
	t.Helper()
	patch := "*** Begin Patch\n*** Update File: " + target + "\n@@\n k\n+x\n*** End Patch\n"
	command := patch
	if form == "heredoc" {
		command = "apply_patch <<P\n" + patch + "P\n"
	}
	body, err := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch",
		"tool_input": map[string]any{"command": command}, "cwd": project})
	if err != nil {
		t.Fatal(err)
	}
	return watchOfEvidence(ResolveConnector("codex", "", "PreToolUse", body))
}
