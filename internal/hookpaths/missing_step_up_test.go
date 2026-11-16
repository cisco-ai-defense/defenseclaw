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

// TestMissingStepUpReadsAsTheCleanedName: a step up out of a directory that
// does not exist is the cleaned name, while a step up that leaves an existing
// directory (a link among them) keeps its physical meaning, and a cleaned name
// that is a protected file still reaches it.
func TestMissingStepUpReadsAsTheCleanedName(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	project, other := filepath.Join(root, "proj"), filepath.Join(root, "other")
	for _, dir := range []string{project, other, filepath.Join(root, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(other, filepath.Join(project, "lnk")); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	rows := []struct {
		path, want string
		changed    bool
	}{
		{project + "/sub/../notes.txt", project + "/notes.txt", true},
		{project + "/sub/../sub/notes.txt", project + "/sub/notes.txt", true},
		{project + "/sub/../../.ssh/authorized_keys", root + "/.ssh/authorized_keys", true},
		{project + "/lnk/../notes.txt", "", false},
		{project + "/notes.txt", "", false},
	}
	for _, row := range rows {
		got, ok, changed := ResolveWriteTargetPastMissingStepUps(row.path)
		if changed != row.changed || changed && (!ok || got != row.want) {
			t.Errorf("%s = %q, %t, %t; want %q, changed %t", row.path, got, ok, changed, row.want, row.changed)
		}
	}
}

// TestPatchEvidenceAnswersAStepUpOutOfAMissingFolder: the hook client lists the
// raw spelling of an Add File header that steps up out of a missing folder with
// the cleaned file as its text, beside the empty answer the spelling has, so a
// managed gateway judges the file instead of refusing an unplaced name. The
// same spelling that reaches a key file lists that file.
func TestPatchEvidenceAnswersAStepUpOutOfAMissingFolder(t *testing.T) {
	root, err := filepath.EvalSymlinks(t.TempDir())
	if err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", root)
	project := filepath.Join(root, "proj")
	for _, dir := range []string{project, filepath.Join(root, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for name, want := range map[string]string{
		"sub/../notes.txt":               project + "/notes.txt",
		"sub/../../.ssh/authorized_keys": root + "/.ssh/authorized_keys",
	} {
		patch := "*** Begin Patch\n*** Add File: " + name + "\n+x\n*** End Patch\n"
		body, _ := json.Marshal(map[string]any{"hook_event_name": "PreToolUse", "tool_name": "apply_patch", "cwd": project,
			"tool_input": map[string]string{"command": patch}})
		targets, ok := Decode(Resolve(body))
		if !ok {
			t.Fatalf("%s: no evidence", name)
		}
		raw := project + "/" + name
		if got := targets[LinkTextFactPrefix+raw]; got != want || targets[raw] != "" {
			t.Errorf("%s: text %q, answer %q; want text %q and no answer (evidence %v)", name, got, targets[raw], want, targets)
		}
	}
}
