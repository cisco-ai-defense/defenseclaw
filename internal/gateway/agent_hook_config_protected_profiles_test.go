// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestAgentHookConfigProtectedTargetsBlockInEveryProfile pins that a change
// that turns the agent's DefenseClaw hooks off, or removes the installed hook
// executable, blocks in the permissive pack as well as default and strict,
// per-user and managed, while an ordinary settings edit stays allowed.
func TestAgentHookConfigProtectedTargetsBlockInEveryProfile(t *testing.T) {
	h := newGAP0048Home(t)
	hook := filepath.Join(h.home, ".local", "bin", "defenseclaw-hook-user")
	if err := os.MkdirAll(filepath.Dir(hook), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("#!/bin/sh\n"), 0o755); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name  string
		tool  string
		input map[string]any
		block bool
		// managedLocked: under managed enterprise the vendor's managed lock
		// sits above the user settings file, so a native edit of that file
		// is not judged by this rule.
		managedLocked bool
	}{
		{"disable all hooks", "Write", map[string]any{"file_path": h.userSettings, "content": `{"disableAllHooks":true}`}, true, true},
		{"hook executable removed", "Bash", map[string]any{"command": "rm " + hook}, true, false},
		{"ordinary settings edit", "Edit", map[string]any{"file_path": h.userSettings, "old_string": `"env": {"FOO": "1"}`, "new_string": `"env": {"FOO": "1", "BAR": "2"}`}, false, false},
	} {
		for _, profile := range []string{"permissive", "default", "strict"} {
			for _, managed := range []bool{false, true} {
				if managed && tc.managedLocked {
					continue
				}
				name := tc.name + "/" + profile
				if managed {
					name += "/managed"
				}
				t.Run(name, func(t *testing.T) {
					got := rv3Judge(t, "claudecode", profile, h.project, managed, tc.tool, tc.input)
					want := "allow"
					if tc.block {
						want = "block"
					}
					if action := rv2Action(got); action != want {
						t.Errorf("got %s, want %s: %s", action, want, strings.TrimSpace(got))
					}
				})
			}
		}
	}
}

// TestAgentHookConfigGitWorktreeFromCommandAssignments pins that a Git
// command whose worktree comes from GIT_DIR / GIT_WORK_TREE assignments on
// that command is graded as the --work-tree spelling is, from any folder.
func TestAgentHookConfigGitWorktreeFromCommandAssignments(t *testing.T) {
	h := newGAP0048Home(t)
	gitDir := filepath.Join(h.project, ".git")
	if err := os.MkdirAll(gitDir, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(gitDir, "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	other := filepath.Join(h.ext, "other")
	if err := os.MkdirAll(filepath.Join(other, ".git"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, tc := range []struct {
		name, command string
		graded        bool
	}{
		{"git dir and work tree", "GIT_DIR=" + gitDir + " GIT_WORK_TREE=" + h.project + " git checkout HEAD~1 -- .claude/settings.json", true},
		{"work tree only", "GIT_WORK_TREE=" + h.project + " git checkout HEAD~1 -- .claude/settings.json", true},
		{"git dir reset", "GIT_DIR=" + gitDir + " git reset --hard", true},
		{"work tree option", "git --work-tree=" + h.project + " checkout HEAD~1 -- .claude/settings.json", true},
		{"work tree of a repository without a registration file", "GIT_WORK_TREE=" + other + " git reset --hard", false},
		{"unrelated assignment", "LC_ALL=C git status", false},
		{"read-only command with a work tree", "GIT_WORK_TREE=" + h.project + " git status", false},
	} {
		for _, profile := range []string{"default", "strict"} {
			t.Run(tc.name+"/"+profile, func(t *testing.T) {
				got := rv2Action(rv3Judge(t, "claudecode", profile, h.ext, false, "Bash", map[string]any{"command": tc.command}))
				want := "allow"
				if tc.graded {
					want = "alert"
					if profile == "strict" {
						want = "block"
					}
				}
				if got != want {
					t.Errorf("got %s, want %s", got, want)
				}
			})
		}
	}
}
