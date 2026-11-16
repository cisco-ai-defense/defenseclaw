// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// GAP-1440: a managed gateway behind ProtectHome cannot walk the user's
// home. A link the command creates there used to leave every later name
// unknown, so an ordinary hard link was blocked as an SSH key write. The
// managed Claude Code hook client walks the same links as the user; its
// answer decides the name, and a real key alias still blocks.
func TestR104ProtectHomeHardLinkUsesClientWalk(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "project1")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{ssh, project, filepath.Join(project, "docs"),
		filepath.Join(home, "persona-src"), filepath.Join(home, "scratch")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(ssh, "authorized_keys")
	for _, file := range []string{keys, filepath.Join(project, "CLAUDE.md"),
		filepath.Join(home, "persona-src", "soul.txt")} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(keys, filepath.Join(project, "hl")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink(keys, filepath.Join(project, "keylink")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	cases := map[string]bool{
		"ln CLAUDE.md notes.txt":                         false,
		"ln ~/persona-src/soul.txt ~/scratch/h.txt":      false,
		"ln -f CLAUDE.md notes.txt":                      false,
		"ln -s CLAUDE.md notes.txt":                      false,
		"ln -sr CLAUDE.md docs/c.md":                     false,
		"link CLAUDE.md notes.txt":                       false,
		"cp -l CLAUDE.md notes.txt":                      false,
		"ln CLAUDE.md docs/":                             false,
		"ln CLAUDE.md notes.txt && echo ok >> notes.txt": false,
		"ln hl notes.txt && echo x >> notes.txt":         true,
		"ln keylink n.txt && echo x >> n.txt":            true,
		"cp -l hl notes.txt && echo x >> notes.txt":      true,
		"ln -s ~/.ssh/authorized_keys n && echo x >> n":  true,
		"ln -s ../.ssh/authorized_keys n && echo x >> n": true,
		"ln CLAUDE.md ~/.ssh/authorized_keys":            true,
		"link hl notes.txt; printf x >> notes.txt":       true,
	}
	for command, want := range cases {
		t.Run(command, func(t *testing.T) {
			if err := os.Chmod(homes, 0o700); err != nil {
				t.Fatal(err)
			}
			body, err := json.Marshal(map[string]any{"session_id": "gap1440", "hook_event_name": "PreToolUse",
				"tool_name": "Bash", "cwd": project,
				"tool_input": map[string]any{"command": command, "description": "Create hard link"}})
			if err != nil {
				t.Fatal(err)
			}
			evidence := hookpaths.Resolve(body)
			if err := os.Chmod(homes, 0); err != nil {
				t.Fatal(err)
			}
			got := overLimitHostHookWithEvidence(t, "claudecode", home, string(body), evidence)
			if blocked := nativeWriteBlocked(t, got); blocked != want {
				t.Fatalf("blocked = %t, want %t: %.600s", blocked, want, got)
			}
		})
	}
}
