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

// GAP-2428 (GitHub #1166, class of GAP-1556): a managed gateway behind
// ProtectHome cannot place a relative command operand in the user's
// project, so a write named by a command operand or an output option
// (install and dd of= destinations, find -fprint, git config -f, gawk -i
// inplace, uniq and sort -o outputs) through an existing link to
// ~/.ssh/authorized_keys was never judged, although the user's hook had
// resolved it to the keys file. The redirect, cp and tee forms were
// already blocked; a per-user gateway blocks every form.
func TestProtectHomeCommandOperandWriteThroughLinkUsesClientWalk(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "project")
	for _, dir := range []string{filepath.Join(home, ".ssh", "d"), filepath.Join(project, "a")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	for _, file := range []string{keys, filepath.Join(project, "payload"), filepath.Join(project, "input.txt"),
		filepath.Join(project, "notes.txt")} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, link := range []struct{ name, target string }{
		{filepath.Join(project, "a", "b"), filepath.Join(home, ".ssh", "d")},
		{filepath.Join(project, "a", "l"), filepath.FromSlash("b/../authorized_keys")},
		{filepath.Join(project, "alias"), keys},
	} {
		if err := os.Symlink(link.target, link.name); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	cases := []struct {
		command string
		block   bool
	}{
		{"echo k >> a/l", true},
		{"cp payload a/l", true},
		{"tee -a a/l < payload", true},
		{"install payload a/l", true},
		{"dd if=payload of=a/l", true},
		{"find . -maxdepth 0 -fprint alias", true},
		{"git config -f alias verifier.value x", true},
		{"gawk -i inplace {print} alias", true},
		{"uniq input.txt alias", true},
		{"sort -o alias input.txt", true},
		{"install payload out.txt", false},
		{"dd if=payload of=out.txt", false},
		{"find . -maxdepth 0 -fprint out.txt", false},
		{"git config -f project.cfg verifier.value x", false},
		{"gawk -i inplace {print} notes.txt", false},
		{"uniq input.txt out.txt", false},
		{"sort -o out.txt input.txt", false},
		{"dd if=alias of=out.txt", false},
		{"git config -f alias --get verifier.value", false},
		{"uniq alias", false},
		{"cat alias", false},
		{"rm alias", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		for _, tc := range cases {
			t.Run(connector+"/"+tc.command, func(t *testing.T) {
				if err := os.Chmod(homes, 0o700); err != nil {
					t.Fatal(err)
				}
				event := map[string]any{"session_id": "gap2428", "hook_event_name": "PreToolUse",
					"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": tc.command}}
				if connector == "codex" {
					event["turn_id"], event["tool_use_id"] = "t1", "tu-gap2428"
				}
				body, err := json.Marshal(event)
				if err != nil {
					t.Fatal(err)
				}
				evidence := hookpaths.Resolve(body)
				if err := os.Chmod(homes, 0); err != nil {
					t.Fatal(err)
				}
				got := overLimitHostHookWithEvidence(t, connector, home, string(body), evidence)
				if blocked := nativeWriteBlocked(t, got); blocked != tc.block {
					t.Fatalf("blocked = %t, want %t: %.600s", blocked, tc.block, got)
				}
			})
		}
	}
}
