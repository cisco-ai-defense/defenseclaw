// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A call whose working directory reaches the account home only through a
// symlinked parent step (project/lnk/.., lnk -> ~/.ssh) runs in the home. The
// hook client and the gateway place the call by the file system, not by a
// text clean-up of the parent step, so a hard link to authorized_keys in the
// home is the protected file whatever the length of the operand list and
// whichever way the working directory is spelled.
func TestOnTimeCallWithAWorkdirThroughASymlinkedParentStepTellsTheHome(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home", "eng1")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	ordinary := filepath.Join(home, "ordinary.txt")
	for _, file := range []string{keys, ordinary} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"hlk-home": keys, "hlk-ord": ordinary} {
		if err := os.Link(target, filepath.Join(home, name)); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, ".ssh"), filepath.Join(project, "lnk")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	operands := func(count int, last string) string {
		words := make([]string, 0, count+1)
		for i := 0; i < count; i++ {
			words = append(words, fmt.Sprintf("f%d", i))
		}
		return "touch " + strings.Join(append(words, last), " ")
	}
	type call struct {
		name, connector, tool string
		cwd, workdir          string
	}
	calls := []call{
		{"claudecode cwd through link", "claudecode", "Bash", project + "/lnk/..", ""},
		{"claudecode cwd through link, dot", "claudecode", "Bash", project + "/lnk/../.", ""},
		{"codex cwd through link", "codex", "Bash", project + "/lnk/..", ""},
		{"codex exec_command relative workdir", "codex", "exec_command", project, "lnk/.."},
		{"codex exec_command absolute workdir", "codex", "exec_command", project, project + "/lnk/.."},
	}
	homes := filepath.Dir(home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	for _, c := range calls {
		for _, count := range []int{0, 5000} {
			for _, probe := range []struct {
				target string
				want   bool
			}{{"hlk-home", true}, {"hlk-ord", false}} {
				for _, protectHome := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%d operands/%s/protect home=%t", c.name, count, probe.target, protectHome), func(t *testing.T) {
						input := map[string]any{"command": operands(count, probe.target)}
						if c.tool == "exec_command" {
							input = map[string]any{"cmd": operands(count, probe.target)}
							if c.workdir != "" {
								input["workdir"] = c.workdir
							}
						}
						body, err := json.Marshal(map[string]any{"session_id": "c903", "hook_event_name": "PreToolUse",
							"tool_name": c.tool, "cwd": c.cwd, "tool_input": input})
						if err != nil {
							t.Fatal(err)
						}
						evidence := hookpaths.ResolveConnector(c.connector, "", "preToolUse", body)
						if protectHome {
							// A managed gateway behind ProtectHome cannot walk the home:
							// the hook clients evidence decides.
							if err := os.Chmod(homes, 0); err != nil {
								t.Fatal(err)
							}
							defer func() { _ = os.Chmod(homes, 0o700) }()
						}
						got := overLimitHostHookWithEvidence(t, c.connector, home, string(body), evidence)
						if blocked := nativeWriteBlocked(t, got); blocked != probe.want {
							t.Fatalf("blocked = %t, want %t: %.600s", blocked, probe.want, got)
						}
					})
				}
			}
		}
	}
}
