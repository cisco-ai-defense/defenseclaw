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

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// A call past the operand bound is described by the hook client in a map of
// bounded size. In a deep home folder (a macOS temporary folder is one) the
// operand entries fill the whole map, and the client then gave up the map for
// a header of the cwd alone, which lost the one fact a managed gateway needs
// for a protected name: its own reading of the call found a protected target
// (GAP-0943). A hard link to the keys file named past the bound is blocked in
// every profile, however deep the folder and however the working directory is
// given; an ordinary file of the same shape is the allowing bound alert.
func TestProtectedLinkPastTheOperandBoundIsBlockedWhenTheEvidenceMapIsFull(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	home := filepath.Join(root, "home", strings.Repeat("d", 60), strings.Repeat("e", 60), "eng1")
	project := filepath.Join(home, "proj")
	for _, dir := range []string{filepath.Join(home, ".ssh"), project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	ordinary := filepath.Join(project, "ordinary.txt")
	for _, file := range []string{keys, ordinary} {
		if err := os.WriteFile(file, []byte("# base\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for name, target := range map[string]string{"hlk-keys": keys, "hlk-ord": ordinary} {
		if err := os.Link(target, filepath.Join(project, name)); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	homes := filepath.Dir(filepath.Dir(filepath.Dir(home)))
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	command := func(count int, last string) string {
		words := make([]string, 0, count+1)
		for i := 0; i < count; i++ {
			words = append(words, fmt.Sprintf("f%d", i))
		}
		return "touch " + strings.Join(append(words, last), " ")
	}
	calls := []struct {
		name, connector, tool, cwd, workdir string
	}{
		{"codex absolute workdir", "codex", "exec_command", project, project},
		{"codex absolute workdir with a parent step", "codex", "exec_command", project, project + "/../proj"},
		{"codex relative workdir", "codex", "exec_command", home, "proj"},
		{"codex session folder", "codex", "exec_command", project, ""},
		{"claudecode session folder", "claudecode", "Bash", project, ""},
	}
	for _, c := range calls {
		for _, count := range []int{actionfacts.MaxOperandsPerCall + 1, 5000} {
			for _, probe := range []struct {
				target string
				want   bool
			}{{"hlk-keys", true}, {"hlk-ord", false}} {
				for _, protectHome := range []bool{false, true} {
					t.Run(fmt.Sprintf("%s/%d operands/%s/protect home=%t", c.name, count, probe.target, protectHome), func(t *testing.T) {
						input := map[string]any{"command": command(count, probe.target)}
						if c.tool == "exec_command" {
							input = map[string]any{"cmd": command(count, probe.target)}
							if c.workdir != "" {
								input["workdir"] = c.workdir
							}
						}
						body, err := json.Marshal(map[string]any{"session_id": "c943", "hook_event_name": "PreToolUse",
							"tool_name": c.tool, "cwd": c.cwd, "tool_input": input})
						if err != nil {
							t.Fatal(err)
						}
						evidence := hookpaths.ResolveConnector(c.connector, "", "preToolUse", body)
						targets, ok := hookpaths.Decode(evidence)
						if !ok {
							t.Fatalf("evidence does not decode: %.200s", evidence)
						}
						if probe.want && targets[hookpaths.ActionDecisionKey] != hookpaths.ProtectedTargetDecision {
							t.Fatalf("the map of a call that names a protected link lost its protected-target reading (%d entries)", len(targets))
						}
						if protectHome {
							// A managed gateway behind ProtectHome cannot walk the home:
							// the hook client evidence decides.
							if err := os.Chmod(homes, 0); err != nil {
								t.Fatal(err)
							}
							defer func() { _ = os.Chmod(homes, 0o700) }()
						}
						got := overLimitHostHookWithEvidence(t, c.connector, home, string(body), evidence)
						if blocked := nativeWriteBlockedOverBound(t, got, true); blocked != probe.want {
							t.Fatalf("blocked = %t, want %t: %.600s", blocked, probe.want, got)
						}
					})
				}
			}
		}
	}
}
