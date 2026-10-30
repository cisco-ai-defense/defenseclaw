// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"encoding/json"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/hookpaths"
)

// TestProtectHomeLinkAfterCdStaysOrdinary pins GAP-2570: a managed gateway
// that cannot read the caller's home (ProtectHome, the macOS service
// account) reads a benign project link made after a cd, plain, after ;, in
// a subshell or into a missing directory, as the per-user gateway does
// (GAP-2550): allowed. The link and write forms to SSH and DefenseClaw
// state keep their blocks.
func TestProtectHomeLinkAfterCdStaysOrdinary(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	for _, dir := range []string{filepath.Join(home, ".defenseclaw", "hooks"), filepath.Join(home, ".ssh"),
		filepath.Join(home, "p1"), filepath.Join(home, "p2", "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(home, ".defenseclaw", "config.yaml"), filepath.Join(home, ".ssh", "authorized_keys"),
		filepath.Join(home, "p1", "a.txt"), filepath.Join(home, "p2", "a.txt")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	cases := []struct {
		project, command string
		block            bool
	}{
		{"p1", "cd src && ln -s ../a.txt b", false},
		{"p1", "(cd src && ln -s ../a.txt b)", false},
		{"p1", "cd src; ln -s ../a.txt b", false},
		{"p1", "(cd src; ln -s ../a.txt b)", false},
		{"p1", "cd ~/p1 && ln -s ../a.txt b", false},
		{"p2", "cd src && ln -s ../a.txt b", false},
		{"p2", "(cd src && ln -s ../a.txt b)", false},
		{"p2", "cd src; ln -s ../a.txt b", false},
		{"p2", "cd src && ln -s x y", false},
		{"p2", "cd /tmp && ln -s ../a.txt b", false},
		{"p2", "ln -s ../a.txt b", false},
		{"p2", "cd ~ && ln -s .defenseclaw hc && echo x >> hc/config.yaml", true},
		{"p2", "cd ~ && ln -s .ssh sd && echo k >> sd/authorized_keys", true},
		{"p2", "cd src && ln -s ../../.ssh sd && echo k >> sd/authorized_keys", true},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, tc := range cases {
			t.Run(connector+"/"+tc.project+"/"+tc.command, func(t *testing.T) {
				if err := os.Chmod(homes, 0o700); err != nil {
					t.Fatal(err)
				}
				event := map[string]any{"session_id": "gap2570", "hook_event_name": "PreToolUse",
					"tool_name": "Bash", "cwd": filepath.Join(home, tc.project), "tool_input": map[string]any{"command": tc.command}}
				if connector == "codex" {
					event["turn_id"], event["tool_use_id"] = "t1", "tu-gap2570"
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
				var resp map[string]any
				if err := json.Unmarshal([]byte(got), &resp); err != nil {
					t.Fatalf("verdict %q: %v", got, err)
				}
				if blocked := resp["action"] == "block"; blocked != tc.block {
					t.Fatalf("blocked = %t, want %t: evidence=%v %.600s", blocked, tc.block, evidence, got)
				}
				if tc.block && strings.Contains(tc.command, ".defenseclaw") && !strings.Contains(got, "tamper.detector_state_write") {
					t.Fatalf("blocked by another rule: %.600s", got)
				}
			})
		}
	}
}
