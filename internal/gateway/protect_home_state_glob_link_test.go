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

// GAP-2544: a managed gateway behind ProtectHome cannot list the user's
// ~/.defenseclaw, so a pathname pattern there (cp a.txt
// ~/.defenseclaw/conf*.yaml, cp a.txt ~/.def*/config.yaml) had no
// expanded reading, and a write through a link the same command makes to
// the state directory (nohup ln -s ~/.defenseclaw hc; cp a.txt
// hc/config.yaml) was allowed, while a per-user gateway blocks every form
// (GAP-2496, GAP-2522). Reads, copies out of the state and project links
// stay allowed.
func TestProtectHomeStateGlobAndLinkWritesBlock(t *testing.T) {
	if os.Geteuid() == 0 {
		t.Skip("requires an unprivileged POSIX gateway walk")
	}
	root := t.TempDir()
	homes := filepath.Join(root, "homes")
	home := filepath.Join(homes, "eng1")
	project := filepath.Join(home, "project")
	state := filepath.Join(home, ".defenseclaw")
	for _, dir := range []string{filepath.Join(state, "hooks"), filepath.Join(project, "src")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, file := range []string{filepath.Join(state, "config.yaml"), filepath.Join(state, "session-facts.json"),
		filepath.Join(state, "hooks", "x.sh"), filepath.Join(project, "a.txt"), filepath.Join(project, "src", "n.txt")} {
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	t.Cleanup(func() { _ = os.Chmod(homes, 0o700) })
	cases := []struct {
		command string
		block   bool
	}{
		{"cp a.txt ~/.defenseclaw/config.yaml", true},
		{"cp a.txt ~/.defenseclaw/conf*.yaml", true},
		{"cp a.txt ~/.def*/config.yaml", true},
		{"cp a.txt $HOME/.defense?law/config.yaml", true},
		{"cp a.txt ~/.defenseclaw/hook?/x.sh", true},
		{"cp a.txt ~/.defenseclaw/hooks/*.sh", true},
		{"tee ~/.def*/config.yaml < a.txt", true},
		{"nohup ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"ln -s ~/.defenseclaw hc; cp a.txt hc/config.yaml", true},
		{"ln -s ~/.defenseclaw/hooks hh; cp a.txt hh/x.sh", true},
		{"ln -s ~/.defenseclaw hc && echo x > hc/config.yaml", true},
		{"cp a.txt src/*.txt", false},
		{"cp a.txt b.txt", false},
		{"ls ~/.def*/config.yaml", false},
		{"cat ~/.defenseclaw/conf*.yaml", false},
		{"cp ~/.def*/config.yaml backup.yaml", false},
		{"nohup ln -s src s; cp a.txt s/b.txt", false},
		{"ln -s ~/.defenseclaw dc; cat dc/config.yaml", false},
		{"ln -s ~/.defenseclaw dc; cp dc/config.yaml backup.yaml", false},
	}
	for _, connector := range []string{"claudecode", "codex"} {
		installDefaultProfileConnector(t, connector)
		for _, tc := range cases {
			t.Run(connector+"/"+tc.command, func(t *testing.T) {
				if err := os.Chmod(homes, 0o700); err != nil {
					t.Fatal(err)
				}
				event := map[string]any{"session_id": "gap2544", "hook_event_name": "PreToolUse",
					"tool_name": "Bash", "cwd": project, "tool_input": map[string]any{"command": tc.command}}
				if connector == "codex" {
					event["turn_id"], event["tool_use_id"] = "t1", "tu-gap2544"
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
				blocked := resp["action"] == "block"
				if blocked != tc.block {
					t.Fatalf("blocked = %t, want %t: %.600s", blocked, tc.block, got)
				}
				if blocked && !strings.Contains(got, "tamper.detector_state_write") {
					t.Fatalf("blocked by another rule: %.600s", got)
				}
			})
		}
	}
}
