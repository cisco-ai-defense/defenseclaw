// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// BenchmarkGAP0483ServeOperands times the per-user gateway answer to a benign
// touch of many operands next to the one of a short command. The gateway's
// cost must stay near the short call (GAP-0483): the hook client's round
// trip adds this to the agent's own wait.
func BenchmarkGAP0483ServeOperands(b *testing.B) {
	root := b.TempDir()
	f := b36ManagedHookFixture{homes: filepath.Join(root, "homes")}
	f.home = filepath.Join(f.homes, "alice")
	f.project = filepath.Join(f.home, "project")
	f.keys = filepath.Join(f.home, ".ssh", "authorized_keys")
	for _, dir := range []string{filepath.Dir(f.keys), f.project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			b.Fatal(err)
		}
	}
	if err := os.WriteFile(f.keys, []byte("# decoy\n"), 0o600); err != nil {
		b.Fatal(err)
	}
	b.Setenv("HOME", f.home)
	words := make([]string, 4000)
	for i := range words {
		words[i] = fmt.Sprintf("lo%d.txt", i)
	}
	for _, bc := range []struct{ name, command string }{
		{"echo", "echo hi"},
		{"touch-250", "touch " + strings.Join(words[:250], " ")},
		{"touch-500", "touch " + strings.Join(words[:500], " ")},
		{"touch-1000", "touch " + strings.Join(words[:1000], " ")},
		{"touch-2000", "touch " + strings.Join(words[:2000], " ")},
		{"touch-4000", "touch " + strings.Join(words, " ")},
	} {
		payload, err := json.Marshal(map[string]any{"session_id": "g483", "hook_event_name": "PreToolUse", "cwd": f.project,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_g483",
			"tool_input": map[string]any{"command": bc.command, "description": "bench"}})
		if err != nil {
			b.Fatal(err)
		}
		for _, connector := range []string{"claudecode", "codex"} {
			b.Run(connector+"/"+bc.name, func(b *testing.B) {
				call := &hookCall{name: bc.name, connector: connector, payload: payload}
				for b.Loop() {
					if v, _ := f.serve(call); v != "allow" {
						b.Fatalf("verdict %s", v)
					}
				}
			})
		}
	}
}
