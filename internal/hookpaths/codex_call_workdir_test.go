// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

func rolloutLine(t *testing.T, id, workdir string) []byte {
	t.Helper()
	arguments, _ := json.Marshal(map[string]any{"cmd": "true", "workdir": workdir})
	line, err := json.Marshal(map[string]any{"type": "response_item", "payload": map[string]any{
		"type": "function_call", "name": "exec_command", "arguments": string(arguments), "call_id": id,
	}})
	if err != nil {
		t.Fatal(err)
	}
	return append(line, '\n')
}

// The workdir of a Codex shell call is read from the call in the session
// rollout, only from a regular rollout file inside the home, and only for the
// call the hook names.
func TestCodexRolloutCallWorkdir(t *testing.T) {
	home := t.TempDir()
	sessions := filepath.Join(home, ".codex", "sessions")
	if err := os.MkdirAll(sessions, 0o700); err != nil {
		t.Fatal(err)
	}
	rollout := filepath.Join(sessions, "rollout-2026-11-09T00-00-00-x.jsonl")
	content := append(rolloutLine(t, "call_a", "/etc"), rolloutLine(t, "call_b", "")...)
	if err := os.WriteFile(rollout, content, 0o600); err != nil {
		t.Fatal(err)
	}
	outside := filepath.Join(t.TempDir(), "rollout-2026-11-09T00-00-00-y.jsonl")
	if err := os.WriteFile(outside, rolloutLine(t, "call_a", "/etc"), 0o600); err != nil {
		t.Fatal(err)
	}
	linked := filepath.Join(sessions, "rollout-2026-11-09T00-00-00-link.jsonl")
	if err := os.Symlink(rollout, linked); err != nil {
		t.Skipf("no symlinks: %v", err)
	}
	notRollout := filepath.Join(sessions, "notes.jsonl")
	if err := os.WriteFile(notRollout, rolloutLine(t, "call_a", "/etc"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, transcript, id, want string
	}{
		{"the call named", rollout, "call_a", "/etc"},
		{"a call without a workdir", rollout, "call_b", ""},
		{"another call", rollout, "call_c", ""},
		{"a rollout outside the home", outside, "call_a", ""},
		{"a file that is no rollout", notRollout, "call_a", ""},
		{"a link to a rollout", linked, "call_a", ""},
		{"a relative transcript path", "rollout-x.jsonl", "call_a", ""},
		{"an id that breaks the marker", rollout, "call_a\"", ""},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			if got := CodexRolloutCallWorkdir(home, row.transcript, row.id); got != row.want {
				t.Fatalf("workdir = %q, want %q", got, row.want)
			}
		})
	}
}
