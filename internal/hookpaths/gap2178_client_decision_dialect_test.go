// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// rel-1-0-10:GAP-2178: the hook client carries its per-user decision
// (ActionDecisionKey) for a call the map cannot describe in full, so a
// managed gateway that cannot read the user's links still has the proof. On
// a Windows home the client read a Claude Code Bash call only without a
// dialect, while the per-user gateway reads it as Git Bash (DialectPOSIX):
// 300 touch operands ending in a hard-linked second name of the keys file
// carried the decision on Linux and none on Windows. The same rows run on
// every OS and must give the same answer: the second name of the keys file
// carries the decision, an ordinary file does not.
func TestGAP2178ClientDecisionKeepsTheHookDialectReading(t *testing.T) {
	home := t.TempDir()
	cwd := filepath.Join(home, "project")
	for _, dir := range []string{cwd, filepath.Join(home, ".ssh")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.WriteFile(keys, []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(cwd, "plain.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	// A hard link: a standard Windows account may make one.
	if err := os.Link(keys, filepath.Join(cwd, "output")); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	t.Setenv("USERPROFILE", home)
	operands := func(n int) string {
		words := make([]string, n)
		for i := range words {
			words[i] = fmt.Sprintf("h%04d", i)
		}
		return strings.Join(words, " ")
	}
	for _, row := range []struct {
		name, command string
		want          bool
	}{
		{"256 operands then the second name", "touch " + operands(256) + " output", true},
		{"300 operands then the second name", "touch " + operands(300) + " output", true},
		{"300 ordinary operands", "touch " + operands(300) + " plain.txt", false},
		{"1100 operands then the second name", "touch " + operands(1100) + " output", true},
		{"1100 ordinary operands", "touch " + operands(1100) + " plain.txt", false},
	} {
		body, err := json.Marshal(map[string]any{
			"hook_event_name": "PreToolUse", "cwd": cwd, "tool_name": "Bash",
			"tool_input": map[string]string{"command": row.command},
		})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(body))
		if !ok {
			t.Fatalf("%s: the client map does not decode", row.name)
		}
		if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != row.want {
			t.Errorf("%s: client protected-target decision = %v, want %v", row.name, got, row.want)
		}
	}
}
