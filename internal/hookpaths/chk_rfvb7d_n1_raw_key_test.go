// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"encoding/json"
	"os"
	"path/filepath"
	"testing"
)

// A dot-dot operand is keyed by its clean spelling and, for a managed gateway
// that keeps the step raw, by its raw spelling (rel-1-0-10:GAP-2294). A
// spelling written twice keeps the last answer under the clean key (a later
// writer overrides an early safe redirect); the raw key kept the first, so a
// gateway that cannot read the home asked by the raw spelling and got the
// earlier, weaker answer (CHK-RF-VB7D N1, found by code reading; none of
// these shapes reached it before the fix, so the test pins that both keys
// answer alike).
func TestRawDotDotKeyKeepsTheCleanKeyAnswer(t *testing.T) {
	root := t.TempDir()
	home := filepath.Join(root, "home")
	cwd := filepath.Join(home, "work")
	if err := os.MkdirAll(filepath.Join(cwd, "sub"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	if err := os.WriteFile(filepath.Join(cwd, "note.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	clean := filepath.Join(cwd, "note.txt")
	raw := cwd + "/sub/../note.txt"
	commands := []string{
		`echo hi > sub/../note.txt; ln -s "$V" lnk; echo more > sub/../note.txt`,
		`echo hi > sub/../note.txt; ln -s /opt/elsewhere note.txt; echo more > sub/../note.txt`,
		`echo hi > sub/../note.txt; ln -sf "$V" note.txt; cp src sub/../note.txt`,
		`echo hi > sub/../note.txt; tar -xf a.tar; cp src sub/../note.txt`,
		`echo hi > sub/../note.txt; ln -s "$V" "$W"; echo more > sub/../note.txt`,
		`echo hi > sub/../note.txt; cd "$V"; cd -; echo more > sub/../note.txt`,
	}
	listed := 0
	for _, command := range commands {
		payload, err := json.Marshal(map[string]any{"session_id": "s", "hook_event_name": "PreToolUse", "cwd": cwd,
			"tool_name": "Bash", "tool_input": map[string]any{"command": command}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(ResolveConnector("claudecode", "", "PreToolUse", payload))
		if !ok {
			t.Fatalf("%q: no target map", command)
		}
		rawAnswer, rawListed := targets[raw]
		cleanAnswer, cleanListed := targets[clean]
		if !rawListed || !cleanListed {
			continue
		}
		listed++
		if rawAnswer != cleanAnswer {
			t.Errorf("%q: raw key answers %q, clean key %q", command, rawAnswer, cleanAnswer)
		}
	}
	if listed == 0 {
		t.Fatal("no command listed both spellings")
	}
}
