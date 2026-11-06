// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// TestManagedWriteTargetTheHookCannotResolveIsNamedAsUnresolved: from a
// working folder the user cannot enter (in the home or outside it), the
// managed hook client cannot stat an ordinary write target and sends an
// empty answer for it. A managed gateway that still fails closed names the
// block as a target that could not be resolved, not as an SSH authorized
// keys mutation; a write that names the keys file from the same folder keeps
// the block and the SSH rule title (rel-1-0-2:GAP-0690).
func TestManagedWriteTargetTheHookCannotResolveIsNamedAsUnresolved(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	inHome := filepath.Join(f.project, "locked")
	outside := filepath.Join(filepath.Dir(f.homes), "locked")
	for _, dir := range []string{inHome, outside} {
		if err := os.Mkdir(dir, 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.Chmod(dir, 0); err != nil {
			t.Fatal(err)
		}
	}
	t.Cleanup(func() {
		_ = os.Chmod(f.homes, 0o700)
		_ = os.Chmod(inHome, 0o700)
		_ = os.Chmod(outside, 0o700)
	})
	const keysTitle = "SSH authorized keys mutation"
	blocked := 0
	for _, cwd := range []string{inHome, outside} {
		for _, row := range []struct {
			name, command string
			unresolved    bool
		}{
			{"redirect", "echo hi > notes.txt", true},
			{"tee", "echo hi | tee notes2.txt", true},
			{"redirect onto the keys file", "echo hi >> ~/.ssh/authorized_keys", false},
		} {
			payload := mustJSON(t, map[string]any{"session_id": "gap0690", "hook_event_name": "PreToolUse", "cwd": cwd,
				"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_gap0690",
				"tool_input": map[string]any{"command": row.command, "description": "Run test fixture command"}})
			header := f.clientHeader(t, payload)
			for _, connector := range []string{"claudecode", "codex"} {
				if err := os.Chmod(f.homes, 0); err != nil {
					t.Fatal(err)
				}
				verdict, body := f.serve(&hookCall{connector: connector, payload: payload, header: header, managed: true})
				if err := os.Chmod(f.homes, 0o700); err != nil {
					t.Fatal(err)
				}
				where := "in the home"
				if cwd == outside {
					where = "outside the home"
				}
				named := strings.Contains(body, unresolvedWriteTargetTitle)
				keys := strings.Contains(body, keysTitle)
				switch {
				case !row.unresolved && (verdict != "block" || named || !keys):
					t.Errorf("%s %s %s: %s, unresolved title %v, keys title %v, want a block named %q: %.300s", connector, where, row.name, verdict, named, keys, keysTitle, body)
				case row.unresolved && verdict == "block" && (!named || keys):
					t.Errorf("%s %s %s: block with unresolved title %v, keys title %v, want it named as unresolved: %.300s", connector, where, row.name, named, keys, body)
				case row.unresolved && verdict == "block":
					blocked++
				case row.unresolved && verdict != "allow":
					t.Errorf("%s %s %s: %s", connector, where, row.name, verdict)
				}
			}
		}
	}
	if blocked == 0 {
		t.Fatal("no unresolved write failed closed: the fixture does not reach the empty client answer")
	}
}
