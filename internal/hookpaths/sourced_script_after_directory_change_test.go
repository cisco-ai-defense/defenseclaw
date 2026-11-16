// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestClientDecisionReadsTheScriptWhereTheDirectoryChangeLeavesTheShell: a
// script named after cd a && is the file of that name in a, not the file of
// that name in the folder the hook started in. Every spelling that passes a
// folder link and then .. is read as the system opens it from a. A decoy of
// the other kind at the starting spelling does not decide, and a sourced file
// before the call may have changed the folder, so the starting one is read
// too (rel-1-0-9:GAP-1038).
func TestClientDecisionReadsTheScriptWhereTheDirectoryChangeLeavesTheShell(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("the Windows API resolves .. before it follows a link")
	}
	_, home, project := r106KeysHome(t)
	writer := "echo marker >> $HOME/.ssh/authorized_keys\n"
	ordinary := "echo ordinary >> report.txt\n"
	for _, dir := range []string{
		filepath.Join(home, "chain", "live"), filepath.Join(home, "other", "live"), filepath.Join(project, "a"),
	} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for file, body := range map[string]string{
		filepath.Join(home, "chain", "ok.sh"): ordinary,
		filepath.Join(home, "chain", "wk.sh"): writer,
		filepath.Join(home, "other", "ok.sh"): writer,
		filepath.Join(home, "other", "wk.sh"): ordinary,
		filepath.Join(project, "ok.sh"):       writer,
		filepath.Join(project, "wk.sh"):       ordinary,
		filepath.Join(project, "a", "ok.sh"):  ordinary,
		filepath.Join(project, "a", "wk.sh"):  writer,
		filepath.Join(project, "noop.sh"):     ordinary,
	} {
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(filepath.Join(home, "other", "live"), filepath.Join(project, "portal")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	if err := os.Symlink(filepath.Join(home, "chain", "live"), filepath.Join(project, "a", "portal")); err != nil {
		t.Skipf("link unavailable: %v", err)
	}
	t.Setenv("HOME", home)
	for _, row := range []struct {
		command string
		block   bool
	}{
		{"cd a && source portal/../ok.sh", false},
		{"cd a && source portal/../wk.sh", true},
		{"cd a && . ./portal/../ok.sh", false},
		{"cd a && . ./portal/../wk.sh", true},
		{"cd a && source ok.sh", false},
		{"cd a && source wk.sh", true},
		{"cd a && bash portal/../ok.sh", false},
		{"cd a && bash portal/../wk.sh", true},
		{`bash -c "cd a && . ./portal/../ok.sh"`, false},
		{`bash -c "cd a && . ./portal/../wk.sh"`, true},
		// Without the change the starting folder decides.
		{"source portal/../ok.sh", true},
		{"source portal/../wk.sh", false},
		// A sourced file before the call may have changed the folder.
		{"source noop.sh && source portal/../ok.sh", true},
	} {
		payload, err := json.Marshal(map[string]any{"session_id": "c1013", "hook_event_name": "PreToolUse",
			"cwd": project, "tool_name": "Bash", "tool_input": map[string]any{"command": row.command}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok {
			t.Fatalf("%q: client header does not decode", row.command)
		}
		if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != row.block {
			t.Errorf("%s: client decision = %t, want %t", fmt.Sprintf("%q", row.command), got, row.block)
		}
	}
}
