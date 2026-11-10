// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"encoding/json"
	"fmt"
	"os"
	"path/filepath"
	"testing"
)

// TestClientDecisionReadsTheScriptOfAShellWrapperWhereTheDirectoryChangeLeavesTheShell:
// the script a shell -c body names after cd a && is the file of that name in
// a, for the hook client header (the decision) and for the readers of the
// write targets, whatever launcher stands before the body
// (rel-1-0-9:GAP-1038).
func TestClientDecisionReadsTheScriptOfAShellWrapperWhereTheDirectoryChangeLeavesTheShell(t *testing.T) {
	_, home, project := r106KeysHome(t)
	a := filepath.Join(project, "a")
	if err := os.MkdirAll(a, 0o700); err != nil {
		t.Fatal(err)
	}
	writer := "echo marker >> $HOME/.ssh/authorized_keys\n"
	ordinary := "echo ordinary >> report.txt\n"
	for file, body := range map[string]string{
		filepath.Join(project, "ok.sh"): writer,
		filepath.Join(project, "wk.sh"): ordinary,
		filepath.Join(a, "ok.sh"):       ordinary,
		filepath.Join(a, "wk.sh"):       writer,
	} {
		if err := os.WriteFile(file, []byte(body), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	type row struct {
		line  string
		block bool
	}
	var rows []row
	for _, shape := range []string{
		`cd a && bash -c "source %s"`,
		`cd a && sh -c ". ./%s"`,
		`cd a && env X=1 bash -c "source %s"`,
		`cd a && bash -lc "source %s"`,
		`cd a && nice bash -c "source %s"`,
		`cd a && bash -c "bash %s"`,
		`(cd a && bash -c "source %s")`,
	} {
		for _, name := range []string{"ok.sh", "wk.sh"} {
			rows = append(rows, row{fmt.Sprintf(shape, name), name == "wk.sh"})
		}
	}
	rows = append(rows,
		row{`cd a && cd .. && bash -c "source wk.sh"`, false},
		row{`cd a && cd .. && bash -c "source ok.sh"`, true},
		row{`bash -c "source ok.sh"`, true},
		row{`bash -c "source wk.sh"`, false},
	)
	for _, r := range rows {
		payload, err := json.Marshal(map[string]any{"session_id": "wrapper-after-cd", "hook_event_name": "PreToolUse",
			"cwd": project, "tool_name": "Bash", "tool_input": map[string]any{"command": r.line}})
		if err != nil {
			t.Fatal(err)
		}
		targets, ok := Decode(Resolve(payload))
		if !ok {
			t.Fatal("client header does not decode")
		}
		if got := targets[ActionDecisionKey] == ProtectedTargetDecision; got != r.block {
			t.Errorf("%q: client decision protected = %t, want %t", r.line, got, r.block)
		}
		writes := false
		for _, operand := range LiteralWriteOperands(r.line, project, home) {
			writes = writes || samePathName(operand, filepath.Join(home, ".ssh", "authorized_keys"))
		}
		if writes != r.block {
			t.Errorf("%q: literal write operands reach the keys file = %t, want %t", r.line, writes, r.block)
		}
		if unproven := UnprovenProtectedWrite(r.line, project, home); unproven != "" && !r.block {
			t.Errorf("%q: unproven write %q for an ordinary script", r.line, unproven)
		}
	}
}
