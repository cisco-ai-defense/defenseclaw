// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

func TestGAP0375VariableHeldLoopAndGAP0395VersionOnlyUnzipFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	clean := filepath.Join(f.home, "clean")
	if err := os.MkdirAll(filepath.Join(clean, "build"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(clean, "keylink")); err != nil {
		t.Fatal(err)
	}
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
	rows := []struct{ name, command, want string }{
		{"GAP0375/forvar", `f=a.txt; for x in $f; do cp $x build/; done; echo hi > report.txt`, "allow"},
		{"GAP0375/forvar-cd", `cd ~/clean && f=a.txt; for x in $f; do cp $x build/; done; echo hi > report.txt`, "allow"},
		{"GAP0375/literal-control", `cd ~/clean && for x in a.txt; do cp $x build/; done; echo hi > report.txt`, "allow"},
		{"GAP0375/protected-variable-destination", `f=keylink; for x in $f; do cp a.txt $x; done; echo hi > report.txt`, "alert"},
		{"GAP0375/protected-variable-destination-cd", `cd ~/clean && f=keylink; for x in $f; do cp a.txt $x; done; echo hi > report.txt`, "alert"},
		{"GAP0395/unzip-version-cd", `cd ~/clean && unzip -v >/dev/null 2>&1; cp a.txt build/ && echo ok`, "allow"},
		{"GAP0395/unzip-version", `unzip -v >/dev/null 2>&1; cp a.txt build/ && echo ok`, "allow"},
		{"GAP0395/unzip-version-protected", `unzip -v >/dev/null 2>&1; cp a.txt keylink && echo ok`, "alert"},
		{"GAP0395/unzip-list-archive", `unzip -v x.zip; cp a.txt build/`, "allow"},
		{"GAP0395/unzip-list-archive-protected", `unzip -v x.zip; cp a.txt keylink`, "alert"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": clean,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
			"tool_input": map[string]any{"command": row.command, "description": "Run test fixture command"}}))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode(row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}
