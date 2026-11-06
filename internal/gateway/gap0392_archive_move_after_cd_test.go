// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-0392: a placed cd does not turn an absolute archive extraction and
// safe rename into an unbounded link write. A later write into that scope
// still keeps the conservative protected decision.
func TestGAP0392ArchiveMoveAfterCdFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	clean := filepath.Join(f.home, "clean")
	if err := os.MkdirAll(clean, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, "out.tgz"), []byte("fixture archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute). Its rows here alert.
	rows := []struct{ name, command, want string }{
		{"and-cd", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo done`, "allow"},
		{"semicolon-cd", `cd ~/clean; tar -xzf out.tgz -C /tmp; mv /tmp/src /tmp/src-old; echo done`, "allow"},
		{"redirected-cd", `cd ~/clean && tar -xzf out.tgz -C /tmp 2>/dev/null; mv /tmp/src /tmp/src-old 2>/dev/null; echo done`, "allow"},
		{"no-cd-control", `tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo done`, "allow"},
		{"scope-write-after-rename", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo x >> /tmp/src-old/authorized_keys`, "alert"},
		{"keys-link-write-after-rename", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo x >> ~/clean/keylink`, "alert"},
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(clean, "keylink")); err != nil {
		t.Fatal(err)
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
		calls = append(calls, everyMode("GAP0392/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}
