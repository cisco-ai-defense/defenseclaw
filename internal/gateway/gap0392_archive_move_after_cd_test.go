// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-0392: a placed cd does not turn an absolute archive extraction and
// safe rename into an unbounded link write. A later write into that scope
// still keeps the conservative protected decision.
//
// The extraction goes to an absolute staging folder of its own, not /tmp:
// with TMPDIR=/tmp (a CI runner) the fixture home and its ~/.defenseclaw
// are under /tmp, and an archive that cannot be listed extracted into a
// folder that holds the state is a possible state write, the HIGH alert of
// the default packs (rel-1-0-10:GAP-1173, GAP-0747), which is not what this
// test is about.
func TestGAP0392ArchiveMoveAfterCdFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	stage := t.TempDir()
	clean := filepath.Join(f.home, "clean")
	if err := os.MkdirAll(clean, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(clean, "out.tgz"), []byte("fixture archive"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"and-cd", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo done`, "allow"},
		{"semicolon-cd", `cd ~/clean; tar -xzf out.tgz -C /tmp; mv /tmp/src /tmp/src-old; echo done`, "allow"},
		{"redirected-cd", `cd ~/clean && tar -xzf out.tgz -C /tmp 2>/dev/null; mv /tmp/src /tmp/src-old 2>/dev/null; echo done`, "allow"},
		{"no-cd-control", `tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo done`, "allow"},
		{"scope-write-after-rename", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo x >> /tmp/src-old/authorized_keys`, "block"},
		{"keys-link-write-after-rename", `cd ~/clean && tar -xzf out.tgz -C /tmp && mv /tmp/src /tmp/src-old && echo x >> ~/clean/keylink`, "block"},
	}
	if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(clean, "keylink")); err != nil {
		t.Fatal(err)
	}
	var payloads [][]byte
	for _, row := range rows {
		command := strings.ReplaceAll(row.command, "/tmp", stage)
		payloads = append(payloads, mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": clean,
			"permission_mode": "default", "tool_name": "Bash", "tool_use_id": "toolu_b36",
			"tool_input": map[string]any{"command": command, "description": "Run test fixture command"}}))
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
