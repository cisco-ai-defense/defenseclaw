// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// The two projects have the same ordinary files. Only linked has write
// destinations reaching the decoy keys file; managed calls cannot search
// either project and must use the user-side hook reading.
func TestGAP0373And0374FourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	projects := map[string]string{"ordinary": filepath.Join(f.home, "clean"), "protected": filepath.Join(f.home, "linked")}
	for _, dir := range projects {
		for _, sub := range []string{"build", "build/sub", "copy", "src"} {
			if err := os.MkdirAll(filepath.Join(dir, sub), 0o700); err != nil {
				t.Fatal(err)
			}
		}
		for _, name := range []string{"a.txt", "b.txt", "README.md", "authorized_keys"} {
			if err := os.WriteFile(filepath.Join(dir, name), []byte("x\n"), 0o600); err != nil {
				t.Fatal(err)
			}
		}
	}
	linked := projects["protected"]
	for name, target := range map[string]string{
		"build/opt1.cfg": "../../.ssh/authorized_keys",
		"out.debug":      "../.ssh/authorized_keys",
		"a.txt.bak":      "../.ssh/authorized_keys",
		"build/a.o":      "../../.ssh/authorized_keys",
		"copy/a.txt":     "../../.ssh/authorized_keys",
	} {
		if err := os.Symlink(target, filepath.Join(linked, name)); err != nil {
			t.Fatal(err)
		}
	}
	multiline := "set -e\nBUILD=build\nif [ \"$1\" = clean ]; then\n  rm -rf \"$BUILD\"\nfi\nmkdir -p \"$BUILD\"\nfor src in *.txt; do\n  obj=\"$BUILD/${src%.txt}.o\"\n  cp \"$src\" \"$obj\"\n  echo \"$obj\" >> \"$BUILD/manifest\"\ndone\nLOG=\"$BUILD/build.log\"\ncase \"$MODE\" in\n  ci) LOG=\"$BUILD/ci.log\" ;;\nesac\ndate > \"$LOG\""
	rows := []struct{ name, project, command, want string }{
		{"GAP0373/glob-backup", "ordinary", `for f in *.txt; do out=$f.bak; cp "$f" "$out"; echo "$out" >> backups.list; done`, "allow"},
		// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
		{"GAP0373/glob-backup-link", "protected", `for f in *.txt; do out=$f.bak; cp "$f" "$out"; echo "$out" >> backups.list; done`, "alert"},
		{"GAP0374/multiline-build", "ordinary", multiline, "allow"},
		{"GAP0374/multiline-build-link", "protected", multiline, "alert"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, mustJSON(t, map[string]any{"session_id": "b36", "hook_event_name": "PreToolUse", "cwd": projects[row.project],
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
		call.verdict = r106AlertVerdict(call.verdict)
		want := rows[i/4].want
		t.Logf("FBROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}

// Changing Bash's glob options before the loop can add hidden files to the
// expansion. The bounded copy proof must leave those commands conservative.
func TestGAP0373GlobOptionChangeKeepsProtectedTwin(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{".secret.txt", "SECRET.TXT"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
		if err := os.Symlink("../.ssh/authorized_keys", filepath.Join(f.project, name+".bak")); err != nil {
			t.Fatal(err)
		}
	}
	commands := []string{
		`shopt -s nocaseglob; for f in *.txt; do out=$f.bak; cp "$f" "$out"; done`,
		`GLOBIGNORE=ignore; for f in *.txt; do out=$f.bak; cp "$f" "$out"; done`,
	}
	var calls []*hookCall
	for _, command := range commands {
		payload := f.payload(t, command)
		calls = append(calls, everyMode("GAP0373/glob-option", payload, f.clientHeader(t, payload))...)
	}
	f.answerAll(t, calls)
	for _, call := range calls {
		// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
		if call.verdict = r106AlertVerdict(call.verdict); call.verdict != "alert" {
			t.Errorf("%s: verdict %s, want alert; body %.200s", call.name, call.verdict, call.body)
		}
	}
}
