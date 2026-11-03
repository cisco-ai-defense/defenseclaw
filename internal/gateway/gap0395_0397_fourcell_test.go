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
func TestGAP0395And0397FourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	projects := map[string]string{"ordinary": filepath.Join(f.home, "clean"), "protected": filepath.Join(f.home, "linked")}
	for _, dir := range projects {
		for _, sub := range []string{"build", "build/sub", "copy", "src", "out"} {
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
		"build/a.txt":    "../../.ssh/authorized_keys",
		"out/a.txt":      "../../.ssh/authorized_keys",
		"copy/a.txt":     "../../.ssh/authorized_keys",
	} {
		if err := os.Symlink(target, filepath.Join(linked, name)); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct{ name, project, command, want string }{
		{"GAP0396/source-glob-build", "ordinary", `cp *.txt build/`, "allow"},
		{"GAP0396/source-glob-build-link", "protected", `cp *.txt build/`, "block"},
		{"GAP0396/source-glob-out", "ordinary", `cp *.txt out/`, "allow"},
		{"GAP0396/source-glob-out-link", "protected", `cp *.txt out/`, "block"},
		{"GAP0397/copy-file-in-folder", "ordinary", `for f in a.txt b.txt; do cp $f copy/$f; done; echo done > report.txt`, "allow"},
		{"GAP0397/copy-file-in-folder-link", "protected", `for f in a.txt b.txt; do cp $f copy/$f; done; echo done > report.txt`, "block"},
		{"GAP0395/P06-find-exec-mv", "ordinary", `cd ~/clean && find . -name '*.txt' -exec mv {} build/ \;`, "allow"},
		{"GAP0395/P06-find-exec-mv-link", "protected", `cd ~/linked && find . -name authorized_keys -exec mv {} ../.ssh/ \;`, "block"},
		{"GAP0395/P07-name-mkdir", "ordinary", `cd ~/clean && NAME=release; mkdir -p $NAME && cp README.md $NAME/ && tar -czf $NAME.tgz $NAME`, "allow"},
		{"GAP0395/P07-name-mkdir-link", "protected", `cd ~/linked && NAME=../.ssh; mkdir -p $NAME && cp authorized_keys $NAME/ && tar -czf $NAME.tgz $NAME`, "block"},
		{"GAP0395/P17-D-build-sub", "ordinary", `cd ~/clean && D=build/sub; mkdir -p $D; cp a.txt $D; cp b.txt "$D/"`, "allow"},
		{"GAP0395/P17-D-build-sub-link", "protected", `cd ~/linked && D=../.ssh; mkdir -p $D; cp authorized_keys $D; cp b.txt "$D/"`, "block"},
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
		want := rows[i/4].want
		t.Logf("FBROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
}

// IFS can turn the loop's unquoted source and destination into more argv
// words, whether inherited or assigned earlier. The last word may name the
// keys directory link.
func TestGAP0397ChangedIFSKeepsProtectedCopy(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.MkdirAll(filepath.Join(f.project, "copy"), 0o700); err != nil {
		t.Fatal(err)
	}
	for _, name := range []string{"a", "a.txt", "authorized_keys", "authorized_keys.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("replacement\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink("../.ssh", filepath.Join(f.project, "txt")); err != nil {
		t.Fatal(err)
	}
	if err := os.Symlink("authorized_keys", filepath.Join(f.home, ".ssh", "a")); err != nil {
		t.Fatal(err)
	}
	var calls []*hookCall
	for _, command := range []string{
		`IFS=.; for f in authorized_keys.txt; do cp $f copy/$f; done`,
		`IFS=.; for f in a.txt; do cp $f copy/$f; done`,
		`for f in a.txt; do cp $f copy/$f; done`,
	} {
		payload := f.payload(t, command)
		calls = append(calls, everyMode("GAP0397/changed-IFS", payload, f.clientHeader(t, payload))...)
	}
	f.answerAll(t, calls)
	for _, call := range calls {
		if call.verdict != "block" {
			t.Errorf("%s: verdict %s, want block; body %.200s", call.name, call.verdict, call.body)
		}
	}
}
