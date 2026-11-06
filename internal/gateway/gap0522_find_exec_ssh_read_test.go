// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"testing"
)

// A find child that only reads SSH files has the same action-mode verdict as
// the corresponding direct reader. Children that can write authorized_keys
// retain the protected verdict, including a shell child and later actions.
func TestGAP0522FindExecSSHReadersFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute). Its rows here alert.
	rows := []struct{ name, command, want string }{
		{"plain-find", `find ~/.ssh -maxdepth 1 -type f`, "allow"},
		{"reported-exec-ls-plus", `find ~/.ssh -maxdepth 1 -type f -exec ls -l {} +`, "allow"},
		{"exec-ls-semicolon", `find ~/.ssh -maxdepth 1 -type f -exec ls -l {} \;`, "allow"},
		{"execdir-stat-plus", `find ~/.ssh -maxdepth 1 -type f -execdir stat {} +`, "allow"},
		{"ok-cat-semicolon", `find ~/.ssh -maxdepth 1 -type f -ok cat {} \;`, "allow"},
		{"okdir-wc-semicolon", `find ~/.ssh -maxdepth 1 -type f -okdir wc -l {} \;`, "allow"},
		{"exec-head-plus", `find ~/.ssh -maxdepth 1 -type f -exec head -n 1 {} +`, "allow"},
		{"exec-ls-and-print", `find ~/.ssh -maxdepth 1 -type f -exec ls -l {} + -print`, "allow"},
		{"exec-copy-keys", `find ~/.ssh -maxdepth 1 -type f -exec cp {} ~/.ssh/authorized_keys \;`, "alert"},
		{"exec-shell-append-keys", `find ~/.ssh -maxdepth 1 -type f -exec sh -c 'printf key >> "$HOME/.ssh/authorized_keys"' _ {} \;`, "alert"},
		{"execdir-copy-keys", `find ~/.ssh -maxdepth 1 -type f -execdir cp /dev/null ~/.ssh/authorized_keys \;`, "alert"},
		{"ok-shell-append-keys", `find ~/.ssh -maxdepth 1 -type f -ok sh -c 'printf key >> "$HOME/.ssh/authorized_keys"' _ {} \;`, "alert"},
		{"exec-copy-found-keys", `find ~/.ssh/authorized_keys -exec cp /dev/null {} \;`, "alert"},
		{"exec-shell-append-found-keys", `find ~/.ssh/authorized_keys -exec sh -c 'printf key >> "$1"' _ {} \;`, "alert"},
		{"exec-reader-then-copy", `find ~/.ssh -maxdepth 1 -type f -exec ls -l {} \; -exec cp {} ~/.ssh/authorized_keys \;`, "alert"},
		{"exec-reader-then-delete", `find ~/.ssh -maxdepth 1 -type f -exec ls -l {} \; -delete`, "alert"},
		{"exec-reader-then-fprint", `find ~/.ssh -maxdepth 1 -type f -exec ls -l {} \; -fprint ~/.ssh/authorized_keys`, "alert"},
		{"exec-reader-redirect-keys", `find ~/.ssh -maxdepth 1 -type f -exec ls -l {} + > ~/.ssh/authorized_keys`, "alert"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("GAP0522/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		t.Logf("CF522ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if contents, err := os.ReadFile(f.keys); err != nil || string(contents) != "# decoy\n" {
		t.Fatalf("keys fixture changed: %q, %v", contents, err)
	}
}
