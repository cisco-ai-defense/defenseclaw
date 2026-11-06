// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A listing of the SSH directory is read-only even when a later statement
// prints a fixed marker or the working directory. A later write to the keys
// file in the same compound command must still be denied.
func TestGAP0515SSHListingCompoundFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	ssh := filepath.ToSlash(filepath.Join(f.home, ".ssh"))
	rows := []struct{ name, command, want string }{
		{"single-listing", `ls ~/.ssh`, "allow"},
		{"semicolon-echo", `ls ~/.ssh; echo done`, "allow"},
		{"and-echo", `ls ~/.ssh && echo done`, "allow"},
		{"semicolon-pwd", `ls ~/.ssh; pwd`, "allow"},
		{"and-pwd", `ls ~/.ssh && pwd`, "allow"},
		{"three-semicolon", `ls ~/.ssh; pwd; echo done`, "allow"},
		{"read-then-pwd", `ls ~/.ssh; stat .; pwd`, "allow"},
		{"three-and", `ls ~/.ssh && pwd && echo done`, "allow"},
		{"echo-then-pwd", `ls ~/.ssh; echo done; pwd`, "allow"},
		{"pwd-physical", `ls -la ~/.ssh; pwd -P`, "allow"},
		{"pwd-discard", `ls ~/.ssh; pwd > /dev/null`, "allow"},
		{"pwd-or", `ls ~/.ssh || pwd`, "allow"},
		{"long-listing-semicolon-echo", `ls -la ~/.ssh; echo done`, "allow"},
		{"home-variable-semicolon-pwd", `ls "$HOME/.ssh"; pwd`, "allow"},
		{"absolute-home-semicolon-pwd", `ls ` + ssh + `; pwd`, "allow"},
		{"absolute-home-and-echo", `ls ` + ssh + ` && echo done`, "allow"},
		// rel-1-0-6:GAP-0675 (owner 2026-11-06): the default profile alerts on a shell-command protected-file write; strict blocks it (TestGAP0675ShellProtectedFileWarnsOutsideStrictOnEveryRoute).
		{"semicolon-keys-write", `ls ~/.ssh; echo marker >> ~/.ssh/authorized_keys`, "alert"},
		{"and-keys-write", `ls ~/.ssh && echo marker >> ~/.ssh/authorized_keys`, "alert"},
		{"semicolon-pwd-keys-write", `ls ~/.ssh; pwd > ~/.ssh/authorized_keys`, "alert"},
		{"and-pwd-keys-write", `ls ~/.ssh && pwd > ~/.ssh/authorized_keys`, "alert"},
		{"three-statement-keys-write", `ls ~/.ssh; pwd; echo marker >> ~/.ssh/authorized_keys`, "alert"},
		{"read-then-keys-write", `ls ~/.ssh; stat .; pwd > ~/.ssh/authorized_keys`, "alert"},
		{"semicolon-keys-copy", `ls ~/.ssh; cp keylink ~/.ssh/authorized_keys`, "alert"},
		{"and-keys-copy", `ls ~/.ssh && cp keylink ~/.ssh/authorized_keys`, "alert"},
		{"absolute-home-keys-write", `ls ` + ssh + `; echo marker >> ` + ssh + `/authorized_keys`, "alert"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode(row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		if strings.HasPrefix(call.body, `{"action":"alert"`) {
			call.verdict = "alert" // rel-1-0-6:GAP-0675
		}
		t.Logf("CF515ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if contents, err := os.ReadFile(f.keys); err != nil || string(contents) != "# decoy\n" {
		t.Fatalf("keys fixture changed: %q, %v", contents, err)
	}
}
