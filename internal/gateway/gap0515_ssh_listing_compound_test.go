// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
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
		{"long-listing-semicolon-echo", `ls -la ~/.ssh; echo done`, "allow"},
		{"home-variable-semicolon-pwd", `ls "$HOME/.ssh"; pwd`, "allow"},
		{"absolute-home-semicolon-pwd", `ls ` + ssh + `; pwd`, "allow"},
		{"absolute-home-and-echo", `ls ` + ssh + ` && echo done`, "allow"},
		{"semicolon-keys-write", `ls ~/.ssh; echo marker >> ~/.ssh/authorized_keys`, "block"},
		{"and-keys-write", `ls ~/.ssh && echo marker >> ~/.ssh/authorized_keys`, "block"},
		{"semicolon-pwd-keys-write", `ls ~/.ssh; pwd > ~/.ssh/authorized_keys`, "block"},
		{"and-pwd-keys-write", `ls ~/.ssh && pwd > ~/.ssh/authorized_keys`, "block"},
		{"semicolon-keys-copy", `ls ~/.ssh; cp keylink ~/.ssh/authorized_keys`, "block"},
		{"and-keys-copy", `ls ~/.ssh && cp keylink ~/.ssh/authorized_keys`, "block"},
		{"absolute-home-keys-write", `ls ` + ssh + `; echo marker >> ` + ssh + `/authorized_keys`, "block"},
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
		t.Logf("CF515ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if contents, err := os.ReadFile(f.keys); err != nil || string(contents) != "# decoy\n" {
		t.Fatalf("keys fixture changed: %q, %v", contents, err)
	}
}
