// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A literal project destination remains known after a print, inside a
// function, and when passed to a nested shell. Each protected twin names
// the actual authorized-keys file from the same link-free project.
func TestGAP0507KnownCopyDestinationFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	f.project = filepath.Join(f.home, "clean")
	if err := os.MkdirAll(filepath.Join(f.project, "ordinary"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command, want string }{
		{"plain-copy", `f=ordinary/n2; cp a.txt $f`, "allow"},
		{"plain-copy-keys", `f=../.ssh/authorized_keys; cp a.txt $f`, "block"},
		{"for-loop", `for f in ordinary/n2; do cp a.txt $f; done`, "allow"},
		{"for-loop-keys", `for f in ../.ssh/authorized_keys; do cp a.txt $f; done`, "block"},
		{"printf-redirect", `f=ordinary/n2; printf %s hello > ordinary/n3; cp a.txt $f`, "allow"},
		{"printf-redirect-keys", `f=../.ssh/authorized_keys; printf %s hello > ordinary/n3; cp a.txt $f`, "block"},
		{"printf", `f=ordinary/n2; printf %s hello; cp a.txt $f`, "allow"},
		{"printf-keys", `f=../.ssh/authorized_keys; printf %s hello; cp a.txt $f`, "block"},
		{"function-body", `g() { cp a.txt $f; }; f=ordinary/n2; g`, "allow"},
		{"function-body-keys", `g() { cp a.txt $f; }; f=../.ssh/authorized_keys; g`, "block"},
		{"function-after-assignment", `f=ordinary/n2; g() { cp a.txt $f; }; g`, "allow"},
		{"function-after-assignment-keys", `f=../.ssh/authorized_keys; g() { cp a.txt $f; }; g`, "block"},
		{"env-bash-c", `f=ordinary/n2 bash -c "cp a.txt \$f"`, "allow"},
		{"env-bash-c-keys", `f=../.ssh/authorized_keys bash -c "cp a.txt \$f"`, "block"},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("GAP0507/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/4].want
		t.Logf("GAP0507ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || strings.TrimSpace(string(data)) != "# decoy" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

// The destination can also be a project link to the real keys file. The
// managed gateway must retain the hook client's resolved target in each form.
func TestGAP0507LinkedKeysDestinationFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("source\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command string }{
		{"printf-redirect", `f=keylink; printf %s hello > ordinary/n3; cp a.txt $f`},
		{"printf", `f=keylink; printf %s hello; cp a.txt $f`},
		{"function-body", `g() { cp a.txt $f; }; f=keylink; g`},
		{"function-after-assignment", `f=keylink; g() { cp a.txt $f; }; g`},
		{"env-bash-c", `f=keylink bash -c "cp a.txt \$f"`},
	}
	var payloads [][]byte
	for _, row := range rows {
		payloads = append(payloads, f.payload(t, row.command))
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		calls = append(calls, everyMode("GAP0507/link/"+row.name, payloads[i], headers[i])...)
	}
	f.answerAll(t, calls)
	for _, call := range calls {
		t.Logf("GAP0507LINKROW %s | %s | want block", call.name, call.verdict)
		if call.verdict != "block" {
			t.Errorf("%s: verdict %s, want block; body %.200s", call.name, call.verdict, call.body)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || strings.TrimSpace(string(data)) != "# decoy" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}
