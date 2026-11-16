// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// A managed gateway cannot search the user's home. Its hook-client reading
// must keep the protected link result for each variable source that the
// per-user gateway finds. The ordinary twin of every command remains allowed.
func TestGAP0356VariableSourcesFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"a.txt", "out.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	forms := []struct{ name, command string }{
		{"for-var", `f=a.txt; for f in keylink; do :; done; echo m >> "$f"`},
		{"funcdef-before", `setf() { f=keylink; }; f=a.txt; setf; echo m >> "$f"`},
		{"funcdef-after", `f=a.txt; setf() { f=keylink; }; setf; echo m >> "$f"`},
		{"env-prefix", `f=keylink; f=a.txt true; echo m >> "$f"`},
		{"nameref", `g=keylink; declare -n f=g; echo m >> "$f"`},
		{"trap", `trap "f=keylink" DEBUG; f=a.txt; echo m >> "$f"`},
		{"command-eval", `f=a.txt; command eval f=keylink; echo m >> "$f"`},
		{"builtin-eval", `f=a.txt; builtin eval f=keylink; echo m >> "$f"`},
		{"eval-dynamic", `g=keylink; f=a.txt; eval f=; echo m >> "$f"`},
		{"assign-default", `f=; : "${f:=keylink}"; echo m >> "$f"`},
		{"group-redirect", `f=a.txt; { f=keylink; echo m >> "$f"; }`},
		{"install", `f=keylink; install -m 600 a.txt "$f"`},
		{"rsync", `f=keylink; rsync a.txt "$f"`},
	}
	var payloads [][]byte
	var names, wants []string
	for _, form := range forms {
		for _, kind := range []string{"protected", "benign"} {
			command, want := form.command, "block"
			if kind == "benign" {
				command, want = strings.ReplaceAll(command, "keylink", "out.txt"), "allow"
			}
			payloads = append(payloads, f.payload(t, command))
			names = append(names, form.name+"/"+kind)
			wants = append(wants, want)
		}
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, payload := range payloads {
		calls = append(calls, everyMode(names[i], payload, headers[i])...)
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := wants[i/4]
		t.Logf("GAP0356ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}
