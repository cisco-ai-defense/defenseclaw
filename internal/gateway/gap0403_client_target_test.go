// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// gap0403Rows are the GAP-0403 rows: an ordinary write after a protected name went dead.
var gap0403Rows = []struct{ name, command string }{
	{"fourth-statement", `f=keylink; f=a.txt; echo m >> "$f"; echo done`},
	{"printf", `f=keylink; f=a.txt; printf m >> "$f"`},
	{"cat", `f=keylink; f=a.txt; cat b.txt >> "$f"`},
	{"echo-param", `f=keylink; f=a.txt; echo "$f" >> "$f"`},
	{"dot-suffix", `f=keylink; f=a.txt; echo m >> "$f.log"`},
	{"extra-assignment", `f=keylink; f=a.txt; g=b.txt; echo m >> "$f"`},
	{"for-prefix", `for f in keylink; do :; done; f=a.txt; echo m >> "$f"`},
	{"install", `f=keylink; f=a.txt; install -m 644 b.txt "$f"`},
	{"rsync", `f=keylink; f=a.txt; rsync b.txt "$f"`},
	{"leading-cd", `cd ~/project && f=keylink; f=a.txt; echo m >> "$f"`},
	{"if-writer", `f=keylink; f=a.txt; if true; then echo m >> "$f"; fi`},
	{"append-assign", `f=keylink; f+=x; echo m >> "$f"`},
	{"echo-cmdsub", `f=keylink; f=a.txt; echo $(echo m) >> "$f"`},
	{"two-words", `f=$(echo keylink x); echo m >> "$f"`},
	{"if-noop", `f=keylink; if [ -n "$X" ]; then :; fi; f=a.txt; echo m >> "$f"`},
}

// rel-1-0-6:GAP-0403: each command is an ordinary write. The earlier
// protected name is dead at the write target. Per-user blocks on these rows
// precede this branch; the regression was carrying them into managed cells.
func TestGAP0403DeadValuesStayAllowedWithProtectHome(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"a.txt", "b.txt"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := gap0403Rows
	for _, row := range rows {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode("GAP0403/"+row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("GAP0403ROW %s | %s | want allow", call.name, call.verdict)
			if call.managed && call.verdict != "allow" {
				t.Errorf("%s: verdict %s, want allow; body %.200s", call.name, call.verdict, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

// A later assignment in the same compound statement cannot erase a write
// that ran before it. These rows guard the dead-value exemption.
func TestGAP0403WriteBeforeReassignmentStillBlocks(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, row := range []struct{ name, command string }{
		{"brace", `f=keylink; { echo m >> "$f"; f=a.txt; }; echo m >> "$f"`},
		{"if", `f=keylink; if true; then echo m >> "$f"; f=a.txt; fi; echo m >> "$f"`},
		{"and", `f=keylink && echo m >> "$f" && f=a.txt; echo m >> "$f"`},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, call := range everyMode("GAP0403/write-before-reassign/"+row.name, payload, header) {
			mode := os.FileMode(0o700)
			if call.managed {
				mode = 0
			}
			if err := os.Chmod(f.homes, mode); err != nil {
				t.Fatal(err)
			}
			call.verdict, call.body = f.serve(call)
			t.Logf("GAP0403ROW %s | %s | want block", call.name, call.verdict)
			if call.verdict != "block" {
				t.Errorf("%s: verdict %s, want block; body %.200s", call.name, call.verdict, call.body)
			}
		}
		if err := os.Chmod(f.homes, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}

// rel-1-0-6:GAP-0371: a cp destination bound by a fixed for-word list
// reaches the protected link even when its harmless neighbour is first.
func TestGAP0371LoopCopyDestinationsFourCell(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct{ name, command string }{
		{"harmless-first", `for f in out2.txt keylink; do cp a.txt $f; done`},
		{"link-first", `for f in keylink out2.txt; do cp a.txt $f; done`},
		{"quoted", `for f in out2.txt keylink; do cp a.txt "$f"; done`},
	}
	var payloads [][]byte
	var names, wants []string
	for _, row := range rows {
		for _, kind := range []string{"protected", "benign"} {
			command, want := row.command, "block"
			if kind == "benign" {
				command, want = strings.ReplaceAll(command, "keylink", "out3.txt"), "allow"
			}
			payloads = append(payloads, f.payload(t, command))
			names = append(names, "GAP0371/"+row.name+"/"+kind)
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
		t.Logf("GAP0371ROW %s | %s | want %s", call.name, call.verdict, want)
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s; body %.200s", call.name, call.verdict, want, call.body)
		}
	}
	if data, err := os.ReadFile(f.keys); err != nil || string(data) != "# decoy\n" {
		t.Fatalf("decoy keys file changed: %q %v", data, err)
	}
}
