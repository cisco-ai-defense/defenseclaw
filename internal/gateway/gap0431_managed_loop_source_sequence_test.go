// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A loop that runs its body judges cp by its name as a writer whatever its
// source operand holds: an empty or option-shaped source is a fact about the
// program the name reaches, which the hook does not consult, so a destination
// that reaches a protected file through a link blocks in every profile
// (rel-1-0-6:GAP-0880, GAP-0885).
func TestGAP0431ManagedLoopSourceAndSequence(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	for _, name := range []string{"a.txt", "-n", "0", "1"} {
		if err := os.WriteFile(filepath.Join(f.project, name), []byte("source\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	rows := []struct{ name, command, want string }{
		{"assigned-source", "src=a.txt; for f in keylink; do cp \"$src\" \"$f\"; done", "block"},
		{"assigned-source-force", "src=a.txt; for f in keylink; do cp -f \"$src\" \"$f\"; done", "block"},
		{"option-source-no-separator", "src=-n; for f in keylink; do cp \"$src\" \"$f\"; done", "block"},
		{"option-source-force-no-separator", "src=-n; for f in keylink; do cp -f \"$src\" \"$f\"; done", "block"},
		{"option-source-separator", "src=-n; for f in keylink; do cp -- \"$src\" \"$f\"; done", "block"},
		{"option-source-force-separator", "src=-n; for f in keylink; do cp -f -- \"$src\" \"$f\"; done", "block"},
		{"empty-source", "src=; for f in keylink; do cp \"$src\" \"$f\"; done", "block"},
		{"empty-slice-offset", `src=; for f in keylink; do cp "${src:1:1}" "$f"; done`, "block"},
		{"empty-slice-rest", `src=; for f in keylink; do cp "${src:0}" "$f"; done`, "block"},
		{"empty-trim-prefix", `src=; for f in keylink; do cp "${src#x}" "$f"; done`, "block"},
		{"empty-set-alternative", `src=; for f in keylink; do cp "${src+}" "$f"; done`, "block"},
		{"set-alternative-with-write", `src=; for f in keylink; do cp "${src+$(printf x >> keylink)}" "$f"; done`, "block"},
		{"empty-source-default", "src=; for f in keylink; do cp \"${src:-a.txt}\" \"$f\"; done", "block"},
		{"empty-source-unset-default", "src=; for f in keylink; do cp \"${src-a.txt}\" \"$f\"; done", "block"},
		{"empty-source-unset-plain", "src=; for f in keylink; do cp \"${src-}\" \"$f\"; done", "block"},
		{"empty-source-null-alternative", "src=; for f in keylink; do cp \"${src:+a.txt}\" \"$f\"; done", "block"},
		{"empty-source-required", "src=; for f in keylink; do cp \"${src?missing}\" \"$f\"; done", "block"},
		{"empty-source-substring", "src=; for f in keylink; do cp \"${src:0:1}\" \"$f\"; done", "block"},
		{"empty-source-assign-default", "src=; for f in keylink; do cp \"${src:=a.txt}\" \"$f\"; done", "block"},
		{"special-seconds", "SECONDS=; for f in keylink; do cp \"$SECONDS\" \"$f\"; done", "block"},
		{"special-optind", "OPTIND=; for f in keylink; do cp \"$OPTIND\" \"$f\"; done", "block"},
		{"two-loops-protected-second", "for f in ordinary; do cp a.txt \"$f\"; done; for f in keylink; do cp a.txt \"$f\"; done", "block"},
		{"two-loops-protected-first", "for f in keylink; do cp a.txt \"$f\"; done; for f in ordinary; do cp a.txt \"$f\"; done", "block"},
	}
	payloads := make([][]byte, len(rows))
	for i, row := range rows {
		payloads[i] = f.payload(t, row.command)
	}
	headers := f.clientHeaders(t, payloads)
	var calls []*hookCall
	for i, row := range rows {
		for _, connector := range []string{"claudecode", "codex"} {
			calls = append(calls, &hookCall{name: row.name + "/" + connector, connector: connector, managed: true, payload: payloads[i], header: headers[i]})
		}
	}
	f.answerAll(t, calls)
	for i, call := range calls {
		want := rows[i/2].want
		if call.verdict != want {
			t.Errorf("%s: verdict %s, want %s", call.name, call.verdict, want)
		}
	}
}
