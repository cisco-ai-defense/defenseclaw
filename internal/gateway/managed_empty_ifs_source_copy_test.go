// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import (
	"os"
	"path/filepath"
	"testing"
)

// A copy whose source the straight-line walk reads as the empty string opens
// no file, so the managed hook client does not describe its destination as a
// write; a copy with a source that names a file, or a loop word that keeps a
// value, still reaches the link (rel-1-0-6:GAP-0880, GAP-0885, GAP-0431). A
// copy written outside a loop keeps its recorded conservative answer.
func TestManagedEmptyIFSSourceCopyIsBenignAndANamedSourceStaysBlocked(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, row := range []struct {
		name, command, want string
	}{
		{"loop", `IFS=; for f in keylink; do cp "$IFS" "$f"; done`, "allow"},
		{"loop-option", `IFS=; for f in keylink; do cp -f "$IFS" "$f"; done`, "allow"},
		{"assigned-source", `src=; for f in keylink; do cp "$src" "$f"; done`, "allow"},
		{"loop-named-source", `IFS=; for f in keylink; do cp a.txt "$f"; done`, "block"},
		{"direct-named-source", `IFS=; cp a.txt keylink`, "block"},
		{"loop-nonempty-ifs", `IFS=x; for f in keylink; do cp "$IFS" "$f"; done`, "block"},
		{"direct-nonempty-ifs", `IFS=x; cp "$IFS" keylink`, "block"},
		{"target-directory-option", `IFS=; cp -t keylink "$IFS"`, "block"},
	} {
		payload := f.payload(t, row.command)
		header := f.clientHeader(t, payload)
		for _, connector := range []string{"claudecode", "codex"} {
			if got := f.post(t, connector, payload, header); got != row.want {
				t.Errorf("%s %s: %s = %s, want %s", connector, row.name, row.command, got, row.want)
			}
		}
	}
}

// The empty-source proof holds only for the system cp and for a source the
// command cannot change: a project cp that PATH reaches, a PATH assignment, a
// program word naming a project file or a read that sets the source each
// leave the link write described and blocked, in every managed profile the
// reading is judged in (rel-1-0-6:GAP-0880, GAP-0885).
func TestManagedEmptySourceCopyProofNeedsTheCopyAndTheSourceThatRun(t *testing.T) {
	f := newB36ManagedHookFixture(t)
	t.Setenv("BASH_ENV", "")
	t.Setenv("ENV", "")
	if err := os.WriteFile(filepath.Join(f.project, "cp"), []byte("#!/bin/sh\nprintf altered > \"$2\"\n"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(f.project, "a.txt"), []byte("a\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	check := func(rows []struct{ name, command, want string }) {
		t.Helper()
		for _, row := range rows {
			payload := f.payload(t, row.command)
			header := f.clientHeader(t, payload)
			for _, connector := range []string{"claudecode", "codex"} {
				if got := f.post(t, connector, payload, header); got != row.want {
					t.Errorf("%s %s: %s = %s, want %s", connector, row.name, row.command, got, row.want)
				}
			}
		}
	}
	check([]struct{ name, command, want string }{
		{"system-cp", `IFS=; for f in keylink; do cp "$IFS" "$f"; done`, "allow"},
		{"path-dot-before-ifs", `PATH=.; IFS=; for f in keylink; do cp "$IFS" "$f"; done`, "block"},
		{"path-dot-after-ifs", `IFS=; PATH=.; for f in keylink; do cp "$IFS" "$f"; done`, "block"},
		{"path-dot-and-system", `PATH=.:/usr/bin; IFS=; for f in keylink; do cp "$IFS" "$f"; done`, "block"},
		{"source-read-in-loop", `IFS=; src=; for f in keylink; do read src <<< a.txt; cp "$src" "$f"; done`, "block"},
		{"source-assigned-in-loop", `IFS=; src=; for f in keylink; do src=a.txt; cp "$src" "$f"; done`, "block"},
		{"source-read-after-loop", `IFS=; for f in keylink; do cp "$IFS" "$f"; done; read IFS <<< a.txt; cp "$IFS" keylink`, "block"},
	})
	t.Setenv("PATH", f.project+string(os.PathListSeparator)+os.Getenv("PATH"))
	check([]struct{ name, command, want string }{
		{"ambient-path-project-cp", `IFS=; for f in keylink; do cp "$IFS" "$f"; done`, "block"},
	})
}
