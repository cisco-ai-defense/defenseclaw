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
