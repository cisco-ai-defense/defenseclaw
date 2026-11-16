// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"io"
	"os"
	"path/filepath"
	"testing"
)

// rel-1-0-4 GAP-2607: every Setup /ensure runs prepare, and its compileall
// started a Python and one worker per CPU on a tree that was already
// compiled. A prepared tree is compiled once; a tree prepare unpacked again,
// a marker for another archive and a compile that stopped are compiled again.
func TestCompilePreparedRuntimeCompilesOnce(t *testing.T) {
	previous := compileRuntime
	t.Cleanup(func() { compileRuntime = previous })
	compiles, finishes := 0, true
	compileRuntime = func(string, io.Writer) bool { compiles++; return finishes }
	const sha = "aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000aaaa0000"
	dir := t.TempDir()

	if !compilePreparedRuntime(dir, sha, io.Discard) || compiles != 1 {
		t.Fatalf("first prepare: compiles=%d, want 1", compiles)
	}
	for range 3 {
		if compilePreparedRuntime(dir, sha, io.Discard) {
			t.Fatal("a compiled runtime was compiled again")
		}
	}
	if compiles != 1 {
		t.Fatalf("compiles after no-op prepares = %d, want 1", compiles)
	}

	// Another archive's marker (a folder name collision) does not count.
	if err := os.WriteFile(filepath.Join(dir, compiledMarker), []byte("bbbb"), 0o644); err != nil {
		t.Fatal(err)
	}
	if !compilePreparedRuntime(dir, sha, io.Discard) || compiles != 2 {
		t.Fatalf("other archive's marker: compiles=%d, want 2", compiles)
	}

	// A tree prepare removed and unpacked again has no marker.
	if err := clearRuntimeDir(dir); err != nil {
		t.Fatal(err)
	}
	if err := os.MkdirAll(dir, 0o755); err != nil {
		t.Fatal(err)
	}
	if !compilePreparedRuntime(dir, sha, io.Discard) || compiles != 3 {
		t.Fatalf("unpacked again: compiles=%d, want 3", compiles)
	}

	// A compile that did not run to its end leaves no marker.
	other := t.TempDir()
	finishes = false
	compilePreparedRuntime(other, sha, io.Discard)
	finishes = true
	if !compilePreparedRuntime(other, sha, io.Discard) || compiles != 5 {
		t.Fatalf("stopped compile: compiles=%d, want 5", compiles)
	}
	if _, err := os.Stat(filepath.Join(other, compiledMarker)); err != nil {
		t.Fatalf("marker after a finished compile: %v", err)
	}
}
