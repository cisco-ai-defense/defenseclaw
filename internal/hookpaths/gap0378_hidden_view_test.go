// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// In a folder this process cannot see (the working folder is not there for
// it), the one shell word resolver adds no glob uncertainty: the
// protected-target readers' name fallback decides the call, as on
// rel/1.0.10. A blind gateway (ProtectHome) keeps every such word uncertain,
// the client's evidence deciding it. In a folder the walk sees, a word the
// resolver cannot expand exactly (GLOBIGNORE, a sourced file that may change
// the options, an extglob form) is proven when a reading wider than any bash
// may take names no protected file, and stays uncertain when it names one (a
// hard link to the keys) (rel-1-0-10:GAP-0378, GAP-0380).
func TestGAP0378HiddenViewAddsNoGlobUncertainty(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX glob walk")
	}
	home := t.TempDir()
	keys := filepath.Join(home, ".ssh", "authorized_keys")
	if err := os.MkdirAll(filepath.Dir(keys), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(keys, []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	gone := filepath.Join(home, "work", "not-here")
	seen := filepath.Join(home, "work", "here")
	linked := filepath.Join(home, "work", "linked")
	for _, dir := range []string{seen, linked} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Link(keys, filepath.Join(linked, "notes.txt")); err != nil {
		t.Skipf("no hard links here: %v", err)
	}
	for _, row := range []struct {
		command, cwd string
		blind        bool
		uncertain    bool
	}{
		{"rm -f build/*.o", gone, false, false},
		{"chmod 644 */*.md", gone, false, false},
		{"GLOBIGNORE=.keep; rm -f build/*.o", gone, false, false},
		{"rm -f build/*.o", gone, true, true},
		{"GLOBIGNORE=.keep; rm -f build/*.o", gone, true, true},
		{"rm -f build/*.o", seen, false, false},
		{"GLOBIGNORE=.keep; rm -f build/*.o", seen, false, false},
		{"source ./env.sh; chmod 644 cfg/*", seen, false, false},
		{"rg -n abc.*(x|y) logs", seen, false, false},
		{"GLOBIGNORE=.keep; rm -f *.txt", linked, false, true},
		{"source ./env.sh; chmod 644 *", linked, false, true},
		{"chmod 600 +(notes).txt", linked, false, true},
	} {
		got := UncertainGlobWriteReason(row.command, row.cwd, home, nil, row.blind)
		if (got != "") != row.uncertain {
			t.Errorf("%q cwd=%s blind=%v: reason %q, uncertain wanted %v", row.command, filepath.Base(row.cwd), row.blind, got, row.uncertain)
		}
	}
}

// A doubtful bracket (a range whose order the user's locale decides) makes a
// glob answer inexact only when it can change it: [3-m] names no file of
// another length in any locale, so an assignment of a bracket list is no
// possible key name (rel-1-0-10:GAP-0378, the owner A/B of s7/hlinkport-r2).
func TestGAP0378DoubtfulBracketDecidesOnlyWhenItCan(t *testing.T) {
	for _, row := range []struct {
		pattern, name  string
		matched, exact bool
	}{
		{"[3-m]", "authorized_keys", false, true},
		{"[3-m]x", ".ssh", false, true},
		{"[3-m]", "a", true, false},
		{"[!3-m]", "a", false, false},
		{"[3-m]uthorized_keys", "authorized_keys", true, false},
		{"[a-c]", "b", true, true},
	} {
		matched, exact := bashGlobMatch(row.pattern, row.name, false)
		if exact != row.exact || exact && matched != row.matched {
			t.Errorf("bashGlobMatch(%q, %q) = %v, exact %v; want %v, exact %v", row.pattern, row.name, matched, exact, row.matched, row.exact)
		}
	}
	if runtime.GOOS == "windows" {
		return
	}
	home := t.TempDir()
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("# decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	for _, command := range []string{"list=[3-m,x-y] true", "items=[alpha-9,beta-2] echo done"} {
		if got := ActionCommandDecisionInShell(command, home, home, nil, true); got != "" {
			t.Errorf("%q: decision %q, want none", command, got)
		}
	}
}
