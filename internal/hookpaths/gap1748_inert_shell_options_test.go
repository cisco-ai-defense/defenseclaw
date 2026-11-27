// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// TestGAP1748InertShellOptionsReadOnly: a set or shopt that changes neither
// expansion nor what runs leaves a read-only call read-only, so a cd into the
// keys folder in it names no write (rel-1-0-10:GAP-1748: shopt -s lastpipe;
// cd ~/.ssh | cat; cat notes.txt blocked as a keys mutation in every tier).
// A write after the cd, and an option that changes expansion, keep their
// reading.
func TestGAP1748InertShellOptionsReadOnly(t *testing.T) {
	home := t.TempDir()
	for _, dir := range []string{".ssh", "proj"} {
		if err := os.MkdirAll(filepath.Join(home, dir), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("k\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	cwd := filepath.Join(home, "proj")
	for _, c := range []struct {
		command, want string
	}{
		{"shopt -s lastpipe; cd ~/.ssh | cat; cat notes.txt", ""},
		{"shopt -s lastpipe; cd ~/.ssh | cat; ls", ""},
		{"set -o pipefail; cd ~/.ssh | cat; ls", ""},
		{"set -euo pipefail; cd ~/.ssh; ls", ""},
		{"shopt -u checkjobs; cd ~/.ssh", ""},
		// the plain reading of the same call, for parity
		{"cd ~/.ssh | cat; cat notes.txt", ""},
		// writes after the cd keep the protected-target reading
		{"shopt -s lastpipe; cd ~/.ssh; echo k >> authorized_keys", "protected-target"},
		{"set -e; cd ~/.ssh && cp ../proj/x authorized_keys", "protected-target"},
		{"shopt -s lastpipe; echo x | cd ~/.ssh; echo k >> authorized_keys", "protected-target"},
		// options that change expansion or rebind words are not inert
		{"shopt -s dotglob; cd ~/.ssh", "protected-target"},
		{"set -- a b; cd ~/.ssh", "protected-target"},
		{"set -f; cd ~/.ssh", "protected-target"},
	} {
		if got := ActionCommandDecision(c.command, cwd, home); got != c.want {
			t.Errorf("ActionCommandDecision(%q) = %q, want %q", c.command, got, c.want)
		}
	}
	for _, c := range []struct {
		program string
		args    []string
		want    bool
	}{
		{"set", []string{"-e"}, true},
		{"set", []string{"+euxv"}, true},
		{"set", []string{"-euo", "pipefail"}, true},
		{"set", []string{"-o", "noclobber"}, false},
		{"set", []string{"-o"}, false},
		{"set", []string{"--"}, false},
		{"set", []string{"x"}, false},
		{"set", nil, false},
		{"shopt", []string{"-s", "lastpipe"}, true},
		{"shopt", []string{"-qs", "lastpipe", "checkjobs"}, true},
		{"shopt", []string{"-s", "expand_aliases"}, false},
		{"shopt", []string{"-o", "pipefail"}, false},
		{"shopt", []string{"lastpipe", "-s"}, false},
	} {
		if got := actionInertShellOptions(c.program, c.args); got != c.want {
			t.Errorf("actionInertShellOptions(%s %q) = %v, want %v", c.program, c.args, got, c.want)
		}
	}
}
