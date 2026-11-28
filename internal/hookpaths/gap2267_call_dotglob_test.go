// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP2267StatementReadsTheCallDotglob: a statement judged on its own
// (the gateway's pass over each statement of an eval body) is read with the
// dotglob its whole call may turn on (TargetMemo.WithCallWords,
// rel-1-0-10:GAP-2267). The statement alone, and a call that names no such
// option, keep the plain reading; a listing keeps its read-only excuse.
func TestGAP2267StatementReadsTheCallDotglob(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text")
	}
	t.Cleanup(UseSystemShellProfilesForTests(nil, ""))
	t.Setenv("BASHOPTS", "")
	t.Setenv("GLOBIGNORE", "")
	home := filepath.Join(t.TempDir(), "alice")
	if err := os.MkdirAll(filepath.Join(home, ".ssh"), 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(home, ".ssh", "authorized_keys"), []byte("x\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	q := "\x27"
	statement := "rm -rf *"
	for _, tc := range []struct {
		call, statement, want string
	}{
		{"", statement, ""},
		{"eval " + q + "cd ~; shopt -s dotglob; rm -rf *" + q, statement, "protected-target"},
		{"eval " + q + "cd ~; setopt globdots; rm -rf *" + q, statement, "protected-target"},
		{"eval " + q + "cd ~; rm -rf *" + q, statement, ""},
		{"eval " + q + "cd ~; shopt -s dotglob; ls *" + q, "ls *", ""},
	} {
		memo := NewTargetMemo().WithCallWords(tc.call)
		if got := memo.ActionCommandDecisionInShell(tc.statement, home, home, nil, true); got != tc.want {
			t.Errorf("call %q: statement %q = %q, want %q", tc.call, tc.statement, got, tc.want)
		}
	}
}
