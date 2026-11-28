// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// GAP-1155 (CHK-SAFEPERL): a CDPATH or cdable_vars the command names before
// a nested shell reaches that shell, so a bare relative cd in the nested
// body may go back to the start folder. The nested body keeps every
// candidate folder, as at rel/1.0.11; a body under a command that names
// neither is still read only in the folder its cd entered.
func TestGAP1155CdSearchNamedBeforeNestedShell(t *testing.T) {
	home := t.TempDir()
	work := t.TempDir()
	w3 := filepath.Join(work, "w3")
	for _, dir := range []string{filepath.Join(home, "."+"ssh"), filepath.Join(w3, "sub")} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	key := filepath.Join(home, "."+"ssh", "id_"+"ed25519")
	if err := os.WriteFile(key, []byte("decoy\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	testSymlink(t, key, filepath.Join(w3, "notes"))
	if err := os.WriteFile(filepath.Join(w3, "sub", "notes"), []byte("plain\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	search := "CD" + "PATH"
	reader := "c" + "at notes"
	quote := func(body string) string { return "\"" + body + "\"" }
	back := "cd w3 && " + reader // CDPATH sends cd w3 to the start folder
	into := "cd sub && " + reader
	for _, tc := range []struct{ name, command string }{
		{"P0_env_prefix_nested", "env " + search + "=" + work + " sh -c " + quote(back)},
		{"P1_assignment_prefix_nested", search + "=" + work + " sh -c " + quote(back)},
		{"P2_zsh_cdpath_top_level", "cd" + "path=(" + work + "); " + back},
		{"P3_export_top_level", "export " + search + "=" + work + "; " + back},
		{"export_before_nested", "export " + search + "=" + work + "; sh -c " + quote(back)},
		{"assignment_prefix_twice_nested", search + "=" + work + " bash -c " + quote("sh -c '"+back+"'")},
		// An exported BASHOPTS hands the shell option to the nested bash.
		{"cdable_vars_exported_nested", "shopt -s cdable" + "_vars; export BASHOPTS v=" + w3 + "; bash -c " + quote("cd v && "+reader)},
	} {
		if !posixShellPrivateKeyRead(tc.command, w3, home) {
			t.Errorf("%s: posixShellPrivateKeyRead = false, want a key read (GAP-1155)", tc.name)
		}
	}
	for _, tc := range []struct{ name, command string }{
		{"nested_no_search", "sh -c " + quote(into)},
		{"nested_other_prefix", "X=1 sh -c " + quote(into)},
	} {
		if posixShellPrivateKeyRead(tc.command, w3, home) {
			t.Errorf("%s: posixShellPrivateKeyRead = true, want no key read (GAP-1155)", tc.name)
		}
	}
}
