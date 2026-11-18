// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"testing"
)

// A file sed reads is no sed script: a hook path whose folders spell a w / e
// command (/etc, a run folder such as x0e-base) is read, not written
// (rel-1-0-10:GAP-0849: the native run tag in the temporary folder decided
// TestRegistrationWriteReachFlowConstructs/sed_prints_the_hook_in_a_list).
func TestRegistrationSedFileOperandIsNoScript(t *testing.T) {
	root := filepath.Join(t.TempDir(), "etc", "n7c30e-base", "w1")
	home := filepath.Join(root, "home")
	bin := filepath.Join(home, ".local", "bin")
	hook := filepath.Join(bin, "defenseclaw-hook-user")
	if err := os.MkdirAll(bin, 0o700); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(hook, []byte("x"), 0o600); err != nil {
		t.Fatal(err)
	}
	rows := []struct {
		name, command string
		want          bool
	}{
		{"script then the hook", "sed -n 1p " + hook + "; echo done", false},
		{"expression then the hook", "sed -n -e 1p " + hook + "; echo done", false},
		{"clustered expression", "sed -ne 1p " + hook + "; echo done", false},
		{"long expression", "sed --quiet --expression=1p " + hook + "; echo done", false},
		{"hook after the end of options", "sed -n 1p -- " + hook + "; echo done", false},
		{"options after the files", "sed 1p " + hook + " -n; echo done", false},
		// A w / e command in a script word still writes.
		{"w command onto the hook", "sed -n 'w " + hook + "' /dev/null; echo done", true},
		{"second expression writes the hook", "sed -e 1p -e 'w " + hook + "' /dev/null; echo done", true},
		{"in place on the hook", "sed -i s/a/b/ " + hook + "; echo done", true},
	}
	for _, row := range rows {
		t.Run(row.name, func(t *testing.T) {
			got := len(RegistrationWriteReached(row.command, root, home, []string{hook, bin})) > 0
			if got != row.want {
				t.Errorf("reached %v, want %v for %q", got, row.want, row.command)
			}
		})
	}
}

func TestSedScriptWords(t *testing.T) {
	rows := []struct {
		args    []string
		scripts []string
		ok      bool
	}{
		{[]string{"-n", "1p", "a/e1", "b"}, []string{"1p"}, true},
		{[]string{"-ne", "w x", "f0e-1"}, []string{"w x"}, true},
		{[]string{"-e1p", "-f", "s.sed", "w0e", "e1"}, []string{"1p", "s.sed"}, true},
		{[]string{"--expr", "1p", "e1"}, []string{"1p"}, true},
		{[]string{"1p", "e1", "-e", "w0e"}, []string{"1p", "w0e"}, true},
		{[]string{"-l", "5", "1p", "e1"}, []string{"1p"}, true},
		{[]string{"--", "w x", "e1"}, []string{"w x"}, true},
		{[]string{"1p", "e1", "--", "w0e"}, []string{"1p"}, true},
		{[]string{"-I", ".bak", "1p", "e1"}, nil, false},
		{[]string{"--f", "x"}, nil, false},
	}
	for _, row := range rows {
		scripts, ok := sedScriptWords(row.args)
		if ok != row.ok || ok && len(scripts) != len(row.scripts) {
			t.Fatalf("sedScriptWords(%q) = %q, %v; want %q, %v", row.args, scripts, ok, row.scripts, row.ok)
		}
		for i := range scripts {
			if ok && scripts[i] != row.scripts[i] {
				t.Fatalf("sedScriptWords(%q) = %q; want %q", row.args, scripts, row.scripts)
			}
		}
	}
}
