// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/actionfacts"
)

// GAP-1717: a POSIX shell's call (the POSIX dialect hint: Claude Code's Bash
// tool runs Git Bash on Windows) is read with the POSIX grammar on the host's
// file system, so the Linux rows hold under a native Windows home: a quoted
// word is text, * skips a dot name, an uncalled function never runs. A call
// that spells something only Windows reads (a Windows home variable, a
// backslash path, a PowerShell launcher) keeps every reading, and every
// write of the key blocks in either form.
func TestGAP1717GitBashCallIsReadWithThePOSIXGrammar(t *testing.T) {
	home := t.TempDir()
	project := filepath.Join(home, "project")
	ssh := filepath.Join(home, ".ssh")
	for _, dir := range []string{ssh, project} {
		if err := os.MkdirAll(dir, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	for _, name := range []string{"authorized_keys", "id_ed25519"} {
		if err := os.WriteFile(filepath.Join(ssh, name), []byte("k\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.Symlink(ssh, filepath.Join(project, ".private")); err != nil {
		t.Fatal(err)
	}
	windows := runtime.GOOS == "windows"
	slashHome := filepath.ToSlash(home)
	for _, tc := range []struct {
		name, cwd, command string
		block, windowsOnly bool
	}{
		{"quoted star from the home", home, `echo "*"`, false, false},
		{"quoted patch marker from the home", home, `grep -rn "*** Begin Patch" .`, false, false},
		{"quoted tilde is a literal name", home, `cp payload '~/.ssh/authorized_keys'`, false, false},
		{"printed quoted tilde", home, `printf '%s\n' '~/.ssh/authorized_keys'`, false, false},
		{"uncalled function", home, `f() { echo k >> ~/.ssh/authorized_keys; }; echo ok`, false, false},
		{"star skips a dot link", project, `git add */*`, false, false},
		{"star skips a dot link in a copy", project, `cp payload */authorized_keys`, false, false},
		{"redirect to the key", home, `echo k >> ~/.ssh/authorized_keys`, true, false},
		{"copy onto the key", project, `cp payload ~/.ssh/authorized_keys`, true, false},
		{"called function", home, `f() { echo k >> ~/.ssh/authorized_keys; }; f`, true, false},
		{"nested shell body", home, `sh -c 'echo k >> ~/.ssh/authorized_keys'`, true, false},
		{"explicit dot pattern", project, `cp payload .p*/authorized_keys`, true, false},
		{"through the dot link", project, `echo k >> .private/authorized_keys`, true, false},
		{"Windows home variable", project, `echo k >> "$USERPROFILE/.ssh/authorized_keys"`, true, true},
		{"drive path with slashes", project, `cp payload ` + slashHome + `/.ssh/authorized_keys`, true, true},
		{"drive path with backslashes", project, `cp payload "` + home + `\.ssh\authorized_keys"`, true, true},
		{"MSYS drive root", project, `cp payload /` + slashHome[:1] + slashHome[2:] + `/.ssh/authorized_keys`, true, true},
		{"PowerShell launcher", project, `powershell -NoProfile -Command "Add-Content ~/.ssh/authorized_keys k"`, true, true},
		{"case form of the key", home, `echo k >> ~/.SSH/AUTHORIZED_KEYS`, true, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			if tc.windowsOnly && !windows {
				t.Skip("a Windows spelling")
			}
			got := ActionCommandDecisionWithDialectAndGlobFacts(tc.command, tc.cwd, home, actionfacts.DialectPOSIX, nil)
			if (got == "protected-target") != tc.block {
				t.Fatalf("decision(%q) = %q, want block %t", tc.command, got, tc.block)
			}
		})
	}
	for _, tc := range []struct {
		command string
		read    bool
	}{
		{`head -n 5 */*`, false},
		{`cat */id_*`, false},
		{`head -n 1 */* | wc -l`, false},
		{`cat ~/.ssh/id_ed25519`, true},
		{`cat .ssh/id_*`, true},
	} {
		if got := ActionPrivateKeyReadWithDialect(tc.command, home, home, actionfacts.DialectPOSIX); got != tc.read {
			t.Errorf("key read(%q) = %t, want %t", tc.command, got, tc.read)
		}
	}
}
