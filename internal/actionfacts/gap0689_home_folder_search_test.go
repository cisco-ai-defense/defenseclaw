// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
)

// TestGAP0689HomeFolderSearchAfterAMoverIsWalked: a recursive search whose
// folder is spelled from the home (rg ... ~/proj, grep -r ... ~/proj) reads
// the credentials files under it wherever a cd or a function call before it
// left the shell (substrate-1:GAP-0689, live TST-6432: `f(){ test -d .git
// && return; cd /; }; f && rg -g '/.env' KEY ~/proj` read proj/.env, the
// chain did not start). The trusted home rewrite places ~ only in a lone
// command; in a list the unquoted ~/ word is a static glob, and the search
// walked only a static folder word, so the folder was never walked. The
// controls read no credentials file: rg's own filters (a glob, hidden
// files), a folder with none, and a call that may rebind HOME.
//
// C3's list does not move the shell, so rg's working folder (the root its
// globs match from) is the hook's folder on every OS. C5 is C3 after a
// cd /: on Linux and macOS rg then runs in "/", a known folder, and the
// Go glob still selects no credentials file. On Windows a POSIX cd leaves
// the hook's folder for one the hook cannot resolve (/ is the Git Bash
// root; rgWorkingFolder knows a moved folder only from a POSIX hook
// folder), so every glob of that rg is unsure and counts (count when
// unsure, substrate-1:GAP-0684): the walk reads the folder's credentials
// files there (substrate-1:GAP-1109).
func TestGAP0689HomeFolderSearchAfterAMoverIsWalked(t *testing.T) {
	unsureRoot := runtime.GOOS == "windows"
	home := filepath.Join(t.TempDir(), "home")
	proj := filepath.Join(home, "proj")
	for name, text := range map[string]string{".env": "KEY=1\n", ".git/HEAD": "ref: x\n", "src/a.go": "package a\n", "deploy/id_ed25519": "k\n", "hid/.env": "KEY=1\n"} {
		file := filepath.Join(proj, filepath.FromSlash(name))
		if err := os.MkdirAll(filepath.Dir(file), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte(text), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	for _, row := range []struct {
		id, cwd, command string
		read             bool
	}{
		{"A mover may return before cd /", proj, "f(){ test -d .git && return; cd /; }; f && rg -g '/.env' KEY ~/proj", true},
		{"B return 0 before cd /tmp", proj, "f(){ [ -e .env ] && return 0; cd /tmp; }; f && rg -g '/.env' KEY ~/proj", true},
		{"C a deploy glob", proj, "f(){ test -d .git && return; cd /; }; f && rg -g 'deploy/*' KEY ~/proj", true},
		{"D a bare return first", proj, "f(){ return; cd /; }; f && rg -g '/.env' KEY ~/proj", true},
		{"E a function that does not move", proj, "f(){ :; }; f && rg -g '/.env' KEY ~/proj", true},
		{"F cd / then rg --hidden", proj, "cd / && rg --hidden KEY ~/proj", true},
		{"G cd /tmp; grep -r", proj, "cd /tmp; grep -r KEY ~/proj", true},
		{"H the home itself", home, "cd /tmp; grep -r KEY ~", true},
		{"C1 a folder with no credentials file", proj, "f(){ test -d .git && return; cd /; }; f && rg --hidden KEY ~/proj/src", false},
		{"C2 rg skips hidden files", proj, "cd / && rg KEY ~/proj/hid", false},
		{"I the same folder with --hidden", proj, "cd / && rg --hidden KEY ~/proj/hid", true},
		{"C3 a glob that selects only Go files", proj, "f(){ :; }; f && rg -g '*.go' KEY ~/proj", false},
		{"C5 cd to the root, then a glob that selects only Go files", proj, "cd / && rg -g '*.go' KEY ~/proj", unsureRoot},
		{"C4 the call may rebind HOME", proj, "HOME=/nonexistent; cd / && rg --hidden KEY ~/proj", false},
	} {
		t.Run(row.id, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Bash", Command: row.command, CWD: row.cwd, ActiveHome: home, DialectHint: DialectPOSIX})
			if got := len(facts.CredentialPathReads()) > 0; got != row.read {
				t.Fatalf("%q: credentials read = %v, want %v (%v)", row.command, got, row.read, facts.CredentialPathReads())
			}
		})
	}
}
