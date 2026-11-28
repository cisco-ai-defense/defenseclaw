// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"testing"
)

// TestGAP0686ShadowedMoveKeepsTheSpelledFolder is substrate-1:GAP-0686: a
// call that defines a function named cd, pushd or command before a move may
// run that function instead of the builtin, so the move may go anywhere;
// it may also go where the builtin goes (cd(){ builtin cd "$@"; } does just
// that). The spelled folder stays one the next command may run in, so the
// call is never weaker than its plain form: a write of a git hook after
// `cd .git/hooks` alerts (default) or blocks (strict) with or without the
// function. A move to an ordinary folder stays allowed.
func TestGAP0686ShadowedMoveKeepsTheSpelledFolder(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX walk of a shadowed cd/pushd: on a Windows host the shadowed spelling keeps the 1.0.10 reading, as at rel 8a1e883539 (P49-FIX2 native rows)")
	}
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, d := range []string{filepath.Join(project, ".git", "hooks"), filepath.Join(project, "src")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	if err := os.WriteFile(filepath.Join(project, ".git", "HEAD"), []byte("ref: refs/heads/main\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	prefixes := []string{
		`cd(){ builtin cd "$@"; }; `,
		`pushd(){ builtin pushd "$@"; }; `,
		`command(){ "$@"; }; `,
		`chdir(){ :; }; `,
	}
	moves := []string{"cd .git/hooks && ", "pushd .git/hooks >/dev/null && ", "cd ./.git/hooks; "}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0686-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = project
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, move := range moves {
			cmd := move + "echo ok > pre-push"
			plain := verdict(cmd)
			if plain == "allow" {
				t.Fatalf("%s: plain %q = allow, want the git hook write judged", pack, cmd)
			}
			for _, prefix := range prefixes {
				if got := verdict(prefix + cmd); got != plain {
					t.Errorf("%s: %q = %s, want %s (its plain form)", pack, prefix+cmd, got, plain)
				}
				control := prefix + "cd src && echo ok > out.txt"
				if got := verdict(control); got != "allow" {
					t.Errorf("%s: control %q = %s, want allow", pack, control, got)
				}
			}
		}
	}
}
