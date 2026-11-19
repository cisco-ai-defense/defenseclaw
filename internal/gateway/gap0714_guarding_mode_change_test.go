// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"strconv"
	"strings"
	"testing"
)

// TestGAP0714GuardingModeChangeIsReadAsRel: a change of a protected file's
// mode that guards it (chmod 600 of a key) after a call the split cannot
// read, or after a cd the walk cannot follow, is judged as the same change of
// an ordinary file after the same shape (an allow, or the alert eval "$c" has
// of its own), as at rel 740c0de8fd. The unresolved-folder tier knows only
// the file's name, so it reads rel's access kinds (read, write, append,
// delete) only; after a split gap the call's own twins judge a mode or owner
// change, and a change that opens or hands away a protected file (chmod 644,
// chmod 777, chown) stays at least the unknown tier (substrate-1:GAP-0714:
// `f(){ cd /tmp; "$@"; }; f cd && chmod 600 .aws/credentials` from the home
// was alert/block at t6/fix-0690 b318c23b43 and allow/allow at rel and FU11
// c8090b1056).
func TestGAP0714GuardingModeChangeIsReadAsRel(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX home fixture: the plain spelling joins the home with backslashes on Windows (substrate-1:GAP-0716)")
	}
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	files := []string{".aws/credentials", ".bashrc", ".netrc", ".git-credentials", ".ssh/id_rsa", ".kube/config"}
	for _, name := range append([]string{"x.txt"}, files...) {
		file := filepath.Join(home, name)
		if err := os.MkdirAll(filepath.Dir(file), 0o700); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(file, []byte("x\n"), 0o600); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	// The mover shapes of the FIX-0711-CK grid (M1: args, var, var;, eval,
	// subst; G8) and the cd shapes the walk cannot follow (cdD, fcdD,
	// pushdD).
	movers := []string{
		`f(){ cd /tmp; "$@"; }; f cd && `,
		`f(){ cd /tmp; $r ~; }; f && `,
		`f(){ cd /tmp; $r ~; }; f; `,
		`f(){ cd /tmp; eval "$c"; }; f && `,
		`f(){ test -f .bashrc && $(echo return); cd /tmp; }; f && `,
		`f(){ cd /tmp && "$@"; }; f cd && `,
	}
	cds := []string{`cd "$D" && `, `f(){ cd "$D"; }; f && `, `pushd "$D" >/dev/null && `}
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	tier := map[string]string{"default": "alert", "strict": "block"}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		decide := func(command string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "gap0714-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), command)
			ev["cwd"] = home
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, name := range files {
			guard := "chmod 600 " + name
			if got := decide(guard); got != "allow" {
				t.Fatalf("%s: plain %q is %s, want allow", pack, guard, got)
			}
			for _, shape := range append(append([]string{}, movers...), cds...) {
				if got, want := decide(shape+guard), decide(shape+"chmod 600 x.txt"); got != want {
					t.Errorf("%s: %q is %s, want %s (the same change of an ordinary file)", pack, shape+guard, got, want)
				}
			}
			for _, change := range []string{"chmod 644 ", "chmod 777 ", "chown nobody "} {
				if decide(change+filepath.Join(home, name)) == "allow" {
					continue
				}
				for _, shape := range movers {
					command := shape + change + name
					if got := decide(command); rank[got] < rank[tier[pack]] {
						t.Errorf("%s: %q is %s, want at least %s", pack, command, got, tier[pack])
					}
				}
			}
		}
		// A guarding change of many files, and of ordinary files, stays an
		// allow as well.
		many := strings.Join(files, " ")
		for _, command := range []string{
			`f(){ cd /tmp; "$@"; }; f cd && chmod 600 ` + many,
			`cd "$D" && chmod 600 ` + many,
		} {
			if got := decide(command); got != "allow" {
				t.Errorf("%s: %q is %s, want allow", pack, command, got)
			}
		}
	}
}
