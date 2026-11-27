// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP0713ArgRunnerCDIsTheCD is substrate-1:GAP-0713: after a function
// that only runs its arguments (f() { "$@"; }), a call f cd X moves the shell
// as cd X does, so the next relative operand is read in X: the call gets the
// verdict of the plain cd form in both packs: the strict pack on its folder
// walk, the default pack on its straight-line function walk, which runs the
// call's arguments as the body (rel allowed it; the plain form blocks). The
// same call before an ordinary file stays allowed.
func TestGAP0713ArgRunnerCDIsTheCD(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	for _, d := range []string{".aws", "proj"} {
		if err := os.MkdirAll(filepath.Join(home, d), 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	rows := []struct{ cwd, plain string }{
		{filepath.Join(home, "proj"), "cd .. && rm .aws/credentials"},
		{home, "cd .aws && rm credentials"},
		{home, "cd .aws && cp /tmp/x credentials"},
		{home, "cd .aws && cat credentials"},
		{home, `cd "$HOME/.aws" && rm credentials`},
	}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cwd, cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0713-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, row := range rows {
			want := verdict(row.cwd, row.plain)
			if want == "allow" {
				t.Fatalf("%s: %q = allow, want it judged", pack, row.plain)
			}
			runner := `f(){ "$@"; }; f ` + row.plain
			got := verdict(row.cwd, runner)
			if got != want {
				t.Errorf("%s: %q = %s, want %s (its plain cd form)", pack, runner, got, want)
			}
		}
		for _, control := range []string{`f(){ "$@"; }; f cd .. && rm notes.txt`, `f(){ "$@"; }; f echo hi`} {
			if got := verdict(filepath.Join(home, "proj"), control); got != "allow" {
				t.Errorf("%s: control %q = %s, want allow", pack, control, got)
			}
		}
	}
}
