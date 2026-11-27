// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP1166UnsetRunnerIsNotInForce is substrate-1:GAP-1166: a runner
// definition f() { "$@"; } that an unset of the text may remove (unset -f f,
// or unset f, which removes the function when no variable has the name) is
// not surely in force at its call, which may run the builtin of the name: the
// shell may stay where it was, so the next relative operand keeps at least
// the verdict of its plain form there in every pack (rel 03e3969a86:
// alert/alert/block), on the folder tracker and on the straight-line walk.
// A mover of the name is read the same way. The same runner with no unset,
// or with an unset of variables only, still runs its cd (allow).
func TestGAP1166UnsetRunnerIsNotInForce(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	if err := os.MkdirAll(filepath.Join(home, ".aws"), 0o700); err != nil {
		t.Fatal(err)
	}
	t.Setenv("HOME", home)
	rank := map[string]int{"allow": 0, "alert": 1, "block": 2}
	plain := "rm .aws/credentials"
	rows := []string{
		`true() { "$@"; }; unset -f true; true cd /tmp && rm .aws/credentials`,
		`true() { "$@"; }; unset true; true cd /tmp && rm .aws/credentials`,
		`true() { "$@"; }; unset -f true; true cd /tmp; rm .aws/credentials`,
		`true() { "$@"; }; builtin unset -f -- true; true cd /tmp && rm .aws/credentials`,
		`true() { cd /tmp; }; unset -f true; true && rm .aws/credentials`,
	}
	controls := []string{
		`true() { "$@"; }; true cd /tmp && rm .aws/credentials`,
		`true() { "$@"; }; unset -v true; true cd /tmp && rm .aws/credentials`,
	}
	for _, pack := range []string{"default", "permissive", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g1166-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = home
			return callAgentHookForTest(t, handler, ev).Action
		}
		want := verdict(plain)
		if want == "allow" {
			t.Fatalf("%s: plain %q = allow, want it judged", pack, plain)
		}
		for index, row := range rows {
			if got := verdict(row); rank[got] < rank[want] {
				t.Errorf("%s: row %d = %s, want at least %s (its plain form where the shell stays)", pack, index+1, got, want)
			}
		}
		for index, control := range controls {
			if got := verdict(control); got != "allow" {
				t.Errorf("%s: control %d = %s, want allow (the runner's cd runs)", pack, index+1, got)
			}
		}
	}
}
