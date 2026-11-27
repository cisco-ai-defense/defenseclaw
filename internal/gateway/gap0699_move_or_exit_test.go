// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP0699MoveOrExitIsCertainOnTheHook is substrate-1:GAP-0699: from the
// home, `cd proj || exit 1; <write .npmrc or .aws/credentials>` writes the
// project file (the exit ends the shell where the cd failed), as `cd proj
// && ...` does: allowed in every pack. The same write after `cd proj;` keeps
// its reading in the home too (the cd may fail, the write still runs), as
// rel reads a shell profile after `cd proj;`: not allowed. A move into the
// home before `|| exit` is judged as its && form.
func TestGAP0699MoveOrExitIsCertainOnTheHook(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	project := filepath.Join(home, "proj")
	for _, d := range []string{filepath.Join(project, ".aws"), filepath.Join(home, ".aws")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	writes := []string{"echo registry=x > .npmrc", "cp /tmp/x .aws/credentials"}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd, cwd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0699-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = cwd
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, write := range writes {
			for _, move := range []string{"cd proj || exit 1; ", "cd proj || exit\n", "cd proj || { echo no; exit 1; }; ", "cd proj && "} {
				if got := verdict(move+write, home); got != "allow" {
					t.Errorf("%s: %q from the home = %s, want allow (it writes the project file)", pack, move+write, got)
				}
			}
			if got := verdict("cd proj; "+write, home); got == "allow" {
				t.Errorf("%s: %q from the home = allow, want the home reading judged", pack, "cd proj; "+write)
			}
			plain := verdict("cd ~ && "+write, project)
			if got := verdict("cd ~ || exit 1; "+write, project); got != plain {
				t.Errorf("%s: %q from the project = %s, want %s (its && form)", pack, "cd ~ || exit 1; "+write, got, plain)
			}
		}
	}
}
