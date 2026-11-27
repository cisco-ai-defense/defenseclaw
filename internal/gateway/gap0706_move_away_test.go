// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strconv"
	"testing"
)

// TestGAP0706MoveAwayIsTheDelete is substrate-1:GAP-0706 (and the mv-away
// rows of GAP-0700): mv of a protected home credential file takes it away
// from where it is, as rm does, so the call gets the verdict of the rm of
// that file, spelled from the home or relatively. A rename of an ordinary
// project file (also one named credentials.py or config) and of a project
// .env stays allowed.
func TestGAP0706MoveAwayIsTheDelete(t *testing.T) {
	installCorrelationHMACForTest(t)
	home := filepath.Join(t.TempDir(), "home", "alice")
	for _, d := range []string{filepath.Join(home, ".aws"), filepath.Join(home, ".kube"), filepath.Join(home, "proj", "src")} {
		if err := os.MkdirAll(d, 0o700); err != nil {
			t.Fatal(err)
		}
	}
	t.Setenv("HOME", home)
	files := []string{"~/.aws/credentials", ".aws/credentials", "~/.kube/config", "~/.npmrc", "~/.git-credentials"}
	controls := []string{"mv proj/a.txt /tmp/a.txt", "mv proj/credentials.py proj/src/credentials.py", "mv proj/config proj/config.old", "mv proj/.env proj/.env.bak"}
	for _, pack := range []string{"default", "strict"} {
		handler := hostClaudeHookHandlerForTest(t, pack)
		n := 0
		verdict := func(cmd string) string {
			n++
			ev := claudeToolEvent("PreToolUse", "g0706-"+pack+strconv.Itoa(n), "c"+strconv.Itoa(n), cmd)
			ev["cwd"] = home
			return callAgentHookForTest(t, handler, ev).Action
		}
		for _, file := range files {
			remove := verdict("rm " + file)
			if remove == "allow" {
				t.Fatalf("%s: rm %s = allow, want it judged", pack, file)
			}
			if got := verdict("mv " + file + " /tmp/staged"); got != remove {
				t.Errorf("%s: mv %s away = %s, want %s (its rm)", pack, file, got, remove)
			}
		}
		for _, control := range controls {
			if got := verdict(control); got != "allow" {
				t.Errorf("%s: control %q = %s, want allow", pack, control, got)
			}
		}
	}
}
