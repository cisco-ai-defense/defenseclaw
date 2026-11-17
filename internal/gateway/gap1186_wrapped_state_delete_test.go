// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"runtime"
	"testing"
	"time"
)

// gap1186Wrappers are prefix wrappers the shared prefix reader
// (actionfacts.StaticPrefixWrapperChild) knows, with options of each, and a
// chain of two.
var gap1186Wrappers = []string{
	"nohup", "nice", "nice -n 5", "time", "timeout 5", "env", "command", "exec", "sudo -n",
	"doas", "setsid", "setsid -f", "stdbuf -o0", "ionice -c3", "taskset -c 0", "chrt -i 0",
	"flock .lock", "caffeinate -i", "builtin command", "nohup nice", "nice setsid",
}

// TestStateDeleteBehindAnyPrefixWrapperFiveTiers: a delete of the DefenseClaw
// state run through any prefix wrapper the shared reader knows removes what
// the plain delete removes, so a plain delete that blocks blocks wrapped in
// every tier. setsid, nice, stdbuf, ionice, doas, chrt, taskset and flock
// were a clean allow in all five tiers on rel da4177e225 while nohup blocked
// (rel-1-0-10:GAP-1186). The plain delete is the oracle, never a hard-coded
// letter. The same wrappers around a delete in the project stay allowed.
func TestStateDeleteBehindAnyPrefixWrapperFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text; OpenClaw exec is PowerShell on native Windows")
	}
	home := filepath.Join(t.TempDir(), "homes", "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	state := "~/.defenseclaw"
	deletes := []string{
		"rm -rf " + state,
		"rm -f " + state + "/config.yaml",
		"rm -r " + state + "/hooks",
		"unlink " + state + "/config.yaml",
		"shred -u " + state + "/config.yaml",
	}
	required := map[string]bool{deletes[0]: true, deletes[1]: true}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		a.inspectToolScanTimeout = 30 * time.Second
		verdict := func(command string) (string, map[string]any) {
			out := gap0437Inspect(t, a, cwd, command)
			action, _ := out["action"].(string)
			return action, out
		}
		for _, plain := range deletes {
			oracle, _ := verdict(plain)
			if oracle != "block" {
				if required[plain] {
					t.Fatalf("%s: %q is %s, the oracle needs a block", p.name, plain, oracle)
				}
				continue
			}
			for _, wrapper := range gap1186Wrappers {
				if got, out := verdict(wrapper + " " + plain); got != oracle {
					t.Errorf("%s: %q is %s, its plain delete is %s: %v", p.name, wrapper+" "+plain, got, oracle, out)
				}
			}
		}
		for _, wrapper := range gap1186Wrappers {
			command := wrapper + " rm -rf ./build"
			if got, out := verdict(command); got != "allow" {
				t.Errorf("%s: %q is %s, want allow: %v", p.name, command, got, out)
			}
		}
	}
}
