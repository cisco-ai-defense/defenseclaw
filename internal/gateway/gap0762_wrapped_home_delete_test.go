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

// TestHomeDeleteBehindSetsidOrAnsweredPromptsFiveTiers: a recursive delete of
// the home run through setsid or by xargs from the words an echo or printf
// prints (rel-1-0-10:GAP-0762), with
// --interactive=never, or with every prompt answered by yes
// (rel-1-0-10:GAP-0743) removes what rm -rf ~ removes, so it gets the verdict
// of rm -rf ~ in every tier. The plain delete is the oracle, never a
// hard-coded letter. A delete that still asks (rm -ri ~, yes n | rm -ri ~,
// --interactive=always) keeps the verdict of rm -ri ~, and setsid of an
// ordinary program or folder stays allowed. A wrapped delete of the
// DefenseClaw state (a partial reading of the state match) is the class of
// rel-1-0-10:GAP-0892, fixed on its own train.
func TestHomeDeleteBehindSetsidOrAnsweredPromptsFiveTiers(t *testing.T) {
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
	sameAsDelete := []string{
		"setsid rm -rf ~",
		"setsid -f rm -rf ~",
		"setsid --wait rm -rf ~",
		"setsid -- rm -rf ~",
		"nice setsid rm -rf ~",
		"rm -r --interactive=never ~",
		"rm -ri --interactive=never ~",
		"yes | rm -ri ~",
		"yes y | rm -r -i ~",
		"echo ~ | xargs rm -rf",
		"echo $HOME | xargs -r rm -rf",
		"printf '%s\\n' ~ | xargs -n1 rm -rf",
		"echo -n ~ | xargs --max-args=1 rm -rf",
	}
	sameAsAsking := []string{
		"yes n | rm -ri ~",
		"rm -r --interactive=always ~",
		"rm -r --interactive=never -i ~",
	}
	allowed := []string{
		"setsid sleep 30",
		"setsid rm -rf ./build",
		"yes | rm -ri ./build",
		"rm -r --interactive=never ./build",
		"echo ./build | xargs rm -rf",
		"printf '%s\\n' ./build ./dist | xargs rm -rf",
		"echo ~ | xargs ls -la",
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		a.inspectToolScanTimeout = 30 * time.Second
		verdict := func(command string) (string, map[string]any) {
			out := gap0437Inspect(t, a, cwd, command)
			action, _ := out["action"].(string)
			return action, out
		}
		oracle, _ := verdict("rm -rf ~")
		if oracle != "block" {
			t.Fatalf("%s: rm -rf ~ is %s, the oracle needs a block", p.name, oracle)
		}
		for _, command := range sameAsDelete {
			if got, out := verdict(command); got != oracle {
				t.Errorf("%s: %q is %s, its plain delete is %s: %v", p.name, command, got, oracle, out)
			}
		}
		asking, _ := verdict("rm -ri ~")
		for _, command := range sameAsAsking {
			if got, out := verdict(command); got != asking {
				t.Errorf("%s: %q is %s, rm -ri ~ is %s: %v", p.name, command, got, asking, out)
			}
		}
		for _, command := range allowed {
			if got, out := verdict(command); got != "allow" {
				t.Errorf("%s: %q is %s, want allow: %v", p.name, command, got, out)
			}
		}
	}
}
