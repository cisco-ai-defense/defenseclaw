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

// TestHomeDeleteRmLongOptionAbbreviationsFiveTiers: rm takes any unambiguous
// prefix of a long option (GNU getopt) and of the WHEN value of
// --interactive (argmatch), so --recursive, --force and --interactive=never
// spelled short remove what the full spelling removes
// (rel-1-0-10:GAP-0743). The plain delete is the oracle; an abbreviation of
// a prompting WHEN keeps the verdict of rm -ri ~.
func TestHomeDeleteRmLongOptionAbbreviationsFiveTiers(t *testing.T) {
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
		"rm -r --interactive=ne ~",
		"rm -r --interactive=n ~",
		"rm -r --interactive=non ~",
		"rm -r --inter=never ~",
		"rm --rec --for ~",
		"rm --r --f ~",
		"rm -r --int=no ~",
	}
	sameAsAsking := []string{
		"rm -r --interactive=al ~",
		"rm -r --int=yes ~",
		"rm -r --i ~",
		"rm -r --interactive=ne -i ~",
	}
	allowed := []string{
		"rm -r --interactive=ne ./build",
		"rm --rec --for ./build",
	}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		a.inspectToolScanTimeout = 30 * time.Second
		verdict := func(command string) string {
			action, _ := gap0437Inspect(t, a, cwd, command)["action"].(string)
			return action
		}
		oracle := verdict("rm -rf ~")
		if oracle != "block" {
			t.Fatalf("%s: rm -rf ~ is %s, the oracle needs a block", p.name, oracle)
		}
		for _, command := range sameAsDelete {
			if got := verdict(command); got != oracle {
				t.Errorf("%s: %q is %s, its plain delete is %s", p.name, command, got, oracle)
			}
		}
		asking := verdict("rm -ri ~")
		for _, command := range sameAsAsking {
			if got := verdict(command); got != asking {
				t.Errorf("%s: %q is %s, rm -ri ~ is %s", p.name, command, got, asking)
			}
		}
		for _, command := range allowed {
			if got := verdict(command); got != "allow" {
				t.Errorf("%s: %q is %s, want allow", p.name, command, got)
			}
		}
	}
}
