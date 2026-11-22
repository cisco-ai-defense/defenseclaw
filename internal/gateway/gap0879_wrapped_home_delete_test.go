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

// TestWrappedHomeDeleteSpellingsKeepThePlainVerdictFiveTiers: the glob
// spellings of the home delete behind a wrapper (nice rm -rf ~/*, setsid rm
// -rf $HOME/*), the HOME word in double quotes inside a shell -c body and a
// chain of more than four wrappers get the verdict of the plain delete
// (rel-1-0-10:GAP-0879, GAP-0743). The plain delete is the oracle.
func TestWrappedHomeDeleteSpellingsKeepThePlainVerdictFiveTiers(t *testing.T) {
	if runtime.GOOS == "windows" {
		t.Skip("POSIX shell text")
	}
	home := filepath.Join(t.TempDir(), "homes", "alice")
	cwd := filepath.Join(home, "project")
	if err := os.MkdirAll(cwd, 0o700); err != nil {
		t.Fatal(err)
	}
	gap0568StateFile(t, home)
	t.Setenv("HOME", home)
	plain := map[string][]string{
		"rm -rf ~/*": {"nice rm -rf ~/*", "setsid rm -rf $HOME/*", "nice setsid rm -rf ~/*",
			"env FOO=1 rm -rf ~/*", "timeout 5 rm -rf ~/*"},
		"rm -rf ~/.*": {"setsid rm -rf ~/.*", "nice rm -rf $HOME/.*"},
		"rm -rf ~": {"sh -c \"rm -rf \\\"$HOME\\\"\"", "bash -c \"rm -rf $HOME\"",
			"nice nice nice nice nice rm -rf ~", "nice setsid nice setsid nice setsid rm -rf ~"},
	}
	allowed := []string{"nice rm -rf ./build/*", "setsid rm -rf $PWD/build/*"}
	for _, p := range gap0437Packs {
		a := gap0437Server(t, p, "openclaw", "action")
		a.inspectToolScanTimeout = 30 * time.Second
		verdict := func(command string) string {
			action, _ := gap0437Inspect(t, a, cwd, command)["action"].(string)
			return action
		}
		for oracleCommand, commands := range plain {
			oracle := verdict(oracleCommand)
			if oracle == "allow" {
				t.Fatalf("%s: %q is allow, the oracle needs a finding", p.name, oracleCommand)
			}
			for _, command := range commands {
				if got := verdict(command); got != oracle {
					t.Errorf("%s: %q is %s, %q is %s", p.name, command, got, oracleCommand, oracle)
				}
			}
		}
		for _, command := range allowed {
			if got := verdict(command); got != "allow" {
				t.Errorf("%s: %q is %s, want allow", p.name, command, got)
			}
		}
	}
}
