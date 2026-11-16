// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import "testing"

func TestGAP0462OutputOptionWrites(t *testing.T) {
	const target = "/home/alice/.ssh/authorized_keys"
	for _, command := range []string{
		"find . -fprint " + target,
		"find . -fprint0 " + target,
		"find . -fls " + target,
		"find . -fprintf " + target + " %p",
		"git config -f " + target + " verifier.value x",
		"git config -f" + target + " verifier.value x",
		"git config --file=" + target + " verifier.value x",
		"GIT_CONFIG_GLOBAL=" + target + " git config --global verifier.value x",
		"gawk -i inplace '{print}' " + target,
		"gawk -iinplace '{print}' " + target,
		"gawk --include=inplace '{print}' " + target,
		"uniq input.txt " + target,
		"uniq -ci -w4 input.txt " + target,
		"fixture-tool --output=" + target,
		"fixture-tool -o" + target,
	} {
		t.Run(command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/home/alice/project", ActiveHome: "/home/alice"})
			for _, path := range facts.Paths {
				if path.Value == target && path.Access == PathAccessWrite {
					if command[:4] == "gawk" && facts.Parse.Status != StatusPartial {
						t.Fatalf("AWK source was treated as complete: %+v", facts.Parse)
					}
					return
				}
			}
			t.Fatalf("missing output write path: parse=%+v paths=%+v", facts.Parse, facts.Paths)
		})
	}
	for _, command := range []string{
		"find . -name " + target + " -print",
		"git config -f " + target + " --get verifier.value",
		"GIT_CONFIG_GLOBAL=" + target + " git config --global --get verifier.value",
		"GIT_CONFIG_GLOBAL=" + target + " git config --global -f notes.conf verifier.value x",
		"gawk '{print}' " + target,
		"uniq " + target,
		"fixture-tool --input=" + target,
	} {
		t.Run("input only "+command, func(t *testing.T) {
			facts := Analyze(Input{Tool: "Bash", Command: command, CWD: "/home/alice/project", ActiveHome: "/home/alice"})
			for _, path := range facts.Paths {
				if path.Value == target && path.Access == PathAccessWrite {
					t.Fatalf("read input became an output path: %+v", facts.Paths)
				}
			}
		})
	}
}
