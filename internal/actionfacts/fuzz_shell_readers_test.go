// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
)

// FuzzShellReadersNeverPanic drives the shell parser entry points of the hook
// below their recover guards (analyze, simpleCommandsOfCall), so a reader
// panic is reported here instead of being turned into an unknown verdict at
// run time (gas-ux-r2:GAP-0082). SimpleCommands and Analyze keep their own
// guards; this target checks that nothing reaches them. Seeds are benign
// agent commands and the forms past reader faults were found in.
func FuzzShellReadersNeverPanic(f *testing.F) {
	for _, seed := range []string{
		"command -v unzip && command -v uncompress && command -v tar",
		"cd \"$(mktemp -d)\" && command -v tar && p=$!",
		"cd dir && (sleep 1 &) ; p=$! ; wait $p",
		"a=b c=d",
		"ln /app/assets/f.dat /tmp/l && mv /tmp/l '/app/assets/file*with*stars.dat'",
		"ln /app/a.dat /tmp/l && mv /tmp/l $'/app/file\\nwith\\nnewlines.dat'",
		"cat <<\"EOT\"\n*** Begin Patch\n*** End Patch\nEOT",
		"rm -f /app/data/*\ntar -xjf /app/backups/a.dat -C /app/data/",
		"cp /etc/pam.d/* /backups/pam.d/",
		"eval \"$(python3 x.py)\" && echo ok",
		"for f in *.txt; do cp \"$f\" out/; done",
		"pushd ~1 && popd",
		"x=$(cat <<'E'\nbody\nE\n)",
	} {
		f.Add(seed, "/home/u/work", byte(0))
		f.Add(seed, "", byte(1))
	}
	dialects := []Dialect{"", DialectPOSIX, DialectPowerShell}
	f.Fuzz(func(t *testing.T, command, cwd string, hint byte) {
		if len(command) > 2048 || strings.ContainsRune(cwd, 0) {
			return
		}
		input := Input{Tool: "shell", Command: command, CWD: cwd, DialectHint: dialects[int(hint)%len(dialects)]}
		facts := analyze(input, "", nil)
		simpleCommandsOfCall(input, facts, nil)
		for _, simple := range SimpleCommands(input, facts) {
			if simple.EvaluationFailure == EvaluationFailureInternal {
				t.Fatalf("reader failed internally on %q", command)
			}
		}
	})
}
