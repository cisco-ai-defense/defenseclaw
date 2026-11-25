// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package gateway

import "testing"

// TestGAP0893InlineReadPrintedFiveTiers: inline interpreter code that prints
// the file it reads (print(open(sys.argv[1]).read()) with the key as the
// argument) shows the file to the agent as cat does, so it takes the cat
// cell in five tiers x two connectors (rel-1-0-10:GAP-0893 var2: allow in
// every tier, where cat ~/.ssh/id_rsa blocks). The same code on a project
// file stays allowed.
func TestGAP0893InlineReadPrintedFiveTiers(t *testing.T) {
	useDefaultEffectsLane(t)
	home, _ := r3TierHome(t)
	r3CheckPosixTierRows(t, home, []r3TierRow{
		{gap: "GAP-0893 argv read printed", command: `python3 -c "import sys; print(open(sys.argv[1]).read())" ~/.ssh/id_rsa`, want: "ctl:cat ~/.ssh/id_rsa"},
		{gap: "GAP-0893 argv read written to stdout", command: `python3 -c "import sys; sys.stdout.write(open(sys.argv[1]).read())" ~/.aws/credentials`, want: "ctl:cat ~/.aws/credentials"},
		{gap: "GAP-0893 literal read printed", command: `python3 -c "print(open('` + home + `/.ssh/id_rsa').read())"`, want: "ctl:cat ~/.ssh/id_rsa"},
		{gap: "GAP-0893 fp: argv read of a project file", command: `python3 -c "import sys; print(open(sys.argv[1]).read())" notes.txt`, want: "allow"},
		{gap: "GAP-0893 fp: separate private read", command: `python3 -c "import sys; print(open('notes.txt').read()); open(sys.argv[1]).read()" ~/.ssh/id_rsa`, want: "allow"},
	})
}
