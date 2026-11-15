// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"slices"
	"testing"
)

// rel-1-0-10:GAP-0859: an awk program behind an exact wrapper reaches
// analyzeStructuredArgv, which reads the commands it starts like the shell
// parser does for a bare call (GAP-0499).
func TestWrappedAwkProgramCommandsAreRead(t *testing.T) {
	const program = `awk 'BEGIN{system("touch /home/a/.ssh/authorized_keys")}'`
	for _, wrapper := range []string{"", "env ", "sudo ", "timeout 5 ", "nice "} {
		facts := Analyze(Input{Tool: "shell", Command: wrapper + program, CWD: "/home/a", ActiveHome: "/home/a"})
		var programs []string
		for _, command := range facts.Commands {
			programs = append(programs, command.Program)
		}
		if !slices.Contains(programs, "touch") {
			t.Errorf("%q: programs %v, want the touch the awk program starts", wrapper+program, programs)
		}
	}
}
