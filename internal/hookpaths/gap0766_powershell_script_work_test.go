// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package hookpaths

import (
	"fmt"
	"strings"
	"testing"
)

// gap0766Script is n ordinary PowerShell lines, as the GAP-0589 rows send
// them: each assigns the output of a call.
func gap0766Script(n int) string {
	lines := make([]string, n)
	for i := range lines {
		lines[i] = fmt.Sprintf("$o%d = & git rev-parse HEAD", i)
	}
	return strings.Join(lines, "\n")
}

// TestPowerShellScriptReachScansWalkEachWordOnce is rel-1-0-10:GAP-0766, a P1:
// the hook decision for a PowerShell call of the fixture plus 100 ordinary
// lines took 27 s on a Windows host (0.4 s on Linux), past the hook answer
// window: a managed hook failed closed with a deny, and a per-user one
// failed open with nothing checked. The reach scans of a shell call ("does it
// reach a protected file or the DefenseClaw state") resolved every word of
// the text again for each statement that asked, and again for each member of
// the registration set: 446,000 lstat calls for 100 lines. Each distinct word
// is now resolved once per scan.
//
// The bound is a count of write-target walks, not time, so it holds on a busy
// runner: the walks are linear in the lines (one for each distinct word), and
// the same lines twice as many cost twice as many, never four times.
//
// (RegistrationWriteReached walks each distinct word once for the whole
// registration set the same way; its count is read by the gateway timing row
// TestGAP0766CappedPowerShellDecisionStaysInsideTheAnswerWindow.)
func TestPowerShellScriptReachScansWalkEachWordOnce(t *testing.T) {
	home, cwd := t.TempDir(), t.TempDir()
	walks := func(command string) int64 {
		before := writeTargetWalks.Load()
		UnprovenProtectedWrite(command, cwd, home)
		return writeTargetWalks.Load() - before
	}
	// 50 and 100 lines: 100 lines is under the statement budget, where the
	// reach scan still runs for every statement.
	w50, w100 := walks(gap0766Script(50)), walks(gap0766Script(100))
	t.Logf("write-target walks: 50 lines %d, 100 lines %d", w50, w100)
	// A few walks for each line (the words of one line differ from the next
	// only by the variable number), and twice the lines at most twice the
	// walks: never four times (it was 21,100 walks for 100 lines).
	if w100 > 8*100 || w100 > 2*w50+50 {
		t.Errorf("%d walks for 50 lines and %d for 100: want linear, a few for each line", w50, w100)
	}
}
