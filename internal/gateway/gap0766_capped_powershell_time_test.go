// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"testing"
	"time"
)

// TestGAP0766CappedPowerShellDecisionStaysInsideTheAnswerWindow is the native
// timing row of rel-1-0-10:GAP-0766 (P1): one Claude Code PowerShell hook
// decision for the UAC event-viewer fixture beside 100 ordinary lines took
// about 27 s on a hosted Windows runner (0.4 s on Linux), past the hook answer
// window, so a managed hook failed closed with a deny and a per-user one
// failed open with nothing checked. The reach scans resolved every word of the
// call again for each statement and for each registered hook file; the work
// is now one walk for each distinct word (the work-unit bound is
// hookpaths.TestPowerShellScriptReachScansWalkEachWordOnce).
//
// The wall-clock bound is deliberately loose (several times the answer
// window): it catches the superlinear case on a busy runner without flaking
// on a slow one. Every verdict is the one the five-tier rows of
// TestGAP0589PowerShellCappedReadingFiveTiers pin.
func TestGAP0766CappedPowerShellDecisionStaysInsideTheAnswerWindow(t *testing.T) {
	gap0589WindowsHost(t)
	cwd := t.TempDir()
	fixture := windowsAtomicParityPositives[2].command
	api := gap0589TierAPI(t, "claudecode", "default", false, boundedTestTiers[0].tier)
	route := gap0589Routes[0]
	const limit = 8 * time.Second
	for _, row := range []struct{ name, command string }{
		{"first+100", gap0589Join([]string{fixture}, gap0589Filler(100))},
		{"100+last", gap0589Join(gap0589Filler(100), []string{fixture})},
		{"127 lines", gap0589Join(gap0589Filler(127))},
	} {
		started := time.Now()
		action, findings := route.decide(t, api, cwd, row.command)
		elapsed := time.Since(started)
		t.Logf("%s: %s in %s", row.name, action, elapsed.Round(time.Millisecond))
		if elapsed > limit {
			t.Errorf("%s: the decision took %s, want under %s (the hook answer window is about 3.4 s)", row.name, elapsed, limit)
		}
		if boundedParse(action) < boundedParse("alert") {
			t.Errorf("%s: action %s, want at least the unknown tier; findings %v", row.name, action, findings)
		}
	}
}
