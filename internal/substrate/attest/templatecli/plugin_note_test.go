// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package templatecli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// rel-1-0-10 GAP-0279: the scan output says plainly that a plugin folder in a
// personal skills folder does not load as a plugin in an actor, and prints nothing extra when there is no note.
func TestPrintScanShowsTheUserScopePluginNote(t *testing.T) {
	sum := attest.ScanSummary{Plugins: 1, Verdict: attest.VerdictClean, Findings: map[string]int{},
		Notes: []string{"a plugin folder in a personal skills folder (~/.claude/skills) does not load as a plugin in Substrate actors, because personal config is restricted (CLAUDE_CODE_RESTRICT_PERSONAL_CONFIG=1): Claude Code loads it as skills only. Install it as a marketplace plugin enabled at project or managed scope instead. Affected: demo"}}
	var out bytes.Buffer
	printScan(&out, sum, attest.HookChecks{RootOwned: true, PhoneHomeOff: true})
	got := out.String()
	if !strings.Contains(got, "NOTE a plugin folder in a personal skills folder") || !strings.Contains(got, "project or managed scope") {
		t.Fatalf("scan output lacks the note:\n%s", got)
	}
	if !strings.Contains(got, "verdict clean") {
		t.Fatalf("the note changed the verdict line:\n%s", got)
	}

	sum.Notes = nil
	out.Reset()
	printScan(&out, sum, attest.HookChecks{RootOwned: true, PhoneHomeOff: true})
	if strings.Contains(out.String(), "NOTE") {
		t.Fatalf("a scan without notes printed one:\n%s", out.String())
	}
}
