// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package templatecli

import (
	"bytes"
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/substrate/attest"
)

// rel-1-0-10 GAP-0279: the scan output says plainly that a user-scope plugin
// does not load in an actor, and prints nothing extra when there is no note.
func TestPrintScanShowsTheUserScopePluginNote(t *testing.T) {
	sum := attest.ScanSummary{Plugins: 1, Verdict: attest.VerdictClean, Findings: map[string]int{},
		Notes: []string{"user-scope plugins do not load in Substrate actors, because personal config is restricted; use project or managed scope instead. Plugins in a personal folder: demo"}}
	var out bytes.Buffer
	printScan(&out, sum, attest.HookChecks{RootOwned: true, PhoneHomeOff: true})
	got := out.String()
	if !strings.Contains(got, "NOTE user-scope plugins do not load in Substrate actors") || !strings.Contains(got, "project or managed scope") {
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
