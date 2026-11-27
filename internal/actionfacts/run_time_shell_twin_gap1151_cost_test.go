// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package actionfacts

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/shellparse"
)

// TestGAP1151PendingLineTwinCost: an eval, -c or written-file run on a line
// whose here-documents are still pending respells them as here-strings
// (rel-1-0-10:GAP-1151, GAP-2291). That reads each document once, not once
// per run, and drops overlapped respellings in one sweep (CHK-RF-HOOKSHELL-R2
// B1): 2000 pending documents under 2000 evals, and 6000 under one eval, take
// within 6x of the same command with the evals on a line before the
// documents, where nothing is pending (the same evals, documents and size).
func TestGAP1151PendingLineTwinCost(t *testing.T) {
	documents := func(docs int) (operators, bodies string) {
		return "cat" + strings.Repeat(" <<A", docs), strings.Repeat("a\nA\n", docs)
	}
	pendingLine := func(docs, evals int) string {
		operators, bodies := documents(docs)
		return operators + strings.Repeat("; eval x", evals) + "\n" + bodies
	}
	evalsFirst := func(docs, evals int) string {
		operators, bodies := documents(docs)
		return strings.Repeat("eval x; ", evals) + "\n" + operators + "\n" + bodies
	}
	cost := func(command string) time.Duration {
		best := time.Duration(1<<63 - 1)
		for range 3 {
			started := time.Now()
			RunTimeShellTwin(command)
			best = min(best, time.Since(started))
		}
		return best
	}
	twin, ok, _, _ := RunTimeShellTwin(pendingLine(3, 1))
	if _, parsed := shellparse.Parse(twin); !ok || !parsed || strings.Count(twin, "<<< 'a'") != 3 {
		t.Fatalf("three documents pending under an eval: twin %q ok=%v, want three here-strings that parse", twin, ok)
	}
	for _, row := range []struct{ docs, evals int }{{2000, 2000}, {6000, 1}} {
		if twin, ok, _, _ := RunTimeShellTwin(pendingLine(row.docs, row.evals)); !ok || strings.Count(twin, "<<< 'a'") != row.docs {
			t.Fatalf("%d documents pending under %d evals: ok=%v, %d here-strings", row.docs, row.evals, ok, strings.Count(twin, "<<< 'a'"))
		}
		pending, first := cost(pendingLine(row.docs, row.evals)), cost(evalsFirst(row.docs, row.evals))
		ratio := float64(pending) / float64(first)
		t.Logf("%d documents, %d evals: %v pending, %v evals first (%.1fx)", row.docs, row.evals, pending, first, ratio)
		if ratio > 6 {
			t.Errorf("%d documents pending under %d evals took %v, %.1fx the %v with the evals first; want at most 6x", row.docs, row.evals, pending, ratio, first)
		}
	}
}
