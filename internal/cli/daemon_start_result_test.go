// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/gateway"
)

// GAP-1860: a start whose boot skipped a configured connector printed only
// "OK" and the health line.
func TestPrintDaemonStartResultNamesSkippedConnectors(t *testing.T) {
	snap := readinessSnapshot(gateway.StateRunning, gateway.StateDisabled)
	snap.Guardrail.Details = map[string]interface{}{"connectors_not_started": []interface{}{"opencode"}}
	out := captureStdout(t, func() { printDaemonStartResult(42, snap) })
	if !strings.Contains(out, "OK (PID 42)") ||
		!strings.Contains(out, "(opencode) was skipped: its setup failed, so it is not enforced") ||
		!strings.Contains(out, "run: defenseclaw setup opencode") {
		t.Fatalf("output = %q, want the skipped connector named with a next step", out)
	}
	snap.Guardrail.Details = nil
	if out := captureStdout(t, func() { printDaemonStartResult(42, snap) }); strings.Contains(out, "skipped") {
		t.Fatalf("output = %q, want no skipped line when every connector started", out)
	}
}

// GAP-1858: the PID registration and readiness waits share one clock, so
// the second wait does not count from zero again.
func TestStartProgressPrinterCountsFromItsStart(t *testing.T) {
	p := newStartProgressPrinter()
	p.started = time.Now().Add(-95 * time.Second)
	out := captureStdout(t, func() { p.report(5*time.Second, "waiting for the gateway to answer") })
	if !strings.Contains(out, "still starting after 1m35s: waiting for the gateway to answer") {
		t.Fatalf("output = %q, want the elapsed time since the start", out)
	}
}
