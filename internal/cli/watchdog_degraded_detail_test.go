// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
)

// GAP-1968: watchdog status in the degraded state names the cause the
// watchdog logged and the next step, not a generic sentence.
func TestWatchdogStatusDegradedNamesTheLoggedCause(t *testing.T) {
	dataDir := t.TempDir()
	if got := lastWatchdogDegradedDetail(dataDir); got != "" {
		t.Fatalf("detail without a log = %q", got)
	}
	log := "2026-10-02T22:30:00Z [watchdog] protection degraded: Required guardrail is stopped\n" +
		"2026-10-02T22:31:00Z [watchdog] gateway recovered: degraded → healthy\n" +
		"2026-10-02T22:34:28Z [watchdog] protection degraded: Required connector opencode is missing from the health response\n"
	if err := os.WriteFile(filepath.Join(dataDir, watchdogLogFile), []byte(log), 0o600); err != nil {
		t.Fatal(err)
	}
	detail := lastWatchdogDegradedDetail(dataDir)
	if detail != "Required connector opencode is missing from the health response" {
		t.Fatalf("detail = %q", detail)
	}
	out := captureStdout(t, func() { printWatchdogDegraded(detail) })
	for _, want := range []string{"degraded: Required connector opencode is missing", "defenseclaw setup opencode"} {
		if !strings.Contains(out, want) {
			t.Errorf("output %q does not contain %q", out, want)
		}
	}
	out = captureStdout(t, func() { printWatchdogDegraded("") })
	if !strings.Contains(out, "defenseclaw-gateway status") || strings.Contains(out, "did not converge") {
		t.Errorf("generic degraded output %q", out)
	}
}
