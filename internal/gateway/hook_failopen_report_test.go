// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
)

func appendHookFailures(t *testing.T, logDir string, lines ...string) {
	t.Helper()
	if err := os.MkdirAll(logDir, 0o700); err != nil {
		t.Fatal(err)
	}
	f, err := os.OpenFile(filepath.Join(logDir, hookFailuresFile), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0o600)
	if err != nil {
		t.Fatal(err)
	}
	defer f.Close()
	for _, line := range lines {
		if _, err := f.WriteString(line); err != nil {
			t.Fatal(err)
		}
	}
}

func degradedAlerts(t *testing.T, store *audit.Store) []audit.Event {
	t.Helper()
	events, err := store.ListAlerts(100)
	if err != nil {
		t.Fatalf("ListAlerts: %v", err)
	}
	var out []audit.Event
	for _, e := range events {
		if e.Action == string(audit.ActionGuardrailDegraded) && strings.Contains(e.Details, "fail-open") {
			out = append(out, e)
		}
	}
	return out
}

// TestReportHookFailOpenCalls pins GAP-0414: Hermes and Copilot calls that
// ran fail-open while the gateway was stopped left only lines in
// hook-failures.jsonl, and no alert or audit row. The gateway now reports
// them, once, as one alert per connector when it starts again.
func TestReportHookFailOpenCalls(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		`{"ts":"2026-10-13T09:49:01Z","connector":"hermes","hook":"hermes-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open"}`+"\n",
		`{"ts":"2026-10-13T09:49:20Z","connector":"copilot","hook":"copilot-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open"}`+"\n",
		`{"ts":"2026-10-13T09:49:40Z","connector":"hermes","hook":"hermes-hook","reason":"gateway returned HTTP 502","category":"transport","fail_mode":"open"}`+"\n",
		// A fail-closed call was blocked in the agent: not a silent bypass.
		`{"ts":"2026-10-13T09:49:50Z","connector":"codex","hook":"codex-hook","reason":"gateway unreachable","category":"transport","fail_mode":"closed"}`+"\n",
		// Older than the report window.
		`{"ts":"2026-09-01T00:00:00Z","connector":"claudecode","hook":"claude-code-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open"}`+"\n",
		"not json\n",
	)

	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatalf("report: %v", err)
	}
	alerts := degradedAlerts(t, store)
	if len(alerts) != 2 {
		t.Fatalf("got %d fail-open alerts, want 2 (copilot, hermes): %+v", len(alerts), alerts)
	}
	byConnector := map[string]audit.Event{}
	for _, a := range alerts {
		byConnector[a.Connector] = a
	}
	hermes, ok := byConnector["hermes"]
	if !ok || !strings.Contains(hermes.Details, "2 hermes hook calls ran without a DefenseClaw check") ||
		!strings.Contains(hermes.Details, "first 2026-10-13T09:49:01Z, last 2026-10-13T09:49:40Z") ||
		!strings.Contains(hermes.Details, "last reason: gateway returned HTTP 502") {
		t.Fatalf("hermes alert = %+v", hermes)
	}
	if hermes.Severity != "HIGH" {
		t.Fatalf("hermes alert severity = %q, want HIGH", hermes.Severity)
	}
	if _, ok := byConnector["copilot"]; !ok {
		t.Fatalf("no copilot alert: %+v", alerts)
	}

	// The next start reports nothing again, then only the new call. A last
	// line still being written waits for the next report.
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	if got := len(degradedAlerts(t, store)); got != 2 {
		t.Fatalf("a second start reported the same calls again: %d alerts", got)
	}
	appendHookFailures(t, logDir,
		`{"ts":"2026-10-13T09:55:00Z","connector":"copilot","hook":"copilot-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open"}`+"\n",
		`{"ts":"2026-10-13T09:56:00Z","connector":"hermes"`,
	)
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	if got := len(degradedAlerts(t, store)); got != 3 {
		t.Fatalf("got %d alerts after one new copilot call, want 3", got)
	}

	// A file replaced by a shorter one is read from its start.
	if err := os.WriteFile(filepath.Join(logDir, hookFailuresFile),
		[]byte(`{"ts":"2026-10-13T09:58:00Z","connector":"hermes","reason":"gateway unreachable","category":"transport","fail_mode":"open"}`+"\n"), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	if got := len(degradedAlerts(t, store)); got != 4 {
		t.Fatalf("got %d alerts after the file was replaced, want 4", got)
	}
}

func TestReportHookFailOpenCallsWithoutAFile(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	if err := reportHookFailOpenCallsIn(logDir, logger, time.Now().UTC()); err != nil {
		t.Fatalf("report without hook-failures.jsonl: %v", err)
	}
	if got := len(degradedAlerts(t, store)); got != 0 {
		t.Fatalf("got %d alerts without a hook-failures file", got)
	}
}

// rel-1-0-4 GAP-0127: with Codex set open, two calls ran fail-open and two
// that DEFENSECLAW_STRICT_AVAILABILITY blocked were logged with fail mode open
// and outcome fail_closed. The recovery alert counts the two that ran.
func TestReportHookFailOpenCallsSkipsStrictClosedCalls(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 21, 8, 30, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		`{"ts":"2026-10-21T08:27:22Z","connector":"codex","hook":"codex-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-10-21T08:27:23Z","connector":"codex","hook":"codex-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-10-21T08:27:47Z","connector":"codex","hook":"codex-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_closed"}`+"\n",
		`{"ts":"2026-10-21T08:27:48Z","connector":"codex","hook":"codex-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_closed"}`+"\n",
	)
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatalf("report: %v", err)
	}
	alerts := degradedAlerts(t, store)
	if len(alerts) != 1 {
		t.Fatalf("got %d fail-open alerts, want 1: %+v", len(alerts), alerts)
	}
	if d := alerts[0].Details; !strings.Contains(d, "2 codex hook calls") || !strings.Contains(d, "last 2026-10-21T08:27:23Z") {
		t.Fatalf("alert counts the strict-closed calls: %s", d)
	}
}

// 1.0.4 review: a diagnostic record (a call the gateway still checked) and a
// strict-blocked Hermes call are not unchecked calls; lines an older hook
// wrote without an outcome, or with unknown (1.0.3 shell hooks), keep the
// fail-mode rule so an upgrade does not hide a call that ran unchecked.
func TestReportHookFailOpenCallsCountsOnlyCallsThatRanUnchecked(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 21, 8, 30, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		`{"ts":"2026-10-21T08:27:20Z","connector":"hermes","hook":"hermes-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open"}`+"\n",
		`{"ts":"2026-10-21T08:27:21Z","connector":"hermes","hook":"hermes-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_closed"}`+"\n",
		`{"ts":"2026-10-21T08:27:22Z","connector":"hermes","hook":"hermes-hook","reason":"rejected malformed traceparent (length=3)","category":"response","fail_mode":"open","outcome":"diagnostic"}`+"\n",
		`{"ts":"2026-10-21T08:27:23Z","connector":"kiro","hook":"kiro-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"unknown"}`+"\n",
		`{"ts":"2026-10-21T08:27:24Z","connector":"kiro","hook":"kiro-hook","reason":"gateway unreachable","category":"transport","fail_mode":"open"}`+"\n",
		`{"ts":"2026-10-21T08:27:25Z","connector":"kiro","hook":"kiro-hook","reason":"gateway unreachable","category":"transport","fail_mode":"closed","outcome":"unknown"}`+"\n",
	)
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatalf("report: %v", err)
	}
	alerts := degradedAlerts(t, store)
	if len(alerts) != 2 {
		t.Fatalf("got %d fail-open alerts, want 2: %+v", len(alerts), alerts)
	}
	details := alerts[0].Details + "\n" + alerts[1].Details
	if !strings.Contains(details, "1 hermes hook call") || strings.Contains(details, "2 hermes hook calls") ||
		!strings.Contains(details, "2 kiro hook calls") {
		t.Fatalf("alerts count calls that did not run unchecked: %s", details)
	}
}
