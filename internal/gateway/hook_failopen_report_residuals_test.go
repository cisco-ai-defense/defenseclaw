// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func hookFailOpenCallLine(connector, ts, session, call, event string) string {
	return fmt.Sprintf(`{"ts":%q,"connector":%q,"hook":"h","event":%q,"reason":"gateway unreachable","category":"transport","fail_mode":"open","outcome":"fail_open","session_id":%q,"call_id":%q}`+"\n",
		ts, connector, event, session, call)
}

// rel-1-0-2 GAP-0446 item 8: one Hermes turn wrote 16 hook-failure lines and
// the alert said 16 calls; its Target column was empty. The alert counts
// distinct calls, names the hook events and sessions, and its target is the
// connector.
func TestHookFailOpenAlertCountsCallsAndNamesTheConnector(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		hookFailOpenCallLine("hermes", "2026-10-30T11:59:01Z", "s1", "tool-1", "pre_tool_call"),
		hookFailOpenCallLine("hermes", "2026-10-30T11:59:02Z", "s1", "tool-1", "post_tool_call"),
		hookFailOpenCallLine("hermes", "2026-10-30T11:59:03Z", "s1", "llm-1", "pre_llm_call"),
		hookFailOpenCallLine("hermes", "2026-10-30T11:59:04Z", "s2", "tool-1", "pre_tool_call"),
	)
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	alerts := degradedAlerts(t, store)
	if len(alerts) != 1 {
		t.Fatalf("got %d alerts, want 1: %+v", len(alerts), alerts)
	}
	if d := alerts[0].Details; !strings.Contains(d, "3 hermes hook calls (4 hook events) in 2 sessions ran without a DefenseClaw check") {
		t.Fatalf("alert counts hook events as calls: %s", d)
	}
	if alerts[0].Target != "hermes" {
		t.Fatalf("alert target = %q, want hermes", alerts[0].Target)
	}

	var one hookFailOpenSummary
	one.Connector = "opencode"
	one.count(hookFailureLine{SessionID: "ses_1", CallID: "call_1"}, 10)
	if d := describeHookFailOpenCalls(one); !strings.HasPrefix(d, "1 opencode hook call in 1 session ran without a DefenseClaw check") {
		t.Fatalf("one OpenCode call reads %q", d)
	}
}

// rel-1-0-2 GAP-0446 item 5, the report's half: a line whose configured mode
// was closed but whose call ran (a Hermes or Copilot event that cannot
// block) counts, by its outcome.
func TestReportHookFailOpenCallsCountsTheLoggedOutcome(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 30, 12, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir,
		`{"ts":"2026-10-30T11:59:01Z","connector":"copilot","hook":"h","reason":"gateway unreachable","category":"transport","fail_mode":"closed","outcome":"fail_open","call_id":"c1"}`+"\n",
		`{"ts":"2026-10-30T11:59:02Z","connector":"copilot","hook":"h","reason":"gateway unreachable","category":"transport","fail_mode":"closed","outcome":"fail_closed","call_id":"c2"}`+"\n",
	)
	if err := reportHookFailOpenCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	alerts := degradedAlerts(t, store)
	if len(alerts) != 1 || !strings.Contains(alerts[0].Details, "1 copilot hook call ran without") {
		t.Fatalf("alerts = %+v, want one for the call that ran", alerts)
	}
}

// rel-1-0-2 GAP-0446 item 3: lines after a recorded position are new, so a
// gateway that stayed stopped for more than 7 days still reports them. A
// first read of a file still leaves out lines older than 7 days.
func TestReportHookFailOpenCallsKeepsOldLinesAfterAKnownPosition(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	start := time.Date(2026, 10, 1, 9, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir, hookFailOpenLine("hermes", "2026-10-01T09:00:00Z"))
	if err := reportHookFailOpenCallsIn(logDir, logger, start); err != nil {
		t.Fatal(err)
	}
	appendHookFailures(t, logDir, hookFailOpenLine("copilot", "2026-10-01T10:00:00Z"))
	if err := reportHookFailOpenCallsIn(logDir, logger, start.Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if alerts := degradedAlerts(t, store); len(alerts) != 2 {
		t.Fatalf("got %d alerts, want 2: the copilot call after the recorded position was dropped: %+v", len(alerts), alerts)
	}

	fresh := filepath.Join(t.TempDir(), "logs")
	appendHookFailures(t, fresh, hookFailOpenLine("codex", "2026-10-01T10:00:00Z"))
	if err := reportHookFailOpenCallsIn(fresh, logger, start.Add(10*24*time.Hour)); err != nil {
		t.Fatal(err)
	}
	if alerts := degradedAlerts(t, store); len(alerts) != 2 {
		t.Fatalf("a first read reported a 10-day-old line: %+v", alerts)
	}
}

// rel-1-0-2 GAP-0446 item 3: a call that ran fail-open while the gateway was
// up (busy, a server error) is reported while the gateway runs, once, not at
// the next start.
func TestRunningGatewayReportsFailOpenCallsWithoutARestart(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	dataDir := t.TempDir()
	interval := hookFailOpenReportInterval
	hookFailOpenReportInterval = 10 * time.Millisecond
	t.Cleanup(func() { hookFailOpenReportInterval = interval })
	s := &Sidecar{logger: logger, cfg: &config.Config{DataDir: dataDir}}
	ctx, cancel := context.WithCancel(context.Background())
	done := make(chan struct{})
	go func() {
		s.watchHookFailOpenCalls(ctx)
		close(done)
	}()
	t.Cleanup(func() {
		cancel()
		<-done
	})
	time.Sleep(30 * time.Millisecond)
	appendHookFailures(t, filepath.Join(dataDir, "logs"), hookFailOpenLine("copilot", time.Now().UTC().Format(time.RFC3339)))
	deadline := time.Now().Add(10 * time.Second)
	for len(degradedAlerts(t, store)) == 0 {
		if time.Now().After(deadline) {
			t.Fatal("a running gateway did not report the fail-open call")
		}
		time.Sleep(20 * time.Millisecond)
	}
	time.Sleep(100 * time.Millisecond)
	if alerts := degradedAlerts(t, store); len(alerts) != 1 || alerts[0].Connector != "copilot" {
		t.Fatalf("alerts = %+v, want one copilot alert", alerts)
	}
}

// A managed gateway starts no fail-open report timer.
func TestManagedGatewayStartsNoFailOpenReportTimer(t *testing.T) {
	_, logger := testStoreAndLogger(t)
	SetManagedEnterpriseActive(true)
	t.Cleanup(func() { SetManagedEnterpriseActive(false) })
	s := &Sidecar{logger: logger, cfg: &config.Config{DataDir: t.TempDir()}}
	done := make(chan struct{})
	go func() {
		s.watchHookFailOpenCalls(context.Background())
		close(done)
	}()
	select {
	case <-done:
	case <-time.After(5 * time.Second):
		t.Fatal("the managed gateway runs the fail-open report loop")
	}
}

// rel-1-0-2 GAP-0446 item 9: with a custom data_dir the hooks still write to
// DEFENSECLAW_HOME (else ~/.defenseclaw), which the report did not read. It
// reads both, a folder once, and creates no logs folder for a missing file.
func TestReportHookFailOpenCallsReadsTheHooksHomeWithACustomDataDir(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	hooksHome, dataDir := t.TempDir(), t.TempDir()
	home := hookFailuresHooksHome
	hookFailuresHooksHome = func() string { return hooksHome }
	t.Cleanup(func() { hookFailuresHooksHome = home })
	appendHookFailures(t, filepath.Join(hooksHome, "logs"), hookFailOpenLine("codex", time.Now().UTC().Format(time.RFC3339)))
	s := &Sidecar{logger: logger, cfg: &config.Config{DataDir: dataDir}}
	s.reportHookFailOpenCalls()
	if alerts := degradedAlerts(t, store); len(alerts) != 1 || alerts[0].Connector != "codex" {
		t.Fatalf("alerts = %+v, want the codex call from the hooks' folder", alerts)
	}
	if _, err := os.Stat(filepath.Join(dataDir, "logs")); !os.IsNotExist(err) {
		t.Fatalf("the report created the data directory's logs folder: %v", err)
	}
	if dirs := hookFailOpenLogDirs(hooksHome); len(dirs) != 1 {
		t.Fatalf("one folder listed twice: %v", dirs)
	}
	link := filepath.Join(t.TempDir(), "home-link")
	if err := os.Symlink(hooksHome, link); err == nil {
		if dirs := hookFailOpenLogDirs(link); len(dirs) != 1 {
			t.Fatalf("a folder reached through a link listed twice: %v", dirs)
		}
	}
}
