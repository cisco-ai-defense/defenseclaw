// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"fmt"
	"os"
	"path/filepath"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
)

func hookFailOpenLine(connector, ts string) string {
	return fmt.Sprintf(`{"ts":%q,"connector":%q,"hook":"h","reason":"gateway unreachable","category":"transport","fail_mode":"open"}`+"\n", ts, connector)
}

// rel-1-0-2 GAP-0446: a hook-failure log replaced by a longer file is read
// from its start, not from the middle of a line at the old offset.
func TestReportHookFailOpenCallsRereadsALongerReplacement(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	appendHookFailures(t, logDir, hookFailOpenLine("hermes", "2026-10-13T09:00:00Z"))
	if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	var replacement strings.Builder
	for i := 0; i < 5; i++ {
		replacement.WriteString(hookFailOpenLine("copilot", fmt.Sprintf("2026-10-13T09:1%d:00Z", i)))
	}
	if err := os.WriteFile(filepath.Join(logDir, hookFailuresFile), []byte(replacement.String()), 0o600); err != nil {
		t.Fatal(err)
	}
	if err := reportHookFailureCallsIn(logDir, logger, now); err != nil {
		t.Fatal(err)
	}
	var copilot string
	for _, alert := range degradedAlerts(t, store) {
		if alert.Connector == "copilot" {
			copilot = alert.Details
		}
	}
	if !strings.Contains(copilot, "5 copilot hook calls") {
		t.Fatalf("copilot alert = %q, want all 5 calls of the replacement file", copilot)
	}
}

// A connector already recorded before a later connector's audit write
// failed is not recorded again for the same lines; its newer lines are.
func TestReadHookFailOpenCallsSkipsConnectorsAlreadyRecorded(t *testing.T) {
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	first := hookFailOpenLine("hermes", "2026-10-13T09:00:00Z") + hookFailOpenLine("copilot", "2026-10-13T09:01:00Z")
	appendHookFailures(t, logDir, first)
	_, read, err := readHookFailureCalls(logDir, now)
	if err != nil {
		t.Fatal(err)
	}
	// hermes was recorded, then copilot's write failed.
	read.start.Done = map[string]int64{"hermes": read.next}
	if err := writeHookFailuresReported(logDir, read.start); err != nil {
		t.Fatal(err)
	}
	appendHookFailures(t, logDir, hookFailOpenLine("hermes", "2026-10-13T09:02:00Z"))
	summaries, _, err := readHookFailureCalls(logDir, now)
	if err != nil {
		t.Fatal(err)
	}
	got := map[string]int{}
	for _, sum := range summaries {
		got[sum.Connector] = sum.Calls
	}
	if got["copilot"] != 1 || got["hermes"] != 1 {
		t.Fatalf("calls = %v, want copilot 1 (not recorded yet) and hermes 1 (only the new line)", got)
	}
}

// With more than hookFailOpenReportMaxBytes unread, the report reads the
// newest lines, starting at a line boundary.
func TestReadHookFailOpenCallsReadsTheNewestLinesOfALargeFile(t *testing.T) {
	logDir := filepath.Join(t.TempDir(), "logs")
	now := time.Date(2026, 10, 13, 10, 0, 0, 0, time.UTC)
	old := hookFailOpenLine("codex", "2026-10-13T08:00:00Z")
	var body strings.Builder
	for int64(body.Len()) < hookFailOpenReportMaxBytes+int64(len(old)) {
		body.WriteString(old)
	}
	body.WriteString(hookFailOpenLine("hermes", "2026-10-13T09:59:00Z"))
	appendHookFailures(t, logDir, body.String())
	summaries, read, err := readHookFailureCalls(logDir, now)
	if err != nil {
		t.Fatal(err)
	}
	var hermes bool
	for _, sum := range summaries {
		hermes = hermes || sum.Connector == "hermes"
	}
	if !hermes || read.next != int64(body.Len()) {
		t.Fatalf("summaries %+v next %d of %d: the newest line was not read", summaries, read.next, body.Len())
	}
}

// The start-up wiring: recordLocalWriteGapV8 (gateway start and local
// history recovery) reports the fail-open calls (GAP-0446 item 7).
func TestRecordLocalWriteGapReportsHookFailOpenCalls(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	dataDir := t.TempDir()
	appendHookFailures(t, filepath.Join(dataDir, "logs"), hookFailOpenLine("hermes", time.Now().UTC().Format(time.RFC3339)))
	s := &Sidecar{logger: logger, cfg: &config.Config{DataDir: dataDir}}
	s.recordLocalWriteGapV8()
	if alerts := degradedAlerts(t, store); len(alerts) != 1 || alerts[0].Connector != "hermes" {
		t.Fatalf("alerts after the start-up report = %+v, want one hermes alert", alerts)
	}
}
