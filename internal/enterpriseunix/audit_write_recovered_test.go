// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strings"
	"testing"
	"time"
)

// A persistent audit write failure (a full disk) that was fixed, with later
// records written, keeps its class in /health for the gateway's whole life.
// Status and verify keep reporting it only within auditWriteFailureWindow of
// the last failed write, not until the gateway restarts (GAP-1627); a recent
// one, or one without a time, is still reported (GAP-0773).
func TestStatusAndVerifyStopReportingALongRecoveredAuditWriteFailure(t *testing.T) {
	for _, tc := range []struct {
		name      string
		failureAt func(now time.Time) string
		reported  bool
	}{
		{"recovered long ago", func(now time.Time) string {
			return now.Add(-auditWriteFailureWindow - time.Minute).UTC().Format(time.RFC3339Nano)
		}, false},
		{"recent", func(now time.Time) string { return now.Add(-time.Minute).UTC().Format(time.RFC3339Nano) }, true},
		{"no time", func(time.Time) string { return "" }, true},
	} {
		t.Run(tc.name, func(t *testing.T) {
			h := newTestHost(t, "linux")
			requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
			writeFreshLedger(t, h)
			health := func(details string) {
				h.env.HealthGet = func(context.Context) (int, []byte, error) {
					return 200, []byte(`{"api":{"state":"running"},"telemetry":{"state":"running","details":{` + details + `}}}`), nil
				}
			}
			health("")
			baseline := map[string]bool{}
			for _, action := range []string{ActionStatus, ActionVerify} {
				baseline[action] = h.run(Options{Action: action}).SecurityComplete
			}
			details := `"event_history_last_sqlite_class":"full"`
			if at := tc.failureAt(h.env.Now()); at != "" {
				details += `,"event_history_last_failure_at":"` + at + `"`
			}
			health(details)
			for _, action := range []string{ActionStatus, ActionVerify} {
				result := h.run(Options{Action: action})
				message := messagesOf(result.Warnings, codeAuditWriteFailed)
				if tc.reported {
					if result.SecurityComplete || !strings.Contains(message, "full") {
						t.Fatalf("%s: security_complete=%t audit warning %q", action, result.SecurityComplete, message)
					}
					continue
				}
				if message != "" || result.SecurityComplete != baseline[action] {
					t.Fatalf("%s: a failure fixed %s ago still reported: warning %q security_complete=%t (want %t)",
						action, auditWriteFailureWindow, message, result.SecurityComplete, baseline[action])
				}
			}
		})
	}
}
