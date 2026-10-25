// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strings"
	"testing"
)

// GAP-0773: a fault that fails only some audit writes (a trigger on the hook
// rows) refused the agent's calls, while every other record still committed
// and cleared the active failure, so status and verify stayed
// security-complete with no audit warning. A write failure the gateway saw
// since it started keeps the audit warning and security_complete false.
func TestStatusAndVerifyReportAnAuditWriteFailureThatOtherRecordsCleared(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	writeFreshLedger(t, h)
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		return 200, []byte(`{"api":{"state":"running"},"telemetry":{"state":"running","details":{"event_history_last_sqlite_class":"constraint_corrupt"}}}`), nil
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		message := messagesOf(result.Warnings, codeAuditWriteFailed)
		if result.SecurityComplete || !strings.Contains(message, "since it started") || !strings.Contains(message, "constraint_corrupt") {
			t.Fatalf("%s: security_complete=%t audit warning %q", action, result.SecurityComplete, message)
		}
		if strings.Contains(messagesOf(result.Errors, codeAuditWriteFailed), "audit") {
			t.Fatalf("%s: the audit warning must not be a verify error: %+v", action, result.Errors)
		}
	}
}
