// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

//go:build !windows

package enterpriseunix

import (
	"context"
	"strings"
	"testing"
)

// id.GAP-1264: status and verify list the gateway's inert human-approval
// warning, which names its own setting, without a "guardrail profile" lead.
func TestStatusAndVerifyListTheInertApprovalWarning(t *testing.T) {
	h := newTestHost(t, "linux")
	requireOK(t, h.run(Options{Action: ActionInstall, PayloadDir: h.payload("1.0.0")}))
	const warning = "guardrail: human approval at HIGH cannot ask: block_at HIGH blocks those findings first; lower hilt.min_severity or raise block_at"
	h.env.HealthGet = func(context.Context) (int, []byte, error) {
		return 200, []byte(`{"api":{"state":"running"},"inspection":{"local":"active","ai_defense":"disabled"},` +
			`"profile_warnings":["` + warning + `"]}`), nil
	}
	for _, action := range []string{ActionStatus, ActionVerify} {
		result := h.run(Options{Action: action})
		got := messagesOf(result.Warnings, codeProfileAssignment)
		if !strings.Contains(got, warning) || strings.Contains(got, "guardrail profile guardrail") {
			t.Fatalf("%s warnings = %q, want %q once, as the gateway words it", action, got, warning)
		}
	}
}
