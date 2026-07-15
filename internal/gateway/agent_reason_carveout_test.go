// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// carveoutReason carries a matched literal (an email) after a PII rule id.
// ForSinkReason keeps the rule id but redacts the literal, so a redacted
// pass is easy to distinguish from the raw pass-through.
const carveoutReason = "matched: PII-EMAIL:alice@example.com"

// TestAgentReasonCarveOut_HookResponses pins the managed_enterprise
// contract for every connector response shaper: with the agent-reason
// carve-out enabled, the reason handed back to codex/cursor/claude is the
// full, non-redacted string; with it disabled the reason is redacted.
//
// All three shapers set the top-level Reason to the same safeReason that
// feeds their nested output message fields, so asserting on Reason covers
// the whole agent-visible message.
func TestAgentReasonCarveOut_HookResponses(t *testing.T) {
	t.Cleanup(func() {
		redaction.SetAgentReasonRedactionDisabled(false)
		redaction.SetDisableAll(false)
	})
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	t.Setenv("DEFENSECLAW_DISABLE_REDACTION", "")
	redaction.SetDisableAll(false)

	shapers := map[string]func() string{
		"cursor": func() string {
			resp := agentHookResponseFor(
				agentHookRequest{ConnectorName: "cursor", HookEventName: "PreToolUse"},
				"block", "block", "HIGH", carveoutReason, nil, "action", false,
				connector.HookCapability{},
			)
			return resp.Reason
		},
		"codex": func() string {
			resp := codexResponseFor(
				"PreToolUse", "block", "block", "HIGH", carveoutReason, nil, "action", false,
			)
			return resp.Reason
		},
		"claudecode": func() string {
			resp := claudeCodeResponseFor(
				claudeCodeHookRequest{HookEventName: "PreToolUse"},
				"block", "block", "HIGH", carveoutReason, nil, "action", false,
			)
			return resp.Reason
		},
	}

	for name, shape := range shapers {
		t.Run(name+"/carveout_on_raw", func(t *testing.T) {
			redaction.SetAgentReasonRedactionDisabled(true)
			got := shape()
			if got != carveoutReason {
				t.Fatalf("%s carve-out on must return raw reason, got %q want %q", name, got, carveoutReason)
			}
			if !strings.Contains(got, "alice@example.com") {
				t.Fatalf("%s carve-out on must expose the matched literal, got %q", name, got)
			}
		})

		t.Run(name+"/carveout_off_redacted", func(t *testing.T) {
			redaction.SetAgentReasonRedactionDisabled(false)
			got := shape()
			if !strings.Contains(got, "<redacted") {
				t.Fatalf("%s carve-out off must redact the reason, got %q", name, got)
			}
			if strings.Contains(got, "alice@example.com") {
				t.Fatalf("%s carve-out off leaked the matched literal, got %q", name, got)
			}
		})
	}
}
