// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package cli

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// TestApplyPrivacyConfig_AgentReasonCarveOut pins that the
// managed_enterprise agent-reason carve-out is wired from deployment_mode:
// applyPrivacyConfig must enable redaction.ReasonForAgent passthrough in
// managed_enterprise and leave it redacting in every other mode, without
// disturbing the global DisableAll kill-switch.
func TestApplyPrivacyConfig_AgentReasonCarveOut(t *testing.T) {
	t.Cleanup(func() {
		redaction.SetAgentReasonRedactionDisabled(false)
		redaction.SetDisableAll(false)
	})
	t.Setenv("DEFENSECLAW_REVEAL_PII", "")
	t.Setenv("DEFENSECLAW_DISABLE_REDACTION", "")

	const reason = "matched: PII-EMAIL:alice@example.com"

	// managed_enterprise with redaction ON: the agent still sees raw.
	applyPrivacyConfig(&config.Config{DeploymentMode: "managed_enterprise"})
	if got := redaction.ReasonForAgent(reason); got != reason {
		t.Fatalf("managed_enterprise must expose raw reason to agent, got %q want %q", got, reason)
	}
	// Persistent sinks are unaffected — they still redact.
	if got := redaction.ForSinkReason(reason); !strings.Contains(got, "<redacted") {
		t.Fatalf("managed_enterprise must not disable persistent-sink redaction, got %q", got)
	}

	// Non-managed mode: agent reason redacts per the flag.
	applyPrivacyConfig(&config.Config{DeploymentMode: "local"})
	if got := redaction.ReasonForAgent(reason); !strings.Contains(got, "<redacted") {
		t.Fatalf("non-managed mode must redact the agent reason, got %q", got)
	}

	// Empty deployment mode is treated as non-managed.
	applyPrivacyConfig(&config.Config{})
	if got := redaction.ReasonForAgent(reason); !strings.Contains(got, "<redacted") {
		t.Fatalf("empty deployment mode must redact the agent reason, got %q", got)
	}
}
