// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// SPDX-License-Identifier: Apache-2.0

package redaction

import (
	"strings"
	"testing"
)

// TestReasonForAgent_CarveOut pins the managed_enterprise contract:
// ReasonForAgent returns the raw reason when the agent-reason carve-out
// is enabled, and otherwise falls through to the always-redacting
// ForSinkReason compatibility projection. The reason string carries a matched literal so a redacting
// pass would visibly replace it with a "<redacted ...>" placeholder.
func TestReasonForAgent_CarveOut(t *testing.T) {
	// Always restore the carve-out so the rest of the suite keeps the
	// default-redacting contract.
	t.Cleanup(func() {
		SetAgentReasonRedactionDisabled(false)
	})
	t.Setenv(revealEnvVar, "")

	const reason = "matched: PII-EMAIL:alice@example.com"

	// Default: carve-out off, redaction on -> the literal is redacted.
	SetAgentReasonRedactionDisabled(false)
	got := ReasonForAgent(reason)
	if !strings.Contains(got, "<redacted") {
		t.Fatalf("carve-out off must redact the reason, got %q", got)
	}
	if strings.Contains(got, "alice@example.com") {
		t.Fatalf("carve-out off leaked the matched literal, got %q", got)
	}
	if got != ForSinkReason(reason) {
		t.Fatalf("carve-out off must equal ForSinkReason, got %q want %q", got, ForSinkReason(reason))
	}

	// Carve-out on: the agent sees the full, non-redacted reason while
	// persistent compatibility sinks remain redacted.
	SetAgentReasonRedactionDisabled(true)
	if got := ReasonForAgent(reason); got != reason {
		t.Fatalf("carve-out on must return raw reason, got %q want %q", got, reason)
	}
	// The carve-out must NOT leak into the persistent-sink helper.
	if got := ForSinkReason(reason); !strings.Contains(got, "<redacted") {
		t.Fatalf("carve-out must not affect ForSinkReason, got %q", got)
	}

	// Toggle off again: back to redacting.
	SetAgentReasonRedactionDisabled(false)
	if got := ReasonForAgent(reason); !strings.Contains(got, "<redacted") {
		t.Fatalf("carve-out off again must redact, got %q", got)
	}
}
