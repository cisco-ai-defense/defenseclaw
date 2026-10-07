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

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// Status reported security_complete:false and pending:4 with empty errors and
// warnings (WIN-R1-22).
func TestEnterpriseSecurityIncompleteNamesItsReasons(t *testing.T) {
	result := &enterprisestatus.Result{
		Readiness: enterprisestatus.Readiness{Guardian: true},
		MachinePolicy: map[string]enterprisestatus.MachinePolicyState{
			"claudecode": {Ownership: "merge", Lock: "enforce"},
			"codex":      {Ownership: "merge", Lock: "enforce", EffectiveLock: "enforce"},
		},
		Enrollment: enterprisestatus.Enrollment{Targets: 6, Pending: 4},
	}
	addEnterpriseSecurityIncompleteReasons(result, false)
	if len(result.Warnings) != 1 || result.Warnings[0].Code != "security_incomplete" {
		t.Fatalf("warnings = %+v", result.Warnings)
	}
	message := result.Warnings[0].Message
	if !strings.Contains(message, "claudecode machine policy") || strings.Contains(message, "codex machine policy") ||
		!strings.Contains(message, "/repair ATTESTCLAUDEEFFECTIVEPOLICY=1") ||
		!strings.Contains(message, "4 per-user enrollment(s) are pending (waiting for an active, connected session") ||
		!strings.Contains(message, "each pending or failed account's Account line (enrollment.accounts[].reason in --json) says why") {
		t.Fatalf("message = %q", message)
	}
	// GAP-1733: with nothing pending, only the attestation is named, not a
	// per-account cause.
	result.Enrollment.Pending = 0
	result.Warnings = nil
	addEnterpriseSecurityIncompleteReasons(result, false)
	if message := result.Warnings[0].Message; strings.Contains(message, "account") || strings.Contains(message, "guardian log") {
		t.Fatalf("nothing pending, message = %q", message)
	}
	result.Enrollment.Pending = 4

	// GAP-0223: a deployment that enrolled nobody for Codex, Claude Code or
	// Cursor names that, not a guardian log that names no cause.
	empty := &enterprisestatus.Result{Readiness: enterprisestatus.Readiness{Guardian: true}}
	addEnterpriseSecurityIncompleteReasons(empty, false)
	if message := empty.Warnings[0].Message; !strings.Contains(message, "no account is enrolled for Codex, Claude Code or Cursor") ||
		strings.Contains(message, "guardian log") {
		t.Fatalf("no enabled target, message = %q", message)
	}

	result.SecurityComplete = true
	result.Warnings = nil
	addEnterpriseSecurityIncompleteReasons(result, false)
	if len(result.Warnings) != 0 {
		t.Fatalf("a complete result got %+v", result.Warnings)
	}
}

// GAP-2494: a repair that restored the Cursor adapter still names why
// security is not complete; a warning that explains it still suppresses it.
func TestEnterpriseSecurityIncompleteIgnoresInformationalWarnings(t *testing.T) {
	result := &enterprisestatus.Result{
		Readiness: enterprisestatus.Readiness{Guardian: true},
		MachinePolicy: map[string]enterprisestatus.MachinePolicyState{
			"claudecode": {Ownership: "merge", Lock: "enforce"},
		},
	}
	result.AddWarning("cursor_adapter_restored", "restored")
	result.AddWarning("stale_lifecycle_journal_removed", "removed")
	addEnterpriseSecurityIncompleteReasons(result, false)
	if len(result.Warnings) != 3 || result.Warnings[2].Code != "security_incomplete" ||
		!strings.Contains(result.Warnings[2].Message, "ATTESTCLAUDEEFFECTIVEPOLICY=1") {
		t.Fatalf("warnings = %+v", result.Warnings)
	}

	result.Warnings = nil
	result.AddWarning("cursor_adapter_restored", "restored")
	result.AddWarning("user_registrations_pending", "pending")
	addEnterpriseSecurityIncompleteReasons(result, false)
	if len(result.Warnings) != 2 {
		t.Fatalf("an explaining warning did not suppress the reason: %+v", result.Warnings)
	}
}
