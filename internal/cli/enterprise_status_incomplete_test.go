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
		!strings.Contains(message, "4 per-user enrollment(s) are pending") {
		t.Fatalf("message = %q", message)
	}

	result.SecurityComplete = true
	result.Warnings = nil
	addEnterpriseSecurityIncompleteReasons(result, false)
	if len(result.Warnings) != 0 {
		t.Fatalf("a complete result got %+v", result.Warnings)
	}
}
