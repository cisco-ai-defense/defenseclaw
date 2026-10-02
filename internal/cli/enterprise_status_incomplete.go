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
	"fmt"
	"sort"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/enterprisestatus"
)

// claudeAttestationHint names the step that verifies Claude Code's machine
// policy on Windows. Each install and upgrade replaces the hook binary, which
// makes an earlier attestation stale.
const claudeAttestationHint = " (it needs an administrator's attestation, and each upgrade makes the last one stale: " +
	"confirm that an enrolled user's Claude Code runs DefenseClaw's hooks, then run Setup /repair ATTESTCLAUDEEFFECTIVEPOLICY=1, " +
	"or `enterprise windows repair --profile standalone --attest-claude-effective-policy`)"

// addEnterpriseSecurityIncompleteReasons names why security is not complete
// when nothing else in the result does. Windows standalone status and verify
// reported security_complete:false with empty errors and warnings, so an
// administrator had to read the guardian log to learn the cause.
func addEnterpriseSecurityIncompleteReasons(result *enterprisestatus.Result, transactionPending bool) {
	if result == nil || result.SecurityComplete || len(result.Errors) > 0 || len(result.Warnings) > 0 {
		return
	}
	var reasons []string
	if transactionPending {
		reasons = append(reasons, "a lifecycle transaction is pending")
	}
	if !result.Readiness.Guardian {
		reasons = append(reasons, "the guardian is not ready")
	}
	names := make([]string, 0, len(result.MachinePolicy))
	for name := range result.MachinePolicy {
		names = append(names, name)
	}
	sort.Strings(names)
	for _, name := range names {
		state := result.MachinePolicy[name]
		if state.Ownership != "off" && state.Lock == "enforce" && state.EffectiveLock != "enforce" {
			reason := fmt.Sprintf("the %s machine policy is not verified in force", name)
			if name == "claudecode" {
				reason += claudeAttestationHint
			}
			reasons = append(reasons, reason)
		}
	}
	pending, failed := result.Enrollment.Pending, result.Enrollment.Failed
	if pending > 0 {
		reasons = append(reasons, fmt.Sprintf("%d per-user enrollment(s) are pending (waiting for an active, connected session of that account)", pending))
	}
	if failed > 0 {
		reasons = append(reasons, fmt.Sprintf("%d per-user enrollment(s) failed", failed))
	}
	noReason := len(reasons) == 0
	if noReason {
		reasons = append(reasons, "the installer gave no reason")
	}
	// Point at per-account detail only when an account is pending or
	// failed, and at the guardian log only when the guardian is the cause
	// or nothing else is named (GAP-1733).
	where := ""
	switch {
	case pending > 0 || failed > 0:
		where = "; each pending or failed account's Account line (enrollment.accounts[].reason in --json) says why"
	case !result.Readiness.Guardian || noReason:
		where = "; the guardian log names the cause"
	}
	result.AddWarning("security_incomplete", "security is not complete: "+strings.Join(reasons, "; ")+where)
}
