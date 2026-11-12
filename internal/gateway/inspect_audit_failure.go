// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/managed"
)

const (
	// inspectAuditDegradedReason is the reason of an allow whose audit row
	// could not be written in the default and permissive tiers.
	inspectAuditDegradedReason = "DefenseClaw audit is degraded: this call was allowed, but its audit record " +
		"could not be written. Check the DefenseClaw data directory and gateway log."
	// inspectAuditFailedClosedReason is the reason of the strict, managed or
	// sandbox block of a call whose audit row could not be written.
	inspectAuditFailedClosedReason = "DefenseClaw could not write the audit record of this call, so it was " +
		"blocked. Operators: check the free space of the DefenseClaw data directory and the gateway log " +
		"for \"inspect audit persistence failed\"."
)

// inspectAuditFailureVerdict applies the hook route's failed-audit rule
// (hookAuditFailureResponse) to a direct inspect verdict whose audit row
// could not be written: the disk is full, or the audit store stayed busy
// through its busy timeout and retries (GAP-0593). The OpenClaw plugin's
// tool and prompt checks arrive only on this route.
//
//   - An existing block is never weakened.
//   - A computed allow or alert in a per-user default or permissive tier
//     stays allowed: an allow carries the degraded-audit warning as its
//     reason, an alert keeps its finding (the hook routes' allow, whose raw
//     action is alert, is the same decision).
//   - Every other verdict, and every verdict in the strict tier, on a managed
//     install or for a sandbox, becomes a block in action mode, as a failed
//     check does on the hook route.
//   - Results the caller cannot refuse (tool results, completions and
//     responses) keep their verdict, as on the strict install-window gate.
//   - Secure Client keeps its separate failure contract and its answers.
//
// It reports whether the verdict became a block.
func (a *APIServer) inspectAuditFailureVerdict(ctx context.Context, connectorName string, req *ToolInspectRequest, verdict *ToolInspectVerdict) bool {
	if verdict == nil || req == nil || verdict.Action == "block" {
		return false
	}
	switch strings.ToLower(strings.TrimSpace(req.Direction)) {
	case "tool_result", "tool-response", "completion", "response":
		return false
	}
	cfg := a.decisionConfig(ctx)
	if cfg != nil && cfg.SecureClientIntegration() {
		return false
	}
	if (verdict.Action == "allow" || verdict.Action == "alert") && cfg != nil &&
		!managed.IsManagedEnterprise(cfg.DeploymentMode) &&
		cfg.HookPolicyTierForConnector(connectorName) != config.HookPolicyTierStrict &&
		!sandboxHookForConnector(ctx, connectorName) {
		if verdict.Action == "alert" {
			return false
		}
		verdict.RawAction = "alert"
		verdict.Severity = "WARN"
		verdict.WouldBlock = false
		verdict.Reason = inspectAuditDegradedReason
		return false
	}
	verdict.Action, verdict.RawAction, verdict.Severity = "block", "block", "HIGH"
	verdict.Mode = "action"
	verdict.WouldBlock = false
	verdict.Reason = inspectAuditFailedClosedReason
	return true
}
