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

package manager

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/openshell/sandboxapi"
)

// An alert verdict let the tool call run and flagged it, but it never
// reached the activity feed ("every finding lands in the feed"). It is a
// finding event now, with the verdict's severity; allowed and blocked
// verdicts are not.
func TestFlaggedHookVerdictsReachTheFeed(t *testing.T) {
	e := newEnv(t, nil)
	sb := e.create(sandboxapi.CreateRequest{Name: "alertbox"})
	binding, _ := e.store.Lookup(sb.Name)
	base := HookDecision{BindingID: binding.ID, SandboxName: sb.Name, Event: "PreToolUse", Tool: "Bash"}

	allow := base
	allow.Action, allow.Severity = "allow", "NONE"
	e.m.ObserveHookDecision(allow)
	block := base
	block.Action, block.Severity, block.WouldBlock = "block", "HIGH", true
	block.Reason = "Blocked by DefenseClaw rule E2E-SANDBOX-MARKER: E2E sandbox marker command."
	e.m.ObserveHookDecision(block)
	alert := base
	alert.Action, alert.Severity = "alert", "high"
	alert.Reason = "Allowed but flagged by DefenseClaw rule E2E-SANDBOX-ALERT: E2E sandbox alert marker. " +
		"The action was allowed; DefenseClaw recorded the finding for the user's review."
	e.m.ObserveHookDecision(alert)

	var findings []sandboxapi.ActivityEvent
	for _, ev := range e.m.ActivitySince(0, sb.Name) {
		if ev.Kind == sandboxapi.ActivityFinding && ev.Reason == sandboxapi.ReasonHookFinding {
			findings = append(findings, ev)
		}
	}
	if len(findings) != 1 || findings[0].Severity != "HIGH" || findings[0].Tool != "Bash" ||
		!strings.HasPrefix(findings[0].Message, "⚠ Bash: Allowed but flagged by DefenseClaw rule E2E-SANDBOX-ALERT") {
		t.Fatalf("finding events = %+v", findings)
	}
	got, _ := e.m.Get(t.Context(), sb.Name)
	if got.Hooks.ToolCalls != 3 || got.Hooks.ToolBlocked != 1 {
		t.Fatalf("hook counts = %+v", got.Hooks)
	}
}
