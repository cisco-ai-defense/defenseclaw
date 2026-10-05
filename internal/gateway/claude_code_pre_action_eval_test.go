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
	"testing"
)

// GAP-1955: one Claude Code Bash call with an alert-level finding made two
// identical alerts, one from PreToolUse and one from PermissionRequest.
func TestClaudeCodePermissionRequestReusesPreToolUseFindings(t *testing.T) {
	store, logger := testStoreAndLogger(t)
	api := &APIServer{store: store, logger: logger}
	alerts := func() int {
		counts, err := store.GetCounts()
		if err != nil {
			t.Fatal(err)
		}
		return counts.Alerts
	}
	verdict := func() *ToolInspectVerdict {
		return &ToolInspectVerdict{
			Action:   "alert",
			Severity: "HIGH",
			Findings: []string{"PATH-SSH-DIR:SSH directory access"},
			DetailedFindings: []RuleFinding{{
				RuleID: "PATH-SSH-DIR", Title: "SSH directory access", Severity: "HIGH", Confidence: 0.95,
			}},
		}
	}
	call := func(event, command string) string {
		req := claudeCodeHookRequest{
			HookEventName: event,
			SessionID:     "s1",
			ToolName:      "Bash",
			ToolInput:     map[string]interface{}{"command": command},
		}
		return api.emitClaudeCodeHookRuleFindings(context.Background(), req, verdict(), 0).EvaluationID
	}

	pre := call("PreToolUse", "echo x >> ~/.ssh/id_rsa")
	if pre == "" {
		t.Fatal("PreToolUse emitted no evaluation")
	}
	one := alerts()
	if one == 0 {
		t.Fatal("PreToolUse raised no alert")
	}
	if perm := call("PermissionRequest", "echo x >> ~/.ssh/id_rsa"); perm != pre {
		t.Fatalf("PermissionRequest evaluation = %q, want the PreToolUse one %q", perm, pre)
	}
	if got := alerts(); got != one {
		t.Fatalf("alerts after PermissionRequest = %d, want %d (no second alert)", got, one)
	}
	// The next call with the same command is its own tool call.
	again := call("PreToolUse", "echo x >> ~/.ssh/id_rsa")
	if again == "" || again == pre {
		t.Fatalf("second PreToolUse evaluation = %q, want a new one (first %q)", again, pre)
	}
	if other := call("PermissionRequest", "echo y >> ~/.ssh/id_rsa"); other == "" || other == again {
		t.Fatalf("PermissionRequest for another input = %q, want its own evaluation", other)
	}
}
