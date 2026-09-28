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

//go:build !windows

package gateway

import (
	"strings"
	"testing"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

// A profile can answer a HIGH rule with a plain allow (live: action=allow
// raw_action=allow severity=HIGH for the E2E alert marker). The verdict
// still carries a finding: the feed and the last reason read "Allowed but
// flagged by DefenseClaw rule …" instead of the redacted verdict text,
// while the harness output stays that of an allow.
func TestSandboxAllowWithFindingIsFlagged(t *testing.T) {
	installSandboxMarkerRules(t)
	api := &APIServer{}
	profile := connector.NewClaudeCodeConnector().HookProfile(connector.SetupOpts{})
	ctx := sandboxCtx(sandboxTestBinding("claudecode"))
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse"}
	body := []byte(`{"hook_event_name":"PreToolUse","tool_name":"Bash"}`)
	payload := map[string]interface{}{"hook_event_name": "PreToolUse"}
	in := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "HIGH", Reason: "matched: <redacted len=26 sha=0123abcd>",
		RuleIDs: []string{"E2E-SANDBOX-MARKER"}, HookOutput: map[string]interface{}{"continue": true}}
	got := api.applySandboxVerdictReason(ctx, profile, "claudecode", req, body, payload, in)
	if !strings.HasPrefix(got.Reason, "Allowed but flagged by DefenseClaw rule E2E-SANDBOX-MARKER") ||
		!strings.HasSuffix(got.Reason, sandboxFlaggedNote) || hookSourceReason(got) != in.Reason {
		t.Fatalf("reason %q, source %q", got.Reason, hookSourceReason(got))
	}
	if got.AdditionalContext != "" || got.HookOutput["continue"] != true {
		t.Fatalf("an allow's harness output changed: context %q, output %v", got.AdditionalContext, got.HookOutput)
	}
	// A plain allow without a finding keeps its reason.
	plain := agentHookResponse{Action: "allow", RawAction: "allow", Severity: "NONE", Reason: "kept", RuleIDs: []string{"E2E-SANDBOX-MARKER"}}
	if got := api.applySandboxVerdictReason(ctx, profile, "claudecode", req, body, payload, plain); got.Reason != "kept" {
		t.Fatalf("plain allow reason = %q", got.Reason)
	}
}
