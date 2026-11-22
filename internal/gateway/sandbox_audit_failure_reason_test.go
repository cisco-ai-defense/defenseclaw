// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"fmt"
	"strings"
	"testing"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/sandboxauth"
)

// GAP-0402 (E3, 15 actors): the gateway's audit store filled its volume, and
// every sandbox hook call was refused with "DefenseClaw hit an internal error
// while checking this call", the reason of a crashed check: the agent and
// the user could not tell that the audit store was full. The call still fails
// closed (the hook is the only gate in a sandbox), and its reason names the
// audit record that could not be written.
func TestSandboxAuditFailureNamesTheAuditStore(t *testing.T) {
	fixture := newAuditFailureHookFixture(t, "")
	fixture.emitter.fail = true
	sink := &sandboxRelayDecisionSink{}
	ctx := sandboxauth.WithRequest(t.Context(), sandboxauth.Binding{ID: "binding-audit-full", SandboxName: "sbx", Connector: "claudecode"}, nil)
	ctx = context.WithValue(ctx, sandboxRelayStateKey{}, &sandboxRelayState{sink: sink})
	req := agentHookRequest{ConnectorName: "claudecode", HookEventName: "PreToolUse", SessionID: "s-audit-full", ToolName: "Bash",
		Payload: map[string]interface{}{"tool_name": "Bash"}}
	allow := agentHookResponse{Action: "allow", RawAction: "allow", Mode: "action", EvaluationID: "eval-audit-full"}
	result := fixture.api.finalizeAgentHook(ctx, "claudecode", req, allow, nil, preToolUseBody(t, "toolu-audit-full"), time.Millisecond, false, nil)
	if !result.AuditFailedClosed || result.Response.Action != "block" {
		t.Fatalf("sandbox allow with a failed audit write: %+v, want the closed block", result)
	}
	reason := result.Response.Reason
	if reason == sandboxInternalErrorReason || !strings.Contains(reason, "could not write the call's audit record") ||
		!strings.Contains(reason, "audit store") || !strings.Contains(reason, "not a policy decision") {
		t.Fatalf("sandbox audit-failure reason = %q, want one that names the audit store", reason)
	}
	if out := fmt.Sprint(result.Response.HookOutput); !strings.Contains(out, "could not write the call's audit record") {
		t.Fatalf("Claude Code hook output %s does not carry the audit-failure reason", out)
	}
	// A crashed check keeps the internal-error reason.
	crashed := fixture.api.failSandboxHookClosed(ctx, fixture.api.hookProfileForRequest(ctx, "claudecode"), "claudecode", req,
		preToolUseBody(t, "toolu-crash"), req.Payload, agentHookResponse{Action: "block", RawAction: "block"})
	if crashed.Reason != sandboxInternalErrorReason {
		t.Fatalf("crashed check reason = %q, want %q", crashed.Reason, sandboxInternalErrorReason)
	}
}
