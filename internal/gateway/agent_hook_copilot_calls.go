// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/copilotargs"
)

// copilotNativeToolCalls returns the calls of a native Copilot CLI
// preToolUse whose toolCalls envelope carries more than one (a model's
// parallel tool calls), or nil. The one hook answer covers every call, so
// each is proven and judged and the most restrictive verdict answers: a
// well-formed envelope is never HOOK-TOOL-CALL-UNPARSED (GAP-1016).
func copilotNativeToolCalls(req agentHookRequest) []copilotargs.NativeCall {
	if req.ToolCallUnparsed {
		return nil
	}
	calls, ok := copilotargs.NativeCalls(req.Payload["toolCalls"])
	if !ok || len(calls) < 2 {
		return nil
	}
	return calls
}

// copilotCallsUnproven is copilotWriteCallUnproven for the request's call,
// or for each call of a parallel envelope.
func copilotCallsUnproven(req agentHookRequest, calls []copilotargs.NativeCall, cwd, home string, evidence map[string]string) bool {
	if len(calls) == 0 {
		return copilotWriteCallUnproven(req.ToolName, req.ToolArgs, cwd, home, evidence)
	}
	for _, call := range calls {
		if copilotWriteCallUnproven(call.Name, call.Args, cwd, home, evidence) {
			return true
		}
	}
	return false
}

// safeEvaluateHookCalls is safeEvaluateHook for the request's call, or for
// each call of a parallel envelope: the most restrictive verdict answers and
// its call names the request in the audit row. The findings, rule IDs and
// highest severity of every other call that did not simply allow join that
// answer, so the audit row keeps each call's finding (GAP-1834); the action
// stays the decided one. The calls share one hook judge deadline, the one
// round trip the hook client waits for (GAP-1835). A panic answers at once.
func (a *APIServer) safeEvaluateHookCalls(
	ctx context.Context,
	connectorName string,
	req agentHookRequest,
	calls []copilotargs.NativeCall,
	rawBody []byte,
	payload map[string]interface{},
	runtime hookProfileRuntime,
) (agentHookResponse, bool, agentHookRequest) {
	if len(calls) < 2 {
		resp, panicked := a.safeEvaluateHook(ctx, connectorName, req, rawBody, payload, runtime)
		return resp, panicked, req
	}
	ctx = withHookJudgeBudget(ctx, time.Now().Add(hookJudgeTimeout(a.decisionConfig(ctx))))
	responses := make([]agentHookResponse, 0, len(calls))
	decided := 0
	decidedReq := req
	for i, call := range calls {
		one := req
		one.ToolName, one.ToolArgs = call.Name, append(json.RawMessage(nil), call.Args...)
		resp, panicked := a.safeEvaluateHook(ctx, connectorName, one, rawBody, payload, runtime)
		if panicked {
			return resp, true, one
		}
		responses = append(responses, resp)
		if i == 0 || hookVerdictRank(resp) > hookVerdictRank(responses[decided]) {
			decided, decidedReq = i, one
		}
	}
	out := responses[decided]
	for i, resp := range responses {
		// A call that simply allowed adds nothing: its findings are allow
		// markers such as STATIC-ALLOW, never a reason for this answer
		// (GAP-1925).
		if i == decided || hookVerdictRank(resp) == 0 {
			continue
		}
		out.Findings = appendUniqueStrings(out.Findings, resp.Findings...)
		out.RuleIDs = appendUniqueStrings(out.RuleIDs, resp.RuleIDs...)
		if guardrailSeverityRank(resp.Severity) > guardrailSeverityRank(out.Severity) {
			out.Severity = resp.Severity
		}
	}
	return out, false, decidedReq
}

// hookVerdictRank orders verdicts by restriction: the effective action
// first, then the raw (observe-mode) action. An unknown action ranks as a
// block.
func hookVerdictRank(resp agentHookResponse) int {
	rank := func(action string) int {
		switch action {
		case "", "allow":
			return 0
		case "alert":
			return 1
		case "confirm":
			return 2
		default:
			return 3
		}
	}
	return rank(resp.Action)*4 + rank(resp.RawAction)
}
