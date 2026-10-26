// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"encoding/json"

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
// its call names the request in the audit row. A panic answers at once.
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
	var decided agentHookResponse
	decidedReq := req
	for i, call := range calls {
		one := req
		one.ToolName, one.ToolArgs = call.Name, append(json.RawMessage(nil), call.Args...)
		resp, panicked := a.safeEvaluateHook(ctx, connectorName, one, rawBody, payload, runtime)
		if panicked {
			return resp, true, one
		}
		if i == 0 || hookVerdictRank(resp) > hookVerdictRank(decided) {
			decided, decidedReq = resp, one
		}
	}
	return decided, false, decidedReq
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
