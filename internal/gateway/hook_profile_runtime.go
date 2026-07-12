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
	"encoding/json"

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
)

type hookProfileRuntime struct {
	RememberRawEvents func(a *APIServer, req agentHookRequest, rawBody []byte, payload map[string]interface{}) []string
	EmitLLMEvent      func(a *APIServer, ctx context.Context, req agentHookRequest, rawBody []byte, payload map[string]interface{}, rawEventIDs []string)
	Evaluate          func(a *APIServer, ctx context.Context, req agentHookRequest, rawBody []byte, payload map[string]interface{}) agentHookResponse
	EnrichSpan        func(ctx context.Context, rawBody []byte, payload map[string]interface{})
}

type hookProfileRuntimeFactory func(profile connector.HookProfile) hookProfileRuntime

var hookProfileRuntimes = map[string]hookProfileRuntimeFactory{
	"codex":      codexHookProfileRuntime,
	"claudecode": claudeCodeHookProfileRuntime,
}

func hookRuntimeForProfile(profile connector.HookProfile) hookProfileRuntime {
	runtime := defaultHookProfileRuntime(profile)
	if factory, ok := hookProfileRuntimes[profile.Name]; ok {
		specialized := factory(profile)
		if specialized.RememberRawEvents != nil {
			runtime.RememberRawEvents = specialized.RememberRawEvents
		}
		if specialized.EmitLLMEvent != nil {
			runtime.EmitLLMEvent = specialized.EmitLLMEvent
		}
		if specialized.Evaluate != nil {
			runtime.Evaluate = specialized.Evaluate
		}
		if specialized.EnrichSpan != nil {
			runtime.EnrichSpan = specialized.EnrichSpan
		}
	}
	return runtime
}

func defaultHookProfileRuntime(_ connector.HookProfile) hookProfileRuntime {
	return hookProfileRuntime{
		RememberRawEvents: func(a *APIServer, req agentHookRequest, _ []byte, _ map[string]interface{}) []string {
			return a.rememberHookRawEvents(req)
		},
		EmitLLMEvent: func(a *APIServer, ctx context.Context, req agentHookRequest, rawBody []byte, _ map[string]interface{}, _ []string) {
			a.emitAgentHookLLMEvent(ctx, req, rawBody)
		},
		Evaluate: func(a *APIServer, ctx context.Context, req agentHookRequest, _ []byte, _ map[string]interface{}) agentHookResponse {
			return a.evaluateAgentHook(ctx, req)
		},
	}
}

func codexHookProfileRuntime(_ connector.HookProfile) hookProfileRuntime {
	return hookProfileRuntime{
		RememberRawEvents: func(a *APIServer, _ agentHookRequest, rawBody []byte, payload map[string]interface{}) []string {
			return a.rememberCodexRawHookEvents(decodeCodexRequestFromBytes(rawBody, payload))
		},
		EmitLLMEvent: func(a *APIServer, ctx context.Context, _ agentHookRequest, rawBody []byte, payload map[string]interface{}, rawEventIDs []string) {
			a.emitCodexHookLLMEvent(ctx, decodeCodexRequestFromBytes(rawBody, payload), rawEventIDs, rawBody)
		},
		Evaluate: func(a *APIServer, ctx context.Context, _ agentHookRequest, rawBody []byte, payload map[string]interface{}) agentHookResponse {
			cxReq := decodeCodexRequestFromBytes(rawBody, payload)
			enrichCodexHookSpan(ctx, cxReq)
			return codexResponseToAgentHookResponse(a.evaluateCodexHook(ctx, cxReq))
		},
	}
}

func claudeCodeHookProfileRuntime(_ connector.HookProfile) hookProfileRuntime {
	return hookProfileRuntime{
		RememberRawEvents: func(a *APIServer, _ agentHookRequest, rawBody []byte, payload map[string]interface{}) []string {
			return a.rememberClaudeCodeRawHookEvents(decodeClaudeCodeRequestFromBytes(rawBody, payload))
		},
		EmitLLMEvent: func(a *APIServer, ctx context.Context, _ agentHookRequest, rawBody []byte, payload map[string]interface{}, rawEventIDs []string) {
			a.emitClaudeCodeHookLLMEvent(ctx, decodeClaudeCodeRequestFromBytes(rawBody, payload), rawEventIDs, rawBody)
		},
		Evaluate: func(a *APIServer, ctx context.Context, _ agentHookRequest, rawBody []byte, payload map[string]interface{}) agentHookResponse {
			return claudeCodeResponseToAgentHookResponse(a.evaluateClaudeCodeHook(ctx, decodeClaudeCodeRequestFromBytes(rawBody, payload)))
		},
	}
}

func decodeClaudeCodeRequestFromBytes(rawBody []byte, payload map[string]interface{}) claudeCodeHookRequest {
	var req claudeCodeHookRequest
	_ = json.Unmarshal(rawBody, &req)
	req.Payload = payload
	agentID, agentName, agentType := extractAgentIdentityFromHookPayload(payload)
	req.AgentID = firstNonEmpty(req.AgentID, agentID)
	if payloadString(req.Payload, "agent_name") == "" && agentName != "" {
		req.Payload["agent_name"] = agentName
	}
	req.AgentType = firstNonEmpty(req.AgentType, agentType)
	req.CWD = sanitizeHookCWD(req.CWD)
	req.NewCWD = sanitizeHookCWD(req.NewCWD)
	req.OldCWD = sanitizeHookCWD(req.OldCWD)
	return req
}

func decodeCodexRequestFromBytes(rawBody []byte, payload map[string]interface{}) codexHookRequest {
	var req codexHookRequest
	_ = json.Unmarshal(rawBody, &req)
	req.Payload = payload
	req.CWD = sanitizeHookCWD(req.CWD)
	return req
}

func claudeCodeResponseToAgentHookResponse(resp claudeCodeHookResponse) agentHookResponse {
	return agentHookResponse{
		Action:            resp.Action,
		RawAction:         resp.RawAction,
		Severity:          resp.Severity,
		Reason:            resp.Reason,
		Findings:          resp.Findings,
		Mode:              resp.Mode,
		WouldBlock:        resp.WouldBlock,
		AdditionalContext: resp.AdditionalContext,
		HookOutput:        resp.ClaudeCodeOutput,
		EvaluationID:      resp.EvaluationID,
		RuleIDs:           resp.RuleIDs,
		RedactionEnabled:  resp.RedactionEnabled,
		SourceReason:      resp.SourceReason,
	}
}

func codexResponseToAgentHookResponse(resp codexHookResponse) agentHookResponse {
	return agentHookResponse{
		Action:            resp.Action,
		RawAction:         resp.RawAction,
		Severity:          resp.Severity,
		Reason:            resp.Reason,
		Findings:          resp.Findings,
		Mode:              resp.Mode,
		WouldBlock:        resp.WouldBlock,
		AdditionalContext: resp.AdditionalContext,
		HookOutput:        resp.CodexOutput,
		EvaluationID:      resp.EvaluationID,
		RuleIDs:           resp.RuleIDs,
		RedactionEnabled:  resp.RedactionEnabled,
		SourceReason:      resp.SourceReason,
	}
}
