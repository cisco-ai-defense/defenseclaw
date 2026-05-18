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
)

// bespoke_hook_adapter.go — the bridge between the unified hook
// pipeline (handleAgentHook) and the connector-specific evaluator
// logic that remains in claude_code_hook.go and codex_hook.go.
//
// Why this file exists
// --------------------
// Prior to PR #284 (this PR), codex and claudecode each owned a
// full bespoke HTTP handler (handleCodexHook, handleClaudeCodeHook)
// that re-implemented the entire pipeline: parse → enrich context →
// remember raw events → emit LLM event → evaluate → record metrics →
// write audit envelope → render JSON. Three copies of the same
// pipeline meant every shared concern (audit envelope refresh,
// dispatch metric, dedup, trace propagation, native-OTLP path-token
// lookup) had to be wired in three places. The F2 audit-correlation
// bug landed in live Splunk verification precisely because one of
// the three copies (claudecode) skipped the audit envelope refresh.
//
// PR #284 deletes the duplicate handlers. handleAgentHook is now the
// SOLE entry point for every connector hook route (codex,
// claudecode, hermes, cursor, windsurf, geminicli, copilot). The
// shared pipeline lives in exactly one place; adding a new
// cross-cutting concern means touching one function, not three.
//
// What stays bespoke
// ------------------
// Three pieces of connector-specific behaviour cannot collapse into
// the generic evaluateAgentHook without losing fidelity:
//
//   - the evaluator (evaluateClaudeCodeHook / evaluateCodexHook):
//     hook-event switches on Claude-specific names (SessionStart,
//     UserPromptExpansion, PermissionRequest, PermissionDenied,
//     ConfigChange, …) and Codex-specific scans
//     (codex_inspect, notify-bridge stop). Folding these into
//     the generic switch would either bloat that function or
//     add per-connector case-tables that recreate the bespoke
//     evaluators by stealth.
//
//   - the LLM-event emitter (emitClaudeCodeHookLLMEvent /
//     emitCodexHookLLMEvent): pulls fields from connector-specific
//     payload shapes (req.MCPServerName, req.ToolUseID,
//     req.LastAssistantMessage, …) that aren't in agentHookRequest.
//
//   - the raw-event deduper (rememberClaudeCodeRawHookEvents /
//     rememberCodexRawHookEvents): the raw event IDs are derived
//     from connector-specific identifiers so the SIEM can join a
//     hook decision row against the matching OTLP log row from the
//     agent's native channel.
//
// Each of these functions takes a connector-specific request type
// (claudeCodeHookRequest / codexHookRequest). The adapters in this
// file translate the generic agentHookRequest + raw payload bytes
// into the bespoke request types, call the bespoke logic, and
// translate the bespoke response back into the unified
// agentHookResponse shape.
//
// Wire-format preservation
// ------------------------
// The wire JSON shape returned to Claude Code and Codex agents MUST
// stay byte-identical to the pre-unification format — these agents
// reject hook responses that don't match their expected schema. The
// adapters preserve the bespoke ResponseFor() helpers which produce
// the connector-specific JSON keys (hookSpecificOutput,
// permissionDecision, etc.). handleAgentHook then renders the
// top-level wrapper using HookProfile.Respond to select the right
// outer field name (claude_code_output for claudecode, codex_output
// for codex, hook_output for everything else).
//
// Future direction
// ----------------
// The next refactor (out of scope for this PR) collapses the
// bespoke evaluators by pushing per-connector hook-event coverage
// into the classifier helpers (isPromptLikeEvent, etc.) and the
// asset-policy / scan-on-event behaviours into HookProfile
// callbacks. That refactor is intentionally deferred because it
// requires reshaping the connector-specific request types and has
// broader test impact — the goal of THIS PR is the F2-class drift
// hazard fix, not the full type unification.

// decodeClaudeCodeRequestFromBytes parses raw hook payload bytes
// directly into a claudeCodeHookRequest. The unified handler
// already decoded the bytes into a map (payload) and the
// normalized agentHookRequest (req); we re-parse against the
// bespoke type so the connector-specific JSON tags
// (`new_cwd`, `permission_mode`, `mcp_server_name`,
// `last_assistant_message`, `scan_components`, …) populate the
// claudecode-shaped fields without us having to enumerate them
// here. The payload map is attached separately so the evaluator
// can still recover arbitrary unmodeled fields.
//
// Errors are intentionally ignored — handleAgentHook has already
// validated the payload as valid JSON via rawPayloadFromJSONDecoder
// so json.Unmarshal cannot fail here for a malformed-bytes reason.
// A field-level type mismatch produces a zero-valued field which is
// the same behaviour the legacy handleClaudeCodeHook had.
func decodeClaudeCodeRequestFromBytes(rawBody []byte, payload map[string]interface{}) claudeCodeHookRequest {
	var req claudeCodeHookRequest
	_ = json.Unmarshal(rawBody, &req)
	req.Payload = payload
	req.CWD = sanitizeHookCWD(req.CWD)
	req.NewCWD = sanitizeHookCWD(req.NewCWD)
	req.OldCWD = sanitizeHookCWD(req.OldCWD)
	return req
}

// decodeCodexRequestFromBytes is the codex counterpart of
// decodeClaudeCodeRequestFromBytes. See that helper's godoc for
// the rationale.
func decodeCodexRequestFromBytes(rawBody []byte, payload map[string]interface{}) codexHookRequest {
	var req codexHookRequest
	_ = json.Unmarshal(rawBody, &req)
	req.Payload = payload
	req.CWD = sanitizeHookCWD(req.CWD)
	return req
}

// claudeCodeResponseToAgentHookResponse projects a Claude Code
// bespoke response into the unified agentHookResponse shape so the
// remainder of handleAgentHook (audit envelope, metrics, span
// enrichment) operates on a single type. The connector-specific
// JSON output (hookSpecificOutput / decision / continue / …) is
// preserved verbatim in HookOutput; handleAgentHook later places
// that map under the "claude_code_output" key per HookProfile.Respond.
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
	}
}

// codexResponseToAgentHookResponse is the codex counterpart of
// claudeCodeResponseToAgentHookResponse. See that helper's godoc
// for the rationale.
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
	}
}

// evaluateBespokeOrGenericHook dispatches the hook evaluation to a
// connector-specific evaluator when one exists (codex, claudecode)
// and falls through to the generic evaluator otherwise. The unified
// handleAgentHook calls this AFTER the shared pipeline (parse,
// envelope refresh, dedup, LLM event emit) so every connector pays
// the same audit / metrics / trace cost regardless of which
// evaluator runs.
//
// rawBody is supplied because the bespoke decoders rely on the
// connector-specific JSON tags to populate fields that
// normalizeAgentHookRequest does not extract (e.g. NewCWD,
// PermissionMode, MCPServerName for claudecode; ToolUseID,
// LastAssistantMessage for codex). Re-parsing the bytes is cheaper
// than enumerating every field union in normalizeAgentHookRequest
// and keeps the bespoke evaluators verbatim.
//
// The returned agentHookResponse carries the bespoke
// connector-specific output map in HookOutput; handleAgentHook
// renders the wire JSON by placing that map under the
// HookProfile.Respond-supplied field name (claude_code_output /
// codex_output / hook_output) so the agent CLI receives the exact
// schema it expects.
//
// Why dispatch lives here, not in a HookProfile callback: the
// bespoke evaluators are *APIServer methods that need access to
// scanner / asset-policy / notifier subsystems wired on the gateway.
// HookProfile is a connector-package value type with no gateway
// import; the dispatch must happen on the gateway side.
func (a *APIServer) evaluateBespokeOrGenericHook(
	ctx context.Context,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
) agentHookResponse {
	switch connectorName {
	case "claudecode":
		ccReq := decodeClaudeCodeRequestFromBytes(rawBody, payload)
		return claudeCodeResponseToAgentHookResponse(a.evaluateClaudeCodeHook(ctx, ccReq))
	case "codex":
		cxReq := decodeCodexRequestFromBytes(rawBody, payload)
		// enrichCodexHookSpan stamps codex-specific span
		// attributes (turn_id, gen_ai.tool.call.id, model)
		// that the generic enrichAgentHookSpan does not set.
		// Pre-PR-#284 the legacy enrichCodexHookContext called
		// this; we preserve the behavior here so dashboards
		// keyed off defenseclaw.codex.hook.turn_id stay green.
		enrichCodexHookSpan(ctx, cxReq)
		return codexResponseToAgentHookResponse(a.evaluateCodexHook(ctx, cxReq))
	default:
		return a.evaluateAgentHook(ctx, req)
	}
}

// emitBespokeOrGenericLLMEvent dispatches LLM-event emission to a
// connector-specific emitter when one exists and falls through to
// the generic emitter otherwise. Same rationale as
// evaluateBespokeOrGenericHook: connector-specific emitters pull
// fields (req.MCPServerName, req.ToolUseID, req.LastAssistantMessage,
// …) that the generic agentHookRequest does not model verbatim.
//
// rawEventIDs is the slice rememberHookRawEvents (or the bespoke
// equivalent) produced; the codex/claudecode emitters pass it
// through to the LLM event meta so the SIEM can join LLM logs
// against the OTLP raw-event channel by ID.
func (a *APIServer) emitBespokeOrGenericLLMEvent(
	ctx context.Context,
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
	rawEventIDs []string,
) {
	switch connectorName {
	case "claudecode":
		ccReq := decodeClaudeCodeRequestFromBytes(rawBody, payload)
		a.emitClaudeCodeHookLLMEvent(ctx, ccReq, rawEventIDs, rawBody)
	case "codex":
		cxReq := decodeCodexRequestFromBytes(rawBody, payload)
		a.emitCodexHookLLMEvent(ctx, cxReq, rawEventIDs, rawBody)
	default:
		a.emitAgentHookLLMEvent(ctx, req, rawBody)
	}
}

// rememberBespokeOrGenericRawEvents dispatches raw-event
// deduplication to a connector-specific deduper when one exists and
// falls through to the generic deduper otherwise. The bespoke
// dedupers compute event IDs from connector-specific identifiers
// (codex tool_use_id, claudecode permission_request_id, …) that
// must match the IDs the agent's native OTLP channel emits so a
// SIEM JOIN aligns hook decisions against OTLP raw events.
func (a *APIServer) rememberBespokeOrGenericRawEvents(
	connectorName string,
	req agentHookRequest,
	rawBody []byte,
	payload map[string]interface{},
) []string {
	switch connectorName {
	case "claudecode":
		ccReq := decodeClaudeCodeRequestFromBytes(rawBody, payload)
		return a.rememberClaudeCodeRawHookEvents(ccReq)
	case "codex":
		cxReq := decodeCodexRequestFromBytes(rawBody, payload)
		return a.rememberCodexRawHookEvents(cxReq)
	default:
		return a.rememberHookRawEvents(req)
	}
}
