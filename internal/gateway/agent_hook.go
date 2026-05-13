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
	"fmt"
	"net/http"
	"os"
	"strconv"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gateway/notifier"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"
)

type agentHookRequest struct {
	ConnectorName string
	AgentID       string
	AgentName     string
	AgentType     string
	HookEventName string
	SessionID     string
	TurnID        string
	CWD           string
	ToolName      string
	ToolArgs      json.RawMessage
	Content       string
	Direction     string
	Payload       map[string]interface{}
}

type agentHookResponse struct {
	Action            string                 `json:"action"`
	RawAction         string                 `json:"raw_action,omitempty"`
	Severity          string                 `json:"severity"`
	Reason            string                 `json:"reason,omitempty"`
	Findings          []string               `json:"findings,omitempty"`
	Mode              string                 `json:"mode"`
	WouldBlock        bool                   `json:"would_block"`
	AdditionalContext string                 `json:"additional_context,omitempty"`
	HookOutput        map[string]interface{} `json:"hook_output,omitempty"`
	AgentControl      *agentControlDecision  `json:"agent_control,omitempty"`
}

func (a *APIServer) handleAgentHook(connectorName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			a.recordConnectorHookRejection(r.Context(), connectorName, "unknown", "method", 0)
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		payload, b, err := rawPayloadFromJSONDecoder(json.NewDecoder(r.Body))
		if err != nil {
			a.recordConnectorHookRejection(r.Context(), connectorName, "unknown", "invalid_json", 0)
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		req := normalizeAgentHookRequest(connectorName, payload)
		if req.HookEventName == "" {
			a.recordConnectorHookRejection(r.Context(), connectorName, "unknown", "missing_event", int64(len(b)))
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hook event name is required"})
			return
		}
		req.CWD = sanitizeHookCWD(req.CWD)
		ctx := enrichAgentHookContext(r.Context(), req)

		// Emit the LLM event (prompt/tool/response) BEFORE the
		// evaluator runs. Mirrors handleClaudeCodeHook /
		// handleCodexHook ordering: the audit/event log captures
		// what the agent attempted regardless of whether the
		// evaluation later blocks it. This is what brings
		// hermes/cursor/windsurf/geminicli/copilot to LLM-event
		// parity with claudecode/codex.
		a.emitAgentHookLLMEvent(ctx, req, b)

		t0 := time.Now()
		resp := a.evaluateAgentHook(ctx, req)
		elapsed := time.Since(t0)
		enrichAgentHookSpan(ctx, req, resp, elapsed)

		if a.health != nil {
			a.health.RecordConnectorRequest()
			if resp.Action == "block" {
				a.health.RecordToolBlock()
			}
			if isGenericToolInspectionEvent(req.HookEventName) {
				a.health.RecordToolInspection()
			}
		}

		if a.otel != nil {
			reason := resp.Action
			if resp.WouldBlock {
				reason = "would_block"
			}
			a.otel.RecordConnectorHookInvocation(ctx, connectorName, req.HookEventName, "ok", reason, float64(elapsed.Milliseconds()))
			a.otel.RecordInspectEvaluation(ctx, connectorName+":"+req.HookEventName, resp.Action, resp.Severity)
			a.otel.RecordInspectLatency(ctx, connectorName+":"+req.HookEventName, float64(elapsed.Milliseconds()))
			a.otel.EmitConnectorTelemetryLog(ctx, "hook", connectorName, "ok", 1, int64(len(b)),
				fmt.Sprintf("source=hook connector=%s event=%s tool=%s decision=%s raw_action=%s would_block=%v mode=%s duration_ms=%d",
					connectorName, req.HookEventName, req.ToolName, resp.Action, resp.RawAction, resp.WouldBlock, resp.Mode, elapsed.Milliseconds()))
		}

		details := fmt.Sprintf("action=%s raw_action=%s severity=%s mode=%s would_block=%v elapsed=%s",
			resp.Action, resp.RawAction, resp.Severity, resp.Mode, resp.WouldBlock, elapsed)
		details = appendRawTelemetryDetails(details, "raw_payload", b)
		a.logConnectorHookAudit(ctx, connectorName, req.HookEventName, details)

		a.writeJSON(w, http.StatusOK, resp)
	}
}

func enrichAgentHookContext(ctx context.Context, req agentHookRequest) context.Context {
	ctx = ContextWithSessionID(ctx, req.SessionID)
	ctx = ContextWithAgentIdentity(ctx, agentIdentityForGenericHook(ctx, req))
	enrichHTTPSpanFromContext(ctx)
	return ctx
}

func agentIdentityForGenericHook(ctx context.Context, req agentHookRequest) AgentIdentity {
	agentName := firstNonEmpty(req.AgentName, req.AgentType, req.ConnectorName)
	agentType := firstNonEmpty(req.AgentType, req.ConnectorName)
	identity := AgentIdentity{
		AgentID:   strings.TrimSpace(req.AgentID),
		AgentName: agentName,
		AgentType: agentType,
	}
	if reg := SharedAgentRegistry(); reg != nil {
		resolved := reg.Resolve(ctx, req.SessionID, identity.AgentID)
		if identity.AgentID == "" {
			identity.AgentID = resolved.AgentID
		}
		identity.AgentInstanceID = resolved.AgentInstanceID
		identity.SidecarInstanceID = resolved.SidecarInstanceID
	}
	return identity
}

func enrichAgentHookSpan(ctx context.Context, req agentHookRequest, resp agentHookResponse, elapsed time.Duration) {
	span := trace.SpanFromContext(ctx)
	if span == nil || !span.IsRecording() {
		return
	}
	reason := resp.Action
	if resp.WouldBlock {
		reason = "would_block"
	}
	attrs := []attribute.KeyValue{
		attribute.String("defenseclaw.connector", req.ConnectorName),
		attribute.String("defenseclaw.connector.source", req.ConnectorName),
		attribute.String("defenseclaw.connector.signal", "hook"),
		attribute.String("defenseclaw.connector.result", "ok"),
		attribute.String("defenseclaw.hook.reason", reason),
		attribute.String("defenseclaw.telemetry.source", "hook"),
		attribute.String("defenseclaw.hook.event", req.HookEventName),
		attribute.String("defenseclaw.tool.name", req.ToolName),
		attribute.String("defenseclaw.workspace", req.CWD),
		attribute.String("defenseclaw.decision", resp.Action),
		attribute.String("defenseclaw.raw_action", resp.RawAction),
		attribute.Bool("defenseclaw.would_block", resp.WouldBlock),
		attribute.String("defenseclaw.mode", resp.Mode),
		attribute.Int64("defenseclaw.duration_ms", elapsed.Milliseconds()),
	}
	if req.SessionID != "" {
		attrs = append(attrs, attribute.String("gen_ai.conversation.id", req.SessionID))
	}
	identity := AgentIdentityFromContext(ctx)
	if identity.AgentName != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.name", identity.AgentName))
	}
	if identity.AgentType != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.type", identity.AgentType))
	}
	if identity.AgentID != "" {
		attrs = append(attrs, attribute.String("gen_ai.agent.id", identity.AgentID))
	}
	if req.TurnID != "" {
		attrs = append(attrs, attribute.String("gen_ai.operation.id", req.TurnID))
	}
	span.SetAttributes(attrs...)
	annotateAgentControlTraceSpan(span, resp.AgentControl)
}

func normalizeAgentHookRequest(connectorName string, payload map[string]interface{}) agentHookRequest {
	event := firstString(payload,
		"hook_event_name",
		"hookEventName",
		"event_name",
		"eventName",
		"agent_action_name",
	)
	if event == "" {
		event = inferAgentHookEvent(payload)
	}
	agentID, agentName, agentType := extractAgentIdentityFromHookPayload(payload)
	sessionID := firstString(payload, "session_id", "sessionId", "task_id", "conversation_id", "conversationId", "thread_id", "threadId")
	turnID := firstString(payload, "turn_id", "turnId", "execution_id", "executionId", "generation_id", "generationId", "tool_call_id", "toolCallId")
	cwd := firstString(payload, "cwd", "working_directory", "workingDirectory")
	if cwd == "" {
		if toolInfo := objectAt(payload, "tool_info"); toolInfo != nil {
			cwd = firstString(toolInfo, "cwd", "working_directory")
		}
	}

	toolName := firstString(payload, "tool_name", "toolName", "command_name", "name")
	if toolName == "" {
		if toolInfo := objectAt(payload, "tool_info"); toolInfo != nil {
			toolName = firstString(toolInfo, "mcp_tool_name", "tool_name", "command_name")
			if toolName == "" && firstString(toolInfo, "command_line", "command") != "" {
				toolName = "shell"
			}
		}
	}
	if toolName == "" && isPromptLikeEvent(event) {
		toolName = "message"
	}
	if toolName == "" {
		toolName = "tool"
	}

	args := firstValue(payload, "tool_input", "toolInput", "tool_args", "toolArgs", "args", "arguments")
	if args == nil {
		args = firstValue(payload, "tool_info", "toolInfo")
	}
	if args == nil {
		args = payload
	}
	argBytes, err := json.Marshal(args)
	if err != nil {
		argBytes = []byte(`{}`)
	}

	content := firstString(payload,
		"prompt",
		"user_prompt",
		"userPrompt",
		"message",
		"initial_prompt",
		"initialPrompt",
		"custom_instructions",
		"customInstructions",
	)
	if content == "" {
		if toolInfo := objectAt(payload, "tool_info"); toolInfo != nil {
			content = firstString(toolInfo, "user_prompt", "content", "command_line", "command", "mcp_result")
		}
	}
	if content == "" {
		content = stringifyHookValue(firstValue(payload, "tool_response", "toolResponse", "tool_result", "toolResult", "result", "error"))
	}

	direction := "tool_call"
	switch {
	case isPromptLikeEvent(event):
		direction = "prompt"
	case isResultLikeEvent(event):
		direction = "tool_result"
	}

	return agentHookRequest{
		ConnectorName: connectorName,
		AgentID:       agentID,
		AgentName:     agentName,
		AgentType:     agentType,
		HookEventName: event,
		SessionID:     sessionID,
		TurnID:        turnID,
		CWD:           cwd,
		ToolName:      toolName,
		ToolArgs:      json.RawMessage(argBytes),
		Content:       content,
		Direction:     direction,
		Payload:       payload,
	}
}

func extractAgentIdentityFromHookPayload(payload map[string]interface{}) (agentID, agentName, agentType string) {
	agentID = firstHookIdentityString(payload, "agent_id", "agentId", "assistant_id", "assistantId", "client_agent_id", "clientAgentId")
	agentName = firstHookIdentityString(payload, "agent_name", "agentName", "assistant_name", "assistantName")
	agentType = firstHookIdentityString(payload, "agent_type", "agentType", "agent_kind", "agentKind", "runtime", "runtime_name")
	if agentObj := objectAt(payload, "agent"); agentObj != nil {
		if agentID == "" {
			agentID = firstHookIdentityString(agentObj, "id", "agent_id", "agentId", "assistant_id", "assistantId")
		}
		if agentName == "" {
			agentName = firstHookIdentityString(agentObj, "name", "agent_name", "agentName", "display_name", "displayName")
		}
		if agentType == "" {
			agentType = firstHookIdentityString(agentObj, "type", "agent_type", "agentType", "kind", "runtime", "runtime_name")
		}
	}
	if agentName == "" {
		agentName = firstHookIdentityString(payload, "agent")
	}
	return agentID, agentName, agentType
}

func inferAgentHookEvent(payload map[string]interface{}) string {
	if firstValue(payload, "toolName", "tool_name", "toolArgs", "tool_args", "tool_input") != nil {
		return "PreToolUse"
	}
	if firstString(payload, "prompt", "user_prompt", "initialPrompt", "initial_prompt") != "" {
		return "UserPromptSubmit"
	}
	if firstValue(payload, "toolResult", "tool_result", "tool_response", "result") != nil {
		return "PostToolUse"
	}
	return ""
}

func (a *APIServer) evaluateAgentHook(ctx context.Context, req agentHookRequest) agentHookResponse {
	mode := a.agentHookMode(req.ConnectorName)
	if a.scannerCfg != nil && !a.agentHookEnabled(req.ConnectorName) {
		return agentHookResponseFor(req, "allow", "allow", "NONE", "", nil, mode, false, connector.HookCapability{})
	}

	verdict := &ToolInspectVerdict{Action: "allow", Severity: "NONE", Findings: []string{}}
	var assetDecisions []runtimeAssetDecision
	switch {
	case isPromptLikeEvent(req.HookEventName):
		verdict = a.inspectMessageContent(&ToolInspectRequest{Tool: "message", Content: req.Content, Direction: "prompt"})
	case isResultLikeEvent(req.HookEventName):
		verdict = a.inspectMessageContent(&ToolInspectRequest{Tool: req.ToolName, Content: req.Content, Direction: "tool_result"})
		// Asset policy still runs on result-shaped events so a
		// PostToolUse referencing an unregistered MCP server gets
		// captured in audit / would-block telemetry. mergeAssetDecision
		// handles the "non-enforceable event" case by downgrading to
		// would-block automatically.
		assetDecisions = a.collectAgentHookAssetDecisions(ctx, req)
	case isGenericToolInspectionEvent(req.HookEventName):
		verdict = a.inspectToolPolicy(&ToolInspectRequest{Tool: req.ToolName, Args: req.ToolArgs, Direction: "tool_call"})
		assetDecisions = a.collectAgentHookAssetDecisions(ctx, req)
	}

	rawAction := normalizeCodexAction(verdict.Action)
	rawActionBeforeAssets := rawAction
	caps := a.hookCapabilities(req.ConnectorName)
	action, wouldBlock := mapHookAction(rawAction, mode, req.HookEventName, caps)
	severity := verdict.Severity
	reason := verdict.Reason
	findings := verdict.Findings

	// Fold runtime asset-policy verdicts into the hook verdict.
	// mergeAssetDecision handles "this event is not enforceable"
	// by returning advisory-only changes (action stays allow,
	// rawAction promoted to block, wouldBlock=true). For events
	// the connector itself does not declare blockable, we further
	// downgrade through mapHookAction so we never tell the agent
	// to block on a surface it cannot honor.
	for _, asset := range assetDecisions {
		mergedAction, mergedRawAction, mergedSeverity, mergedReason, mergedFindings, assetWouldBlock := mergeAssetDecision(
			asset.decision, true, asset.targetType, req.HookEventName,
			action, rawAction, severity, reason, findings,
		)
		if mergedAction == "block" {
			capable, capableWouldBlock := mapHookAction("block", mode, req.HookEventName, caps)
			if capable != "block" {
				mergedAction = capable
				if capableWouldBlock {
					assetWouldBlock = true
				}
			}
		}
		action = mergedAction
		rawAction = mergedRawAction
		severity = mergedSeverity
		reason = mergedReason
		findings = mergedFindings
		if assetWouldBlock {
			wouldBlock = true
		}
	}

	var agentControlDecision *agentControlDecision
	if a.agentControl != nil {
		stage, step := agentControlStepForAgentHook(req)
		agentControlDecision = a.agentControl.evaluate(ctx, stage, step)
		annotateAgentControlSpan(ctx, agentControlDecision)
		emitAgentControlPolicyDecision(a.otel, agentControlDecision)
		if agentControlDecision != nil && agentControlDecision.Matched {
			switch agentControlDecision.Action {
			case "deny":
				rawAction = guardrailActionBlock
				action, wouldBlock = mapHookAction(rawAction, mode, req.HookEventName, caps)
				if guardrailSeverityRank(severity) < severityHigh {
					severity = "HIGH"
				}
				reason = appendVerdictReason(reason, agentControlReason(agentControlDecision))
				findings = append(findings, agentControlFinding(agentControlDecision))
			case "steer":
				if rawAction == "" || rawAction == guardrailActionAllow {
					rawAction = guardrailActionAlert
					action, _ = mapHookAction(rawAction, mode, req.HookEventName, caps)
				}
				if guardrailSeverityRank(severity) < severityMedium {
					severity = "MEDIUM"
				}
				reason = appendVerdictReason(reason, agentControlReason(agentControlDecision))
				findings = append(findings, agentControlFinding(agentControlDecision))
			case "observe":
				findings = append(findings, agentControlFinding(agentControlDecision))
			}
		}
	}

	if !hookNotificationCoveredByAssetPolicy(rawActionBeforeAssets, assetDecisions) {
		a.dispatchAgentHookNotification(req, action, rawAction, severity, reason, wouldBlock)
	}
	resp := agentHookResponseFor(req, action, rawAction, severity, reason, findings, mode, wouldBlock, caps)
	resp.AgentControl = agentControlDecision
	return resp
}

// collectAgentHookAssetDecisions runs the runtime asset-policy
// evaluators (MCP + skill) for a hook-only-connector event and
// returns the matched blocking verdicts. Non-blocking matches and
// non-matches return as zero entries; the caller folds the results
// into the hook decision via mergeAssetDecision.
//
// The MCP and skill probes are derived from the same payload —
// req.Payload, req.ToolName, req.ToolArgs — that the upstream event
// log already covers, so no additional information leaves the
// process. tool_input is derived from ToolArgs lazily because the
// asset probes need a typed map view (ServerName / Command / args)
// that the raw json.RawMessage does not provide directly.
func (a *APIServer) collectAgentHookAssetDecisions(ctx context.Context, req agentHookRequest) []runtimeAssetDecision {
	var out []runtimeAssetDecision
	if decision, matched := a.agentHookMCPAssetDecision(ctx, req); matched {
		out = append(out, runtimeAssetDecision{targetType: "mcp", decision: decision})
	}
	if decision, matched := a.agentHookSkillAssetDecision(ctx, req); matched {
		out = append(out, runtimeAssetDecision{targetType: "skill", decision: decision})
	}
	return out
}

func (a *APIServer) agentHookMCPAssetDecision(ctx context.Context, req agentHookRequest) (config.AssetPolicyDecision, bool) {
	toolInput := decodeAgentHookToolInput(req.ToolArgs)
	probe := mcpProbeFromFields(payloadString(req.Payload, "mcp_server_name"), req.ToolName, toolInput)
	return a.evaluateRuntimeMCPAssetPolicy(ctx, req.ConnectorName, req.HookEventName, probe)
}

func (a *APIServer) agentHookSkillAssetDecision(ctx context.Context, req agentHookRequest) (config.AssetPolicyDecision, bool) {
	toolInput := decodeAgentHookToolInput(req.ToolArgs)
	probe := skillProbeFromFields(req.ToolName, toolInput, req.Payload)
	return a.evaluateRuntimeSkillAssetPolicy(ctx, req.ConnectorName, req.HookEventName, probe)
}

// decodeAgentHookToolInput decodes ToolArgs into a generic map so
// the asset-policy probe helpers can pull command / arguments /
// nested fields. Returns nil on malformed JSON; callers tolerate
// a nil map (the probe falls back to tool-name / payload heuristics).
func decodeAgentHookToolInput(raw json.RawMessage) map[string]interface{} {
	if len(raw) == 0 {
		return nil
	}
	var out map[string]interface{}
	if err := json.Unmarshal(raw, &out); err != nil {
		return nil
	}
	return out
}

// dispatchAgentHookNotification mirrors dispatchClaudeCodeHookNotification
// / dispatchCodexHookNotification but for the five generic hook-only
// connectors. Routing contract:
//
//   - action=="block"                              → OnBlock        (enforced)
//   - rawAction=="block" + (wouldBlock||!block)    → OnWouldBlock   (observe-block)
//   - action=="confirm"                            → OnApprovalPending (real native ask)
//   - rawAction=="confirm" && action!="confirm"    → OnWouldBlock(WouldAsk=true)
//
// The last case is the "would have asked but did not" bucket and
// covers two concrete scenarios:
//
//   - observe mode for any connector — mapHookAction returns
//     ("allow", false) so the response carries permission=allow and
//     no chat ask is issued.
//   - cursor beforeReadFile (and any other event missing from
//     caps.AskEvents) — confirm gets demoted to alert so, again, no
//     chat ask is issued.
//
// Both belong in the would-block category, NOT in OnApprovalPending,
// because OnApprovalPending implies "the user has a chat reply box
// open right now". By collapsing them onto OnWouldBlock with
// WouldAsk=true, a single `notifications.block_would_block: false`
// switch silences every observe-mode hook notification (would-block
// and would-ask alike) — which is the right knob for users running
// connectors in pure observe mode and wanting a quiet desktop.
//
// Reason is run through redaction.ForSinkReason before display so a
// regex-match verdict carrying echoed user content (PII / secrets)
// does not land verbatim on the OS toast. Connector is taken from
// req.ConnectorName so the subtitle reads e.g. "DefenseClaw hermes
// PreToolUse" — operators paging through toasts can attribute each
// one to a specific framework without opening the audit log.
func (a *APIServer) dispatchAgentHookNotification(req agentHookRequest, action, rawAction, severity, reason string, wouldBlock bool) {
	if a == nil || a.notifier == nil {
		return
	}
	target := strings.TrimSpace(req.ToolName)
	if target == "" {
		target = req.HookEventName
	}
	safeReason := string(redaction.ForSinkReason(reason))
	base := notifier.BlockEvent{
		Source:    notifier.SourceHook,
		Target:    target,
		Reason:    safeReason,
		Severity:  severity,
		Connector: req.ConnectorName,
		Event:     req.HookEventName,
	}
	switch {
	case action == "block":
		a.notifier.OnBlock(base)
	case rawAction == "block" && (wouldBlock || action != "block"):
		a.notifier.OnWouldBlock(base)
	case action == "confirm":
		// Native chat-side ask actually issued — only path that
		// belongs in the approvals category.
		a.notifier.OnApprovalPending(notifier.ApprovalEvent{
			Subject:   fmt.Sprintf("%s (%s)", target, req.HookEventName),
			Reason:    safeReason,
			Severity:  severity,
			Source:    notifier.SourceHook,
			Connector: req.ConnectorName,
			Event:     req.HookEventName,
		})
	case rawAction == "confirm":
		// Verdict was confirm but the user will not see a chat ask
		// (observe mode, or event not in caps.AskEvents). Route
		// through the would-block category so a single
		// block_would_block=false silences all observe-mode noise.
		evt := base
		evt.WouldAsk = true
		a.notifier.OnWouldBlock(evt)
	}
}

func (a *APIServer) agentHookEnabled(name string) bool {
	if a.scannerCfg == nil {
		return false
	}
	if a.scannerCfg.ConnectorHookConfig(name).Enabled {
		return true
	}
	return strings.EqualFold(strings.TrimSpace(a.scannerCfg.Guardrail.Connector), name)
}

func (a *APIServer) agentHookMode(name string) string {
	mode := "observe"
	if a.scannerCfg != nil {
		hookCfg := a.scannerCfg.ConnectorHookConfig(name)
		mode = strings.TrimSpace(hookCfg.Mode)
		if mode == "" || strings.EqualFold(mode, "inherit") {
			mode = strings.TrimSpace(a.scannerCfg.Guardrail.Mode)
		}
	}
	return normalizeAgentHookMode(mode)
}

func normalizeAgentHookMode(mode string) string {
	switch strings.ToLower(strings.TrimSpace(mode)) {
	case "action", "enforce":
		return "action"
	default:
		return "observe"
	}
}

func (a *APIServer) hookCapabilities(name string) connector.HookCapability {
	reg := a.connectorRegistry
	if reg == nil {
		reg = connector.NewDefaultRegistry()
	}
	conn, ok := reg.Get(name)
	if !ok {
		return connector.HookCapability{}
	}
	hp, ok := conn.(connector.HookCapabilityProvider)
	if !ok {
		return connector.HookCapability{}
	}
	return hp.HookCapabilities(connector.SetupOpts{
		DataDir:      a.configDataDir(),
		APIAddr:      a.apiAddrForCapabilities(),
		WorkspaceDir: currentWorkingDir(),
	})
}

func (a *APIServer) configDataDir() string {
	if a != nil && a.scannerCfg != nil {
		return a.scannerCfg.DataDir
	}
	return ""
}

func (a *APIServer) apiAddrForCapabilities() string {
	if a != nil && strings.TrimSpace(a.addr) != "" {
		return strings.TrimSpace(a.addr)
	}
	return "127.0.0.1:18970"
}

func currentWorkingDir() string {
	cwd, err := os.Getwd()
	if err != nil {
		return ""
	}
	return cwd
}

func mapHookAction(rawAction, mode, event string, caps connector.HookCapability) (string, bool) {
	rawAction = normalizeCodexAction(rawAction)
	if rawAction == "" {
		rawAction = "allow"
	}
	if mode != "action" {
		return "allow", rawAction == "block"
	}
	switch rawAction {
	case "block":
		if caps.CanBlock && eventIn(event, caps.BlockEvents) {
			return "block", false
		}
		return "allow", true
	case "confirm":
		if caps.CanAskNative && eventIn(event, caps.AskEvents) {
			return "confirm", false
		}
		return "alert", false
	default:
		return rawAction, false
	}
}

func agentHookResponseFor(req agentHookRequest, action, rawAction, severity, reason string, findings []string, mode string, wouldBlock bool, caps connector.HookCapability) agentHookResponse {
	if severity == "" {
		severity = "NONE"
	}
	if action == "" {
		action = "allow"
	}
	if rawAction == "" {
		rawAction = action
	}
	safeReason := string(redaction.ForSinkReason(reason))
	additional := genericHookAdditionalContext(req.ConnectorName, rawAction, severity, safeReason, wouldBlock)
	resp := agentHookResponse{
		Action:            action,
		RawAction:         rawAction,
		Severity:          severity,
		Reason:            safeReason,
		Findings:          findings,
		Mode:              mode,
		WouldBlock:        wouldBlock,
		AdditionalContext: additional,
	}
	resp.HookOutput = hookOutputFor(req, action, rawAction, safeReason, additional, caps)
	return resp
}

func hookOutputFor(req agentHookRequest, action, rawAction, reason, additional string, caps connector.HookCapability) map[string]interface{} {
	reason = connectorReason(req.ConnectorName, action, req.ToolName, reason)
	switch req.ConnectorName {
	case "hermes":
		if action == "block" {
			return map[string]interface{}{"decision": "block", "reason": reason}
		}
		if req.HookEventName == "pre_llm_call" && additional != "" {
			return map[string]interface{}{"context": additional}
		}
	case "cursor":
		switch action {
		case "block":
			return map[string]interface{}{"continue": true, "permission": "deny", "user_message": reason, "agent_message": reason}
		case "confirm":
			return map[string]interface{}{"continue": true, "permission": "ask", "user_message": reason, "agent_message": reason}
		case "alert":
			if additional != "" {
				return map[string]interface{}{"continue": true, "permission": "allow", "agent_message": additional}
			}
		}
	case "windsurf":
		if action == "block" {
			return map[string]interface{}{"message": reason}
		}
	case "geminicli":
		if action == "block" {
			return map[string]interface{}{"decision": "deny", "reason": reason}
		}
		if action == "alert" && additional != "" {
			return map[string]interface{}{"systemMessage": additional}
		}
	case "copilot":
		return copilotHookOutput(req.HookEventName, action, rawAction, reason, additional)
	}
	if rawAction == "confirm" && additional != "" && !caps.CanAskNative {
		return map[string]interface{}{"systemMessage": additional}
	}
	return nil
}

func copilotHookOutput(event, action, rawAction, reason, additional string) map[string]interface{} {
	switch canonicalEvent(event) {
	case "pretooluse":
		switch action {
		case "confirm":
			return map[string]interface{}{"permissionDecision": "ask", "permissionDecisionReason": reason}
		case "block":
			return map[string]interface{}{"permissionDecision": "deny", "permissionDecisionReason": reason}
		}
	case "permissionrequest":
		if action == "block" {
			return map[string]interface{}{"behavior": "deny", "message": reason, "interrupt": true}
		}
	case "agentstop", "stop", "subagentstop":
		if action == "block" {
			return map[string]interface{}{"decision": "block", "reason": reason}
		}
	case "posttoolusefailure":
		if additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
	case "notification":
		if additional != "" {
			return map[string]interface{}{"additionalContext": additional}
		}
	}
	if rawAction == "confirm" && additional != "" {
		return map[string]interface{}{"additionalContext": additional}
	}
	return nil
}

func genericHookAdditionalContext(connectorName, rawAction, severity, reason string, wouldBlock bool) string {
	if rawAction == "allow" || rawAction == "" {
		return ""
	}
	prefix := "DefenseClaw observed"
	if wouldBlock {
		prefix = "DefenseClaw would block this in action mode"
	}
	if reason == "" {
		return fmt.Sprintf("%s a %s %s hook finding.", prefix, severity, connectorName)
	}
	return fmt.Sprintf("%s a %s %s hook finding: %s", prefix, severity, connectorName, reason)
}

func reasonOrDefaultGeneric(connectorName, reason string) string {
	if strings.TrimSpace(reason) != "" {
		return reason
	}
	return fmt.Sprintf("Blocked by DefenseClaw %s policy.", connectorName)
}

// connectorReason renders the user-facing reason string surfaced by
// the per-connector hook_output JSON. Cursor and Copilot pass the
// "permission.user_message" / "permissionDecisionReason" verbatim
// to the operator (chat surface or modal), so a bare upstream reason
// like "matched policy: deny-rm-rf" is too terse to be actionable.
//
// When the upstream verdict already provides a sentence-shape reason
// we pass it through unchanged — operators have invested effort in
// crafting their policy reasons and we should not paper over them.
// We only synthesize a default when reason is empty, and the default
// is action-aware:
//
//   - block:                "DefenseClaw blocked <tool>. Run 'defenseclaw mcp list' / 'skill list' to review approved assets."
//   - confirm (ask):        "DefenseClaw needs your approval before <tool> can run."
//   - alert/allow_with_warn:"DefenseClaw flagged <tool> with a warning."
//   - allow / fallback:     "Allowed by DefenseClaw <connector> policy."
//
// The wording is short on purpose — "permissionDecisionReason"
// renders inside an OS-level approval prompt where long sentences
// get truncated. tool may be empty (e.g. UserPromptSubmit-class
// events); in that case we fall back to a tool-agnostic phrase.
func connectorReason(connectorName, action, tool, reason string) string {
	if r := strings.TrimSpace(reason); r != "" {
		return r
	}
	tool = strings.TrimSpace(tool)
	switch action {
	case "block":
		if tool == "" {
			return "DefenseClaw blocked this action. Run `defenseclaw mcp list` or `skill list` to review approved assets."
		}
		return fmt.Sprintf("DefenseClaw blocked %s. Run `defenseclaw mcp list` or `skill list` to review approved assets.", tool)
	case "confirm":
		if tool == "" {
			return "DefenseClaw needs your approval before this action can run."
		}
		return fmt.Sprintf("DefenseClaw needs your approval before %s can run.", tool)
	case "alert", "allow_with_warning":
		if tool == "" {
			return "DefenseClaw flagged this action with a warning."
		}
		return fmt.Sprintf("DefenseClaw flagged %s with a warning.", tool)
	default:
		if connectorName != "" {
			return fmt.Sprintf("Allowed by DefenseClaw %s policy.", connectorName)
		}
		return "Allowed by DefenseClaw policy."
	}
}

func eventIn(event string, events []string) bool {
	canon := canonicalEvent(event)
	for _, candidate := range events {
		if canonicalEvent(candidate) == canon {
			return true
		}
	}
	return false
}

func canonicalEvent(event string) string {
	event = strings.ToLower(strings.TrimSpace(event))
	event = strings.ReplaceAll(event, "_", "")
	event = strings.ReplaceAll(event, "-", "")
	return event
}

func isGenericToolInspectionEvent(event string) bool {
	switch canonicalEvent(event) {
	case "pretooluse", "beforetool", "pretoolcall", "permissionrequest",
		"beforeshellexecution", "beforemcpexecution", "beforereadfile", "beforetabfileread",
		"prereadcode", "prewritecode", "preruncommand", "premcptooluse":
		return true
	default:
		return false
	}
}

func isPromptLikeEvent(event string) bool {
	switch canonicalEvent(event) {
	case "userpromptsubmit", "userpromptsubmitted", "beforesubmitprompt", "preuserprompt",
		"prellmcall", "beforeagent", "beforemodel":
		return true
	default:
		return false
	}
}

func isResultLikeEvent(event string) bool {
	switch canonicalEvent(event) {
	case "posttooluse", "posttoolusefailure", "aftertool", "posttoolcall",
		"postreadcode", "postwritecode", "postruncommand", "postmcptooluse",
		"aftershellexecution", "aftermcpexecution", "afterfileedit", "aftertabfileedit",
		"afteragentresponse", "afteragentthought", "afteragent", "aftermodel":
		return true
	default:
		return false
	}
}

func firstString(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		if s := stringifyHookValue(obj[key]); strings.TrimSpace(s) != "" {
			return s
		}
	}
	return ""
}

func firstHookIdentityString(obj map[string]interface{}, keys ...string) string {
	for _, key := range keys {
		value, ok := obj[key]
		if !ok || value == nil {
			continue
		}
		switch v := value.(type) {
		case string:
			if s := sanitizeHookIdentityValue(v); s != "" {
				return s
			}
		case json.Number:
			if s := sanitizeHookIdentityValue(v.String()); s != "" {
				return s
			}
		case float64:
			if s := sanitizeHookIdentityValue(strconv.FormatFloat(v, 'f', -1, 64)); s != "" {
				return s
			}
		case bool:
			if s := sanitizeHookIdentityValue(strconv.FormatBool(v)); s != "" {
				return s
			}
		}
	}
	return ""
}

func sanitizeHookIdentityValue(value string) string {
	value = strings.TrimSpace(value)
	if value == "" {
		return ""
	}
	value = strings.Map(func(r rune) rune {
		if r < 0x20 || r == 0x7f {
			return -1
		}
		return r
	}, value)
	runes := []rune(value)
	if len(runes) > 128 {
		value = string(runes[:128])
	}
	return value
}

func firstValue(obj map[string]interface{}, keys ...string) interface{} {
	for _, key := range keys {
		if value, ok := obj[key]; ok && value != nil {
			return value
		}
	}
	return nil
}

func objectAt(obj map[string]interface{}, key string) map[string]interface{} {
	if child, ok := obj[key].(map[string]interface{}); ok {
		return child
	}
	return nil
}

func stringifyHookValue(value interface{}) string {
	switch v := value.(type) {
	case nil:
		return ""
	case string:
		return v
	case json.Number:
		return v.String()
	default:
		b, err := json.Marshal(v)
		if err != nil {
			return fmt.Sprint(v)
		}
		return string(b)
	}
}
