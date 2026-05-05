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

	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
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
}

func (a *APIServer) handleAgentHook(connectorName string) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		if r.Method != http.MethodPost {
			if a.otel != nil {
				a.otel.RecordConnectorHookInvocation(r.Context(), connectorName, "unknown", "rejected", "method", 0)
			}
			http.Error(w, "method not allowed", http.StatusMethodNotAllowed)
			return
		}

		payload, b, err := rawPayloadFromJSONDecoder(json.NewDecoder(r.Body))
		if err != nil {
			if a.otel != nil {
				a.otel.RecordConnectorHookInvocation(r.Context(), connectorName, "unknown", "rejected", "invalid_json", 0)
			}
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "invalid JSON body"})
			return
		}

		req := normalizeAgentHookRequest(connectorName, payload)
		if req.HookEventName == "" {
			if a.otel != nil {
				a.otel.RecordConnectorHookInvocation(r.Context(), connectorName, "unknown", "rejected", "missing_event", 0)
			}
			a.writeJSON(w, http.StatusBadRequest, map[string]string{"error": "hook event name is required"})
			return
		}
		req.CWD = sanitizeHookCWD(req.CWD)
		ctx := enrichAgentHookContext(r.Context(), req)

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

		if a.logger != nil {
			details := fmt.Sprintf("action=%s raw_action=%s severity=%s mode=%s would_block=%v elapsed=%s",
				resp.Action, resp.RawAction, resp.Severity, resp.Mode, resp.WouldBlock, elapsed)
			details = appendRawTelemetryDetails(details, "raw_payload", b)
			_ = a.logger.LogActionCtx(ctx, connectorName+"-hook", req.HookEventName, details)
		}

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
	attrs := []attribute.KeyValue{
		attribute.String("defenseclaw.connector", req.ConnectorName),
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
	switch {
	case isPromptLikeEvent(req.HookEventName):
		verdict = a.inspectMessageContent(&ToolInspectRequest{Tool: "message", Content: req.Content, Direction: "prompt"})
	case isResultLikeEvent(req.HookEventName):
		verdict = a.inspectMessageContent(&ToolInspectRequest{Tool: req.ToolName, Content: req.Content, Direction: "tool_result"})
	case isGenericToolInspectionEvent(req.HookEventName):
		verdict = a.inspectToolPolicy(&ToolInspectRequest{Tool: req.ToolName, Args: req.ToolArgs, Direction: "tool_call"})
	}

	rawAction := normalizeCodexAction(verdict.Action)
	caps := a.hookCapabilities(req.ConnectorName)
	action, wouldBlock := mapHookAction(rawAction, mode, req.HookEventName, caps)
	return agentHookResponseFor(req, action, rawAction, verdict.Severity, verdict.Reason, verdict.Findings, mode, wouldBlock, caps)
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
	reason = reasonOrDefaultGeneric(req.ConnectorName, reason)
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
