// Copyright 2026 Cisco Systems, Inc. and its affiliates
//
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"net/http"
	osuser "os/user"
	"strconv"
	"strings"

	"github.com/google/uuid"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
)

const (
	llmEventUserIDHeader   = "X-DefenseClaw-User-Id"
	llmEventUserNameHeader = "X-DefenseClaw-User-Name"
	maxLLMEventUserLength  = 256
)

type llmEventMeta struct {
	Source         string
	Provider       string
	Model          string
	SessionID      string
	RequestID      string
	RunID          string
	TurnID         string
	PromptID       string
	ResponseID     string
	AgentID        string
	AgentName      string
	AgentType      string
	UserID         string
	UserName       string
	PolicyID       string
	DestinationApp string
	ToolName       string
	ToolID         string
}

func emitLLMPromptEvent(ctx context.Context, meta llmEventMeta, prompt string, rawRequestBody []byte) string {
	if strings.TrimSpace(prompt) == "" && len(rawRequestBody) == 0 {
		return ""
	}
	if meta.PromptID == "" {
		meta.PromptID = stableLLMEventID("prompt", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID)
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType:      gatewaylog.EventLLMPrompt,
		Severity:       gatewaylog.SeverityInfo,
		RunID:          meta.RunID,
		RequestID:      meta.RequestID,
		SessionID:      meta.SessionID,
		Provider:       meta.Provider,
		Model:          meta.Model,
		Direction:      gatewaylog.DirectionPrompt,
		AgentID:        meta.AgentID,
		AgentName:      meta.AgentName,
		AgentType:      meta.AgentType,
		UserID:         meta.UserID,
		UserName:       meta.UserName,
		PolicyID:       meta.PolicyID,
		DestinationApp: meta.DestinationApp,
		ToolName:       meta.ToolName,
		ToolID:         meta.ToolID,
		LLMPrompt: &gatewaylog.LLMPromptPayload{
			PromptID:       meta.PromptID,
			TurnID:         meta.TurnID,
			Role:           "user",
			Prompt:         prompt,
			RawRequestBody: string(rawRequestBody),
			Source:         meta.Source,
		},
	})
	return meta.PromptID
}

func emitLLMResponseEvent(ctx context.Context, meta llmEventMeta, response, rawResponseBody string, finishReasons []string) string {
	if strings.TrimSpace(response) == "" && rawResponseBody == "" && len(finishReasons) == 0 {
		return ""
	}
	if meta.ResponseID == "" {
		meta.ResponseID = stableLLMEventID("response", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID, meta.PromptID)
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType:      gatewaylog.EventLLMResponse,
		Severity:       gatewaylog.SeverityInfo,
		RunID:          meta.RunID,
		RequestID:      meta.RequestID,
		SessionID:      meta.SessionID,
		Provider:       meta.Provider,
		Model:          meta.Model,
		Direction:      gatewaylog.DirectionCompletion,
		AgentID:        meta.AgentID,
		AgentName:      meta.AgentName,
		AgentType:      meta.AgentType,
		UserID:         meta.UserID,
		UserName:       meta.UserName,
		PolicyID:       meta.PolicyID,
		DestinationApp: meta.DestinationApp,
		ToolName:       meta.ToolName,
		ToolID:         meta.ToolID,
		LLMResponse: &gatewaylog.LLMResponsePayload{
			ResponseID:      meta.ResponseID,
			ReplyToPromptID: meta.PromptID,
			TurnID:          meta.TurnID,
			Response:        response,
			RawResponseBody: rawResponseBody,
			FinishReasons:   uniqueNonEmpty(finishReasons),
			Source:          meta.Source,
		},
	})
	return meta.ResponseID
}

func emitToolInvocationEvent(ctx context.Context, meta llmEventMeta, phase, tool, input, output string, exitCode *int) {
	if strings.TrimSpace(tool) == "" || strings.TrimSpace(phase) == "" {
		return
	}
	if meta.ToolID == "" {
		meta.ToolID = stableLLMEventID("tool", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID, tool, phase)
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType:      gatewaylog.EventToolInvocation,
		Severity:       gatewaylog.SeverityInfo,
		RunID:          meta.RunID,
		RequestID:      meta.RequestID,
		SessionID:      meta.SessionID,
		Provider:       meta.Provider,
		Model:          meta.Model,
		Direction:      gatewaylog.DirectionToolCall,
		AgentID:        meta.AgentID,
		AgentName:      meta.AgentName,
		AgentType:      meta.AgentType,
		UserID:         meta.UserID,
		UserName:       meta.UserName,
		PolicyID:       meta.PolicyID,
		DestinationApp: meta.DestinationApp,
		ToolName:       tool,
		ToolID:         meta.ToolID,
		Tool: &gatewaylog.ToolPayload{
			ToolCallID:      meta.ToolID,
			Phase:           phase,
			TurnID:          meta.TurnID,
			Tool:            tool,
			ToolInput:       input,
			ToolOutput:      output,
			ExitCode:        exitCode,
			ReplyToPromptID: meta.PromptID,
			Source:          meta.Source,
		},
	})
}

func emitOpenAIToolCallEvents(ctx context.Context, meta llmEventMeta, toolCallsJSON json.RawMessage) {
	if len(toolCallsJSON) == 0 {
		return
	}
	var toolCalls []struct {
		ID       string `json:"id"`
		Type     string `json:"type"`
		Function struct {
			Name      string `json:"name"`
			Arguments string `json:"arguments"`
		} `json:"function"`
	}
	if err := json.Unmarshal(toolCallsJSON, &toolCalls); err != nil {
		fallback := meta
		fallback.ToolID = stableLLMEventID("tool", meta.Source, meta.SessionID, meta.RequestID, meta.Model, "unparsed")
		emitToolInvocationEvent(ctx, fallback, "call", "unknown", string(toolCallsJSON), "", nil)
		return
	}
	for i, tc := range toolCalls {
		toolName := firstNonEmpty(tc.Function.Name, tc.Type, "unknown")
		callMeta := meta
		callMeta.ToolName = toolName
		callMeta.ToolID = firstNonEmpty(tc.ID, stableLLMEventID("tool", meta.Source, meta.SessionID, meta.RequestID, meta.Model, intString(i)))
		emitToolInvocationEvent(ctx, callMeta, "call", toolName, tc.Function.Arguments, "", nil)
	}
}

func proxyLLMEventMeta(p *GuardrailProxy, r *http.Request, req *ChatRequest, provider string) llmEventMeta {
	env := audit.EnvelopeFromContext(r.Context())
	userID, userName := userFromHTTPRequest(r, req.RawBody)
	sessionID := firstNonEmpty(SessionIDFromContext(r.Context()), r.Header.Get("X-Conversation-ID"), env.SessionID)
	requestID := firstNonEmpty(RequestIDFromContext(r.Context()), env.RequestID)
	return llmEventMeta{
		Source:         p.connectorName(),
		Provider:       provider,
		Model:          req.Model,
		SessionID:      sessionID,
		RequestID:      requestID,
		RunID:          env.RunID,
		AgentID:        firstNonEmpty(env.AgentID, p.agentIDForRequest()),
		AgentName:      firstNonEmpty(env.AgentName, p.agentNameForRequest(r.Header.Get("X-Agent-Name"))),
		AgentType:      p.connectorName(),
		UserID:         userID,
		UserName:       userName,
		PolicyID:       firstNonEmpty(env.PolicyID, p.defaultPolicyID),
		DestinationApp: env.DestinationApp,
	}
}

func streamLLMEventMeta(r *EventRouter, sessionID, runID, provider, model, agentName string) llmEventMeta {
	return llmEventMeta{
		Source:    "openclaw",
		Provider:  provider,
		Model:     model,
		SessionID: sessionID,
		RunID:     firstNonEmpty(runID, gatewaylog.ProcessRunID()),
		AgentID:   SharedAgentRegistry().AgentID(),
		AgentName: r.agentNameForStream(agentName),
		AgentType: r.agentNameForStream(agentName),
		PolicyID:  r.defaultPolicyID,
	}
}

func (a *APIServer) emitCodexHookLLMEvent(ctx context.Context, req codexHookRequest, _ []string, rawPayload []byte) {
	meta := hookLLMEventMeta("codex", req.SessionID, req.TurnID, req.Model, req.Source, req.AgentID, req.AgentType, req.Payload)
	switch req.HookEventName {
	case "UserPromptSubmit":
		meta.PromptID = hookPromptID("codex", req.SessionID, req.TurnID, req.Prompt, rawPayload)
		promptID := emitLLMPromptEvent(ctx, meta, req.Prompt, rawPayload)
		a.rememberHookPromptID("codex", req.SessionID, req.TurnID, promptID)
	case "PreToolUse", "PermissionRequest":
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), codexToolName(req))
		emitToolInvocationEvent(ctx, meta, "call", codexToolName(req), stringFromJSONRaw(codexToolArgs(req)), "", nil)
	case "PostToolUse":
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), codexToolName(req))
		emitToolInvocationEvent(ctx, meta, "result", codexToolName(req), "", codexToolResponseString(req.ToolResponse), nil)
	case "Stop":
		if strings.TrimSpace(req.LastAssistantMessage) == "" {
			return
		}
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ResponseID = stableLLMEventID("response", "codex", req.SessionID, req.TurnID)
		emitLLMResponseEvent(ctx, meta, req.LastAssistantMessage, string(rawPayload), nil)
	}
}

func (a *APIServer) emitClaudeCodeHookLLMEvent(ctx context.Context, req claudeCodeHookRequest, _ []string, rawPayload []byte) {
	meta := hookLLMEventMeta("claudecode", req.SessionID, "", req.Model, req.Source, req.AgentID, req.AgentType, req.Payload)
	switch req.HookEventName {
	case "UserPromptSubmit", "UserPromptExpansion":
		prompt := claudeCodePromptContent(req)
		meta.PromptID = hookPromptID("claudecode", req.SessionID, "", prompt, rawPayload)
		promptID := emitLLMPromptEvent(ctx, meta, prompt, rawPayload)
		a.rememberHookPromptID("claudecode", req.SessionID, "", promptID)
	case "PreToolUse", "PermissionRequest", "PermissionDenied":
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(req.MCPServerName, claudeCodeToolName(req))
		emitToolInvocationEvent(ctx, meta, "call", claudeCodeToolName(req), stringFromJSONRaw(claudeCodeToolArgs(req)), "", nil)
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch":
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(req.MCPServerName, claudeCodeToolName(req))
		emitToolInvocationEvent(ctx, meta, "result", claudeCodeToolName(req), "", claudeCodeToolOutput(req), nil)
	case "Stop", "SubagentStop", "SessionEnd":
		if strings.TrimSpace(req.LastAssistantMessage) == "" {
			return
		}
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ResponseID = stableLLMEventID("response", "claudecode", req.SessionID)
		emitLLMResponseEvent(ctx, meta, req.LastAssistantMessage, string(rawPayload), nil)
	}
}

func hookLLMEventMeta(source, sessionID, turnID, model, hookSource, agentID, agentType string, payload map[string]interface{}) llmEventMeta {
	userID, userName := userFromHookPayload(payload)
	provider := inferSystem("", model)
	if provider == "unknown" {
		provider = strings.TrimSpace(hookSource)
	}
	return llmEventMeta{
		Source:    source,
		Provider:  provider,
		Model:     model,
		SessionID: sessionID,
		TurnID:    turnID,
		AgentID:   agentID,
		AgentName: firstNonEmpty(agentID, agentType, source),
		AgentType: firstNonEmpty(agentType, source),
		UserID:    userID,
		UserName:  userName,
	}
}

func hookToolDestinationApp(serverName, toolName string) string {
	if server := strings.TrimSpace(serverName); server != "" {
		return toolDestinationApp("mcp", server)
	}
	if server := serverFromMCPToolName(toolName); server != "" {
		return toolDestinationApp("mcp", server)
	}
	if strings.TrimSpace(toolName) == "" {
		return ""
	}
	return toolDestinationApp("builtin", "")
}

func (a *APIServer) rememberHookPromptID(source, sessionID, turnID, promptID string) {
	if a == nil || source == "" || sessionID == "" || promptID == "" {
		return
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.llmPromptBySourceSession == nil {
		a.llmPromptBySourceSession = map[string]string{}
	}
	a.llmPromptBySourceSession[source+"\x00"+sessionID] = promptID
	if turnID != "" {
		if a.llmPromptBySourceSessionTurn == nil {
			a.llmPromptBySourceSessionTurn = map[string]string{}
		}
		a.llmPromptBySourceSessionTurn[source+"\x00"+sessionID+"\x00"+turnID] = promptID
	}
}

func (a *APIServer) lastHookPromptID(source, sessionID string) string {
	if a == nil || source == "" || sessionID == "" {
		return ""
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	return a.llmPromptBySourceSession[source+"\x00"+sessionID]
}

func (a *APIServer) lastHookPromptIDForTurn(source, sessionID, turnID string) string {
	if a == nil || source == "" || sessionID == "" || turnID == "" {
		return ""
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	return a.llmPromptBySourceSessionTurn[source+"\x00"+sessionID+"\x00"+turnID]
}

func userFromHookPayload(payload map[string]interface{}) (string, string) {
	if payload == nil {
		return llmEventUserWithLocalFallback("", "")
	}
	userID := firstNonEmpty(
		stringMapValue(payload, "user_id"),
		stringMapValue(payload, "user"),
		stringMapValue(payload, "actor"),
		stringMapValue(payload, "login"),
	)
	userName := firstNonEmpty(
		stringMapValue(payload, "user_name"),
		stringMapValue(payload, "username"),
		stringMapValue(payload, "user_login"),
	)
	return llmEventUserWithLocalFallback(userID, userName)
}

func stringMapValue(m map[string]interface{}, key string) string {
	v, ok := m[key]
	if !ok || v == nil {
		return ""
	}
	s, ok := v.(string)
	if ok {
		return strings.TrimSpace(s)
	}
	return ""
}

func stableLLMEventID(prefix string, parts ...string) string {
	var clean []string
	for _, part := range parts {
		part = strings.TrimSpace(part)
		if part != "" {
			clean = append(clean, part)
		}
	}
	if len(clean) == 0 {
		return prefix + "-" + uuid.NewString()
	}
	sum := sha256.Sum256([]byte(strings.Join(clean, "\x00")))
	return prefix + "-" + hex.EncodeToString(sum[:8])
}

func promptIDForTurn(source, sessionID, turnID string) string {
	if strings.TrimSpace(sessionID) == "" && strings.TrimSpace(turnID) == "" {
		return ""
	}
	return stableLLMEventID("prompt", source, sessionID, turnID)
}

func hookPromptID(source, sessionID, turnID, prompt string, rawPayload []byte) string {
	var rawDigest string
	if len(rawPayload) > 0 {
		sum := sha256.Sum256(rawPayload)
		rawDigest = hex.EncodeToString(sum[:8])
	}
	id := stableLLMEventID("prompt", source, sessionID, turnID, prompt, rawDigest)
	if strings.TrimSpace(id) != "" {
		return id
	}
	return firstNonEmpty(promptIDForTurn(source, sessionID, turnID), stableLLMEventID("prompt", source, sessionID))
}

func promptIDForSessionMessage(sessionID string, messageSeq int, messageID string) string {
	if messageSeq > 0 {
		return stableLLMEventID("prompt", "openclaw", sessionID, intString(messageSeq))
	}
	return stableLLMEventID("prompt", "openclaw", sessionID, messageID)
}

func replyPromptIDForSessionMessage(sessionID string, messageSeq int) string {
	if messageSeq <= 0 {
		return ""
	}
	return stableLLMEventID("prompt", "openclaw", sessionID, intString(messageSeq-1))
}

func intString(v int) string {
	return strconv.Itoa(v)
}

func userFromHTTPRequest(r *http.Request, rawBody []byte) (string, string) {
	userID := firstNonEmpty(
		r.Header.Get(llmEventUserIDHeader),
		r.Header.Get("X-User-Id"),
		r.Header.Get("X-User-ID"),
		r.Header.Get("X-User"),
	)
	userName := firstNonEmpty(
		r.Header.Get(llmEventUserNameHeader),
		r.Header.Get("X-User-Name"),
		r.Header.Get("X-Username"),
	)
	if len(rawBody) > 0 {
		var body struct {
			User     string `json:"user"`
			UserID   string `json:"user_id"`
			UserName string `json:"user_name"`
			Username string `json:"username"`
		}
		if json.Unmarshal(rawBody, &body) == nil {
			userID = firstNonEmpty(userID, body.UserID, body.User)
			userName = firstNonEmpty(userName, body.UserName, body.Username)
		}
	}
	return llmEventUserWithLocalFallback(userID, userName)
}

func llmEventUserWithLocalFallback(userID, userName string) (string, string) {
	userID = sanitizeLLMEventUser(userID)
	userName = sanitizeLLMEventUser(userName)
	if userID != "" || userName != "" {
		return userID, userName
	}
	current, err := osuser.Current()
	if err != nil || current == nil {
		return "", ""
	}
	return sanitizeLLMEventUser(firstNonEmpty(current.Uid, current.Username)),
		sanitizeLLMEventUser(firstNonEmpty(current.Username, current.Name, current.Uid))
}

func sanitizeLLMEventUser(v string) string {
	v = strings.TrimSpace(v)
	if v == "" {
		return ""
	}
	if len(v) > maxLLMEventUserLength {
		v = truncateToRuneBoundary(v, maxLLMEventUserLength)
	}
	if needsRequestIDClean(v) {
		v = sanitizeClientRequestID(v)
	}
	return v
}

func stringFromJSONRaw(raw json.RawMessage) string {
	if len(raw) == 0 {
		return ""
	}
	return string(raw)
}

func responseIDFromRawJSON(raw []byte) string {
	if len(raw) == 0 {
		return ""
	}
	var body struct {
		ID string `json:"id"`
	}
	if json.Unmarshal(raw, &body) != nil {
		return ""
	}
	return strings.TrimSpace(body.ID)
}
