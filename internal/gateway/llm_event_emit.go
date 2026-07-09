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
	"time"

	"github.com/google/uuid"
	"go.opentelemetry.io/otel/attribute"
	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	llmEventUserIDHeader   = "X-DefenseClaw-User-Id"
	llmEventUserNameHeader = "X-DefenseClaw-User-Name"
	maxLLMEventUserLength  = 256
)

type llmEventMeta struct {
	Source          string
	Provider        string
	Model           string
	SessionID       string
	RequestID       string
	RunID           string
	TurnID          string
	PromptID        string
	ResponseID      string
	AgentID         string
	AgentName       string
	AgentType       string
	RootAgentID     string
	ParentAgentID   string
	RootSessionID   string
	ParentSessionID string
	LifecycleID     string
	ExecutionID     string
	LifecycleEvent  string
	LifecycleState  string
	LifecycleDedupe string
	Phase           string
	PreviousPhase   string
	OperationID     string
	Sequence        int64
	AgentDepth      int
	ReportedCostUSD float64
	ReportedCost    bool
	ReportedCostSum bool
	SessionSource   string
	SessionResumed  bool
	UserID          string
	UserName        string
	PolicyID        string
	DestinationApp  string
	ToolName        string
	ToolID          string
	// TraceEventID scopes the short OTel anchor used for one hook delivery.
	// Session and agent identifiers remain stable across deliveries, but a
	// backend must not be asked to append children to a trace it has already
	// indexed and finalized.
	TraceEventID string
}

func agentPhaseCodePointer(meta llmEventMeta) *int {
	if strings.TrimSpace(meta.Phase) == "" {
		return nil
	}
	value := gatewaylog.AgentPhaseCode(meta.Phase)
	return &value
}

func agentDepthPointer(meta llmEventMeta) *int {
	if strings.TrimSpace(meta.AgentID) == "" {
		return nil
	}
	value := meta.AgentDepth
	return &value
}

func agentReportedCostPointer(meta llmEventMeta) *float64 {
	if !meta.ReportedCost {
		return nil
	}
	value := meta.ReportedCostUSD
	return &value
}

func boolPointer(value bool) *bool {
	return &value
}

func emitLLMPromptEvent(ctx context.Context, meta llmEventMeta, prompt string, rawRequestBody []byte) string {
	if strings.TrimSpace(prompt) == "" && len(rawRequestBody) == 0 {
		return ""
	}
	if meta.PromptID == "" {
		meta.PromptID = stableLLMEventID("prompt", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID)
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType:            gatewaylog.EventLLMPrompt,
		Severity:             gatewaylog.SeverityInfo,
		RunID:                meta.RunID,
		RequestID:            meta.RequestID,
		SessionID:            meta.SessionID,
		Provider:             meta.Provider,
		Model:                meta.Model,
		Direction:            gatewaylog.DirectionPrompt,
		AgentID:              meta.AgentID,
		AgentName:            meta.AgentName,
		AgentType:            meta.AgentType,
		RootAgentID:          meta.RootAgentID,
		ParentAgentID:        meta.ParentAgentID,
		RootSessionID:        meta.RootSessionID,
		ParentSessionID:      meta.ParentSessionID,
		AgentLifecycleID:     meta.LifecycleID,
		AgentExecutionID:     meta.ExecutionID,
		AgentLifecycleEvent:  meta.LifecycleEvent,
		AgentLifecycleState:  meta.LifecycleState,
		AgentPhase:           meta.Phase,
		AgentPreviousPhase:   meta.PreviousPhase,
		AgentPhaseCode:       agentPhaseCodePointer(meta),
		AgentSequence:        meta.Sequence,
		AgentOperationID:     meta.OperationID,
		AgentDepth:           agentDepthPointer(meta),
		AgentReportedCostUSD: agentReportedCostPointer(meta),
		AgentReportedCost:    boolPointer(meta.ReportedCost),
		SessionSource:        meta.SessionSource,
		SessionResumed:       boolPointer(meta.SessionResumed),
		UserID:               meta.UserID,
		UserName:             meta.UserName,
		PolicyID:             meta.PolicyID,
		DestinationApp:       meta.DestinationApp,
		ToolName:             meta.ToolName,
		ToolID:               meta.ToolID,
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
		EventType:            gatewaylog.EventLLMResponse,
		Severity:             gatewaylog.SeverityInfo,
		RunID:                meta.RunID,
		RequestID:            meta.RequestID,
		SessionID:            meta.SessionID,
		Provider:             meta.Provider,
		Model:                meta.Model,
		Direction:            gatewaylog.DirectionCompletion,
		AgentID:              meta.AgentID,
		AgentName:            meta.AgentName,
		AgentType:            meta.AgentType,
		RootAgentID:          meta.RootAgentID,
		ParentAgentID:        meta.ParentAgentID,
		RootSessionID:        meta.RootSessionID,
		ParentSessionID:      meta.ParentSessionID,
		AgentLifecycleID:     meta.LifecycleID,
		AgentExecutionID:     meta.ExecutionID,
		AgentLifecycleEvent:  meta.LifecycleEvent,
		AgentLifecycleState:  meta.LifecycleState,
		AgentPhase:           meta.Phase,
		AgentPreviousPhase:   meta.PreviousPhase,
		AgentPhaseCode:       agentPhaseCodePointer(meta),
		AgentSequence:        meta.Sequence,
		AgentOperationID:     meta.OperationID,
		AgentDepth:           agentDepthPointer(meta),
		AgentReportedCostUSD: agentReportedCostPointer(meta),
		AgentReportedCost:    boolPointer(meta.ReportedCost),
		SessionSource:        meta.SessionSource,
		SessionResumed:       boolPointer(meta.SessionResumed),
		UserID:               meta.UserID,
		UserName:             meta.UserName,
		PolicyID:             meta.PolicyID,
		DestinationApp:       meta.DestinationApp,
		ToolName:             meta.ToolName,
		ToolID:               meta.ToolID,
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
		EventType:            gatewaylog.EventToolInvocation,
		Severity:             gatewaylog.SeverityInfo,
		RunID:                meta.RunID,
		RequestID:            meta.RequestID,
		SessionID:            meta.SessionID,
		Provider:             meta.Provider,
		Model:                meta.Model,
		Direction:            gatewaylog.DirectionToolCall,
		AgentID:              meta.AgentID,
		AgentName:            meta.AgentName,
		AgentType:            meta.AgentType,
		RootAgentID:          meta.RootAgentID,
		ParentAgentID:        meta.ParentAgentID,
		RootSessionID:        meta.RootSessionID,
		ParentSessionID:      meta.ParentSessionID,
		AgentLifecycleID:     meta.LifecycleID,
		AgentExecutionID:     meta.ExecutionID,
		AgentLifecycleEvent:  meta.LifecycleEvent,
		AgentLifecycleState:  meta.LifecycleState,
		AgentPhase:           meta.Phase,
		AgentPreviousPhase:   meta.PreviousPhase,
		AgentPhaseCode:       agentPhaseCodePointer(meta),
		AgentSequence:        meta.Sequence,
		AgentOperationID:     meta.OperationID,
		AgentDepth:           agentDepthPointer(meta),
		AgentReportedCostUSD: agentReportedCostPointer(meta),
		AgentReportedCost:    boolPointer(meta.ReportedCost),
		SessionSource:        meta.SessionSource,
		SessionResumed:       boolPointer(meta.SessionResumed),
		UserID:               meta.UserID,
		UserName:             meta.UserName,
		PolicyID:             meta.PolicyID,
		DestinationApp:       meta.DestinationApp,
		ToolName:             tool,
		ToolID:               meta.ToolID,
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
	meta := hookLLMEventMeta("codex", req.SessionID, req.TurnID, req.Model, req.Source, req.AgentID, payloadString(req.Payload, "agent_name"), req.AgentType, req.Payload)
	meta.ToolID = req.ToolUseID
	meta.ToolName = codexToolName(req)
	meta = applyHookEventMeta(meta, req.HookEventName, req.Payload)
	meta = a.beginHookExecution(meta)
	meta = a.reconcileHookParent(meta)
	meta = a.mergeHookSessionLifecycle(meta)
	meta.TraceEventID = hookTraceEventID(ctx, meta)
	meta = a.enrichHookPhase(meta)
	recordLifecycle := a.shouldRecordHookLifecycleTransition(meta)
	emitHookLifecycleEvent(ctx, meta)
	if recordLifecycle {
		meta = a.normalizeHookReportedCost(meta)
		a.recordHookLifecycleMetric(ctx, meta)
		a.emitHookLifecycleTransitionSpan(ctx, meta)
	}
	a.rememberHookLLMSpanUsage(meta, extractHookPayloadTokenUsage(req.Payload))
	switch req.HookEventName {
	case "SessionStart":
		a.ensureHookSessionTrace(ctx, meta, "")
	case "UserPromptSubmit":
		meta.PromptID = hookPromptID("codex", req.SessionID, req.TurnID, req.Prompt, rawPayload)
		promptID := emitLLMPromptEvent(ctx, meta, req.Prompt, rawPayload)
		a.rememberHookPromptID("codex", req.SessionID, req.TurnID, promptID)
		a.rememberHookLLMSpanPrompt(meta, req.Prompt)
		a.ensureHookSessionTrace(ctx, meta, req.Prompt)
	case "SubagentStart":
		prompt := firstString(req.Payload, "task", "prompt", "description")
		if prompt == "" {
			prompt = hookLifecycleContent(meta, "subagent_input_not_reported")
		}
		meta.PromptID = hookPromptID("codex", req.SessionID, req.TurnID, prompt, rawPayload)
		emitLLMPromptEvent(ctx, meta, prompt, rawPayload)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.ensureHookSessionTrace(ctx, meta, prompt)
	case "PreToolUse", "PermissionRequest":
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), codexToolName(req))
		emitToolInvocationEvent(ctx, meta, "call", codexToolName(req), stringFromJSONRaw(codexToolArgs(req)), "", nil)
		a.ensureHookSessionTrace(ctx, meta, stringFromJSONRaw(codexToolArgs(req)))
		a.rememberHookToolInvocation(meta, codexToolName(req), stringFromJSONRaw(codexToolArgs(req)))
	case "PostToolUse":
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), codexToolName(req))
		emitToolInvocationEvent(ctx, meta, "result", codexToolName(req), "", codexToolResponseString(req.ToolResponse), nil)
		a.emitHookToolSpan(ctx, meta, codexToolName(req), stringFromJSONRaw(codexToolArgs(req)), codexToolResponseString(req.ToolResponse), nil)
	case "Stop", "SubagentStop":
		if strings.TrimSpace(req.LastAssistantMessage) == "" {
			return
		}
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ResponseID = stableLLMEventID("response", "codex", req.SessionID, req.TurnID)
		emitLLMResponseEvent(ctx, meta, req.LastAssistantMessage, string(rawPayload), nil)
		a.emitHookLLMSpan(ctx, meta, req.LastAssistantMessage)
	}
}

// emitAgentHookLLMEvent is the LLM-event emitter for the six
// hook-only connectors (hermes, cursor, windsurf, geminicli,
// copilot, openhands). It mirrors emitClaudeCodeHookLLMEvent /
// emitCodexHookLLMEvent so a "give me every prompt and tool call"
// query against the gateway log returns the same shape regardless
// of which framework the operator is running.
//
// Source-of-truth mapping per HookEventName flavor:
//
//   - prompt-like   (UserPromptSubmit, beforeSubmitPrompt,
//     pre_user_prompt, pre_llm_call, BeforeAgent,
//     BeforeModel, ...)        → emitLLMPromptEvent
//   - tool-call-like (PreToolUse, beforeShellExecution,
//     beforeMCPExecution, BeforeTool,
//     pre_run_command, ...)    → emitToolInvocationEvent("call")
//   - result-like    (PostToolUse, AfterTool, postToolUseFailure,
//     post_tool_call, after_*, ...)
//     → emitToolInvocationEvent("result")
//
// The connector name doubles as the event Source so downstream
// dashboards can split prompts/tools by framework. DestinationApp
// follows the same hookToolDestinationApp helper claudecode/codex
// use, which routes "mcp__server__tool" / explicit mcp_server_name
// payload fields to "mcp:<server>" and other tools to "builtin".
func (a *APIServer) emitAgentHookLLMEvent(ctx context.Context, req agentHookRequest, rawPayload []byte) {
	source := strings.TrimSpace(req.ConnectorName)
	if source == "" {
		return
	}
	model := payloadString(req.Payload, "model")
	meta := hookLLMEventMeta(source, req.SessionID, req.TurnID, model, source, req.AgentID, req.AgentName, req.AgentType, req.Payload)
	meta.ToolID = firstString(req.Payload, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId")
	meta.ToolName = req.ToolName
	meta = applyHookEventMeta(meta, req.HookEventName, req.Payload)
	meta = a.beginHookExecution(meta)
	meta = a.reconcileHookParent(meta)
	meta = a.mergeHookSessionLifecycle(meta)
	meta.TraceEventID = hookTraceEventID(ctx, meta)
	meta = a.enrichHookPhase(meta)
	recordLifecycle := a.shouldRecordHookLifecycleTransition(meta)
	emitHookLifecycleEvent(ctx, meta)
	if recordLifecycle {
		meta = a.normalizeHookReportedCost(meta)
		a.recordHookLifecycleMetric(ctx, meta)
		a.emitHookLifecycleTransitionSpan(ctx, meta)
	}
	a.rememberHookLLMSpanUsage(meta, extractHookPayloadTokenUsage(req.Payload))
	if meta.LifecycleEvent == "session_start" {
		a.ensureHookSessionTrace(ctx, meta, "")
		return
	}
	switch {
	case isPromptLikeEvent(req.HookEventName):
		prompt := req.Content
		meta.PromptID = hookPromptID(source, req.SessionID, req.TurnID, prompt, rawPayload)
		promptID := emitLLMPromptEvent(ctx, meta, prompt, rawPayload)
		a.rememberHookPromptID(source, req.SessionID, req.TurnID, promptID)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.ensureHookSessionTrace(ctx, meta, prompt)
	case isModelCompletionEvent(req.HookEventName), isStopCompletionEvent(req.HookEventName):
		response := strings.TrimSpace(req.Content)
		if response == "" {
			return
		}
		meta.PromptID = firstNonEmpty(
			a.lastHookPromptIDForTurn(source, req.SessionID, req.TurnID),
			a.lastHookPromptID(source, req.SessionID),
			promptIDForTurn(source, req.SessionID, req.TurnID),
		)
		meta.ResponseID = stableLLMEventID("response", source, req.SessionID, req.TurnID)
		emitLLMResponseEvent(ctx, meta, response, string(rawPayload), nil)
		a.emitHookLLMSpan(ctx, meta, response)
	case isGenericToolInspectionEvent(req.HookEventName):
		meta.PromptID = firstNonEmpty(
			a.lastHookPromptIDForTurn(source, req.SessionID, req.TurnID),
			a.lastHookPromptID(source, req.SessionID),
			promptIDForTurn(source, req.SessionID, req.TurnID),
		)
		meta.ToolID = firstString(req.Payload, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId")
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), req.ToolName)
		emitToolInvocationEvent(ctx, meta, "call", req.ToolName, stringFromJSONRaw(req.ToolArgs), "", nil)
		a.ensureHookSessionTrace(ctx, meta, stringFromJSONRaw(req.ToolArgs))
		a.rememberHookToolInvocation(meta, req.ToolName, stringFromJSONRaw(req.ToolArgs))
		a.emitInferredDelegatedAgentTransitions(ctx, meta, req.ToolName, stringFromJSONRaw(req.ToolArgs), true)
	case isResultLikeEvent(req.HookEventName):
		meta.PromptID = firstNonEmpty(
			a.lastHookPromptIDForTurn(source, req.SessionID, req.TurnID),
			a.lastHookPromptID(source, req.SessionID),
			promptIDForTurn(source, req.SessionID, req.TurnID),
		)
		meta.ToolID = firstString(req.Payload, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId")
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), req.ToolName)
		emitToolInvocationEvent(ctx, meta, "result", req.ToolName, "", req.Content, nil)
		a.emitInferredDelegatedAgentTransitions(ctx, meta, req.ToolName, stringFromJSONRaw(req.ToolArgs), false)
		a.emitHookToolSpan(ctx, meta, req.ToolName, stringFromJSONRaw(req.ToolArgs), req.Content, nil)
	}
}

func (a *APIServer) emitClaudeCodeHookLLMEvent(ctx context.Context, req claudeCodeHookRequest, _ []string, rawPayload []byte) {
	meta := hookLLMEventMeta("claudecode", req.SessionID, req.TurnID, req.Model, req.Source, req.AgentID, payloadString(req.Payload, "agent_name"), req.AgentType, req.Payload)
	meta.ToolID = req.ToolUseID
	meta.ToolName = claudeCodeToolName(req)
	meta = applyHookEventMeta(meta, req.HookEventName, req.Payload)
	meta = a.beginHookExecution(meta)
	meta = a.reconcileHookParent(meta)
	meta = a.mergeHookSessionLifecycle(meta)
	meta.TraceEventID = hookTraceEventID(ctx, meta)
	meta = a.enrichHookPhase(meta)
	recordLifecycle := a.shouldRecordHookLifecycleTransition(meta)
	emitHookLifecycleEvent(ctx, meta)
	if recordLifecycle {
		meta = a.normalizeHookReportedCost(meta)
		a.recordHookLifecycleMetric(ctx, meta)
		a.emitHookLifecycleTransitionSpan(ctx, meta)
	}
	a.rememberHookLLMSpanUsage(meta, extractHookPayloadTokenUsage(req.Payload))
	switch req.HookEventName {
	case "SessionStart":
		a.ensureHookSessionTrace(ctx, meta, "")
	case "UserPromptSubmit", "UserPromptExpansion":
		prompt := claudeCodePromptContent(req)
		meta.PromptID = hookPromptID("claudecode", req.SessionID, "", prompt, rawPayload)
		promptID := emitLLMPromptEvent(ctx, meta, prompt, rawPayload)
		a.rememberHookPromptID("claudecode", req.SessionID, "", promptID)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.ensureHookSessionTrace(ctx, meta, prompt)
	case "MessageDisplay":
		if strings.TrimSpace(req.Delta) == "" {
			return
		}
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ResponseID = firstNonEmpty(req.MessageID, stableLLMEventID("response", "claudecode", req.SessionID, req.TurnID))
		finish := "streaming"
		if req.DisplayFinal {
			finish = "stop"
		}
		emitLLMResponseEvent(ctx, meta, req.Delta, string(rawPayload), []string{finish})
	case "SubagentStart":
		prompt := firstString(req.Payload, "task", "prompt", "description")
		if prompt == "" {
			prompt = hookLifecycleContent(meta, "subagent_input_not_reported")
		}
		meta.PromptID = hookPromptID("claudecode", req.SessionID, "", prompt, rawPayload)
		emitLLMPromptEvent(ctx, meta, prompt, rawPayload)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.ensureHookSessionTrace(ctx, meta, prompt)
	case "PreToolUse", "PermissionRequest", "PermissionDenied":
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(req.MCPServerName, claudeCodeToolName(req))
		emitToolInvocationEvent(ctx, meta, "call", claudeCodeToolName(req), stringFromJSONRaw(claudeCodeToolArgs(req)), "", nil)
		a.ensureHookSessionTrace(ctx, meta, stringFromJSONRaw(claudeCodeToolArgs(req)))
		a.rememberHookToolInvocation(meta, claudeCodeToolName(req), stringFromJSONRaw(claudeCodeToolArgs(req)))
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch":
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(req.MCPServerName, claudeCodeToolName(req))
		emitToolInvocationEvent(ctx, meta, "result", claudeCodeToolName(req), "", claudeCodeToolOutput(req), nil)
		a.emitHookToolSpan(ctx, meta, claudeCodeToolName(req), stringFromJSONRaw(claudeCodeToolArgs(req)), claudeCodeToolOutput(req), nil)
	case "StopFailure":
		if strings.TrimSpace(req.LastAssistantMessage) != "" {
			meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
			meta.ResponseID = stableLLMEventID("response", "claudecode", req.SessionID, req.TurnID, "failure")
			emitLLMResponseEvent(ctx, meta, req.LastAssistantMessage, string(rawPayload), []string{"error"})
		}
	case "Stop", "SubagentStop", "SessionEnd":
		if strings.TrimSpace(req.LastAssistantMessage) == "" {
			return
		}
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ResponseID = stableLLMEventID("response", "claudecode", req.SessionID)
		emitLLMResponseEvent(ctx, meta, req.LastAssistantMessage, string(rawPayload), nil)
		a.emitHookLLMSpan(ctx, meta, req.LastAssistantMessage)
	}
}

func hookLLMEventMeta(source, sessionID, turnID, model, hookSource, agentID, agentName, agentType string, payload map[string]interface{}) llmEventMeta {
	userID, userName := userFromHookPayload(payload)
	provider := inferSystem("", model)
	if provider == "unknown" {
		provider = strings.TrimSpace(hookSource)
		switch strings.ToLower(provider) {
		case "", "startup", "resume", "clear", "compact":
			provider = source
		}
	}
	lifecycleEvent := canonicalHookLifecycleEvent(firstString(payload,
		"hook_event_name", "hookEventName", "event_type", "eventType", "event_name", "eventName",
	))
	rootAgentID := stableLLMEventID("agent", source, sessionID, "root")
	agentID = strings.TrimSpace(agentID)
	if agentID == "" && (lifecycleEvent == "subagent_start" || lifecycleEvent == "subagent_stop") {
		childIdentity := firstNonEmpty(
			firstString(payload, "subagent_id", "subagentId", "agent_transcript_path", "agentTranscriptPath", "tool_call_id", "toolCallId"),
			firstString(payload, "child_role", "agent_name", "agentName", "agent_type", "agentType"),
			firstString(objectAt(payload, "extra"), "child_role", "agent_name", "agent_type"),
			"subagent",
		)
		agentID = stableLLMEventID("agent", source, sessionID, "subagent", childIdentity)
		agentName = firstNonEmpty(agentName, childIdentity)
	}
	if agentID == "" {
		agentID = rootAgentID
	}
	parentSessionID := firstNonEmpty(
		firstString(payload, "parent_session_id", "parentSessionId", "parentSessionID"),
		firstString(objectAt(payload, "extra"), "parent_session_id", "parentSessionId", "parentSessionID"),
	)
	parentAgentID := firstNonEmpty(
		firstString(payload, "parent_agent_id", "parentAgentId", "parent_id", "parentId"),
		firstString(objectAt(payload, "extra"), "parent_subagent_id", "parentSubagentId", "parent_agent_id", "parentAgentId"),
	)
	if parentAgentID == "" {
		if parentSessionID != "" {
			parentAgentID = stableLLMEventID("agent", source, parentSessionID, "root")
		}
	}
	// A connector-supplied agent ID is not, by itself, proof that this is a
	// child agent: several connectors assign an opaque ID to the root agent.
	// Infer the root parent only for explicit subagent lifecycle events. Later
	// child events inherit the relationship from the retained lifecycle trace.
	if parentAgentID == "" && agentID != rootAgentID &&
		(lifecycleEvent == "subagent_start" || lifecycleEvent == "subagent_stop") {
		parentAgentID = rootAgentID
	}
	rootAgentID = firstNonEmpty(
		firstString(payload, "root_agent_id", "rootAgentId", "rootAgentID"),
		firstString(objectAt(payload, "extra"), "root_agent_id", "rootAgentId", "rootAgentID"),
		parentAgentID, agentID,
	)
	rootSessionID := firstNonEmpty(
		firstString(payload, "root_session_id", "rootSessionId", "rootSessionID"),
		firstString(objectAt(payload, "extra"), "root_session_id", "rootSessionId", "rootSessionID"),
		parentSessionID, sessionID,
	)
	depth := int(firstInt64(payload, "agent_depth", "agentDepth", "depth"))
	if depth < 0 {
		depth = 0
	}
	if parentAgentID != "" && depth == 0 {
		depth = 1
	}
	lifecycleState := hookLifecycleState(lifecycleEvent, payload)
	sessionSource := firstString(payload, "session_source", "sessionSource", "resume_source", "resumeSource")
	if sessionSource == "" && (lifecycleEvent == "session_start" || lifecycleEvent == "session_end") {
		sessionSource = firstString(payload, "source", "reason")
	}
	resumed := strings.Contains(strings.ToLower(sessionSource), "resume")
	executionSeed := firstNonEmpty(gatewaylog.ProcessRunID(), turnID, sessionSource, "gateway-process")
	reportedCost := extractHookPayloadReportedCost(payload)
	return llmEventMeta{
		Source:    source,
		Provider:  provider,
		Model:     model,
		SessionID: sessionID,
		TurnID:    turnID,
		AgentID:   agentID,
		// Prefer a readable runtime name in UIs. The stable opaque identity is
		// still preserved separately as gen_ai.agent.id.
		AgentName:       firstNonEmpty(agentName, agentType, source, agentID),
		AgentType:       firstNonEmpty(agentType, source),
		RootAgentID:     rootAgentID,
		ParentAgentID:   parentAgentID,
		RootSessionID:   rootSessionID,
		ParentSessionID: parentSessionID,
		LifecycleID:     stableLLMEventID("lifecycle", source, sessionID, agentID),
		ExecutionID:     stableLLMEventID("execution", source, sessionID, agentID, executionSeed),
		LifecycleEvent:  lifecycleEvent,
		LifecycleState:  lifecycleState,
		AgentDepth:      depth,
		ReportedCostUSD: reportedCost.USD,
		ReportedCost:    reportedCost.Present,
		ReportedCostSum: reportedCost.Cumulative,
		SessionSource:   sessionSource,
		SessionResumed:  resumed,
		UserID:          userID,
		UserName:        userName,
	}
}

// applyHookEventMeta makes the normalized request event authoritative. Typed
// connector decoders keep the event outside Payload, while generic decoders
// usually leave it inside; relying only on Payload made those two paths produce
// different lifecycle attributes for the same upstream hook.
func applyHookEventMeta(meta llmEventMeta, event string, payload map[string]interface{}) llmEventMeta {
	meta.LifecycleEvent = canonicalHookLifecycleEvent(event)
	meta.LifecycleState = hookLifecycleState(meta.LifecycleEvent, payload)
	meta.LifecycleDedupe = hookLifecycleDedupeKey(meta, payload)
	meta.Phase = hookLifecyclePhase(event, meta.LifecycleEvent, meta.LifecycleState)
	meta.OperationID = hookOperationID(meta)
	if (meta.LifecycleEvent == "session_start" || meta.LifecycleEvent == "session_end") && meta.SessionSource == "" {
		meta.SessionSource = firstString(payload, "source", "reason")
		meta.SessionResumed = strings.Contains(strings.ToLower(meta.SessionSource), "resume")
	}
	if (meta.LifecycleEvent == "subagent_start" || meta.LifecycleEvent == "subagent_stop") &&
		meta.ParentAgentID == "" {
		rootAgentID := stableLLMEventID("agent", meta.Source, meta.SessionID, "root")
		if meta.AgentID != "" && meta.AgentID != rootAgentID {
			meta.ParentAgentID = rootAgentID
			if meta.AgentDepth == 0 {
				meta.AgentDepth = 1
			}
		}
	}
	return meta
}

func canonicalHookLifecycleEvent(event string) string {
	switch canonicalEvent(event) {
	case "sessionstart", "onsessionstart", "onsessionreset", "sessioncreated":
		return "session_start"
	case "sessionend", "onsessionend", "onsessionfinalize", "sessiondeleted", "sessionerror":
		return "session_end"
	case "subagentstart":
		return "subagent_start"
	case "subagentstop":
		return "subagent_stop"
	case "precompact", "precompress":
		return "compact_start"
	case "postcompact", "sessioncompacted":
		return "compact_end"
	case "stop", "stopfailure", "agentstop", "afteragent", "afteragentresponse",
		"postllmcall", "postinvocation", "sessionidle", "teammateidle",
		"postcascaderesponse", "postcascaderesponsewithtranscript":
		return "turn_end"
	case "userpromptsubmit", "userpromptsubmitted", "beforesubmitprompt", "preuserprompt",
		"prellmcall", "beforeagent", "beforemodel", "preinvocation":
		return "turn_start"
	case "pretooluse", "beforetool", "beforetoolselection", "pretoolcall", "preruncommand", "premcptooluse",
		"beforemcpexecution", "beforeshellexecution", "beforereadfile", "beforetabfileread",
		"prereadcode", "prewritecode", "toolexecutebefore", "permissionrequest":
		return "tool_start"
	case "posttooluse", "aftertool", "posttoolcall", "posttoolusefailure", "posttoolbatch",
		"postreadcode", "postwritecode", "postruncommand", "postmcptooluse",
		"aftershellexecution", "aftermcpexecution", "afterfileedit", "aftertabfileedit",
		"toolexecuteafter", "permissiondenied", "postsetupworktree":
		return "tool_end"
	default:
		return "event"
	}
}

func hookLifecycleState(event string, payload map[string]interface{}) string {
	switch event {
	case "session_start", "subagent_start", "turn_start", "tool_start", "compact_start":
		return "active"
	case "session_end", "subagent_stop", "turn_end":
		status := strings.ToLower(firstString(payload, "status", "child_status", "reason", "outcome", "error", "error_details", "termination_reason", "terminationReason"))
		if strings.Contains(status, "fail") || strings.Contains(status, "error") {
			return "failed"
		}
		if strings.Contains(status, "interrupt") || strings.Contains(status, "cancel") {
			return "interrupted"
		}
		return "completed"
	case "compact_end", "tool_end":
		return "active"
	default:
		if firstString(payload, "error", "error_details", "errorContext", "error_context") != "" {
			return "failed"
		}
		return "observed"
	}
}

func hookLifecycleDedupeKey(meta llmEventMeta, payload map[string]interface{}) string {
	lifecycleEvent := strings.TrimSpace(meta.LifecycleEvent)
	if lifecycleEvent == "" || lifecycleEvent == "event" {
		return ""
	}
	identity := ""
	switch lifecycleEvent {
	case "turn_start", "turn_end":
		identity = firstNonEmpty(
			meta.TurnID,
			firstHookIdentityString(payload,
				"turn_id", "turnId", "turnID",
				"request_id", "requestId", "message_id", "messageId",
				"prompt_id", "promptId", "completion_id", "completionId", "response_id", "responseId",
			),
		)
	case "tool_start", "tool_end":
		identity = firstNonEmpty(
			firstHookIdentityString(payload,
				"tool_call_id", "toolCallId", "tool_use_id", "toolUseId",
				"call_id", "callId", "invocation_id", "invocationId", "id",
			),
			stableHookToolIdentity(payload),
		)
	case "session_start", "session_end", "subagent_start", "subagent_stop", "compact_start", "compact_end":
		identity = firstNonEmpty(meta.LifecycleID, meta.SessionID)
	}
	if strings.TrimSpace(identity) == "" {
		return ""
	}
	return stableLLMEventID(
		"lifecycle-transition",
		meta.Source, meta.SessionID, meta.AgentID, meta.LifecycleID, lifecycleEvent, identity,
	)
}

func stableHookToolIdentity(payload map[string]interface{}) string {
	tool := firstHookIdentityString(payload, "tool_name", "toolName", "name", "command")
	input := firstHookIdentityString(payload, "arguments", "args", "input", "tool_input", "toolInput", "command")
	if tool == "" || input == "" {
		return ""
	}
	return stableLLMEventID("tool", tool, input)
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

// hookPromptCacheMaxEntries bounds llmPromptBySourceSession,
// llmPromptBySourceSessionTurn, and the hook-to-GenAI span bridge so a
// misbehaving or compromised
// authenticated hook caller cannot drive the sidecar OOM by spamming
// distinct (source, session) or (source, session, turn) keys.
//
// ("Hook prompt correlation maps grow without
// eviction"): the previous implementation appended forever, with
// keys derived directly from hook JSON (session_id, task_id,
// turn_id, execution_id, tool_call_id) and no Stop/SessionEnd
// cleanup. We now store entries in a bounded LRU that drops the
// oldest entry once we hit the cap, which keeps memory usage
// constant regardless of caller behaviour.
const hookPromptCacheMaxEntries = 8192

// Hook bodies are capped at the HTTP layer, but retaining one full body per
// active session could still create excessive heap pressure. Thirty-two KiB
// preserves useful prompt/response context while bounding both the in-memory
// cache and the eventual OTLP span attribute.
const hookLLMSpanMaxContentBytes = 32 * 1024

const hookLLMSpanMissingInput = "input unavailable: prompt hook was not observed in this gateway process"

type hookLLMSpanPrompt struct {
	meta      llmEventMeta
	content   string
	startedAt time.Time
}

// hookLLMSpanUsage is the bounded correlation bridge between connector-native
// usage telemetry and the canonical chat span emitted at model completion.
// Unknown counts remain absent instead of being rendered as a misleading zero.
type hookLLMSpanUsage struct {
	model            string
	promptTokens     int64
	completionTokens int64
}

type hookToolInvocation struct {
	id        string
	meta      llmEventMeta
	tool      string
	arguments string
	startedAt time.Time
}

// hookSessionTrace retains the latest short trace anchor and the durable
// lifecycle identity for one hook connector session. An anchor is reused only
// within one hook delivery. A later delivery starts a new short trace because
// observability backends such as Galileo may finalize a trace as soon as its
// first batch is indexed. Stable session/agent/lifecycle attributes correlate
// those traces without requiring late child-span appends.
type hookSessionTrace struct {
	spanContext  trace.SpanContext
	meta         llmEventMeta
	traceEventID string
}

// hookPhaseState is the bounded per-execution cursor used to turn unordered
// hook notifications into an explicit execution sequence and directed phase
// transitions. It stores identifiers only; prompt/tool bodies never enter the
// map.
type hookPhaseState struct {
	phase    string
	sequence int64
	// meta is the last normalized lifecycle snapshot for this execution.
	// Unlike hookSessionTraces, it exists even when OTel is disabled, so the
	// later hook-decision and SQLite audit paths retain identical phase and
	// correlation fields.
	meta llmEventMeta
}

func hookPhaseStateKey(meta llmEventMeta) string {
	if strings.TrimSpace(meta.Source) == "" || strings.TrimSpace(meta.AgentID) == "" {
		return ""
	}
	return strings.Join([]string{
		meta.Source, meta.SessionID, meta.AgentID,
		firstNonEmpty(meta.ExecutionID, meta.LifecycleID),
	}, "\x00")
}

func hookLifecyclePhase(rawEvent, lifecycleEvent, lifecycleState string) string {
	canon := canonicalEvent(rawEvent)
	switch canon {
	case "sessionstart", "onsessionstart", "onsessionreset", "sessioncreated", "subagentstart":
		return "session"
	case "userpromptsubmit", "userpromptsubmitted", "beforesubmitprompt", "preuserprompt", "beforeagent":
		return "planning"
	case "prellmcall", "beforemodel", "preinvocation":
		return "model"
	case "postllmcall", "aftermodel", "postinvocation", "afteragentresponse",
		"postcascaderesponse", "postcascaderesponsewithtranscript", "stop", "agentstop":
		return "responding"
	case "permissionrequest":
		return "approval"
	case "pretooluse", "beforetool", "beforetoolselection", "pretoolcall", "preruncommand", "premcptooluse",
		"beforemcpexecution", "beforeshellexecution", "beforereadfile", "beforetabfileread",
		"prereadcode", "prewritecode", "toolexecutebefore":
		return "tool"
	case "posttooluse", "aftertool", "posttoolcall", "posttoolusefailure", "posttoolbatch",
		"postreadcode", "postwritecode", "postruncommand", "postmcptooluse",
		"aftershellexecution", "aftermcpexecution", "afterfileedit", "aftertabfileedit",
		"toolexecuteafter", "permissiondenied", "postsetupworktree":
		return "planning"
	case "sessionidle", "teammateidle", "notification":
		return "waiting"
	case "precompact", "postcompact", "precompress", "sessioncompacted":
		return "maintenance"
	case "sessionend", "onsessionend", "onsessionfinalize", "sessiondeleted", "sessionerror", "subagentstop":
		switch lifecycleState {
		case "failed":
			return "failed"
		case "interrupted":
			return "interrupted"
		default:
			return "completed"
		}
	}
	switch lifecycleEvent {
	case "tool_start":
		return "tool"
	case "tool_end", "turn_start", "compact_end":
		return "planning"
	case "turn_end":
		return "responding"
	case "compact_start":
		return "maintenance"
	case "session_start", "subagent_start":
		return "session"
	case "session_end", "subagent_stop":
		if lifecycleState == "failed" || lifecycleState == "interrupted" {
			return lifecycleState
		}
		return "completed"
	default:
		return "observed"
	}
}

func hookOperationID(meta llmEventMeta) string {
	if value := firstNonEmpty(meta.ToolID, meta.PromptID, meta.TurnID, meta.LifecycleDedupe); value != "" {
		return stableLLMEventID("operation", meta.Source, meta.SessionID, meta.AgentID, value)
	}
	return stableLLMEventID(
		"operation", meta.Source, meta.SessionID, meta.AgentID,
		meta.ExecutionID, meta.LifecycleEvent, meta.TraceEventID,
	)
}

func (a *APIServer) enrichHookPhase(meta llmEventMeta) llmEventMeta {
	if meta.Phase == "" {
		meta.Phase = hookLifecyclePhase("", meta.LifecycleEvent, meta.LifecycleState)
	}
	if phase, ok := gatewaylog.NormalizeAgentPhase(meta.Phase); ok {
		meta.Phase = phase
	}
	if meta.OperationID == "" {
		meta.OperationID = hookOperationID(meta)
	}
	key := hookPhaseStateKey(meta)
	if a == nil || key == "" {
		return meta
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookPhaseStates == nil {
		a.hookPhaseStates = make(map[string]hookPhaseState)
	}
	state, exists := a.hookPhaseStates[key]
	if !exists {
		for len(a.hookPhaseStates) >= hookPromptCacheMaxEntries && len(a.hookPhaseStateOrder) > 0 {
			oldest := a.hookPhaseStateOrder[0]
			a.hookPhaseStateOrder = a.hookPhaseStateOrder[1:]
			delete(a.hookPhaseStates, oldest)
		}
		a.hookPhaseStateOrder = append(a.hookPhaseStateOrder, key)
	}
	// The previous phase is optional. A new execution has no predecessor, and
	// unsupported historical values are not useful enough to invalidate the
	// whole event; omit both instead of inventing a non-contract sentinel.
	meta.PreviousPhase = ""
	if previous, ok := gatewaylog.NormalizeAgentPhase(state.phase); exists && ok {
		meta.PreviousPhase = previous
	}
	state.sequence++
	state.phase = meta.Phase
	meta.Sequence = state.sequence
	state.meta = meta
	a.hookPhaseStates[key] = state
	return meta
}

func (a *APIServer) hookPhaseSnapshot(meta llmEventMeta) (llmEventMeta, bool) {
	if a == nil {
		return llmEventMeta{}, false
	}
	key := hookPhaseStateKey(meta)
	if key == "" {
		return llmEventMeta{}, false
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	state, ok := a.hookPhaseStates[key]
	if ok {
		return state.meta, true
	}
	// Session/subagent starts rotate ExecutionID before phase enrichment. A
	// later decision/audit projection reconstructs the stable base identity and
	// therefore cannot know that random execution ID. Fall back to the newest
	// cursor for the same connector/session/agent; phase-state order is append-
	// ordered by execution and bounded with the same eviction policy as the map.
	for i := len(a.hookPhaseStateOrder) - 1; i >= 0; i-- {
		candidate, exists := a.hookPhaseStates[a.hookPhaseStateOrder[i]]
		if !exists || candidate.meta.Source != meta.Source || candidate.meta.SessionID != meta.SessionID {
			continue
		}
		if meta.AgentID != "" && candidate.meta.AgentID != meta.AgentID {
			continue
		}
		return candidate.meta, true
	}
	return llmEventMeta{}, false
}

const hookSessionStartedOutput = "Live session started. Child operations stream as they complete."

func hookSessionTraceKey(meta llmEventMeta) string {
	source := strings.TrimSpace(meta.Source)
	sessionID := strings.TrimSpace(meta.SessionID)
	if source == "" || sessionID == "" {
		return ""
	}
	agentID := firstNonEmpty(strings.TrimSpace(meta.AgentID), stableLLMEventID("agent", source, sessionID, "root"))
	return strings.Join([]string{source, sessionID, agentID}, "\x00")
}

func hookTraceEventID(ctx context.Context, meta llmEventMeta) string {
	parts := []string{
		"trace-event", meta.Source, meta.SessionID, meta.AgentID,
		meta.LifecycleEvent, meta.TurnID, meta.ToolID,
		strconv.FormatInt(time.Now().UTC().UnixNano(), 10),
	}
	if spanContext := trace.SpanContextFromContext(ctx); spanContext.IsValid() {
		parts = append(parts, spanContext.TraceID().String(), spanContext.SpanID().String())
	}
	return stableLLMEventID(parts[0], parts[1:]...)
}

// beginHookExecution rotates the execution-attempt identity when an upstream
// agent or subagent starts again while preserving its stable lifecycle ID.
// This is intentionally independent of the gateway process ID: an agent can be
// resumed many times without restarting DefenseClaw.
func (a *APIServer) beginHookExecution(meta llmEventMeta) llmEventMeta {
	if a == nil || (meta.LifecycleEvent != "session_start" && meta.LifecycleEvent != "subagent_start") {
		return meta
	}
	key := hookSessionTraceKey(meta)
	if key == "" {
		return meta
	}
	meta.ExecutionID = stableLLMEventID(
		"execution", meta.Source, meta.SessionID, meta.AgentID,
		gatewaylog.ProcessRunID(), strconv.FormatInt(time.Now().UTC().UnixNano(), 10), uuid.NewString(),
	)
	a.llmPromptMu.Lock()
	delete(a.hookSessionTraces, key)
	for i, candidate := range a.hookSessionTraceOrder {
		if candidate == key {
			copy(a.hookSessionTraceOrder[i:], a.hookSessionTraceOrder[i+1:])
			a.hookSessionTraceOrder = a.hookSessionTraceOrder[:len(a.hookSessionTraceOrder)-1]
			break
		}
	}
	a.llmPromptMu.Unlock()
	return meta
}

func (a *APIServer) mergeHookSessionLifecycle(meta llmEventMeta) llmEventMeta {
	if a == nil {
		return meta
	}
	key := hookSessionTraceKey(meta)
	if key == "" {
		return meta
	}
	a.llmPromptMu.Lock()
	snapshot, ok := a.hookSessionTraces[key]
	a.llmPromptMu.Unlock()
	if !ok {
		return meta
	}
	meta.LifecycleID = firstNonEmpty(meta.LifecycleID, snapshot.meta.LifecycleID)
	if snapshot.meta.ExecutionID != "" {
		meta.ExecutionID = snapshot.meta.ExecutionID
	}
	meta.RootAgentID = firstNonEmpty(meta.RootAgentID, snapshot.meta.RootAgentID, snapshot.meta.AgentID)
	meta.ParentAgentID = firstNonEmpty(meta.ParentAgentID, snapshot.meta.ParentAgentID)
	meta.RootSessionID = firstNonEmpty(meta.RootSessionID, snapshot.meta.RootSessionID, snapshot.meta.SessionID)
	meta.ParentSessionID = firstNonEmpty(meta.ParentSessionID, snapshot.meta.ParentSessionID)
	if meta.AgentDepth == 0 && snapshot.meta.AgentDepth > 0 {
		meta.AgentDepth = snapshot.meta.AgentDepth
	}
	meta.SessionSource = firstNonEmpty(meta.SessionSource, snapshot.meta.SessionSource)
	meta.SessionResumed = meta.SessionResumed || snapshot.meta.SessionResumed
	meta.UserID = firstNonEmpty(meta.UserID, snapshot.meta.UserID)
	meta.UserName = firstNonEmpty(meta.UserName, snapshot.meta.UserName)
	return meta
}

func (a *APIServer) hookLifecycleSnapshot(source, sessionID, agentID string) (llmEventMeta, bool) {
	if a == nil || strings.TrimSpace(source) == "" || strings.TrimSpace(sessionID) == "" {
		return llmEventMeta{}, false
	}
	snapshot, ok := a.hookSessionSnapshot(source, sessionID, agentID)
	return snapshot.meta, ok
}

// hookSessionSnapshot resolves the current session even when an upstream
// child event knows only parent_session_id. Prefer an exact native agent ID;
// otherwise choose the shallowest retained agent for that conversation so a
// synthesized fallback cannot displace the real root.
func (a *APIServer) hookSessionSnapshot(source, sessionID, agentID string) (hookSessionTrace, bool) {
	if a == nil || strings.TrimSpace(source) == "" || strings.TrimSpace(sessionID) == "" {
		return hookSessionTrace{}, false
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if agentID != "" {
		key := hookSessionTraceKey(llmEventMeta{Source: source, SessionID: sessionID, AgentID: agentID})
		if snapshot, ok := a.hookSessionTraces[key]; ok {
			return snapshot, true
		}
	}
	var selected hookSessionTrace
	found := false
	for i := len(a.hookSessionTraceOrder) - 1; i >= 0; i-- {
		snapshot, ok := a.hookSessionTraces[a.hookSessionTraceOrder[i]]
		if !ok || snapshot.meta.Source != source || snapshot.meta.SessionID != sessionID {
			continue
		}
		if !found || snapshot.meta.AgentDepth < selected.meta.AgentDepth {
			selected = snapshot
			found = true
		}
	}
	return selected, found
}

// reconcileHookParent replaces a connector-independent synthesized parent ID
// with the authoritative identity retained by the live parent session. Native
// subagent hooks commonly provide a parent session/thread ID but no parent
// agent ID; without this lookup an explicitly named root agent and its child
// were exported as two traces joined only by string attributes.
func (a *APIServer) reconcileHookParent(meta llmEventMeta) llmEventMeta {
	if a == nil || (strings.TrimSpace(meta.ParentSessionID) == "" && strings.TrimSpace(meta.ParentAgentID) == "") {
		return meta
	}
	parentSessionID := firstNonEmpty(meta.ParentSessionID, meta.SessionID)
	snapshot, ok := a.hookSessionSnapshot(meta.Source, parentSessionID, meta.ParentAgentID)
	if !ok {
		return meta
	}
	meta.ParentAgentID = snapshot.meta.AgentID
	meta.RootAgentID = firstNonEmpty(snapshot.meta.RootAgentID, snapshot.meta.AgentID)
	meta.RootSessionID = firstNonEmpty(snapshot.meta.RootSessionID, snapshot.meta.SessionID)
	if meta.AgentDepth <= snapshot.meta.AgentDepth {
		meta.AgentDepth = snapshot.meta.AgentDepth + 1
	}
	meta.UserID = firstNonEmpty(meta.UserID, snapshot.meta.UserID)
	meta.UserName = firstNonEmpty(meta.UserName, snapshot.meta.UserName)
	return meta
}

func applyHookLifecycleSpanAttributes(span trace.Span, meta llmEventMeta) {
	if span == nil {
		return
	}
	attrs := make([]attribute.KeyValue, 0, 24)
	if meta.Source != "" {
		attrs = append(attrs, attribute.String("connector", meta.Source))
	}
	if meta.RootAgentID != "" {
		attrs = append(attrs, attribute.String("defenseclaw.agent.root.id", meta.RootAgentID))
	}
	if meta.ParentAgentID != "" {
		attrs = append(attrs, attribute.String("defenseclaw.agent.parent.id", meta.ParentAgentID))
	}
	if meta.RootSessionID != "" {
		attrs = append(attrs, attribute.String("defenseclaw.session.root.id", meta.RootSessionID))
	}
	if meta.ParentSessionID != "" {
		attrs = append(attrs, attribute.String("defenseclaw.session.parent.id", meta.ParentSessionID))
	}
	if meta.LifecycleID != "" {
		attrs = append(attrs, attribute.String("defenseclaw.agent.lifecycle.id", meta.LifecycleID))
	}
	if meta.ExecutionID != "" {
		attrs = append(attrs, attribute.String("defenseclaw.agent.execution.id", meta.ExecutionID))
	}
	if meta.LifecycleEvent != "" {
		attrs = append(attrs, attribute.String("defenseclaw.agent.lifecycle.event", meta.LifecycleEvent))
	}
	if meta.LifecycleState != "" {
		attrs = append(attrs, attribute.String("defenseclaw.agent.lifecycle.state", meta.LifecycleState))
	}
	if meta.Phase != "" {
		attrs = append(attrs,
			attribute.String("defenseclaw.agent.phase", meta.Phase),
			attribute.Int("defenseclaw.agent.phase.code", telemetry.AgentPhaseCode(meta.Phase)),
		)
	}
	if meta.PreviousPhase != "" {
		attrs = append(attrs, attribute.String("defenseclaw.agent.phase.previous", meta.PreviousPhase))
	}
	if meta.OperationID != "" {
		attrs = append(attrs, attribute.String("defenseclaw.operation.id", meta.OperationID))
	}
	if meta.Sequence > 0 {
		attrs = append(attrs, attribute.Int64("defenseclaw.agent.sequence", meta.Sequence))
	}
	attrs = append(attrs, attribute.Int("defenseclaw.agent.depth", meta.AgentDepth))
	if meta.SessionSource != "" {
		attrs = append(attrs, attribute.String("defenseclaw.session.source", meta.SessionSource))
	}
	attrs = append(attrs, attribute.Bool("defenseclaw.session.resumed", meta.SessionResumed))
	if meta.UserID != "" {
		attrs = append(attrs, attribute.String("user.id", meta.UserID))
	}
	if meta.UserName != "" {
		attrs = append(attrs, attribute.String("defenseclaw.user.name", meta.UserName))
	}
	span.SetAttributes(attrs...)
}

func hookLifecycleContent(meta llmEventMeta, direction string) string {
	payload := map[string]interface{}{
		"agent_id": meta.AgentID,
		"event":    meta.LifecycleEvent,
		"state":    meta.LifecycleState,
	}
	if direction != "" {
		payload["direction"] = direction
	}
	if meta.ParentAgentID != "" {
		payload["parent_agent_id"] = meta.ParentAgentID
	}
	if meta.RootAgentID != "" {
		payload["root_agent_id"] = meta.RootAgentID
	}
	if meta.ParentSessionID != "" {
		payload["parent_session_id"] = meta.ParentSessionID
	}
	if meta.RootSessionID != "" {
		payload["root_session_id"] = meta.RootSessionID
	}
	b, err := json.Marshal(payload)
	if err != nil {
		return ""
	}
	return string(b)
}

func emitHookLifecycleEvent(ctx context.Context, meta llmEventMeta) {
	if strings.TrimSpace(meta.Source) == "" || strings.TrimSpace(meta.SessionID) == "" {
		return
	}
	transition := "ready"
	switch meta.LifecycleEvent {
	case "session_start", "subagent_start", "turn_start", "tool_start", "compact_start":
		transition = "start"
	case "session_end", "subagent_stop", "turn_end":
		transition = "stop"
	case "tool_end", "compact_end":
		transition = "completed"
	}
	details := map[string]string{
		"connector":       meta.Source,
		"lifecycle_event": meta.LifecycleEvent,
		"lifecycle_state": meta.LifecycleState,
		"phase":           meta.Phase,
		"previous_phase":  meta.PreviousPhase,
		"sequence":        strconv.FormatInt(meta.Sequence, 10),
		"agent_depth":     strconv.Itoa(meta.AgentDepth),
	}
	if meta.SessionSource != "" {
		details["session_source"] = meta.SessionSource
	}
	emitEvent(ctx, gatewaylog.Event{
		EventType:            gatewaylog.EventLifecycle,
		Severity:             gatewaylog.SeverityInfo,
		RunID:                meta.RunID,
		RequestID:            meta.RequestID,
		SessionID:            meta.SessionID,
		TurnID:               meta.TurnID,
		Provider:             meta.Provider,
		Model:                meta.Model,
		AgentID:              meta.AgentID,
		AgentName:            meta.AgentName,
		AgentType:            meta.AgentType,
		RootAgentID:          meta.RootAgentID,
		ParentAgentID:        meta.ParentAgentID,
		RootSessionID:        meta.RootSessionID,
		ParentSessionID:      meta.ParentSessionID,
		AgentLifecycleID:     meta.LifecycleID,
		AgentExecutionID:     meta.ExecutionID,
		AgentLifecycleEvent:  meta.LifecycleEvent,
		AgentLifecycleState:  meta.LifecycleState,
		AgentPhase:           meta.Phase,
		AgentPreviousPhase:   meta.PreviousPhase,
		AgentPhaseCode:       agentPhaseCodePointer(meta),
		AgentSequence:        meta.Sequence,
		AgentOperationID:     meta.OperationID,
		AgentDepth:           agentDepthPointer(meta),
		AgentReportedCostUSD: agentReportedCostPointer(meta),
		AgentReportedCost:    boolPointer(meta.ReportedCost),
		SessionSource:        meta.SessionSource,
		SessionResumed:       boolPointer(meta.SessionResumed),
		UserID:               meta.UserID,
		UserName:             meta.UserName,
		Connector:            meta.Source,
		Lifecycle: &gatewaylog.LifecyclePayload{
			Subsystem:  "agent",
			Transition: transition,
			Details:    details,
		},
	})
}

func (a *APIServer) recordHookLifecycleMetric(ctx context.Context, meta llmEventMeta) {
	if a == nil || a.otel == nil || strings.TrimSpace(meta.AgentID) == "" {
		return
	}
	a.otel.RecordAgentLifecycle(ctx, telemetry.AgentLifecycleObservation{
		Connector:           meta.Source,
		Provider:            meta.Provider,
		Model:               meta.Model,
		AgentID:             meta.AgentID,
		AgentName:           meta.AgentName,
		AgentType:           meta.AgentType,
		RootAgentID:         meta.RootAgentID,
		ParentAgentID:       meta.ParentAgentID,
		RootSessionID:       meta.RootSessionID,
		LifecycleID:         meta.LifecycleID,
		ExecutionID:         meta.ExecutionID,
		Event:               meta.LifecycleEvent,
		State:               meta.LifecycleState,
		Phase:               meta.Phase,
		PreviousPhase:       meta.PreviousPhase,
		OperationID:         meta.OperationID,
		Sequence:            meta.Sequence,
		Depth:               meta.AgentDepth,
		ReportedCostUSD:     meta.ReportedCostUSD,
		ReportedCostPresent: meta.ReportedCost,
	})
}

func (a *APIServer) shouldRecordHookLifecycleTransition(meta llmEventMeta) bool {
	key := strings.TrimSpace(meta.LifecycleDedupe)
	if a == nil || key == "" {
		return true
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookLifecycleTransitions == nil {
		a.hookLifecycleTransitions = make(map[string]struct{})
	}
	if _, ok := a.hookLifecycleTransitions[key]; ok {
		return false
	}
	putBoundedStructKey(
		a.hookLifecycleTransitions,
		&a.hookLifecycleTransitionOrder,
		key,
		hookPromptCacheMaxEntries,
	)
	return true
}

func (a *APIServer) normalizeHookReportedCost(meta llmEventMeta) llmEventMeta {
	if a == nil || !meta.ReportedCost || meta.ReportedCostSum {
		return meta
	}
	key := firstNonEmpty(meta.LifecycleID, stableLLMEventID("lifecycle", meta.Source, meta.SessionID, meta.AgentID))
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookReportedCostTotals == nil {
		a.hookReportedCostTotals = make(map[string]float64)
	}
	totalKey := stableLLMEventID("reported-cost", meta.Source, meta.AgentID, key)
	previousTotal, exists := a.hookReportedCostTotals[totalKey]
	if !exists {
		putBoundedFloatKey(
			a.hookReportedCostTotals,
			&a.hookReportedCostTotalOrder,
			totalKey,
			hookPromptCacheMaxEntries,
		)
	}
	meta.ReportedCostUSD += previousTotal
	a.hookReportedCostTotals[totalKey] = meta.ReportedCostUSD
	meta.ReportedCostSum = true
	return meta
}

func (a *APIServer) emitInferredDelegatedAgentTransitions(
	ctx context.Context, parent llmEventMeta, tool, arguments string, starting bool,
) {
	if a == nil || !connectorNeedsInferredDelegation(parent.Source) || !isAgentSpawnerTool(tool) {
		return
	}
	for _, child := range inferredDelegatedAgents(parent, tool, arguments) {
		if starting {
			child.LifecycleEvent = "subagent_start"
			child.LifecycleState = "active"
			child.Phase = "session"
			child = a.beginHookExecution(child)
		} else {
			child.LifecycleEvent = "subagent_stop"
			child.LifecycleState = "completed"
			child.Phase = "completed"
			child = a.mergeHookSessionLifecycle(child)
		}
		child.OperationID = hookOperationID(child)
		child = a.enrichHookPhase(child)
		emitHookLifecycleEvent(ctx, child)
		a.recordHookLifecycleMetric(ctx, child)
		a.emitHookLifecycleTransitionSpan(ctx, child)
	}
}

func connectorNeedsInferredDelegation(source string) bool {
	switch strings.ToLower(strings.TrimSpace(source)) {
	case "antigravity", "geminicli", "windsurf", "openhands":
		return true
	default:
		return false
	}
}

func isAgentSpawnerTool(tool string) bool {
	tool = canonicalEvent(tool)
	switch tool {
	case "agent", "task", "invokesubagent", "delegatetask", "delegate", "runsubagent", "spawnagent":
		return true
	default:
		return false
	}
}

func inferredDelegatedAgents(parent llmEventMeta, tool, arguments string) []llmEventMeta {
	var decoded interface{}
	_ = json.Unmarshal([]byte(arguments), &decoded)
	items := []interface{}{decoded}
	if obj, ok := decoded.(map[string]interface{}); ok {
		for _, key := range []string{"Subagents", "subagents", "agents", "tasks"} {
			if list, ok := obj[key].([]interface{}); ok && len(list) > 0 {
				items = list
				break
			}
		}
	}
	if len(items) == 0 {
		items = []interface{}{nil}
	}
	children := make([]llmEventMeta, 0, len(items))
	for i, item := range items {
		obj, _ := item.(map[string]interface{})
		name := firstNonEmpty(
			firstString(obj, "Role", "role", "name", "agent", "agent_name", "agentName", "TypeName", "typeName", "description"),
			"delegated-agent",
		)
		identity := firstNonEmpty(
			firstString(obj, "id", "agent_id", "agentId", "conversation_id", "conversationId"),
			parent.ToolID, parent.TurnID, tool, strconv.Itoa(i), name,
		)
		child := parent
		child.AgentID = stableLLMEventID("agent", parent.Source, parent.SessionID, "delegated", identity, strconv.Itoa(i))
		child.AgentName = name
		child.AgentType = "subagent"
		child.ParentAgentID = parent.AgentID
		child.ParentSessionID = ""
		child.AgentDepth = parent.AgentDepth + 1
		child.LifecycleID = stableLLMEventID("lifecycle", child.Source, child.SessionID, child.AgentID)
		child.ExecutionID = stableLLMEventID("execution", child.Source, child.SessionID, child.AgentID, gatewaylog.ProcessRunID())
		children = append(children, child)
	}
	return children
}

// emitHookLifecycleTransitionSpan makes lifecycle-only hooks visible to trace
// backends even when they carry no prompt, model response, or tool result.
// Start events are represented by the real-time anchor itself; terminal and
// compaction events become short children so long-running sessions never need
// to keep an unexported span open.
func (a *APIServer) emitHookLifecycleTransitionSpan(ctx context.Context, meta llmEventMeta) {
	if a == nil || a.otel == nil {
		return
	}
	switch meta.LifecycleEvent {
	case "session_start", "subagent_start":
		a.ensureHookSessionTrace(ctx, meta, "")
		return
	case "session_end", "subagent_stop", "turn_end", "compact_start", "compact_end":
		// Continue below.
	default:
		return
	}
	transitionKey := stableLLMEventID(
		"lifecycle-transition", meta.Source, meta.SessionID, meta.AgentID,
		meta.ExecutionID, meta.LifecycleEvent, meta.TurnID, meta.ToolID,
	)
	a.llmPromptMu.Lock()
	if a.hookLLMSpanCompleted == nil {
		a.hookLLMSpanCompleted = make(map[string]struct{})
	}
	if _, duplicate := a.hookLLMSpanCompleted[transitionKey]; duplicate {
		a.llmPromptMu.Unlock()
		return
	}
	putBoundedHookLLMSpanCompletion(
		a.hookLLMSpanCompleted, &a.hookLLMSpanCompletedOrder, transitionKey,
	)
	a.llmPromptMu.Unlock()
	parentCtx := a.ensureHookSessionTrace(ctx, meta, "")
	provider := firstNonEmpty(meta.Provider, meta.Source, "unknown")
	agentName := firstNonEmpty(meta.AgentName, meta.AgentType, meta.Source, meta.AgentID, "agent")
	agentType := firstNonEmpty(meta.AgentType, meta.Source)
	_, span := a.otel.StartAgentSpan(
		parentCtx, meta.SessionID, agentName, agentType, meta.AgentID, provider, meta.Source,
	)
	if span == nil {
		return
	}
	span.SetName("agent.lifecycle " + meta.LifecycleEvent)
	applyHookLifecycleSpanAttributes(span, meta)
	span.SetAttributes(
		attribute.Bool("defenseclaw.agent.lifecycle.transition", true),
		attribute.Bool("defenseclaw.telemetry.input.reported", false),
		attribute.Bool("defenseclaw.telemetry.output.reported", false),
	)
	a.otel.SetGenAIInput(span, hookLifecycleContent(meta, "input"))
	a.otel.SetGenAIOutput(span, hookLifecycleContent(meta, "output"))
	a.otel.EndAgentSpan(span, "")
}

// ensureHookSessionTrace returns a context parented to a short, already
// exported agent root. The root is reused by operations emitted during the
// same hook delivery, then rotated on the next delivery. Ending it immediately
// is intentional: OTel SDKs do not export open spans, and hook sessions may
// run for hours. Stable correlation attributes preserve the session hierarchy
// across these independently indexable real-time traces.
func (a *APIServer) ensureHookSessionTrace(
	ctx context.Context, meta llmEventMeta, input string,
) context.Context {
	if a == nil || a.otel == nil {
		return ctx
	}
	key := hookSessionTraceKey(meta)
	if key == "" {
		return trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	}
	// Recursive parent anchors are synthesized after the top-level hook meta
	// was merged. Re-merge here so rotating a parent's trace for a child event
	// does not overwrite the parent's durable execution/resume identity with a
	// fallback derived from the child.
	meta = a.mergeHookSessionLifecycle(meta)
	if meta.TraceEventID == "" {
		meta.TraceEventID = hookTraceEventID(ctx, meta)
	}

	parentCtx := trace.ContextWithSpanContext(ctx, trace.SpanContext{})
	if meta.AgentID != "" && meta.ParentAgentID != "" && meta.ParentAgentID != meta.AgentID {
		parentMeta := meta
		parentMeta.SessionID = firstNonEmpty(meta.ParentSessionID, meta.SessionID)
		parentMeta.AgentID = meta.ParentAgentID
		parentMeta.AgentName = firstNonEmpty(meta.Source, "agent")
		parentMeta.RootAgentID = firstNonEmpty(meta.RootAgentID, parentMeta.AgentID)
		parentMeta.ParentAgentID = ""
		parentMeta.RootSessionID = firstNonEmpty(meta.RootSessionID, parentMeta.SessionID)
		parentMeta.ParentSessionID = ""
		parentMeta.AgentDepth = max(meta.AgentDepth-1, 0)
		parentMeta.LifecycleID = stableLLMEventID("lifecycle", meta.Source, parentMeta.SessionID, parentMeta.AgentID)
		parentMeta.ExecutionID = stableLLMEventID("execution", meta.Source, parentMeta.SessionID, parentMeta.AgentID, gatewaylog.ProcessRunID())
		parentMeta.LifecycleEvent = "session_start"
		parentMeta.LifecycleState = "active"
		parentCtx = a.ensureHookSessionTrace(ctx, parentMeta, "")
	}

	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if existing, ok := a.hookSessionTraces[key]; ok &&
		existing.spanContext.IsValid() && existing.traceEventID == meta.TraceEventID {
		return trace.ContextWithSpanContext(ctx, existing.spanContext)
	}

	provider := firstNonEmpty(meta.Provider, meta.Source, "unknown")
	agentName := firstNonEmpty(meta.AgentName, meta.AgentType, meta.Source, meta.AgentID, "agent")
	agentType := firstNonEmpty(meta.AgentType, meta.Source)
	rootCtx := parentCtx
	_, root := a.otel.StartAgentSpan(
		rootCtx, meta.SessionID, agentName, agentType, meta.AgentID, provider, meta.Source,
	)
	if root == nil {
		return rootCtx
	}
	applyHookLifecycleSpanAttributes(root, meta)
	root.SetAttributes(attribute.String("defenseclaw.agent.stream.mode", "realtime_anchor"))
	if strings.TrimSpace(input) != "" && input != hookLLMSpanMissingInput {
		a.otel.SetGenAIInput(root, boundedHookLLMSpanContent(input))
		root.SetAttributes(attribute.Bool("defenseclaw.telemetry.input.reported", true))
	} else {
		a.otel.SetGenAIInput(root, hookLifecycleContent(meta, "input"))
		root.SetAttributes(attribute.Bool("defenseclaw.telemetry.input.reported", false))
	}
	a.otel.SetGenAIOutput(root, hookLifecycleContent(meta, "output"))
	root.SetAttributes(attribute.Bool("defenseclaw.telemetry.output.reported", false))
	spanContext := root.SpanContext()
	a.otel.EndAgentSpan(root, "")
	if !spanContext.IsValid() {
		return rootCtx
	}

	if a.hookSessionTraces == nil {
		a.hookSessionTraces = make(map[string]hookSessionTrace)
	}
	if _, exists := a.hookSessionTraces[key]; !exists {
		for len(a.hookSessionTraces) >= hookPromptCacheMaxEntries && len(a.hookSessionTraceOrder) > 0 {
			oldest := a.hookSessionTraceOrder[0]
			a.hookSessionTraceOrder = a.hookSessionTraceOrder[1:]
			delete(a.hookSessionTraces, oldest)
		}
		a.hookSessionTraceOrder = append(a.hookSessionTraceOrder, key)
	}
	a.hookSessionTraces[key] = hookSessionTrace{
		spanContext: spanContext, meta: meta, traceEventID: meta.TraceEventID,
	}
	return trace.ContextWithSpanContext(ctx, spanContext)
}

func hookToolInvocationKey(meta llmEventMeta, tool string) string {
	identity := strings.TrimSpace(meta.ToolID)
	if identity == "" {
		identity = strings.TrimSpace(meta.TurnID) + "\x00" + strings.TrimSpace(tool)
	}
	return strings.Join([]string{
		strings.TrimSpace(meta.Source), strings.TrimSpace(meta.SessionID),
		strings.TrimSpace(meta.AgentID), identity,
	}, "\x00")
}

func (a *APIServer) rememberHookToolInvocation(meta llmEventMeta, tool, arguments string) {
	if a == nil || strings.TrimSpace(tool) == "" {
		return
	}
	key := hookToolInvocationKey(meta, tool)
	if strings.Trim(key, "\x00") == "" {
		return
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookToolInvocations == nil {
		a.hookToolInvocations = make(map[string][]hookToolInvocation)
	}
	for len(a.hookToolInvocationOrder) >= hookPromptCacheMaxEntries {
		oldest := a.hookToolInvocationOrder[0]
		a.hookToolInvocationOrder = a.hookToolInvocationOrder[1:]
		queue := a.hookToolInvocations[oldest]
		if len(queue) <= 1 {
			delete(a.hookToolInvocations, oldest)
		} else {
			a.hookToolInvocations[oldest] = queue[1:]
		}
	}
	startedAt := time.Now()
	a.hookToolInvocationOrder = append(a.hookToolInvocationOrder, key)
	a.hookToolInvocations[key] = append(a.hookToolInvocations[key], hookToolInvocation{
		id: stableLLMEventID(
			"hook-tool-invocation", key, strconv.FormatInt(startedAt.UnixNano(), 10), arguments,
		),
		meta: meta, tool: tool, arguments: boundedHookLLMSpanContent(arguments), startedAt: startedAt,
	})
}

func (a *APIServer) takeHookToolInvocation(
	meta llmEventMeta, tool, result string,
) (hookToolInvocation, bool) {
	key := hookToolInvocationKey(meta, tool)
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	queue := a.hookToolInvocations[key]
	var snapshot hookToolInvocation
	if len(queue) > 0 {
		snapshot = queue[0]
	}
	baseCompletionKey := stableLLMEventID("hook-tool-span", key, result)
	completionKey := baseCompletionKey
	if snapshot.id != "" {
		completionKey = stableLLMEventID("hook-tool-span", baseCompletionKey, snapshot.id)
	}
	if a.hookLLMSpanCompleted == nil {
		a.hookLLMSpanCompleted = make(map[string]struct{})
	}
	if _, duplicate := a.hookLLMSpanCompleted[completionKey]; duplicate {
		return hookToolInvocation{}, false
	}
	putBoundedHookLLMSpanCompletion(
		a.hookLLMSpanCompleted, &a.hookLLMSpanCompletedOrder, completionKey,
	)
	if completionKey != baseCompletionKey {
		putBoundedHookLLMSpanCompletion(
			a.hookLLMSpanCompleted, &a.hookLLMSpanCompletedOrder, baseCompletionKey,
		)
	}
	if len(queue) > 0 {
		if len(queue) == 1 {
			delete(a.hookToolInvocations, key)
		} else {
			a.hookToolInvocations[key] = queue[1:]
		}
		for i, candidate := range a.hookToolInvocationOrder {
			if candidate == key {
				copy(a.hookToolInvocationOrder[i:], a.hookToolInvocationOrder[i+1:])
				a.hookToolInvocationOrder = a.hookToolInvocationOrder[:len(a.hookToolInvocationOrder)-1]
				break
			}
		}
	}
	return snapshot, true
}

func (a *APIServer) emitHookToolSpan(
	ctx context.Context, meta llmEventMeta, tool, fallbackArguments, result string, exitCode *int,
) {
	if a == nil || a.otel == nil || strings.TrimSpace(tool) == "" || strings.TrimSpace(result) == "" {
		return
	}
	snapshot, emit := a.takeHookToolInvocation(meta, tool, result)
	if !emit {
		return
	}
	arguments := snapshot.arguments
	if strings.TrimSpace(arguments) == "" {
		arguments = boundedHookLLMSpanContent(fallbackArguments)
	}
	startedAt := snapshot.startedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	merged := meta
	merged.Source = firstNonEmpty(meta.Source, snapshot.meta.Source)
	merged.SessionID = firstNonEmpty(meta.SessionID, snapshot.meta.SessionID)
	merged.RunID = firstNonEmpty(meta.RunID, snapshot.meta.RunID)
	merged.ToolID = firstNonEmpty(meta.ToolID, snapshot.meta.ToolID)
	merged.DestinationApp = firstNonEmpty(meta.DestinationApp, snapshot.meta.DestinationApp)
	merged.PolicyID = firstNonEmpty(meta.PolicyID, snapshot.meta.PolicyID)
	merged.AgentName = firstNonEmpty(meta.AgentName, snapshot.meta.AgentName)
	merged.AgentType = firstNonEmpty(meta.AgentType, snapshot.meta.AgentType)
	merged.AgentID = firstNonEmpty(meta.AgentID, snapshot.meta.AgentID)
	merged.Phase = "tool"
	merged.OperationID = hookOperationID(merged)
	code := 0
	if exitCode != nil {
		code = *exitCode
	}
	parentCtx := a.ensureHookSessionTrace(ctx, merged, arguments)
	_, span := a.otel.StartToolSpan(
		parentCtx, tool, "completed", json.RawMessage(arguments), code != 0, "", "hook", "",
		telemetry.ToolSpanContext{
			StartedAt: startedAt, ToolID: merged.ToolID, SessionID: merged.SessionID,
			RunID: merged.RunID, DestinationApp: merged.DestinationApp, PolicyID: merged.PolicyID,
			AgentName: merged.AgentName, AgentType: merged.AgentType, AgentID: merged.AgentID,
		},
	)
	if span != nil {
		applyHookLifecycleSpanAttributes(span, merged)
		span.SetAttributes(attribute.Bool("defenseclaw.telemetry.input.reported", strings.TrimSpace(arguments) != ""))
		a.otel.SetGenAIToolResult(span, boundedHookLLMSpanContent(result))
		span.SetAttributes(attribute.Bool("defenseclaw.telemetry.output.reported", true))
	}
	a.otel.EndToolSpan(span, code, len(result), startedAt, tool, "hook")
}

func isModelCompletionEvent(event string) bool {
	switch canonicalEvent(event) {
	case "postllmcall", "afteragentresponse", "aftermodel", "postinvocation",
		"postcascaderesponse", "postcascaderesponsewithtranscript":
		return true
	default:
		return false
	}
}

func isStopCompletionEvent(event string) bool {
	switch canonicalEvent(event) {
	case "stop", "agentstop", "subagentstop":
		return true
	default:
		return false
	}
}

func boundedHookLLMSpanContent(content string) string {
	if len(content) <= hookLLMSpanMaxContentBytes {
		return content
	}
	return strings.ToValidUTF8(content[:hookLLMSpanMaxContentBytes], "\uFFFD")
}

func hookLLMSpanPromptKeys(meta llmEventMeta) []string {
	source := strings.TrimSpace(meta.Source)
	sessionID := strings.TrimSpace(meta.SessionID)
	if source == "" || sessionID == "" {
		return nil
	}
	agentID := firstNonEmpty(strings.TrimSpace(meta.AgentID), stableLLMEventID("agent", source, sessionID, "root"))
	sessionKey := strings.Join([]string{source, sessionID, agentID}, "\x00")
	if turnID := strings.TrimSpace(meta.TurnID); turnID != "" {
		return []string{sessionKey + "\x00" + turnID, sessionKey}
	}
	return []string{sessionKey}
}

func putBoundedHookLLMSpanUsage(
	m map[string]hookLLMSpanUsage,
	order *[]string,
	key string,
	value hookLLMSpanUsage,
) {
	if _, exists := m[key]; !exists {
		for len(m) >= hookPromptCacheMaxEntries && len(*order) > 0 {
			oldest := (*order)[0]
			*order = (*order)[1:]
			delete(m, oldest)
		}
		*order = append(*order, key)
	}
	m[key] = value
}

func deleteHookLLMSpanUsage(m map[string]hookLLMSpanUsage, order *[]string, key string) {
	if _, exists := m[key]; !exists {
		return
	}
	delete(m, key)
	for i, candidate := range *order {
		if candidate == key {
			copy((*order)[i:], (*order)[i+1:])
			*order = (*order)[:len(*order)-1]
			return
		}
	}
}

// rememberHookLLMSpanUsage merges partial input/output observations under the
// same source/session(/turn) aliases used by the prompt bridge. Claude Code
// commonly reports usage on a tool result before Stop, while Codex reports its
// final usage through OTLP just before the completion hook.
func (a *APIServer) rememberHookLLMSpanUsage(meta llmEventMeta, usage hookTokenUsage) {
	if a == nil || (usage.PromptTokens <= 0 && usage.CompletionTokens <= 0 && strings.TrimSpace(usage.Model) == "") {
		return
	}
	keys := hookLLMSpanPromptKeys(meta)
	if len(keys) == 0 {
		return
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookLLMSpanUsage == nil {
		a.hookLLMSpanUsage = make(map[string]hookLLMSpanUsage)
	}
	for _, key := range keys {
		current := a.hookLLMSpanUsage[key]
		if usage.PromptTokens > 0 {
			current.promptTokens = usage.PromptTokens
		}
		if usage.CompletionTokens > 0 {
			current.completionTokens = usage.CompletionTokens
		}
		if model := strings.TrimSpace(usage.Model); model != "" && model != "unknown" && model != "other" {
			current.model = model
		}
		putBoundedHookLLMSpanUsage(a.hookLLMSpanUsage, &a.hookLLMSpanUsageOrder, key, current)
	}
}

// rememberOTLPHookLLMTokenUsage joins completed connector-native OTLP log
// usage to the next completion span. Metric payloads are intentionally not
// joined because many SDKs export cumulative counters rather than per-call
// usage, which would overstate a single Galileo trace.
func (a *APIServer) rememberOTLPHookLLMTokenUsage(source, sessionID string, usage otelTokenUsage) {
	if usage.tokens <= 0 {
		return
	}
	correlated := hookTokenUsage{Model: usage.model}
	switch usage.tokenType {
	case "input":
		correlated.PromptTokens = usage.tokens
	case "output":
		correlated.CompletionTokens = usage.tokens
	default:
		return
	}
	a.rememberHookLLMSpanUsage(llmEventMeta{Source: source, SessionID: sessionID}, correlated)
}

func (a *APIServer) takeHookLLMSpanUsage(meta llmEventMeta) hookLLMSpanUsage {
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	var selected hookLLMSpanUsage
	for _, key := range hookLLMSpanPromptKeys(meta) {
		candidate, exists := a.hookLLMSpanUsage[key]
		if !exists {
			continue
		}
		if selected.promptTokens == 0 {
			selected.promptTokens = candidate.promptTokens
		}
		if selected.completionTokens == 0 {
			selected.completionTokens = candidate.completionTokens
		}
		if selected.model == "" {
			selected.model = candidate.model
		}
		deleteHookLLMSpanUsage(a.hookLLMSpanUsage, &a.hookLLMSpanUsageOrder, key)
	}
	return selected
}

func putBoundedHookLLMSpanPrompt(
	m map[string]hookLLMSpanPrompt,
	order *[]string,
	key string,
	value hookLLMSpanPrompt,
) {
	if _, exists := m[key]; !exists {
		for len(m) >= hookPromptCacheMaxEntries && len(*order) > 0 {
			oldest := (*order)[0]
			*order = (*order)[1:]
			if _, stillThere := m[oldest]; stillThere {
				delete(m, oldest)
			}
		}
		*order = append(*order, key)
	}
	m[key] = value
}

func putBoundedHookLLMSpanCompletion(m map[string]struct{}, order *[]string, key string) {
	if _, exists := m[key]; exists {
		return
	}
	for len(m) >= hookPromptCacheMaxEntries && len(*order) > 0 {
		oldest := (*order)[0]
		*order = (*order)[1:]
		if _, stillThere := m[oldest]; stillThere {
			delete(m, oldest)
		}
	}
	m[key] = struct{}{}
	*order = append(*order, key)
}

func putBoundedStructKey(m map[string]struct{}, order *[]string, key string, maxEntries int) {
	if _, exists := m[key]; exists {
		return
	}
	for len(m) >= maxEntries && len(*order) > 0 {
		oldest := (*order)[0]
		*order = (*order)[1:]
		delete(m, oldest)
	}
	m[key] = struct{}{}
	*order = append(*order, key)
}

func putBoundedFloatKey(m map[string]float64, order *[]string, key string, maxEntries int) {
	if _, exists := m[key]; exists {
		return
	}
	for len(m) >= maxEntries && len(*order) > 0 {
		oldest := (*order)[0]
		*order = (*order)[1:]
		delete(m, oldest)
	}
	*order = append(*order, key)
}

func deleteHookLLMSpanPrompt(m map[string]hookLLMSpanPrompt, order *[]string, key string) {
	if _, exists := m[key]; !exists {
		return
	}
	delete(m, key)
	for i, candidate := range *order {
		if candidate == key {
			copy((*order)[i:], (*order)[i+1:])
			*order = (*order)[:len(*order)-1]
			return
		}
	}
}

// rememberHookLLMSpanPrompt retains the latest prompt only until the matching
// Stop event arrives. Content remains in process memory, is size-bounded, and
// still passes through telemetry.SetGenAIInput's persistent-sink redaction
// before it can enter an exported span.
func (a *APIServer) rememberHookLLMSpanPrompt(meta llmEventMeta, prompt string) {
	if a == nil || strings.TrimSpace(prompt) == "" {
		return
	}
	keys := hookLLMSpanPromptKeys(meta)
	if len(keys) == 0 {
		return
	}
	snapshot := hookLLMSpanPrompt{
		meta: meta, content: boundedHookLLMSpanContent(prompt), startedAt: time.Now(),
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookLLMSpanPrompts == nil {
		a.hookLLMSpanPrompts = make(map[string]hookLLMSpanPrompt)
	}
	for _, key := range keys {
		putBoundedHookLLMSpanPrompt(
			a.hookLLMSpanPrompts, &a.hookLLMSpanPromptOrder, key, snapshot,
		)
	}
}

// takeHookLLMSpanPrompt atomically deduplicates completed hook turns and takes
// the best prompt snapshot: exact source/session/turn first, then the latest
// source/session prompt. A duplicate Stop event therefore cannot create a
// second Galileo trace.
func (a *APIServer) takeHookLLMSpanPrompt(meta llmEventMeta, response string) (hookLLMSpanPrompt, bool) {
	completionKey := stableLLMEventID(
		"hook-span", meta.Source, meta.SessionID, meta.TurnID, meta.PromptID, response,
	)
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookLLMSpanCompleted == nil {
		a.hookLLMSpanCompleted = make(map[string]struct{})
	}
	if _, duplicate := a.hookLLMSpanCompleted[completionKey]; duplicate {
		return hookLLMSpanPrompt{}, false
	}
	putBoundedHookLLMSpanCompletion(
		a.hookLLMSpanCompleted, &a.hookLLMSpanCompletedOrder, completionKey,
	)

	var snapshot hookLLMSpanPrompt
	for _, key := range hookLLMSpanPromptKeys(meta) {
		candidate, exists := a.hookLLMSpanPrompts[key]
		if snapshot.content == "" && exists {
			snapshot = candidate
		}
		// A later overlapping turn may already own the session-level key.
		// Only consume aliases that still refer to the selected prompt.
		if exists && candidate.meta.PromptID == snapshot.meta.PromptID {
			deleteHookLLMSpanPrompt(
				a.hookLLMSpanPrompts, &a.hookLLMSpanPromptOrder, key,
			)
		}
	}
	return snapshot, true
}

// emitHookLLMSpan converts the prompt/Stop lifecycle exposed by Codex and
// Claude Code hooks into one canonical GenAI chat span. General OTLP
// destinations keep the complete operational graph; Galileo's destination
// profile accepts this interoperable inference projection.
func (a *APIServer) emitHookLLMSpan(ctx context.Context, meta llmEventMeta, response string) {
	if a == nil || a.otel == nil || strings.TrimSpace(response) == "" {
		return
	}
	snapshot, emit := a.takeHookLLMSpanPrompt(meta, response)
	if !emit {
		return
	}
	prompt := snapshot.content
	if strings.TrimSpace(prompt) == "" {
		prompt = hookLifecycleContent(meta, "input_not_reported")
	}
	usage := a.takeHookLLMSpanUsage(meta)
	provider := firstNonEmpty(meta.Provider, snapshot.meta.Provider, meta.Source, snapshot.meta.Source, "unknown")
	model := firstNonEmpty(meta.Model, snapshot.meta.Model, usage.model, provider)
	agentName := firstNonEmpty(meta.AgentName, snapshot.meta.AgentName, meta.Source, snapshot.meta.Source)
	agentType := firstNonEmpty(meta.AgentType, snapshot.meta.AgentType, meta.Source, snapshot.meta.Source)
	agentID := firstNonEmpty(meta.AgentID, snapshot.meta.AgentID)
	sessionID := firstNonEmpty(meta.SessionID, snapshot.meta.SessionID)
	system := inferSystem(provider, model)
	startedAt := snapshot.startedAt
	if startedAt.IsZero() {
		startedAt = time.Now()
	}
	spanMeta := meta
	spanMeta.Provider = provider
	spanMeta.SessionID = sessionID
	spanMeta.AgentName = agentName
	spanMeta.AgentType = agentType
	spanMeta.AgentID = agentID
	spanMeta.Phase = "model"
	spanMeta.OperationID = hookOperationID(spanMeta)
	parentCtx := a.ensureHookSessionTrace(ctx, spanMeta, prompt)
	_, span := a.otel.StartLLMSpanAt(parentCtx, system, model, provider, 0, 0, startedAt)
	applyHookLifecycleSpanAttributes(span, spanMeta)
	a.otel.SetGenAIInput(span, prompt)
	a.otel.SetGenAIOutput(span, boundedHookLLMSpanContent(response))
	if span != nil {
		span.SetAttributes(
			attribute.Bool("defenseclaw.telemetry.input.reported", snapshot.content != ""),
			attribute.Bool("defenseclaw.telemetry.output.reported", true),
			attribute.Bool("defenseclaw.telemetry.tokens.reported", usage.promptTokens > 0 || usage.completionTokens > 0),
		)
	}
	a.otel.RecordAgentTokenUsage(ctx, telemetry.AgentLifecycleObservation{
		Connector:   meta.Source,
		Provider:    provider,
		Model:       model,
		AgentID:     agentID,
		AgentName:   agentName,
		AgentType:   agentType,
		RootAgentID: firstNonEmpty(meta.RootAgentID, agentID),
		LifecycleID: meta.LifecycleID,
		ExecutionID: meta.ExecutionID,
	}, usage.promptTokens, usage.completionTokens)
	a.otel.EndLLMSpan(
		ctx, span, model, int(usage.promptTokens), int(usage.completionTokens), []string{"stop"}, 0,
		"connector_hook", "observed", provider, startedAt,
		agentName, agentType, agentID, sessionID,
	)
}

// putBoundedPromptID inserts key=>value into m, ordered by insertion
// in `order`. When the map exceeds maxSize, the oldest insert is
// evicted. Caller must hold a.llmPromptMu.
func putBoundedPromptID(m map[string]string, order *[]string, key, value string, maxSize int) {
	if _, exists := m[key]; !exists {
		if len(m) >= maxSize {
			// Evict oldest. order may have stale entries that
			// were already deleted; skip those.
			for len(*order) > 0 {
				oldest := (*order)[0]
				*order = (*order)[1:]
				if _, stillThere := m[oldest]; stillThere {
					delete(m, oldest)
					break
				}
			}
		}
		*order = append(*order, key)
	}
	m[key] = value
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
	putBoundedPromptID(a.llmPromptBySourceSession, &a.llmPromptBySourceSessionOrder,
		source+"\x00"+sessionID, promptID, hookPromptCacheMaxEntries)
	if turnID != "" {
		if a.llmPromptBySourceSessionTurn == nil {
			a.llmPromptBySourceSessionTurn = map[string]string{}
		}
		putBoundedPromptID(a.llmPromptBySourceSessionTurn, &a.llmPromptBySourceSessionTurnOrder,
			source+"\x00"+sessionID+"\x00"+turnID, promptID, hookPromptCacheMaxEntries)
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
	if userID == "" {
		if email := strings.TrimSpace(strings.ToLower(stringMapValue(payload, "user_email"))); email != "" {
			userID = stableLLMEventID("user", email)
		}
	}
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
