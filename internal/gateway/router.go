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
	"os"
	"strings"
	"sync"
	"time"

	"go.opentelemetry.io/otel/trace"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

// activeSpan tracks a pending tool call span with its start time.
type activeSpan struct {
	span      trace.Span
	ctx       context.Context
	startTime time.Time
	tool      string
	provider  string
}

// activeAgent tracks an invoke_agent span for a running agent session.
type activeAgent struct {
	span       trace.Span
	ctx        context.Context
	startTime  time.Time
	sessionKey string
}

// EventRouter dispatches gateway events to the appropriate handlers and logs
// everything to the audit store.
type EventRouter struct {
	client   *Client
	store    *audit.Store
	logger   *audit.Logger
	policy   *enforce.PolicyEngine
	otel     *telemetry.Provider
	notify   *NotificationQueue
	judge    *LLMJudge
	rulePack *RulePack
	judgeSem chan struct{} // bounds concurrent active tool-judge executions

	autoApprove      bool
	activeToolSpans  map[string][]*activeSpan
	activeAgentSpans map[string]*activeAgent // keyed by runId
	activeLLMCtx     context.Context         // context of most recent LLM span, for tool→LLM hierarchy
	spanMu           sync.Mutex

	activeSessionsMu sync.RWMutex
	activeSessions   map[string]time.Time // sessionKey → last seen

	contextTracker *ContextTracker
	inspector      ContentInspector
	guardrailMode  string
}

// NewEventRouter creates a router that handles gateway events for the sidecar.
func NewEventRouter(client *Client, store *audit.Store, logger *audit.Logger, autoApprove bool, otel *telemetry.Provider) *EventRouter {
	return &EventRouter{
		client:           client,
		store:            store,
		logger:           logger,
		policy:           enforce.NewPolicyEngine(store),
		otel:             otel,
		autoApprove:      autoApprove,
		activeToolSpans:  make(map[string][]*activeSpan),
		activeAgentSpans: make(map[string]*activeAgent),
		activeSessions:   make(map[string]time.Time),
		judgeSem:         make(chan struct{}, 16),
		contextTracker:   NewContextTracker(0, 0),
	}
}

// SetInspector attaches a content inspector for outbound message scanning.
func (r *EventRouter) SetInspector(insp ContentInspector) {
	r.inspector = insp
}

// SetRulePack attaches the loaded rule pack for tool result inspection.
func (r *EventRouter) SetRulePack(rp *RulePack) {
	r.rulePack = rp
}

// SetGuardrailMode sets the enforcement mode (enforce/observe) for outbound inspection.
func (r *EventRouter) SetGuardrailMode(mode string) {
	r.guardrailMode = mode
}

// inspectToolOutput scans tool result output for secrets and sensitive data.
// Runs pattern rules and logs findings as alerts (non-blocking).
func (r *EventRouter) inspectToolOutput(toolName, output string) {
	if r.rulePack == nil {
		return
	}

	st := r.rulePack.GetSensitiveTool(toolName)
	if st == nil || !st.ResultInspection {
		return
	}

	findings := ScanAllRulesRP(output, toolName, r.rulePack)
	if len(findings) == 0 {
		return
	}

	severity := HighestSeverity(findings)
	top := make([]string, 0, 3)
	for i, f := range findings {
		if i >= 3 {
			break
		}
		top = append(top, f.RuleID)
	}

	_ = r.logger.LogAction("guardrail-tool-result-alert", toolName,
		fmt.Sprintf("severity=%s findings=%d top=%v", severity, len(findings), top))
}

// inspectOutboundMessage runs guardrail inspection on an assistant message
// received via the WebSocket path (session.message). This provides defense-in-depth
// for the WS-based message delivery that bypasses the HTTP proxy.
func (r *EventRouter) inspectOutboundMessage(sessionKey, content, model string) {
	if r.inspector == nil {
		return
	}

	ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
	defer cancel()

	messages := []ChatMessage{{Role: "assistant", Content: content}}
	if r.contextTracker != nil && sessionKey != "" {
		if recent := r.contextTracker.RecentMessages(sessionKey, 5); len(recent) > 0 {
			messages = append(recent, messages...)
		}
	}

	mode := r.guardrailMode
	if mode == "" {
		mode = "observe"
	}

	verdict := r.inspector.Inspect(ctx, "completion", content, messages, model, mode)
	if verdict == nil || verdict.Severity == "NONE" {
		return
	}

	_ = r.logger.LogAction("gateway-outbound-message-flagged", sessionKey,
		fmt.Sprintf("severity=%s action=%s findings=%d reason=%s",
			verdict.Severity, verdict.Action, len(verdict.Findings), truncate(verdict.Reason, 200)))

	if r.otel != nil {
		r.otel.RecordGuardrailEvaluation(ctx, "outbound-message-judge", verdict.Action)
	}
}

// getActiveAgentCtx returns the context from the currently active agent span,
// providing parent-child hierarchy for LLM spans.
// Falls back to context.Background() if no agent span is active.
func (r *EventRouter) getActiveAgentCtx() context.Context {
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	for _, aa := range r.activeAgentSpans {
		return aa.ctx
	}
	return context.Background()
}

// getToolParentCtx returns the best parent context for tool/approval spans:
// prefers the most recent LLM span context (for LLM→tool hierarchy),
// falls back to agent context, then context.Background().
func (r *EventRouter) getToolParentCtx() context.Context {
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	if r.activeLLMCtx != nil {
		return r.activeLLMCtx
	}
	for _, aa := range r.activeAgentSpans {
		return aa.ctx
	}
	return context.Background()
}

// ActiveSessionKeys returns session keys seen in the last hour.
func (r *EventRouter) ActiveSessionKeys() []string {
	r.activeSessionsMu.RLock()
	defer r.activeSessionsMu.RUnlock()
	cutoff := time.Now().Add(-1 * time.Hour)
	var keys []string
	for k, t := range r.activeSessions {
		if t.After(cutoff) {
			keys = append(keys, k)
		}
	}
	return keys
}

const maxActiveSessions = 500

func (r *EventRouter) trackSession(sessionKey string) {
	if sessionKey == "" {
		return
	}
	r.activeSessionsMu.Lock()
	r.activeSessions[sessionKey] = time.Now()
	if len(r.activeSessions) > maxActiveSessions {
		r.pruneSessionsLocked()
	}
	r.activeSessionsMu.Unlock()
}

// pruneSessionsLocked removes stale entries. Caller must hold activeSessionsMu.
func (r *EventRouter) pruneSessionsLocked() {
	cutoff := time.Now().Add(-1 * time.Hour)
	for k, t := range r.activeSessions {
		if t.Before(cutoff) {
			delete(r.activeSessions, k)
		}
	}
}

// SetJudge configures the LLM judge for tool call injection detection.
func (r *EventRouter) SetJudge(j *LLMJudge) {
	r.judge = j
}

// Route dispatches a single event frame to the correct handler.
func (r *EventRouter) Route(evt EventFrame) {
	seqStr := "nil"
	if evt.Seq != nil {
		seqStr = fmt.Sprintf("%d", *evt.Seq)
	}

	switch evt.Event {
	case "tool_call":
		readLoopLogf("[bifrost] route → tool_call seq=%s payload_len=%d", seqStr, len(evt.Payload))
		r.handleToolCall(evt)
	case "tool_result":
		readLoopLogf("[bifrost] route → tool_result seq=%s payload_len=%d", seqStr, len(evt.Payload))
		r.handleToolResult(evt)
	case "exec.approval.requested":
		readLoopLogf("[bifrost] route → exec.approval.requested seq=%s payload_len=%d", seqStr, len(evt.Payload))
		// Must not block readLoop: handleApprovalRequest calls ResolveApproval →
		// Client.request, which needs readLoop to deliver the RPC response. If the
		// gateway emits this event before the connect handshake res, synchronous
		// handling deadlocks (sidecar stuck at "waiting for connect response").
		go r.handleApprovalRequest(evt)
	case "session.tool":
		readLoopLogf("[bifrost] route → session.tool seq=%s payload_len=%d", seqStr, len(evt.Payload))
		r.handleSessionTool(evt)
	case "agent":
		readLoopLogf("[bifrost] route → agent seq=%s payload_len=%d", seqStr, len(evt.Payload))
		r.handleAgentEvent(evt)
	case "session.message":
		readLoopLogf("[bifrost] route → session.message seq=%s payload_len=%d", seqStr, len(evt.Payload))
		r.handleSessionMessage(evt)
	case "sessions.changed":
		r.handleSessionsChanged(evt, seqStr)
	case "chat":
		r.handleChatEvent(evt, seqStr)
	case "tick", "health", "presence", "heartbeat",
		"exec.approval.resolved":
		// known lifecycle events, no action needed
	default:
		readLoopLogf("[bifrost] route → UNHANDLED event=%s seq=%s payload_len=%d",
			evt.Event, seqStr, len(evt.Payload))
	}
}

// SessionToolPayload is the payload of a session.tool event from OpenClaw.
// OpenClaw sends tool execution data as session.tool rather than separate
// tool_call/tool_result events.
type SessionToolPayload struct {
	Type     string          `json:"type"` // "call" or "result"
	Tool     string          `json:"tool"`
	Name     string          `json:"name"`
	Args     json.RawMessage `json:"args,omitempty"`
	Input    json.RawMessage `json:"input,omitempty"`
	Output   string          `json:"output,omitempty"`
	Result   string          `json:"result,omitempty"`
	Status   string          `json:"status,omitempty"`
	ExitCode *int            `json:"exit_code,omitempty"`
	CallID   string          `json:"callId,omitempty"`

	// OpenClaw stream format: {data: {phase, name, toolCallId, args, ...}}
	Data *sessionToolData `json:"data,omitempty"`
}

type sessionToolData struct {
	Phase      string          `json:"phase"` // "start", "update", "result"
	Name       string          `json:"name"`  // tool name
	ToolCallID string          `json:"toolCallId"`
	Args       json.RawMessage `json:"args,omitempty"`
	Meta       string          `json:"meta,omitempty"`
	IsError    bool            `json:"isError,omitempty"`
}

func (r *EventRouter) handleSessionTool(evt EventFrame) {
	var payload SessionToolPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		readLoopLogf("[bifrost] session.tool parse error: %v (raw=%s)",
			err, truncate(string(evt.Payload), 200))
		return
	}

	readLoopLogf("[bifrost] session.tool raw: type=%q tool=%q name=%q callId=%q has_data=%v has_args=%v",
		payload.Type, payload.Tool, payload.Name, payload.CallID, payload.Data != nil, payload.Args != nil)

	// Normalize OpenClaw stream format into the flat field layout.
	if payload.Data != nil {
		d := payload.Data
		readLoopLogf("[bifrost] session.tool data: phase=%q name=%q toolCallId=%q isError=%v",
			d.Phase, d.Name, d.ToolCallID, d.IsError)
		if payload.Name == "" && payload.Tool == "" {
			payload.Name = d.Name
		}
		if payload.CallID == "" {
			payload.CallID = d.ToolCallID
		}
		if payload.Args == nil && d.Args != nil {
			payload.Args = d.Args
		}
		switch d.Phase {
		case "start":
			payload.Type = "call"
		case "result":
			payload.Type = "result"
			if d.IsError {
				code := 1
				payload.ExitCode = &code
			}
		case "update":
			readLoopLogf("[bifrost] session.tool phase=update (skipping intermediate progress)")
			return
		default:
			readLoopLogf("[bifrost] session.tool unknown phase=%q, using as type", d.Phase)
			payload.Type = d.Phase
		}
	}

	toolName := payload.Tool
	if toolName == "" {
		toolName = payload.Name
	}

	if toolName == "" && payload.Type == "" {
		readLoopLogf("[bifrost] session.tool DROPPED: no tool name and no type (payload_len=%d)", len(evt.Payload))
		return
	}

	readLoopLogf("[bifrost] session.tool DISPATCHING type=%s tool=%s callId=%s",
		payload.Type, toolName, payload.CallID)

	switch payload.Type {
	case "call", "invoke":
		args := payload.Args
		if args == nil {
			args = payload.Input
		}
		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_call",
			Payload: mustMarshal(ToolCallPayload{Tool: toolName, Args: args, Status: payload.Status}),
			Seq:     evt.Seq,
		}
		r.handleToolCall(syntheticEvt)

	case "result", "output", "response":
		output := payload.Output
		if output == "" {
			output = payload.Result
		}
		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_result",
			Payload: mustMarshal(ToolResultPayload{Tool: toolName, Output: output, ExitCode: payload.ExitCode}),
			Seq:     evt.Seq,
		}
		r.handleToolResult(syntheticEvt)

	default:
		fmt.Fprintf(os.Stderr, "[sidecar] session.tool unknown type=%s tool=%s\n",
			payload.Type, toolName)
	}
}

// handleSessionMessage extracts tool call/result data from session.message
// events. OpenClaw sends tool execution updates inside session.message when
// the sidecar is subscribed to a session, using the same stream format as
// session.tool (runId, stream:"tool", data:{phase, name, ...}).
func (r *EventRouter) handleSessionMessage(evt EventFrame) {
	// OpenClaw sends two session.message formats:
	//   Format A (chat message): {sessionKey, message:{role,content,...}, messageSeq, session:{...}}
	//   Format B (tool stream):  {stream:"tool", data:{phase,name,...}, runId, sessionKey}
	// We handle both.
	var envelope struct {
		// Format B fields
		Stream string          `json:"stream"`
		RunID  string          `json:"runId"`
		Data   json.RawMessage `json:"data,omitempty"`
		// Format A fields
		SessionKey string          `json:"sessionKey"`
		Message    json.RawMessage `json:"message,omitempty"`
		MessageID  string          `json:"messageId"`
		MessageSeq int             `json:"messageSeq"`
	}
	if err := json.Unmarshal(evt.Payload, &envelope); err != nil {
		readLoopLogf("[bifrost] session.message parse error: %v", err)
		return
	}

	// Format B: tool stream → delegate to session.tool handler
	if envelope.Stream == "tool" && envelope.Data != nil {
		readLoopLogf("[bifrost] session.message (tool stream) → handleSessionTool runId=%s", envelope.RunID)
		r.handleSessionTool(evt)
		return
	}

	// Format A: chat message
	if envelope.Message != nil {
		var msg struct {
			Role         string          `json:"role"`
			Content      json.RawMessage `json:"content"`
			Timestamp    int64           `json:"timestamp"`
			StopReason   string          `json:"stopReason"`
			ErrorMessage string          `json:"errorMessage"`
			Provider     string          `json:"provider"`
			Model        string          `json:"model"`
			Usage        *struct {
				PromptTokens     int `json:"prompt_tokens"`
				CompletionTokens int `json:"completion_tokens"`
			} `json:"usage,omitempty"`
		}
		if err := json.Unmarshal(envelope.Message, &msg); err != nil {
			readLoopLogf("[bifrost] session.message: has message field but failed to parse: %v", err)
			return
		}

		contentStr := ""
		// content can be a string or an array of content blocks
		if len(msg.Content) > 0 {
			if msg.Content[0] == '"' {
				_ = json.Unmarshal(msg.Content, &contentStr)
			} else {
				contentStr = string(msg.Content)
			}
		}
		contentPreview := truncate(contentStr, 120)

		readLoopLogf("[bifrost] session.message: role=%s msgId=%s seq=%d session=%s content=(%d chars) %q",
			msg.Role, envelope.MessageID, envelope.MessageSeq, envelope.SessionKey, len(contentStr), contentPreview)

		if msg.StopReason == "error" || msg.ErrorMessage != "" {
			readLoopLogf("[bifrost] session.message ERROR: stopReason=%s error=%q provider=%s model=%s",
				msg.StopReason, msg.ErrorMessage, msg.Provider, msg.Model)
		}

		// Emit LLM span for assistant messages with a known model.
		// This captures LLM invocations that arrive via the WebSocket
		// (the direct OpenClaw → LLM path, not the guardrail proxy).
		// Uses the active agent context as parent for proper hierarchy.
		// Stores the LLM context so subsequent tool spans become children.
		if r.otel != nil && msg.Role == "assistant" && msg.Model != "" {
			system := inferSystem(msg.Provider, msg.Model)
			promptTokens, completionTokens := 0, 0
			if msg.Usage != nil {
				promptTokens = msg.Usage.PromptTokens
				completionTokens = msg.Usage.CompletionTokens
			}
			finishReasons := []string{}
			if msg.StopReason != "" {
				finishReasons = []string{msg.StopReason}
			}
			// Count tool_use blocks in content to populate tool_calls attribute.
			toolCallCount := countToolUseBlocks(msg.Content)

			parentCtx := r.getActiveAgentCtx()
			now := time.Now()
			llmCtx, span := r.otel.StartLLMSpan(
				parentCtx,
				system, msg.Model, msg.Provider,
				0, 0.0,
			)
			r.otel.EndLLMSpan(
				span, msg.Model,
				promptTokens, completionTokens,
				finishReasons, toolCallCount,
				"none", "",
				system, now,
				"openclaw",
			)

			// Store LLM context so tool_call spans become children of this LLM span.
			r.spanMu.Lock()
			r.activeLLMCtx = llmCtx
			r.spanMu.Unlock()

			readLoopLogf("[bifrost] session.message: emitted LLM span model=%s provider=%s system=%s tokens=%d/%d",
				msg.Model, msg.Provider, system, promptTokens, completionTokens)
		}

		// Record message in context tracker for multi-turn analysis.
		if r.contextTracker != nil && envelope.SessionKey != "" && contentStr != "" {
			r.contextTracker.Record(envelope.SessionKey, msg.Role, contentStr)
		}

		// Outbound message judge: inspect assistant messages for policy violations
		// (data leakage, PII in responses) via the WS path.
		if msg.Role == "assistant" && r.inspector != nil && len(contentStr) > 0 {
			go r.inspectOutboundMessage(envelope.SessionKey, contentStr, msg.Model)
		}

		// Multi-turn injection detection: if multiple user turns triggered
		// local patterns, escalate severity in the audit log.
		if msg.Role == "user" && r.contextTracker != nil && envelope.SessionKey != "" {
			if r.contextTracker.HasRepeatedInjection(envelope.SessionKey, 3, r.rulePack) {
				_ = r.logger.LogAction("gateway-multi-turn-injection", envelope.SessionKey,
					"repeated injection patterns detected across multiple user turns")
				if r.otel != nil {
					r.otel.EmitRuntimeAlert(
						telemetry.AlertToolCallFlagged, "HIGH", telemetry.SourceLocalPattern,
						fmt.Sprintf("Multi-turn injection attempt in session %s", truncate(envelope.SessionKey, 32)),
						map[string]string{"session": envelope.SessionKey},
						map[string]string{"action_taken": "alert"},
						"", "",
					)
				}
			}
		}

		_ = r.logger.LogAction("gateway-session-message", envelope.SessionKey,
			fmt.Sprintf("role=%s msgId=%s seq=%d content_len=%d", msg.Role, envelope.MessageID, envelope.MessageSeq, len(contentStr)))
		return
	}

	readLoopLogf("[bifrost] session.message SKIPPED: no message field, stream=%q", envelope.Stream)
}

func (r *EventRouter) handleSessionsChanged(evt EventFrame, seqStr string) {
	var sc struct {
		SessionKey string `json:"sessionKey"`
		Phase      string `json:"phase"`
		RunID      string `json:"runId"`
		MessageID  string `json:"messageId"`
		Ts         int64  `json:"ts"`
		Session    struct {
			Status   string `json:"status"`
			Model    string `json:"model"`
			Provider string `json:"modelProvider"`
		} `json:"session"`
	}
	if err := json.Unmarshal(evt.Payload, &sc); err != nil {
		readLoopLogf("[bifrost] sessions.changed parse error: %v", err)
		return
	}
	readLoopLogf("[bifrost] sessions.changed: phase=%s session=%s status=%s model=%s runId=%s msgId=%s",
		sc.Phase, sc.SessionKey, sc.Session.Status, sc.Session.Model, sc.RunID, sc.MessageID)

	r.trackSession(sc.SessionKey)

	if sc.Session.Status == "failed" || sc.Phase == "error" {
		readLoopLogf("[bifrost] sessions.changed ERROR: session %s status=failed phase=%s", sc.SessionKey, sc.Phase)
		_ = r.logger.LogAction("gateway-session-error", sc.SessionKey,
			fmt.Sprintf("phase=%s runId=%s model=%s", sc.Phase, sc.RunID, sc.Session.Model))
	}
}

func (r *EventRouter) handleChatEvent(evt EventFrame, seqStr string) {
	var ce struct {
		RunID        string `json:"runId"`
		SessionKey   string `json:"sessionKey"`
		Seq          int    `json:"seq"`
		State        string `json:"state"`
		ErrorMessage string `json:"errorMessage"`
	}
	if err := json.Unmarshal(evt.Payload, &ce); err != nil {
		readLoopLogf("[bifrost] chat parse error: %v", err)
		return
	}
	readLoopLogf("[bifrost] chat: state=%s session=%s runId=%s seq=%d",
		ce.State, ce.SessionKey, ce.RunID, ce.Seq)
	if ce.State == "error" {
		readLoopLogf("[bifrost] chat ERROR: %q session=%s runId=%s",
			ce.ErrorMessage, ce.SessionKey, ce.RunID)
		_ = r.logger.LogAction("gateway-chat-error", ce.SessionKey,
			fmt.Sprintf("runId=%s error=%s", ce.RunID, truncate(ce.ErrorMessage, 200)))
	}
}

func mustMarshal(v interface{}) json.RawMessage {
	b, _ := json.Marshal(v)
	return b
}

// agentEventPayload is the structure of an agent streaming event.
// Tool calls appear as type=tool_call or contain toolCall/toolResult fields.
type agentEventPayload struct {
	Type       string           `json:"type"`
	ToolCall   *agentToolCall   `json:"toolCall,omitempty"`
	ToolResult *agentToolResult `json:"toolResult,omitempty"`
	Content    json.RawMessage  `json:"content,omitempty"`
}

type agentToolCall struct {
	ID     string          `json:"id"`
	Name   string          `json:"name"`
	Tool   string          `json:"tool"`
	Args   json.RawMessage `json:"args,omitempty"`
	Input  json.RawMessage `json:"input,omitempty"`
	Status string          `json:"status,omitempty"`
}

type agentToolResult struct {
	ID       string `json:"id"`
	Name     string `json:"name"`
	Tool     string `json:"tool"`
	Output   string `json:"output,omitempty"`
	ExitCode *int   `json:"exitCode,omitempty"`
}

func (r *EventRouter) handleAgentEvent(evt EventFrame) {
	// OpenClaw sends two agent event formats:
	//   Format A (stream): {runId, stream:"lifecycle"|"tool"|"text", data:{phase,...}, sessionKey, seq, ts}
	//   Format B (legacy): {type, toolCall:{...}, toolResult:{...}, content}
	var streamEvt struct {
		RunID      string          `json:"runId"`
		Stream     string          `json:"stream"`
		Data       json.RawMessage `json:"data,omitempty"`
		SessionKey string          `json:"sessionKey"`
		Seq        int             `json:"seq"`
		Ts         int64           `json:"ts"`
	}
	if err := json.Unmarshal(evt.Payload, &streamEvt); err == nil && streamEvt.Stream != "" {
		r.handleAgentStreamEvent(streamEvt, evt)
		return
	}

	// Legacy format with toolCall/toolResult at top level
	var payload agentEventPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		readLoopLogf("[bifrost] agent event parse error: %v", err)
		return
	}

	readLoopLogf("[bifrost] agent event (legacy): type=%q has_toolCall=%v has_toolResult=%v",
		payload.Type, payload.ToolCall != nil, payload.ToolResult != nil)

	if payload.ToolCall == nil && payload.ToolResult == nil {
		readLoopLogf("[bifrost] agent event SKIPPED: no toolCall or toolResult in payload")
		return
	}

	if payload.ToolCall != nil {
		tc := payload.ToolCall
		toolName := tc.Name
		if toolName == "" {
			toolName = tc.Tool
		}
		if toolName == "" {
			return
		}
		args := tc.Args
		if args == nil {
			args = tc.Input
		}

		readLoopLogf("[bifrost] agent event → tool_call tool=%s id=%s", toolName, tc.ID)
		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_call",
			Payload: mustMarshal(ToolCallPayload{Tool: toolName, Args: args, Status: tc.Status}),
			Seq:     evt.Seq,
		}
		r.handleToolCall(syntheticEvt)
	}

	if payload.ToolResult != nil {
		tr := payload.ToolResult
		toolName := tr.Name
		if toolName == "" {
			toolName = tr.Tool
		}
		if toolName == "" {
			return
		}

		readLoopLogf("[bifrost] agent event → tool_result tool=%s id=%s", toolName, tr.ID)
		syntheticEvt := EventFrame{
			Type:    evt.Type,
			Event:   "tool_result",
			Payload: mustMarshal(ToolResultPayload{Tool: toolName, Output: tr.Output, ExitCode: tr.ExitCode}),
			Seq:     evt.Seq,
		}
		r.handleToolResult(syntheticEvt)
	}
}

// agentStreamData captures the data envelope of OpenClaw's stream-based agent events.
type agentStreamData struct {
	Phase      string          `json:"phase"`
	Name       string          `json:"name"`
	ToolCallID string          `json:"toolCallId"`
	Args       json.RawMessage `json:"args,omitempty"`
	Error      string          `json:"error,omitempty"`
	StartedAt  int64           `json:"startedAt,omitempty"`
	EndedAt    int64           `json:"endedAt,omitempty"`
	IsError    bool            `json:"isError,omitempty"`
	Meta       string          `json:"meta,omitempty"`
}

func (r *EventRouter) handleAgentStreamEvent(se struct {
	RunID      string          `json:"runId"`
	Stream     string          `json:"stream"`
	Data       json.RawMessage `json:"data,omitempty"`
	SessionKey string          `json:"sessionKey"`
	Seq        int             `json:"seq"`
	Ts         int64           `json:"ts"`
}, evt EventFrame) {
	var data agentStreamData
	if se.Data != nil {
		_ = json.Unmarshal(se.Data, &data)
	}

	readLoopLogf("[bifrost] agent stream: stream=%s phase=%s runId=%s session=%s seq=%d",
		se.Stream, data.Phase, se.RunID, se.SessionKey, se.Seq)

	switch se.Stream {
	case "lifecycle":
		switch data.Phase {
		case "start":
			readLoopLogf("[bifrost] agent lifecycle START runId=%s", se.RunID)
			_ = r.logger.LogAction("gateway-agent-start", se.SessionKey,
				fmt.Sprintf("runId=%s", se.RunID))

			// Start invoke_agent span as root of this agent run.
			if r.otel != nil && se.RunID != "" {
				// Use sessionKey as conversation.id; fall back to runId.
				conversationID := se.SessionKey
				if conversationID == "" {
					conversationID = se.RunID
				}
				agentCtx, agentSpan := r.otel.StartAgentSpan(
					context.Background(),
					conversationID, // conversation.id
					"openclaw",     // agent name
					"",             // provider filled on session.message
				)
				r.spanMu.Lock()
				r.activeAgentSpans[se.RunID] = &activeAgent{
					span:       agentSpan,
					ctx:        agentCtx,
					startTime:  time.Now(),
					sessionKey: se.SessionKey,
				}
				r.spanMu.Unlock()
			}

		case "error":
			readLoopLogf("[bifrost] agent lifecycle ERROR runId=%s error=%q", se.RunID, data.Error)
			_ = r.logger.LogAction("gateway-agent-error", se.SessionKey,
				fmt.Sprintf("runId=%s error=%s", se.RunID, truncate(data.Error, 200)))

			// End invoke_agent span with error.
			if r.otel != nil && se.RunID != "" {
				r.spanMu.Lock()
				r.activeLLMCtx = nil
				if aa := r.activeAgentSpans[se.RunID]; aa != nil {
					delete(r.activeAgentSpans, se.RunID)
					r.spanMu.Unlock()
					r.otel.EndAgentSpan(aa.span, truncate(data.Error, 256))
				} else {
					r.spanMu.Unlock()
				}
			}

		case "end":
			readLoopLogf("[bifrost] agent lifecycle END runId=%s", se.RunID)
			_ = r.logger.LogAction("gateway-agent-end", se.SessionKey,
				fmt.Sprintf("runId=%s", se.RunID))

			// End invoke_agent span successfully.
			if r.otel != nil && se.RunID != "" {
				r.spanMu.Lock()
				r.activeLLMCtx = nil
				if aa := r.activeAgentSpans[se.RunID]; aa != nil {
					delete(r.activeAgentSpans, se.RunID)
					r.spanMu.Unlock()
					r.otel.EndAgentSpan(aa.span, "")
				} else {
					r.spanMu.Unlock()
				}
			}

		default:
			readLoopLogf("[bifrost] agent lifecycle phase=%s runId=%s", data.Phase, se.RunID)
		}

	case "tool":
		readLoopLogf("[bifrost] agent tool stream: phase=%s name=%s toolCallId=%s",
			data.Phase, data.Name, data.ToolCallID)
		syntheticPayload := SessionToolPayload{
			Tool:   data.Name,
			CallID: data.ToolCallID,
			Args:   data.Args,
			Data:   &sessionToolData{Phase: data.Phase, Name: data.Name, ToolCallID: data.ToolCallID, Args: data.Args, IsError: data.IsError},
		}
		toolEvt := EventFrame{
			Type:    evt.Type,
			Event:   "session.tool",
			Payload: mustMarshal(syntheticPayload),
			Seq:     evt.Seq,
		}
		r.handleSessionTool(toolEvt)

	case "text":
		readLoopLogf("[bifrost] agent text stream: phase=%s (content delivery, no action)", data.Phase)

	default:
		readLoopLogf("[bifrost] agent unknown stream=%s phase=%s", se.Stream, data.Phase)
	}
}

func (r *EventRouter) handleToolCall(evt EventFrame) {
	var payload ToolCallPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse tool_call: %v\n", err)
		return
	}

	_ = r.logger.LogAction("gateway-tool-call", payload.Tool,
		fmt.Sprintf("status=%s args_length=%d", payload.Status, len(payload.Args)))

	// Static block list — checked before any pattern scanning.
	if r.policy != nil {
		if blocked, _ := r.policy.IsBlocked("tool", payload.Tool); blocked {
			fmt.Fprintf(os.Stderr, "[sidecar] BLOCKED tool call: %q is on the static block list\n", payload.Tool)
			_ = r.logger.LogAction("gateway-tool-call-blocked", payload.Tool, "reason=static-block-list")
			if r.otel != nil {
				r.otel.RecordInspectEvaluation(context.Background(), payload.Tool, "block", "HIGH")
			}
			return
		}
	}

	findings := ScanAllRulesRP(string(payload.Args), payload.Tool, r.rulePack)
	severity := HighestSeverity(findings)
	dangerous := len(findings) > 0 && severityRank[severity] >= severityRank["HIGH"]
	flaggedPattern := ""
	if dangerous {
		flaggedPattern = findings[0].RuleID
		_ = r.logger.LogAction("gateway-tool-call-flagged", payload.Tool,
			fmt.Sprintf("reason=%s severity=%s confidence=%.2f",
				findings[0].RuleID, findings[0].Severity, findings[0].Confidence))
		fmt.Fprintf(os.Stderr, "[sidecar] FLAGGED tool call: %s (%s)\n", payload.Tool, findings[0].Title)

		if r.otel != nil {
			r.otel.EmitRuntimeAlert(
				telemetry.AlertToolCallFlagged,
				severity,
				telemetry.SourceToolInspect,
				fmt.Sprintf("Dangerous tool call: %s — %s", payload.Tool, findings[0].Title),
				map[string]string{"tool": payload.Tool},
				map[string]string{"rule_id": flaggedPattern, "action": "flagged"},
				"", "",
			)
		}
	}

	// LLM judge — runs tool injection detection on arguments asynchronously.
	// The semaphore bounds concurrent judge executions while queued goroutines
	// wait for a slot instead of dropping inspection entirely.
	if r.judge != nil && len(payload.Args) > 0 {
		go func(tool string, args json.RawMessage) {
			r.judgeSem <- struct{}{}
			defer func() { <-r.judgeSem }()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			verdict := r.judge.RunToolJudge(ctx, tool, string(args))
			if verdict.Severity != "NONE" {
				fmt.Fprintf(os.Stderr, "[sidecar] LLM JUDGE flagged tool call: %s severity=%s %s\n",
					tool, verdict.Severity, verdict.Reason)
				_ = r.logger.LogAction("gateway-tool-call-judge-flagged", tool,
					fmt.Sprintf("severity=%s findings=%d reason=%s",
						verdict.Severity, len(verdict.Findings), verdict.Reason))
				if r.otel != nil {
					r.otel.RecordInspectEvaluation(ctx, tool, verdict.Action, verdict.Severity)
				}
			}
		}(payload.Tool, payload.Args)
	}

	if r.otel != nil {
		parentCtx := r.getToolParentCtx()
		ctx, span := r.otel.StartToolSpan(
			parentCtx,
			payload.Tool, payload.Status, payload.Args,
			dangerous, flaggedPattern, "builtin", "",
		)
		r.spanMu.Lock()
		r.activeToolSpans[payload.Tool] = append(r.activeToolSpans[payload.Tool], &activeSpan{
			span:      span,
			ctx:       ctx,
			startTime: time.Now(),
			tool:      payload.Tool,
			provider:  "builtin",
		})
		r.spanMu.Unlock()
	}
}

func (r *EventRouter) handleToolResult(evt EventFrame) {
	var payload ToolResultPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse tool_result: %v\n", err)
		return
	}

	exitCode := 0
	if payload.ExitCode != nil {
		exitCode = *payload.ExitCode
	}

	_ = r.logger.LogAction("gateway-tool-result", payload.Tool,
		fmt.Sprintf("exit_code=%d output_len=%d", exitCode, len(payload.Output)))

	if r.rulePack != nil && len(payload.Output) > 0 {
		r.inspectToolOutput(payload.Tool, payload.Output)
	}

	if r.otel != nil {
		r.spanMu.Lock()
		var as *activeSpan
		if q := r.activeToolSpans[payload.Tool]; len(q) > 0 {
			as = q[0]
			r.activeToolSpans[payload.Tool] = q[1:]
			if len(r.activeToolSpans[payload.Tool]) == 0 {
				delete(r.activeToolSpans, payload.Tool)
			}
		}
		r.spanMu.Unlock()

		if as != nil {
			r.otel.EndToolSpan(as.span, exitCode, len(payload.Output), as.startTime, as.tool, as.provider)
		}
	}
}

func (r *EventRouter) handleApprovalRequest(evt EventFrame) {
	var payload ApprovalRequestPayload
	if err := json.Unmarshal(evt.Payload, &payload); err != nil {
		fmt.Fprintf(os.Stderr, "[sidecar] parse exec.approval.requested: %v\n", err)
		return
	}

	rawCmd, argv, cwd := payload.CommandContext()
	if rawCmd == "" && len(argv) > 0 {
		rawCmd = strings.Join(argv, " ")
	}

	cmdName := baseCommand(rawCmd)
	fmt.Fprintf(os.Stderr, "[sidecar] exec.approval.requested: id=%s command=%s argc=%d cwd=%s\n",
		payload.ID, cmdName, len(argv), cwd)
	_ = r.logger.LogAction("gateway-approval-requested", payload.ID,
		fmt.Sprintf("command_name=%s argc=%d cwd=%s", cmdName, len(argv), cwd))

	var approvalSpan trace.Span
	if r.otel != nil {
		parentCtx := r.getToolParentCtx()
		_, approvalSpan = r.otel.StartApprovalSpan(parentCtx, payload.ID, rawCmd, argv, cwd)
	}

	cmdFindings := ScanAllRules(rawCmd, "shell")
	argvFindings := ScanAllRules(strings.Join(argv, " "), "shell")
	allFindings := append(cmdFindings, argvFindings...)
	dangerousByRules := len(allFindings) > 0 && severityRank[HighestSeverity(allFindings)] >= severityRank["HIGH"]
	dangerousByLegacy := r.isCommandDangerous(rawCmd) || r.isArgvDangerous(argv)
	dangerous := dangerousByRules || dangerousByLegacy
	topFinding := RuleFinding{RuleID: "UNKNOWN", Title: "dangerous command pattern"}
	for _, f := range allFindings {
		if severityRank[f.Severity] >= severityRank["HIGH"] {
			topFinding = f
			break
		}
	}
	if topFinding.RuleID == "UNKNOWN" && dangerousByLegacy {
		topFinding = RuleFinding{RuleID: "LEGACY-DANGEROUS-PATTERN", Title: "legacy dangerous command pattern"}
	}

	if dangerous {
		_ = r.logger.LogAction("gateway-approval-denied", payload.ID,
			fmt.Sprintf("reason=%s command_name=%s", topFinding.RuleID, cmdName))
		fmt.Fprintf(os.Stderr, "[sidecar] DENIED exec approval: %s (%s)\n", cmdName, topFinding.Title)

		if r.otel != nil {
			r.otel.EndApprovalSpan(approvalSpan, "denied", "dangerous-command", false, true)

			r.otel.EmitRuntimeAlert(
				telemetry.AlertDangerousCommand, "HIGH", telemetry.SourceLocalPattern,
				fmt.Sprintf("Dangerous command blocked: %s", cmdName),
				map[string]string{"tool": "shell", "command": rawCmd},
				map[string]string{"action_taken": "deny"},
				"", "",
			)
		}

		r.resolveApprovalAsync(payload.ID, false, "defenseclaw: command matched dangerous pattern")
		return
	}

	if r.autoApprove {
		_ = r.logger.LogAction("gateway-approval-granted", payload.ID,
			fmt.Sprintf("reason=auto-approve command_name=%s", cmdName))
		fmt.Fprintf(os.Stderr, "[sidecar] AUTO-APPROVED exec: %s\n", cmdName)

		if r.otel != nil {
			r.otel.EndApprovalSpan(approvalSpan, "approved", "auto-approved safe command", true, false)
		}

		r.resolveApprovalAsync(payload.ID, true, "defenseclaw: auto-approved safe command")
		return
	}

	fmt.Fprintf(os.Stderr, "[sidecar] PENDING exec approval: %s (awaiting manual approval)\n", cmdName)
	_ = r.logger.LogAction("gateway-approval-pending", payload.ID,
		fmt.Sprintf("command_name=%s reason=awaiting-manual-approval", cmdName))

	if r.otel != nil {
		r.otel.EndApprovalSpan(approvalSpan, "pending", "awaiting manual approval", false, false)
	}
}

// approvalCtx returns a context with a timeout for approval resolution RPCs.
// The caller is responsible for calling the returned cancel function.
func (r *EventRouter) approvalCtx() (context.Context, context.CancelFunc) {
	return context.WithTimeout(context.Background(), 10*time.Second)
}

func (r *EventRouter) resolveApprovalAsync(id string, approved bool, reason string) {
	go func() {
		ctx, cancel := r.approvalCtx()
		defer cancel()
		if err := r.client.ResolveApproval(ctx, id, approved, reason); err != nil {
			fmt.Fprintf(os.Stderr, "[sidecar] resolve approval error: %v\n", err)
		}
	}()
}

func truncate(s string, max int) string {
	if len(s) <= max {
		return s
	}
	return s[:max] + "..."
}

func baseCommand(cmd string) string {
	cmd = strings.TrimSpace(cmd)
	if cmd == "" {
		return ""
	}
	fields := strings.Fields(cmd)
	base := fields[0]
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	return base
}

// Legacy pattern helpers retained for backward-compat tests and fallback checks.
var dangerousPatterns = []string{
	"curl",
	"wget",
	"nc ",
	"ncat",
	"netcat",
	"/dev/tcp",
	"base64 -d",
	"base64 --decode",
	"eval ",
	"bash -c",
	"sh -c",
	"python -c",
	"perl -e",
	"ruby -e",
	"rm -rf /",
	"dd if=",
	"mkfs",
	"chmod 777",
	"> /etc/",
	">> /etc/",
	"passwd",
	"shadow",
	"sudoers",
}

func (r *EventRouter) isCommandDangerous(rawCmd string) bool {
	lower := strings.ToLower(rawCmd)
	for _, pattern := range dangerousPatterns {
		if strings.Contains(lower, pattern) {
			return true
		}
	}
	return false
}

// isArgvDangerous checks parsed argv for legacy dangerous patterns.
func (r *EventRouter) isArgvDangerous(argv []string) bool {
	if len(argv) == 0 {
		return false
	}

	combined := strings.ToLower(strings.Join(argv, " "))
	for _, pattern := range dangerousPatterns {
		if strings.Contains(combined, pattern) {
			return true
		}
	}

	base := argv[0]
	if idx := strings.LastIndex(base, "/"); idx >= 0 {
		base = base[idx+1:]
	}
	base = strings.ToLower(base)

	for _, bin := range dangerousBinaries {
		if base == bin {
			return true
		}
	}
	return false
}

var dangerousBinaries = []string{
	"curl", "wget", "nc", "ncat", "netcat",
	"dd", "mkfs", "rm",
}

// inferSystem derives the gen_ai.system value from provider and model strings.
func inferSystem(provider, model string) string {
	p := strings.ToLower(provider)
	switch {
	case strings.Contains(p, "anthropic"):
		return "anthropic"
	case strings.Contains(p, "openai"):
		return "openai"
	case strings.Contains(p, "google"), strings.Contains(p, "vertex"):
		return "google"
	case strings.Contains(p, "nvidia"), strings.Contains(p, "nim"):
		return "nvidia-nim"
	}
	m := strings.ToLower(model)
	switch {
	case strings.HasPrefix(m, "claude"):
		return "anthropic"
	case strings.HasPrefix(m, "gpt"), strings.HasPrefix(m, "o1"), strings.HasPrefix(m, "o3"), strings.HasPrefix(m, "o4"):
		return "openai"
	case strings.HasPrefix(m, "gemini"):
		return "google"
	}
	if provider != "" {
		return strings.ToLower(provider)
	}
	return "unknown"
}

// countToolUseBlocks counts tool_use content blocks in a JSON content field.
// Content may be a string (0 tool calls) or an array of objects with "type" fields.
func countToolUseBlocks(content json.RawMessage) int {
	if len(content) == 0 || content[0] != '[' {
		return 0
	}
	var blocks []struct {
		Type string `json:"type"`
	}
	if err := json.Unmarshal(content, &blocks); err != nil {
		return 0
	}
	count := 0
	for _, b := range blocks {
		if b.Type == "tool_use" || b.Type == "tool_calls" {
			count++
		}
	}
	return count
}
