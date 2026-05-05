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
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
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
	client       *Client
	store        *audit.Store
	logger       *audit.Logger
	policy       *enforce.PolicyEngine
	otel         *telemetry.Provider
	notify       *NotificationQueue
	judge        *LLMJudge
	rp           *guardrail.RulePack
	guardrailCfg *config.GuardrailConfig
	hilt         *HILTApprovalManager
	judgeSem     chan struct{} // bounds concurrent active tool-judge executions

	autoApprove      bool
	activeToolSpans  map[string][]*activeSpan
	activeAgentSpans map[string]*activeAgent // keyed by runId
	activeLLMCtx     context.Context         // context of most recent LLM span, for tool→LLM hierarchy
	spanMu           sync.Mutex

	activeSessionsMu sync.RWMutex
	activeSessions   map[string]time.Time // sessionKey → last seen

	contextTracker *ContextTracker

	// defaultAgentName is the fallback for agent_name when the
	// incoming event doesn't supply one. Populated from
	// cfg.Claw.Mode at sidecar bootstrap via SetDefaultAgentName.
	defaultAgentName string
	// defaultPolicyID is the identifier of the active guardrail /
	// admission policy. Populated at bootstrap via SetDefaultPolicyID.
	defaultPolicyID string
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

func (r *EventRouter) SetHILTApprovalManager(m *HILTApprovalManager) {
	r.hilt = m
}

func (r *EventRouter) SetGuardrailConfig(cfg *config.GuardrailConfig) {
	r.guardrailCfg = cfg
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

// activeAgentCorrelation returns session_id / run_id from the currently
// active agent span, when exactly one is active. Approval events do not
// carry correlation identifiers on the wire, so this is best-effort: if
// no agent span is active, both return values are empty. When multiple
// agents run concurrently (multi-tenant sidecar), we also return empty
// rather than guess — downstream SIEMs should prefer trace_id for
// correlation in that case.
func (r *EventRouter) activeAgentCorrelation() (sessionID, runID string) {
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	if len(r.activeAgentSpans) != 1 {
		return "", ""
	}
	for rid, aa := range r.activeAgentSpans {
		return aa.sessionKey, rid
	}
	return "", ""
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
	if r.hilt != nil {
		r.hilt.TrackSession(sessionKey)
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

// SetDefaultAgentName sets the agent name fallback used when incoming
// events do not carry one (e.g. cfg.Claw.Mode = "openclaw").
func (r *EventRouter) SetDefaultAgentName(name string) {
	r.defaultAgentName = name
}

// SetDefaultPolicyID sets the identifier of the active guardrail /
// admission policy. Threaded into tool and approval spans so downstream
// SIEMs (Splunk Local Bridge, AgentWatch) can aggregate per-policy.
func (r *EventRouter) SetDefaultPolicyID(id string) {
	r.defaultPolicyID = id
}

// agentNameForStream picks the most specific agent name available.
// Stream-provided hints win over the router default (claw mode) so
// that multi-agent deployments can still distinguish per-agent events.
func (r *EventRouter) agentNameForStream(hint string) string {
	if strings.TrimSpace(hint) != "" {
		return hint
	}
	return r.defaultAgentName
}

// streamEnvelope synthesizes an audit correlation envelope for audit
// rows emitted from the Bifrost stream goroutines. These goroutines
// are not HTTP-scoped — no CorrelationMiddleware runs on them — so
// the envelope has to be built from:
//
//   - gatewaylog.ProcessRunID() for run_id (seeded at sidecar boot).
//   - The stream-provided session key for session_id (required; an
//     empty session key leaves session_id unset).
//   - SharedAgentRegistry().Resolve(ctx, sessionKey, "") for the
//     three-tier agent identity (logical AgentID + per-session
//     AgentInstanceID + process-wide SidecarInstanceID).
//   - The router's configured defaults for agent_name (claw mode)
//     and policy_id (guardrail mode) when the registry has nothing
//     more specific.
//
// The envelope deliberately leaves trace_id / request_id empty —
// stream events have no inbound HTTP trace (the outbound OTel spans
// we start internally carry their own trace context for the agent
// invocation). Callers that want to correlate a stream event with
// a matching request should pivot on session_id + run_id.
func (r *EventRouter) streamEnvelope(ctx context.Context, sessionKey string) audit.CorrelationEnvelope {
	env := audit.CorrelationEnvelope{
		RunID:     gatewaylog.ProcessRunID(),
		SessionID: sessionKey,
		AgentName: r.defaultAgentName,
		PolicyID:  r.defaultPolicyID,
	}
	if reg := SharedAgentRegistry(); reg != nil {
		id := reg.Resolve(ctx, sessionKey, "")
		if id.AgentID != "" {
			env.AgentID = id.AgentID
		}
		if id.AgentName != "" {
			env.AgentName = id.AgentName
		}
		if id.AgentInstanceID != "" {
			env.AgentInstanceID = id.AgentInstanceID
		}
		if id.SidecarInstanceID != "" {
			env.SidecarInstanceID = id.SidecarInstanceID
		}
	}
	return env
}

// logStreamAction is the stream-path analogue of
// audit.Logger.LogActionCtx: it synthesizes a correlation envelope
// from the router defaults + the current session and records an
// audit row through the context-aware path. All Bifrost stream
// goroutines (chat/session/tool/approval) route through this so
// the session_id / agent_* / run_id coverage gap does not reappear
// the next time someone adds an event type.
func (r *EventRouter) logStreamAction(sessionKey, action, target, details string) {
	if r == nil || r.logger == nil {
		return
	}
	ctx := audit.ContextWithEnvelope(context.Background(), r.streamEnvelope(context.Background(), sessionKey))
	_ = r.logger.LogActionCtx(ctx, action, target, details)
}

// logStreamToolAction is the tool-scoped analogue of logStreamAction.
// Tool events need more than the generic session-level envelope —
// downstream SQLite / aggregate readers (top_tools in
// /v1/agentwatch/summary, tool_history per session) depend on
// destination_app, tool_name, and tool_id being persisted explicitly
// rather than parsed out of the free-form Details string. This helper
// merges those three dimensions on top of the session envelope
// produced by streamEnvelope and hands off through LogActionCtx so
// the emission path matches the HTTP surface byte-for-byte.
//
// destination_app defaults to "builtin": the Bifrost wire schema
// (ToolCallPayload / ToolResultPayload) does not carry a provider
// field, and every stream-delivered tool call today is an OpenClaw
// built-in. When a multi-provider stream shape appears (MCP-over-
// Bifrost, skill-over-Bifrost), extend the payload first, then plumb
// a provider/qualifier pair through here via toolDestinationApp.
func (r *EventRouter) logStreamToolAction(sessionKey, action, toolName, toolID, details string) {
	if r == nil || r.logger == nil {
		return
	}
	env := audit.MergeEnvelope(
		r.streamEnvelope(context.Background(), sessionKey),
		audit.CorrelationEnvelope{
			DestinationApp: "builtin",
			ToolName:       toolName,
			ToolID:         toolID,
		},
	)
	ctx := audit.ContextWithEnvelope(context.Background(), env)
	_ = r.logger.LogActionCtx(ctx, action, toolName, details)
}

// SetRulePack configures the guardrail rule pack for tool result inspection.
func (r *EventRouter) SetRulePack(rp *guardrail.RulePack) {
	r.rp = rp
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

	// SessionKey / RunID are included when the event was synthesized
	// from an agent stream (which carries them as envelope fields).
	// Direct session.tool frames from OpenClaw don't currently emit
	// them at the top level; when missing we degrade gracefully and
	// let downstream join on other identifiers.
	SessionKey string `json:"sessionKey,omitempty"`
	RunID      string `json:"runId,omitempty"`
	AgentName  string `json:"agentName,omitempty"`

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
		// The raw payload is event JSON that failed to parse.
		// It frequently carries verbatim user text, tool args,
		// or tool results, so redact before printing.
		readLoopLogf("[bifrost] session.tool parse error: %v (raw=%s)",
			err, redaction.MessageContent(truncate(string(evt.Payload), 200)))
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
			Type:  evt.Type,
			Event: "tool_call",
			Payload: mustMarshal(ToolCallPayload{
				Tool:      toolName,
				Args:      args,
				Status:    payload.Status,
				ID:        payload.CallID,
				SessionID: payload.SessionKey,
				RunID:     payload.RunID,
				AgentName: r.agentNameForStream(payload.AgentName),
			}),
			Seq: evt.Seq,
		}
		r.handleToolCall(syntheticEvt)

	case "result", "output", "response":
		output := payload.Output
		if output == "" {
			output = payload.Result
		}
		syntheticEvt := EventFrame{
			Type:  evt.Type,
			Event: "tool_result",
			Payload: mustMarshal(ToolResultPayload{
				Tool:      toolName,
				Output:    output,
				ExitCode:  payload.ExitCode,
				ID:        payload.CallID,
				SessionID: payload.SessionKey,
				RunID:     payload.RunID,
				AgentName: r.agentNameForStream(payload.AgentName),
			}),
			Seq: evt.Seq,
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
		// contentStr is a verbatim message body from an LLM
		// session. The full length is preserved in the log
		// metadata so operators can still tell at a glance
		// whether the payload was truncated by the caller; only
		// the preview is masked when Reveal is off.
		contentPreview := truncate(redaction.MessageContent(contentStr), 120)

		readLoopLogf("[bifrost] session.message: role=%s msgId=%s seq=%d session=%s content=(%d chars) %q",
			msg.Role, envelope.MessageID, envelope.MessageSeq, envelope.SessionKey, len(contentStr), contentPreview)

		msgCtx := ContextWithSessionID(context.Background(), envelope.SessionKey)
		msgMeta := streamLLMEventMeta(r, envelope.SessionKey, envelope.RunID, msg.Provider, msg.Model, "")
		msgMeta.TurnID = firstNonEmpty(envelope.MessageID, intString(envelope.MessageSeq))
		switch msg.Role {
		case "user":
			msgMeta.PromptID = promptIDForSessionMessage(envelope.SessionKey, envelope.MessageSeq, envelope.MessageID)
			emitLLMPromptEvent(msgCtx, msgMeta, contentStr, envelope.Message)
		case "assistant":
			msgMeta.PromptID = replyPromptIDForSessionMessage(envelope.SessionKey, envelope.MessageSeq)
			msgMeta.ResponseID = stableLLMEventID("response", "openclaw", envelope.SessionKey, envelope.MessageID, intString(envelope.MessageSeq))
			finishReasons := []string{}
			if msg.StopReason != "" {
				finishReasons = []string{msg.StopReason}
			}
			emitLLMResponseEvent(msgCtx, msgMeta, contentStr, string(msg.Content), finishReasons)
		}

		if r.hilt != nil && r.hilt.ResolveFromMessage(envelope.SessionKey, msg.Role, contentStr) {
			readLoopLogf("[bifrost] session.message: resolved HILT approval session=%s", envelope.SessionKey)
			return
		}

		if msg.StopReason == "error" || msg.ErrorMessage != "" {
			// Provider error messages have repeatedly shipped
			// echoed user prompts ("rate limit: request was
			// ... <prompt fragment>") and upstream API keys
			// in credential-invalid paths. Redact before
			// hitting stderr.
			readLoopLogf("[bifrost] session.message ERROR: stopReason=%s error=%q provider=%s model=%s",
				msg.StopReason, redaction.MessageContent(msg.ErrorMessage), msg.Provider, msg.Model)
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
			r.otel.SetRawSpanString(span, "defenseclaw.llm.response.content", contentStr)
			r.otel.SetRawSpanString(span, "defenseclaw.llm.response.raw_content", string(msg.Content))
			r.otel.EndLLMSpan(
				span, msg.Model,
				promptTokens, completionTokens,
				finishReasons, toolCallCount,
				"none", "",
				system, now,
				r.defaultAgentName,
				SharedAgentRegistry().AgentID(),
			)

			// Store LLM context so tool_call spans become children of this LLM span.
			r.spanMu.Lock()
			r.activeLLMCtx = llmCtx
			r.spanMu.Unlock()

			readLoopLogf("[bifrost] session.message: emitted LLM span model=%s provider=%s system=%s tokens=%d/%d",
				msg.Model, msg.Provider, system, promptTokens, completionTokens)
		}

		if r.contextTracker != nil && envelope.SessionKey != "" && contentStr != "" {
			r.contextTracker.Record(envelope.SessionKey, msg.Role, contentStr)
		}

		// Best-effort prompt-direction guardrail scan for inbound user
		// messages observed via the WebSocket. Unlike the proxy path
		// this is observational — by the time we see session.message
		// the prompt has already been sent to the LLM, so bad verdicts
		// raise audit rows but cannot block or confirm. Without
		// this hook, prompts that bypass the guardrail HTTP proxy
		// (e.g. OpenClaw shelling out to a separate CLI subprocess
		// whose fetch is not monkey-patched) are logged to
		// gateway.jsonl but never judged.
		if msg.Role == "user" && contentStr != "" {
			r.scanInboundPrompt(envelope.SessionKey, envelope.MessageID, msg.Model, contentStr)
		}

		if msg.Role == "user" && r.contextTracker != nil && envelope.SessionKey != "" {
			if r.contextTracker.HasRepeatedInjection(envelope.SessionKey, 3) {
				r.logStreamAction(envelope.SessionKey, "gateway-multi-turn-injection", envelope.SessionKey,
					"repeated injection patterns detected across multiple user turns")
				// Async read-loop context — stamp session_id so the
				// verdict event carries the conversation identifier
				// even though we're outside any HTTP request.
				vctx := ContextWithSessionID(context.Background(), envelope.SessionKey)
				emitVerdict(vctx, gatewaylog.StageMultiTurn, gatewaylog.DirectionPrompt, "",
					"warn", "repeated injection patterns across user turns",
					gatewaylog.SeverityHigh, []string{"injection:multi-turn"}, 0)
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

		// v7: stream events are off the HTTP path so we route through
		// logStreamAction which synthesizes the correlation envelope
		// locally (session/agent/run) before emitting. Without this,
		// every gateway-session-message row landed in audit_events
		// with session_id / agent_* / run_id NULL.
		r.logStreamAction(envelope.SessionKey, "gateway-session-message", envelope.SessionKey,
			fmt.Sprintf("role=%s msgId=%s seq=%d content_len=%d", msg.Role, envelope.MessageID, envelope.MessageSeq, len(contentStr)))
		return
	}

	readLoopLogf("[bifrost] session.message SKIPPED: no message field, stream=%q", envelope.Stream)
}

// scanInboundPrompt runs a best-effort guardrail scan on a user prompt
// observed via the session.message WebSocket stream. This is the
// observational cousin of the proxy-path guardrail: the prompt has
// already been dispatched to the LLM by the time we see the event, so
// non-allow verdicts produce an audit row + operator notification but
// cannot halt the in-flight request. Runs are bounded by judgeSem so
// a burst of concurrent sessions cannot starve the tool-result judge.
//
// We deliberately do not unconditionally fire the LLM judge on every
// benign user turn — the proxy path already judges every prompt that
// flows through it, and running an LLM round-trip for every OpenClaw
// chat turn would double-bill operators who have the proxy path wired.
// Only prompts that light up the deterministic regex stage escalate
// to the judge.
func (r *EventRouter) scanInboundPrompt(sessionKey, messageID, model, content string) {
	if content == "" {
		return
	}
	start := time.Now()

	verdict := scanLocalPatterns("prompt", content)

	runJudge := r.judge != nil && verdict != nil && verdict.Severity == "HIGH"
	if runJudge {
		select {
		case r.judgeSem <- struct{}{}:
			func() {
				defer func() { <-r.judgeSem }()
				jctx, cancel := context.WithTimeout(context.Background(), 15*time.Second)
				defer cancel()
				if jv := r.judge.RunJudges(jctx, "prompt", content, ""); jv != nil {
					verdict = mergeWithJudge(verdict, jv)
				}
			}()
		default:
			fmt.Fprintf(os.Stderr,
				"[sidecar] session.message prompt judge skipped (at capacity) session=%s msg=%s\n",
				truncate(sessionKey, 32), truncate(messageID, 32))
		}
	}

	if verdict == nil || verdict.Severity == "" || verdict.Severity == "NONE" {
		return
	}

	verdict.Action = guardrailRuntimeActionForGuardrail(r.guardrailCfg, verdict.Severity, false)
	// Mirror the proxy/inspector clamp on this independent prompt-scan
	// path so the session-message surface obeys the same contract:
	// prompts get audited as alerts; tool-call gate handles enforcement.
	clampPromptDirectionVerdict(verdict, "prompt")
	if verdict.Action == guardrailActionAllow {
		return
	}

	latencyMs := time.Since(start).Milliseconds()
	severity := deriveSeverity(verdict.Severity)
	categories := categoriesOf(verdict.Findings)

	vctx := ContextWithSessionID(context.Background(), sessionKey)
	emitVerdict(
		vctx,
		gatewaylog.StageSessionMessage,
		gatewaylog.DirectionPrompt,
		model,
		verdict.Action,
		verdict.Reason,
		severity,
		categories,
		latencyMs,
	)

	// verdict.Findings / verdict.Reason are minted directly from user
	// content and can carry literal PII (emails, SSNs, secrets) when
	// the local-pattern scanner matches. Always redact before any
	// sink, log line, or UI surface — same rules as handleSessionTool.
	scrubbedReason := redaction.ForSinkReason(verdict.Reason)
	r.logStreamAction(sessionKey, "gateway-session-prompt-alert", sessionKey,
		fmt.Sprintf("msgId=%s model=%s action=%s severity=%s findings=%d reason=%s",
			messageID, model, verdict.Action, verdict.Severity,
			len(verdict.Findings), scrubbedReason))

	if r.otel != nil {
		r.otel.EmitRuntimeAlert(
			telemetry.AlertPromptInjection, verdict.Severity, telemetry.SourceLocalPattern,
			fmt.Sprintf("Inbound prompt flagged in session %s", truncate(sessionKey, 32)),
			map[string]string{
				"session":    sessionKey,
				"message_id": messageID,
				"model":      model,
			},
			map[string]string{"action_taken": verdict.Action},
			"", "",
		)
	}

	fmt.Fprintf(os.Stderr,
		"[sidecar] session.message prompt-scan session=%s msg=%s action=%s severity=%s findings=%d (%dms judge=%v)\n",
		truncate(sessionKey, 32), truncate(messageID, 32),
		verdict.Action, verdict.Severity, len(verdict.Findings), latencyMs, runJudge)
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
		r.logStreamAction(sc.SessionKey, "gateway-session-error", sc.SessionKey,
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
		// Chat error messages follow the same leak profile as
		// session.message errors: upstream text frequently
		// includes echoed prompt snippets. Scrub operator-
		// facing stderr and the persistent audit detail.
		// audit.Logger also scrubs again via sanitizeEvent so
		// this is belt-and-braces defense in depth.
		scrubbedErr := redaction.MessageContent(ce.ErrorMessage)
		readLoopLogf("[bifrost] chat ERROR: %q session=%s runId=%s",
			scrubbedErr, ce.SessionKey, ce.RunID)
		r.logStreamAction(ce.SessionKey, "gateway-chat-error", ce.SessionKey,
			fmt.Sprintf("runId=%s error=%s", ce.RunID,
				truncate(redaction.ForSinkString(ce.ErrorMessage), 200)))
		ectx := ContextWithSessionID(context.Background(), ce.SessionKey)
		emitError(ectx, "chat", "chat-error",
			fmt.Sprintf("runId=%s session=%s", ce.RunID, ce.SessionKey),
			fmt.Errorf("%s", redaction.ForSinkString(ce.ErrorMessage)))
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
			Type:  evt.Type,
			Event: "tool_call",
			Payload: mustMarshal(ToolCallPayload{
				Tool:      toolName,
				Args:      args,
				Status:    tc.Status,
				ID:        tc.ID,
				AgentName: r.agentNameForStream(""),
			}),
			Seq: evt.Seq,
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
			Type:  evt.Type,
			Event: "tool_result",
			Payload: mustMarshal(ToolResultPayload{
				Tool:      toolName,
				Output:    tr.Output,
				ExitCode:  tr.ExitCode,
				ID:        tr.ID,
				AgentName: r.agentNameForStream(""),
			}),
			Seq: evt.Seq,
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
			r.logStreamAction(se.SessionKey, "gateway-agent-start", se.SessionKey,
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
					conversationID,           // conversation.id
					r.agentNameForStream(""), // agent name (claw mode fallback)
					SharedAgentRegistry().AgentID(),
					"", // provider filled on session.message
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
			// Agent lifecycle error messages are upstream LLM /
			// framework errors. Same leak profile as chat
			// errors — may quote user prompts or inner
			// model-graph state. Scrub for stderr, audit, and
			// the OTel span tag.
			scrubbedErr := redaction.MessageContent(data.Error)
			readLoopLogf("[bifrost] agent lifecycle ERROR runId=%s error=%q", se.RunID, scrubbedErr)
			r.logStreamAction(se.SessionKey, "gateway-agent-error", se.SessionKey,
				fmt.Sprintf("runId=%s error=%s", se.RunID,
					truncate(redaction.ForSinkString(data.Error), 200)))
			ectx := ContextWithSessionID(context.Background(), se.SessionKey)
			emitError(ectx, "agent", "agent-error",
				fmt.Sprintf("runId=%s session=%s", se.RunID, se.SessionKey),
				fmt.Errorf("%s", redaction.ForSinkString(data.Error)))

			// End invoke_agent span with error.
			if r.otel != nil && se.RunID != "" {
				r.spanMu.Lock()
				r.activeLLMCtx = nil
				if aa := r.activeAgentSpans[se.RunID]; aa != nil {
					delete(r.activeAgentSpans, se.RunID)
					r.spanMu.Unlock()
					r.otel.EndAgentSpan(aa.span, truncate(redaction.ForSinkString(data.Error), 256))
				} else {
					r.spanMu.Unlock()
				}
			}

		case "end":
			readLoopLogf("[bifrost] agent lifecycle END runId=%s", se.RunID)
			r.logStreamAction(se.SessionKey, "gateway-agent-end", se.SessionKey,
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
			Tool:       data.Name,
			CallID:     data.ToolCallID,
			Args:       data.Args,
			SessionKey: se.SessionKey,
			RunID:      se.RunID,
			AgentName:  r.agentNameForStream(""),
			Data:       &sessionToolData{Phase: data.Phase, Name: data.Name, ToolCallID: data.ToolCallID, Args: data.Args, IsError: data.IsError},
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

	r.logStreamToolAction(payload.SessionID, "gateway-tool-call", payload.Tool, payload.ID,
		fmt.Sprintf("status=%s args_length=%d", payload.Status, len(payload.Args)))
	meta := streamLLMEventMeta(r, payload.SessionID, payload.RunID, "builtin", "", payload.AgentName)
	meta.ToolID = payload.ID
	meta.ToolName = payload.Tool
	emitToolInvocationEvent(context.Background(), meta, "call", payload.Tool, stringFromJSONRaw(payload.Args), "", nil)

	// Static block list — checked before any pattern scanning.
	if r.policy != nil {
		if blocked, _ := r.policy.IsBlocked("tool", payload.Tool); blocked {
			fmt.Fprintf(os.Stderr, "[sidecar] BLOCKED tool call: %q is on the static block list\n", payload.Tool)
			r.logStreamToolAction(payload.SessionID, "gateway-tool-call-blocked", payload.Tool, payload.ID, "reason=static-block-list")
			vctx := ContextWithSessionID(context.Background(), payload.SessionID)
			emitVerdict(vctx, gatewaylog.StageBlockList, gatewaylog.DirectionPrompt, payload.Tool,
				"block", "static block list",
				gatewaylog.SeverityHigh, []string{"policy:block", "surface:tool_call"}, 0)
			if r.otel != nil {
				r.otel.RecordInspectEvaluation(context.Background(), payload.Tool, "block", "HIGH")
			}
			return
		}
	}

	// Use the shared rule engine — no tool-name gating.
	findings := ScanAllRules(string(payload.Args), payload.Tool)
	severity := HighestSeverity(findings)
	dangerous := len(findings) > 0 && severityRank[severity] >= severityRank["HIGH"]
	flaggedPattern := ""
	if dangerous {
		flaggedPattern = findings[0].RuleID
		r.logStreamToolAction(payload.SessionID, "gateway-tool-call-flagged", payload.Tool, payload.ID,
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
		go func(tool, sessionID, toolID string, args json.RawMessage) {
			r.judgeSem <- struct{}{}
			defer func() { <-r.judgeSem }()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			verdict := r.judge.RunToolJudge(ctx, tool, string(args))
			if verdict.Severity != "NONE" {
				// Judge verdict reasons are LLM-authored prose
				// that frequently quote the offending argument
				// back verbatim ("Tool call uses user email
				// alice@example.com without consent"). Scrub
				// the stderr emission and the audit detail
				// so the quoted literal never reaches a
				// persistent sink.
				fmt.Fprintf(os.Stderr, "[sidecar] LLM JUDGE flagged tool call: %s severity=%s %s\n",
					tool, verdict.Severity, redaction.Reason(verdict.Reason))
				r.logStreamToolAction(sessionID, "gateway-tool-call-judge-flagged", tool, toolID,
					fmt.Sprintf("severity=%s findings=%d reason=%s",
						verdict.Severity, len(verdict.Findings),
						redaction.ForSinkReason(verdict.Reason)))
				if r.otel != nil {
					r.otel.RecordInspectEvaluation(ctx, tool, verdict.Action, verdict.Severity)
				}
			}
		}(payload.Tool, payload.SessionID, payload.ID, payload.Args)
	}

	if r.otel != nil {
		parentCtx := r.getToolParentCtx()
		agentName := r.agentNameForStream(payload.AgentName)
		ctx, span := r.otel.StartToolSpan(
			parentCtx,
			payload.Tool, payload.Status, payload.Args,
			dangerous, flaggedPattern, "builtin", "",
			telemetry.ToolSpanContext{
				ToolID:         payload.ID,
				SessionID:      payload.SessionID,
				RunID:          payload.RunID,
				DestinationApp: toolDestinationApp("builtin", ""),
				PolicyID:       r.defaultPolicyID,
				AgentName:      agentName,
				AgentID:        SharedAgentRegistry().AgentID(),
			},
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

// toolDestinationApp formats the destination_app field for tool spans
// using the tool provider convention:
//
//	builtin
//	mcp:<server>
//	skill:<key>
//
// The provider argument is "builtin" | "mcp" | "skill" (other values are
// returned verbatim). The qualifier is the MCP server name or skill key;
// it is omitted when empty so generic builtin tools don't get a trailing
// colon.
func toolDestinationApp(provider, qualifier string) string {
	if provider == "" {
		return ""
	}
	if qualifier == "" {
		return provider
	}
	return provider + ":" + qualifier
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

	r.logStreamToolAction(payload.SessionID, "gateway-tool-result", payload.Tool, payload.ID,
		fmt.Sprintf("exit_code=%d output_len=%d", exitCode, len(payload.Output)))
	meta := streamLLMEventMeta(r, payload.SessionID, payload.RunID, "builtin", "", payload.AgentName)
	meta.ToolID = payload.ID
	meta.ToolName = payload.Tool
	emitToolInvocationEvent(context.Background(), meta, "result", payload.Tool, "", payload.Output, &exitCode)

	r.inspectToolResult(payload)

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
			r.otel.SetRawSpanString(as.span, "defenseclaw.tool.output", payload.Output)
			r.otel.EndToolSpan(as.span, exitCode, len(payload.Output), as.startTime, as.tool, as.provider)
		}
	}
}

// inspectToolResult checks tool output against sensitive-tools configuration
// from the rule pack.
//
// The flow is:
//  1. A deterministic regex scan (scanLocalPatterns) runs whenever
//     result_inspection=true, regardless of judge availability. Previously
//     the function was a no-op when judge_result=false OR when the judge
//     was nil — that meant tools like users_org_info (shipped default has
//     result_inspection=true, judge_result=false) received no inspection
//     at all, and any judge-init failure silently disabled every sensitive
//     tool-result scan in the process.
//  2. If judge_result=true AND a judge is configured, the LLM PII judge
//     also runs and its findings are merged with the regex findings.
//  3. If judge_result=true but the judge is unavailable, a warning is
//     logged once per call so the operator can see the degraded state —
//     the deterministic scan still runs.
func (r *EventRouter) inspectToolResult(payload ToolResultPayload) {
	if r.rp == nil || payload.Output == "" {
		return
	}
	stool := r.rp.LookupSensitiveTool(payload.Tool)
	if stool == nil || !stool.ResultInspection {
		return
	}

	fmt.Fprintf(os.Stderr, "[sidecar] inspecting sensitive tool result: %s (output_len=%d judge=%t)\n",
		payload.Tool, len(payload.Output), stool.JudgeResult && r.judge != nil)

	// Stage 1: deterministic regex scan. Always runs.
	verdict := scanLocalPatterns("completion", payload.Output)

	// Stage 2: LLM judge, if requested and available. Merge into verdict.
	if stool.JudgeResult {
		if r.judge == nil {
			fmt.Fprintf(os.Stderr, "[sidecar] tool %s requests judge_result but judge unavailable; using regex-only verdict\n",
				payload.Tool)
		} else {
			select {
			case r.judgeSem <- struct{}{}:
				func() {
					defer func() { <-r.judgeSem }()
					ctx, cancel := context.WithTimeout(context.Background(), 30*time.Second)
					defer cancel()
					if jv := r.judge.RunJudges(ctx, "completion", payload.Output, payload.Tool); jv != nil {
						verdict = mergeWithJudge(verdict, jv)
					}
				}()
			default:
				fmt.Fprintf(os.Stderr, "[sidecar] tool result judge skipped (at capacity), regex scan kept: %s\n",
					payload.Tool)
			}
		}
	}

	if verdict == nil || verdict.Action == "allow" {
		return
	}

	minEntities := stool.MinEntitiesAlert
	if minEntities <= 0 {
		minEntities = 1
	}
	entityCount := verdict.EntityCount
	if entityCount == 0 {
		entityCount = len(verdict.Findings)
	}
	if entityCount < minEntities {
		return
	}

	// verdict.Findings are finding strings minted from PII
	// matches in the tool output (e.g. "email:alice@corp.com",
	// "SSN:123-45-6789"). These absolutely cannot escape
	// unredacted. verdict.Reason is LLM-judge prose and gets the
	// same treatment.
	scrubbedFindings := make([]string, len(verdict.Findings))
	for i, f := range verdict.Findings {
		scrubbedFindings[i] = redaction.Reason(f)
	}
	fmt.Fprintf(os.Stderr, "[sidecar] tool result alert: tool=%s action=%s severity=%s entities=%d findings=%v\n",
		payload.Tool, verdict.Action, verdict.Severity, entityCount, scrubbedFindings)
	r.logStreamToolAction(payload.SessionID, "tool-result-pii-alert", payload.Tool, payload.ID,
		fmt.Sprintf("severity=%s entities=%d findings=%d reason=%s",
			verdict.Severity, entityCount, len(verdict.Findings),
			redaction.ForSinkReason(verdict.Reason)))
	if r.notify != nil {
		// SecurityNotification ultimately surfaces in the TUI
		// and any webhook alert, both of which are operator-
		// visible but must not leak literals. Scrub the Reason
		// at the emit site. Findings count is already numeric.
		r.notify.Push(SecurityNotification{
			SubjectType: "tool-result",
			SkillName:   payload.Tool,
			Severity:    verdict.Severity,
			Findings:    entityCount,
			Actions:     []string{"alert"},
			Reason:      redaction.ForSinkReason(verdict.Reason),
		})
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
	approvalSession, _ := r.activeAgentCorrelation()
	r.logStreamAction(approvalSession, "gateway-approval-requested", payload.ID,
		fmt.Sprintf("command_name=%s argc=%d cwd=%s", cmdName, len(argv), cwd))

	var approvalSpan trace.Span
	if r.otel != nil {
		parentCtx := r.getToolParentCtx()
		sessionID, runID := r.activeAgentCorrelation()
		_, approvalSpan = r.otel.StartApprovalSpan(parentCtx, payload.ID, rawCmd, argv, cwd,
			telemetry.ToolSpanContext{
				ToolID:         payload.ID,
				SessionID:      sessionID,
				RunID:          runID,
				DestinationApp: toolDestinationApp("builtin", ""),
				PolicyID:       r.defaultPolicyID,
				AgentName:      r.agentNameForStream(""),
				AgentID:        SharedAgentRegistry().AgentID(),
			},
		)
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
		sessionID, _ := r.activeAgentCorrelation()
		r.logStreamAction(sessionID, "gateway-approval-denied", payload.ID,
			fmt.Sprintf("reason=%s command_name=%s", topFinding.RuleID, cmdName))
		vctx := ContextWithSessionID(context.Background(), sessionID)
		emitVerdict(vctx, gatewaylog.StageApproval, gatewaylog.DirectionPrompt, cmdName,
			"block", fmt.Sprintf("%s: %s", topFinding.RuleID, topFinding.Title),
			deriveSeverity(topFinding.Severity), []string{"approval:denied", "surface:exec"}, 0)
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
		r.logStreamAction(approvalSession, "gateway-approval-granted", payload.ID,
			fmt.Sprintf("reason=auto-approve command_name=%s", cmdName))
		fmt.Fprintf(os.Stderr, "[sidecar] AUTO-APPROVED exec: %s\n", cmdName)

		if r.otel != nil {
			r.otel.EndApprovalSpan(approvalSpan, "approved", "auto-approved safe command", true, false)
		}

		r.resolveApprovalAsync(payload.ID, true, "defenseclaw: auto-approved safe command")
		return
	}

	fmt.Fprintf(os.Stderr, "[sidecar] PENDING exec approval: %s (awaiting manual approval)\n", cmdName)
	r.logStreamAction(approvalSession, "gateway-approval-pending", payload.ID,
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
