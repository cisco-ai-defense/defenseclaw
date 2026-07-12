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

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/config"
	"github.com/defenseclaw/defenseclaw/internal/enforce"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/guardrail"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	"github.com/defenseclaw/defenseclaw/internal/redaction"
)

// EventRouter dispatches gateway events to the appropriate handlers and logs
// everything to the audit store.
type EventRouter struct {
	client *Client
	store  *audit.Store
	logger *audit.Logger
	policy *enforce.PolicyEngine
	// The process-owned v8 capabilities are published atomically under one lock.
	// EventRouter never retains a runtime generation lease or generated trace
	// handle across WebSocket deliveries.
	observabilityV8LifecycleMu   sync.RWMutex
	observabilityV8Emitter       sidecarRuntimeEmitter
	observabilityV8Lifecycle     lifecycleV8Runtime
	observabilityV8Authoritative bool
	configMu                     sync.RWMutex
	notify                       *NotificationQueue
	judge                        *LLMJudge
	rp                           *guardrail.RulePack
	guardrailCfg                 *config.GuardrailConfig
	hilt                         *HILTApprovalManager
	judgeSem                     chan struct{} // bounds concurrent active tool-judge executions

	autoApprove bool
	spanMu      sync.Mutex
	// Ended W3C model contexts are keyed by source-backed session/run facts.
	// Contexts contain no live span or runtime-generation lease.
	activeLLMContexts map[eventRouterModelContextKey]eventRouterModelContextEntry

	toolObservationMu    sync.Mutex
	toolObservations     map[string]eventRouterToolObservation
	toolObservationOrder []eventRouterToolObservationCacheEntry
	toolObservationNow   func() time.Time

	agentRunObservationMu    sync.Mutex
	agentRunObservationCache map[agentRunObservationKey]time.Time
	agentRunObservationOrder []agentRunObservationCacheEntry
	agentRunTopologies       map[string]agentRunTopologyState
	agentRunExecutions       map[agentRunExecutionKey]agentRunExecutionState
	agentRunObservationNow   func() time.Time

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
func NewEventRouter(client *Client, store *audit.Store, logger *audit.Logger, autoApprove bool) *EventRouter {
	return &EventRouter{
		client:                   client,
		store:                    store,
		logger:                   logger,
		policy:                   enforce.NewPolicyEngine(store),
		autoApprove:              autoApprove,
		activeSessions:           make(map[string]time.Time),
		judgeSem:                 make(chan struct{}, 16),
		contextTracker:           NewContextTracker(0, 0),
		agentRunObservationCache: make(map[agentRunObservationKey]time.Time),
		agentRunTopologies:       make(map[string]agentRunTopologyState),
		agentRunExecutions:       make(map[agentRunExecutionKey]agentRunExecutionState),
		agentRunObservationNow:   time.Now,
		toolObservations:         make(map[string]eventRouterToolObservation),
		toolObservationNow:       time.Now,
		activeLLMContexts:        make(map[eventRouterModelContextKey]eventRouterModelContextEntry),
	}
}

func (r *EventRouter) SetHILTApprovalManager(m *HILTApprovalManager) {
	r.hilt = m
}

func (r *EventRouter) SetGuardrailConfig(cfg *config.GuardrailConfig) {
	r.configMu.Lock()
	r.guardrailCfg = cfg
	r.configMu.Unlock()
}

func (r *EventRouter) guardrailConfig() *config.GuardrailConfig {
	r.configMu.RLock()
	defer r.configMu.RUnlock()
	return r.guardrailCfg
}

// activeAgentCorrelation intentionally returns no inferred identity. Current
// approval frames do not carry a trustworthy session/run anchor, and an
// EventRouter lifecycle observation is not proof that a later frame belongs to
// that run. A version-gated adapter may replace this only when the wire carries
// the complete current/root/parent session and agent topology.
func (r *EventRouter) activeAgentCorrelation() (sessionID, runID string) {
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
	r.configMu.Lock()
	r.defaultAgentName = name
	r.configMu.Unlock()
}

// SetDefaultPolicyID sets the identifier of the active guardrail /
// admission policy. Threaded into tool and approval spans so downstream
// downstream SIEM projections can aggregate per policy.
func (r *EventRouter) SetDefaultPolicyID(id string) {
	r.configMu.Lock()
	r.defaultPolicyID = id
	r.configMu.Unlock()
}

func (r *EventRouter) defaultRoutingMetadata() (string, string) {
	r.configMu.RLock()
	defer r.configMu.RUnlock()
	return r.defaultAgentName, r.defaultPolicyID
}

// connectorName returns the connector this sidecar process is configured for,
// mirroring configuredConnectorName(cfg): the guardrail connector wins, else
// the Claw mode (captured as defaultAgentName at bootstrap). Empty ⇒ only the
// global tool tier is consulted on this lane. Unlike the hook lane (which reads
// a per-request connector), the sidecar is single-connector per process, so
// the connector comes from config rather than the event payload.
func (r *EventRouter) connectorName() string {
	if cfg := r.guardrailConfig(); cfg != nil {
		if name := strings.TrimSpace(cfg.Connector); name != "" {
			return strings.ToLower(name)
		}
	}
	defaultAgentName, _ := r.defaultRoutingMetadata()
	return strings.ToLower(strings.TrimSpace(defaultAgentName))
}

// agentNameForStream picks the most specific agent name available.
// Stream-provided hints win over the router default (claw mode) so
// that multi-agent deployments can still distinguish per-agent events.
func (r *EventRouter) agentNameForStream(hint string) string {
	if strings.TrimSpace(hint) != "" {
		return hint
	}
	defaultAgentName, _ := r.defaultRoutingMetadata()
	return defaultAgentName
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
	defaultAgentName, defaultPolicyID := r.defaultRoutingMetadata()
	env := audit.CorrelationEnvelope{
		RunID:     gatewaylog.ProcessRunID(),
		SessionID: sessionKey,
		AgentName: defaultAgentName,
		PolicyID:  defaultPolicyID,
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

func (r *EventRouter) streamContext(sessionKey string, overlay audit.CorrelationEnvelope) context.Context {
	env := audit.MergeEnvelope(r.streamEnvelope(context.Background(), sessionKey), overlay)
	ctx := context.Background()
	if env.SessionID != "" {
		ctx = ContextWithSessionID(ctx, env.SessionID)
	}
	return audit.ContextWithEnvelope(ctx, env)
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
		// Session message bodies are prompts and responses. The daemon
		// persists stderr to gateway.log, so log only routing metadata and
		// length rather than creating a second conversation transcript.
		//
		// TODO(v8-logging-refactor): Preserve the former bounded preview for
		// consideration when v8 separates local debugging from shipped logs.
		// contentPreview := truncate(redaction.MessageContent(contentStr), 120)
		// readLoopLogf("[bifrost] session.message: role=%s msgId=%s seq=%d session=%s content=(%d chars) %q",
		// 	msg.Role, envelope.MessageID, envelope.MessageSeq, envelope.SessionKey, len(contentStr), contentPreview)
		readLoopLogf("[bifrost] session.message: role=%s msgId=%s seq=%d session=%s content_len=%d content=omitted",
			msg.Role, envelope.MessageID, envelope.MessageSeq, envelope.SessionKey, len(contentStr))

		msgCtx := ContextWithSessionID(context.Background(), envelope.SessionKey)
		msgMeta := streamLLMEventMeta(r, envelope.SessionKey, envelope.RunID, msg.Provider, msg.Model, "")
		msgMeta.TurnID = firstNonEmpty(envelope.MessageID, intString(envelope.MessageSeq))
		switch msg.Role {
		case "user":
			msgMeta.PromptID = promptIDForSessionMessage(envelope.SessionKey, envelope.MessageSeq, envelope.MessageID)
			r.emitLLMPromptEventV8(msgCtx, msgMeta, contentStr, envelope.Message)
		case "assistant":
			msgMeta.PromptID = replyPromptIDForSessionMessage(envelope.SessionKey, envelope.MessageSeq)
			msgMeta.ResponseID = stableLLMEventID("response", "openclaw", envelope.SessionKey, envelope.MessageID, intString(envelope.MessageSeq))
			finishReasons := []string{}
			if msg.StopReason != "" {
				finishReasons = []string{msg.StopReason}
			}
			r.emitLLMResponseEventV8(msgCtx, msgMeta, contentStr, string(msg.Content), finishReasons)
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

		// A completed assistant message is a bounded generated model
		// operation. The source reports no start instant, so the adapter
		// records a truthful zero-duration span and retains only its ended
		// W3C context for a subsequent tool or approval child.
		if msg.Role == "assistant" && msg.Model != "" {
			promptTokens, completionTokens := int64(0), int64(0)
			if msg.Usage != nil {
				promptTokens = int64(msg.Usage.PromptTokens)
				completionTokens = int64(msg.Usage.CompletionTokens)
			}
			finishReasons := []string{}
			if msg.StopReason != "" {
				finishReasons = []string{msg.StopReason}
			}
			toolCallCount := int64(countToolUseBlocks(msg.Content))
			meta := eventRouterModelMeta(
				r, envelope.SessionKey, envelope.RunID, envelope.MessageID,
				envelope.MessageSeq, msg.Provider, msg.Model,
			)
			llmCtx := r.emitEventRouterModelV8(
				context.Background(), meta, msg.Provider, msg.Model, contentStr,
				promptTokens, completionTokens, toolCallCount, finishReasons, time.Now().UTC(),
			)
			r.rememberEventRouterModelContext(
				envelope.SessionKey, envelope.RunID, llmCtx, time.Now().UTC(),
			)

			readLoopLogf("[bifrost] session.message: emitted generated model operation model=%s provider=%s tokens=%d/%d",
				msg.Model, msg.Provider, promptTokens, completionTokens)
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
		// whose fetch is not monkey-patched) are recorded as canonical
		// prompt events but never judged.
		if msg.Role == "user" && contentStr != "" {
			r.scanInboundPrompt(envelope.SessionKey, envelope.MessageID, msg.Model, contentStr)
		}

		if msg.Role == "user" && r.contextTracker != nil && envelope.SessionKey != "" {
			if r.contextTracker.HasRepeatedInjection(envelope.SessionKey, 3) {
				r.logStreamAction(envelope.SessionKey, string(audit.ActionGatewayMultiTurnInjection), envelope.SessionKey,
					"repeated injection patterns detected across multiple user turns")
				// Async read-loop context — stamp session_id so the
				// verdict event carries the conversation identifier
				// even though we're outside any HTTP request.
				vctx := r.streamContext(envelope.SessionKey, audit.CorrelationEnvelope{TurnID: envelope.MessageID})
				emitVerdict(vctx, gatewaylog.StageMultiTurn, gatewaylog.DirectionPrompt, "",
					"warn", "repeated injection patterns across user turns",
					gatewaylog.SeverityHigh, []string{"injection:multi-turn"}, 0)
				meta := streamLLMEventMeta(r, envelope.SessionKey, envelope.RunID, "builtin", msg.Model, "")
				meta.TurnID = envelope.MessageID
				r.recordEventRouterGuardrailMetricsV8(vctx, eventRouterGuardrailMetricObservation{
					meta: meta, severity: "HIGH", alertType: "prompt-injection",
					alertSource: "local-pattern", observedAt: time.Now().UTC(),
				})
			}
		}

		// v7: stream events are off the HTTP path so we route through
		// logStreamAction which synthesizes the correlation envelope
		// locally (session/agent/run) before emitting. Without this,
		// every gateway-session-message row landed in audit_events
		// with session_id / agent_* / run_id NULL.
		r.logStreamAction(envelope.SessionKey, string(audit.ActionGatewaySessionMessage), envelope.SessionKey,
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

	verdict.Action = guardrailRuntimeActionForGuardrail(r.guardrailConfig(), verdict.Severity, false)
	// Mirror the proxy/inspector clamp on this independent prompt-scan
	// path so the session-message surface obeys the same contract:
	// prompts get audited as alerts; tool-call gate handles enforcement.
	clampPromptDirectionVerdict(verdict, "prompt")
	if verdict.Action == guardrailActionAllow {
		return
	}

	elapsed := time.Since(start)
	latencyMs := elapsed.Milliseconds()
	severity := deriveSeverity(verdict.Severity)
	categories := categoriesOf(verdict.Findings)

	vctx := r.streamContext(sessionKey, audit.CorrelationEnvelope{TurnID: messageID})
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
	meta := streamLLMEventMeta(r, sessionKey, "", "builtin", model, "")
	meta.TurnID = messageID
	r.recordEventRouterGuardrailMetricsV8(vctx, eventRouterGuardrailMetricObservation{
		meta: meta, action: verdict.Action, severity: verdict.Severity,
		alertType: "prompt-injection", alertSource: "local-pattern", observedAt: time.Now().UTC(),
	})

	// Preserve the source reason for canonical per-destination redaction. The
	// stderr summary below omits it; only log-injection controls are removed
	// before the structured fact reaches the v8 runtime.
	auditReason := stripLogInjectionRunes(verdict.Reason)
	r.logStreamAction(sessionKey, string(audit.ActionGatewaySessionPromptAlert), sessionKey,
		fmt.Sprintf("msgId=%s model=%s action=%s severity=%s findings=%d reason=%s",
			messageID, model, verdict.Action, verdict.Severity,
			len(verdict.Findings), auditReason))

	r.persistSessionPromptScan(verdict, sessionKey, messageID, elapsed)

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
		r.logStreamAction(sc.SessionKey, string(audit.ActionGatewaySessionError), sc.SessionKey,
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
		// Operator-facing stderr remains redacted. The canonical audit fact keeps
		// bounded source content so every destination can apply its own profile.
		scrubbedErr := redaction.MessageContent(ce.ErrorMessage)
		readLoopLogf("[bifrost] chat ERROR: %q session=%s runId=%s",
			scrubbedErr, ce.SessionKey, ce.RunID)
		r.logStreamAction(ce.SessionKey, string(audit.ActionGatewayChatError), ce.SessionKey,
			fmt.Sprintf("runId=%s error=%s", ce.RunID,
				truncate(stripLogInjectionRunes(ce.ErrorMessage), 200)))
		ectx := ContextWithSessionID(context.Background(), ce.SessionKey)
		emitError(ectx, "chat", "chat-error",
			fmt.Sprintf("runId=%s session=%s", ce.RunID, ce.SessionKey),
			fmt.Errorf("%s", redaction.ForSinkString(ce.ErrorMessage)))
		metricRuntime, _ := r.observabilityV8LifecycleRuntime().(hookLifecycleMetricV8Runtime)
		recordGatewayErrorV8(ectx, metricRuntime, "chat", "chat-error")
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

type agentStreamEnvelope struct {
	RunID            string          `json:"runId"`
	Stream           string          `json:"stream"`
	Data             json.RawMessage `json:"data,omitempty"`
	SessionKey       string          `json:"sessionKey"`
	SessionID        string          `json:"sessionId,omitempty"`
	AgentID          string          `json:"agentId,omitempty"`
	SpawnedBy        string          `json:"spawnedBy,omitempty"`
	ParentSessionKey string          `json:"parentSessionKey,omitempty"`
	ParentSessionID  string          `json:"parentSessionId,omitempty"`
	SpawnDepth       *int64          `json:"spawnDepth,omitempty"`
	Seq              int64           `json:"seq"`
	Ts               int64           `json:"ts"`
}

func (r *EventRouter) handleAgentEvent(evt EventFrame) {
	// OpenClaw sends two agent event formats:
	//   Format A (stream): {runId, stream:"lifecycle"|"tool"|"text", data:{phase,...}, sessionKey, seq, ts}
	//   Format B (legacy): {type, toolCall:{...}, toolResult:{...}, content}
	var streamEvt agentStreamEnvelope
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
	Phase            string          `json:"phase"`
	Name             string          `json:"name"`
	ToolCallID       string          `json:"toolCallId"`
	Args             json.RawMessage `json:"args,omitempty"`
	Error            string          `json:"error,omitempty"`
	StartedAt        int64           `json:"startedAt,omitempty"`
	EndedAt          int64           `json:"endedAt,omitempty"`
	IsError          bool            `json:"isError,omitempty"`
	Meta             string          `json:"meta,omitempty"`
	SessionID        string          `json:"sessionId,omitempty"`
	AgentID          string          `json:"agentId,omitempty"`
	SpawnedBy        string          `json:"spawnedBy,omitempty"`
	ParentSessionKey string          `json:"parentSessionKey,omitempty"`
	ParentSessionID  string          `json:"parentSessionId,omitempty"`
	SpawnDepth       *int64          `json:"spawnDepth,omitempty"`
}

func (r *EventRouter) handleAgentStreamEvent(se agentStreamEnvelope, evt EventFrame) {
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
			r.emitAgentRunObservationV8(se, data)

		case "error":
			// Agent lifecycle error messages are upstream LLM /
			// framework errors. Same leak profile as chat
			// errors — may quote user prompts or inner
			// model-graph state. Scrub for stderr, audit, and
			// the generated record's configured destination projection.
			scrubbedErr := redaction.MessageContent(data.Error)
			readLoopLogf("[bifrost] agent lifecycle ERROR runId=%s error=%q", se.RunID, scrubbedErr)
			r.emitAgentRunObservationV8(se, data)
			r.clearEventRouterModelContexts(se.SessionKey, se.RunID)

		case "end":
			readLoopLogf("[bifrost] agent lifecycle END runId=%s", se.RunID)
			r.emitAgentRunObservationV8(se, data)
			r.clearEventRouterModelContexts(se.SessionKey, se.RunID)

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
	toolStartedAt := time.Now().UTC()
	_, _, observabilityV8Authoritative := r.observabilityV8CapabilitiesSnapshot()

	toolObservation := generatedToolV8Observation{}
	if observabilityV8Authoritative {
		toolObservation = r.observeEventRouterToolCallV8(payload, toolStartedAt, false)
	} else {
		r.logStreamToolAction(payload.SessionID, string(audit.ActionGatewayToolCall), payload.Tool, payload.ID,
			fmt.Sprintf("status=%s args_length=%d", payload.Status, len(payload.Args)))
	}

	// Static block/allow list — checked before any pattern scanning.
	// Connector-scoped (@C/T) entries resolve before the bare global entry;
	// the connector is this sidecar's configured connector (see connectorName).
	if r.policy != nil {
		conn := r.connectorName()
		// MCP-server runtime block: a blocked MCP server (global or
		// --connector scoped) denies all of its tools at runtime. Checked
		// before the per-tool block/allow so a server-level block wins over a
		// tool-level allow; fails closed + loud on a store lookup error.
		if deny, server, reason := mcpServerRuntimeBlock(r.policy, payload.Tool, conn, ""); deny {
			fmt.Fprintf(os.Stderr, "[sidecar] BLOCKED mcp tool call: %s\n", reason)
			r.logStreamToolAction(payload.SessionID, "gateway-tool-call-blocked", payload.Tool, payload.ID,
				"reason=mcp-server-block server="+server)
			vctx := r.streamContext(payload.SessionID, audit.CorrelationEnvelope{
				DestinationApp: "builtin",
				ToolName:       payload.Tool,
				ToolID:         payload.ID,
			})
			emitVerdict(vctx, gatewaylog.StageBlockList, gatewaylog.DirectionPrompt, payload.Tool,
				"block", reason,
				gatewaylog.SeverityHigh, []string{"policy:block", "surface:mcp_server_block"}, 0)
			toolObservation.outcome = observability.OutcomeBlocked
			toolObservation.toolStatus = "blocked"
			toolObservation.dangerous = true
			toolObservation.finishedAt = time.Now().UTC()
			r.recordEventRouterGuardrailMetricsV8(vctx, eventRouterGuardrailMetricObservation{
				meta: toolObservation.meta, tool: payload.Tool, action: "block",
				severity: "HIGH", observedAt: toolObservation.finishedAt,
			})
			r.emitEventRouterToolTerminalV8(toolObservation)
			return
		}
		blocked, err := r.policy.IsToolBlockedForConnector(payload.Tool, conn)
		if err != nil {
			reason := logToolPolicyLookupError("sidecar", "block-list", payload.Tool, conn, err)
			r.logStreamToolAction(payload.SessionID, "gateway-tool-call-blocked", payload.Tool, payload.ID,
				"reason=tool-policy-lookup-error check=block-list")
			vctx := r.streamContext(payload.SessionID, audit.CorrelationEnvelope{
				DestinationApp: "builtin",
				ToolName:       payload.Tool,
				ToolID:         payload.ID,
			})
			emitVerdict(vctx, gatewaylog.StageBlockList, gatewaylog.DirectionPrompt, payload.Tool,
				"block", reason,
				gatewaylog.SeverityHigh, []string{"policy:error", "surface:tool_call", toolPolicyLookupErrorFinding}, 0)
			toolObservation.outcome = observability.OutcomeRejected
			toolObservation.toolStatus = "failed"
			toolObservation.errorType = "policy_lookup_failed"
			toolObservation.technicalFailure = true
			toolObservation.finishedAt = time.Now().UTC()
			r.recordEventRouterGuardrailMetricsV8(vctx, eventRouterGuardrailMetricObservation{
				meta: toolObservation.meta, tool: payload.Tool, action: "block",
				severity: "HIGH", observedAt: toolObservation.finishedAt,
			})
			r.emitEventRouterToolTerminalV8(toolObservation)
			return
		}
		if blocked {
			fmt.Fprintf(os.Stderr, "[sidecar] BLOCKED tool call: %q is on the static block list\n", payload.Tool)
			r.logStreamToolAction(payload.SessionID, "gateway-tool-call-blocked", payload.Tool, payload.ID, "reason=static-block-list")
			vctx := r.streamContext(payload.SessionID, audit.CorrelationEnvelope{
				DestinationApp: "builtin",
				ToolName:       payload.Tool,
				ToolID:         payload.ID,
			})
			emitVerdict(vctx, gatewaylog.StageBlockList, gatewaylog.DirectionPrompt, payload.Tool,
				"block", "static block list",
				gatewaylog.SeverityHigh, []string{"policy:block", "surface:tool_call"}, 0)
			toolObservation.outcome = observability.OutcomeBlocked
			toolObservation.toolStatus = "blocked"
			toolObservation.dangerous = true
			toolObservation.finishedAt = time.Now().UTC()
			r.recordEventRouterGuardrailMetricsV8(vctx, eventRouterGuardrailMetricObservation{
				meta: toolObservation.meta, tool: payload.Tool, action: "block",
				severity: "HIGH", observedAt: toolObservation.finishedAt,
			})
			r.emitEventRouterToolTerminalV8(toolObservation)
			return
		}
		// An explicit allow skips the scan gate: no rule scan, no judge. This
		// lane runs no CodeGuard, so the allow is a full bypass here — the
		// CodeGuard-on-write guarantee (D2) lives on the hook/inspect lane.
		allowed, err := r.policy.IsToolAllowedForConnector(payload.Tool, conn)
		if err != nil {
			reason := logToolPolicyLookupError("sidecar", "allow-list", payload.Tool, conn, err)
			r.logStreamToolAction(payload.SessionID, "gateway-tool-call-blocked", payload.Tool, payload.ID,
				"reason=tool-policy-lookup-error check=allow-list")
			vctx := r.streamContext(payload.SessionID, audit.CorrelationEnvelope{
				DestinationApp: "builtin",
				ToolName:       payload.Tool,
				ToolID:         payload.ID,
			})
			emitVerdict(vctx, gatewaylog.StageBlockList, gatewaylog.DirectionPrompt, payload.Tool,
				"block", reason,
				gatewaylog.SeverityHigh, []string{"policy:error", "surface:tool_call", toolPolicyLookupErrorFinding}, 0)
			toolObservation.outcome = observability.OutcomeRejected
			toolObservation.toolStatus = "failed"
			toolObservation.errorType = "policy_lookup_failed"
			toolObservation.technicalFailure = true
			toolObservation.finishedAt = time.Now().UTC()
			r.recordEventRouterGuardrailMetricsV8(vctx, eventRouterGuardrailMetricObservation{
				meta: toolObservation.meta, tool: payload.Tool, action: "block",
				severity: "HIGH", observedAt: toolObservation.finishedAt,
			})
			r.emitEventRouterToolTerminalV8(toolObservation)
			return
		}
		if allowed {
			// The allow-list disposition is a gateway-tool-call occurrence with
			// an explicit allow reason. "gateway-tool-call-allowed" was never a
			// registered audit action, so the strict v8 runtime correctly rejected
			// it instead of persisting an unclassified compatibility record.
			r.logStreamToolAction(payload.SessionID, string(audit.ActionGatewayToolCall), payload.Tool, payload.ID, "reason=allow-list")
			r.recordEventRouterGuardrailMetricsV8(context.Background(), eventRouterGuardrailMetricObservation{
				meta: toolObservation.meta, tool: payload.Tool, action: "allow",
				severity: "NONE", observedAt: time.Now().UTC(),
			})
			r.rememberEventRouterToolCallV8(toolObservation)
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
		r.logStreamToolAction(payload.SessionID, string(audit.ActionGatewayToolCallFlagged), payload.Tool, payload.ID,
			fmt.Sprintf("reason=%s severity=%s confidence=%.2f",
				findings[0].RuleID, findings[0].Severity, findings[0].Confidence))
		fmt.Fprintf(os.Stderr, "[sidecar] FLAGGED tool call: %s (%s)\n", payload.Tool, findings[0].Title)

		vctx := r.streamContext(payload.SessionID, audit.CorrelationEnvelope{
			DestinationApp: "builtin", ToolName: payload.Tool, ToolID: payload.ID,
		})
		emitVerdict(vctx, gatewaylog.StageRegex, gatewaylog.DirectionToolCall, "",
			"alert", findings[0].Title, deriveSeverity(severity), []string{flaggedPattern}, 0,
			emitVerdictExtras{RuleIDs: []string{flaggedPattern}})
		r.recordEventRouterGuardrailMetricsV8(vctx, eventRouterGuardrailMetricObservation{
			meta: toolObservation.meta, tool: payload.Tool, action: "alert", severity: severity,
			alertType: "tool-call-flagged", alertSource: "tool-inspect", observedAt: time.Now().UTC(),
		})
	}

	// LLM judge — runs tool injection detection on arguments asynchronously.
	// The semaphore bounds concurrent judge executions while queued goroutines
	// wait for a slot instead of dropping inspection entirely.
	if r.judge != nil && len(payload.Args) > 0 {
		go func(tool, sessionID, toolID string, meta llmEventMeta, args json.RawMessage) {
			r.judgeSem <- struct{}{}
			defer func() { <-r.judgeSem }()
			ctx, cancel := context.WithTimeout(context.Background(), 60*time.Second)
			defer cancel()
			verdict := r.judge.RunToolJudge(ctx, tool, string(args))
			if verdict.Severity != "NONE" {
				// Keep stderr redacted, but retain the source reason for the v8
				// route-specific redaction boundary.
				fmt.Fprintf(os.Stderr, "[sidecar] LLM JUDGE flagged tool call: %s severity=%s %s\n",
					tool, verdict.Severity, redaction.Reason(verdict.Reason))
				r.logStreamToolAction(sessionID, string(audit.ActionGatewayToolCallJudgeFlagged), tool, toolID,
					fmt.Sprintf("severity=%s findings=%d reason=%s",
						verdict.Severity, len(verdict.Findings),
						stripLogInjectionRunes(verdict.Reason)))
				r.recordEventRouterGuardrailMetricsV8(ctx, eventRouterGuardrailMetricObservation{
					meta: meta, tool: tool, action: verdict.Action,
					severity: verdict.Severity, observedAt: time.Now().UTC(),
				})
			}
		}(payload.Tool, payload.SessionID, payload.ID, toolObservation.meta, payload.Args)
	}

	toolObservation.dangerous = dangerous
	r.rememberEventRouterToolCallV8(toolObservation)
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

	_, _, observabilityV8Authoritative := r.observabilityV8CapabilitiesSnapshot()
	if observabilityV8Authoritative {
		observation := r.completeEventRouterToolCallV8(payload, time.Now().UTC())
		r.emitEventRouterToolTerminalV8(observation)
	} else {
		r.logStreamToolAction(payload.SessionID, string(audit.ActionGatewayToolResult), payload.Tool, payload.ID,
			fmt.Sprintf("exit_code=%d output_len=%d", exitCode, len(payload.Output)))
	}

	r.inspectToolResult(payload)
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
	r.logStreamToolAction(payload.SessionID, string(audit.ActionToolResultPIIAlert), payload.Tool, payload.ID,
		fmt.Sprintf("severity=%s entities=%d findings=%d reason=%s",
			verdict.Severity, entityCount, len(verdict.Findings),
			stripLogInjectionRunes(verdict.Reason)))
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
	approvalStartedAt := time.Now().UTC()
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
	correlation := payload.CorrelationContext()
	approval := eventRouterApprovalObservation{
		id: payload.ID, sessionKey: correlation.SessionKey, sessionID: correlation.SessionID,
		runID: correlation.RunID, requestID: correlation.RequestID, turnID: correlation.TurnID,
		operationID: correlation.OperationID, agentID: correlation.AgentID, agentName: correlation.AgentName,
		agentType: correlation.AgentType, agentInstanceID: correlation.AgentInstanceID,
		rootAgentID: correlation.RootAgentID, parentAgentID: correlation.ParentAgentID,
		rootSessionID: correlation.RootSessionID, parentSessionID: correlation.ParentSessionID,
		lineageProvenance: correlation.LineageProvenance, lifecycleID: correlation.LifecycleID,
		executionID: correlation.ExecutionID, phase: correlation.Phase,
		userID: correlation.UserID, userName: correlation.UserName,
		policyID: correlation.PolicyID, policyVersion: correlation.PolicyVersion,
		destinationApp: correlation.DestinationApp, toolID: correlation.ToolID,
		toolName: correlation.ToolName, toolType: correlation.ToolType,
		toolCallID: correlation.ToolCallID, toolProvider: correlation.ToolProvider,
		toolSkillKey: correlation.ToolSkillKey,
		commandName:  cmdName, command: rawCmd, argv: append([]string(nil), argv...), cwd: cwd,
		startedAt: approvalStartedAt,
	}
	if correlation.Depth != nil {
		approval.depth, approval.depthSet = *correlation.Depth, true
	}
	if correlation.Sequence != nil {
		approval.sequence, approval.sequenceSet = *correlation.Sequence, true
	}
	approval = r.enrichEventRouterApprovalTopology(approval)
	approvalContext := r.getToolParentCtx(approval.sessionKey, approval.runID)
	_ = r.emitApprovalRequestedV8(approvalContext, approval)

	// a sparse approval frame with no SystemRunPlan,
	// nested `request`, raw command text, OR argv carries no
	// command context for the dangerous-pattern scanner to inspect.
	// Pre-fix the autoApprove branch treated that as a "safe
	// command" and sent allow-once back to the peer without ever
	// looking at a command. A malicious or compromised runtime that
	// can shape the approval event can omit the command context and
	// bypass every dangerous-command check, so we fail CLOSED on an
	// empty context regardless of autoApprove.
	if rawCmd == "" && len(argv) == 0 {
		fmt.Fprintf(os.Stderr,
			"[sidecar] DENIED exec approval: id=%s reason=empty-command-context\n",
			payload.ID)
		approval.result = "denied"
		approval.actorType = "policy"
		approval.reason = "empty-command-context"
		approval.dangerous = true
		approval.finishedAt = time.Now().UTC()
		_ = r.emitApprovalResolutionV8(approvalContext, approval)
		r.resolveApprovalAsync(payload.ID, false,
			"defenseclaw: approval request has no command context")
		return
	}

	fmt.Fprintf(os.Stderr, "[sidecar] exec.approval.requested: id=%s command=%s argc=%d cwd=%s\n",
		payload.ID, cmdName, len(argv), cwd)

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
		vctx := r.streamContext(approval.sessionKey, audit.CorrelationEnvelope{
			DestinationApp: "builtin",
			ToolName:       cmdName,
			ToolID:         payload.ID,
		})
		emitVerdict(vctx, gatewaylog.StageApproval, gatewaylog.DirectionPrompt, cmdName,
			"block", fmt.Sprintf("%s: %s", topFinding.RuleID, topFinding.Title),
			deriveSeverity(topFinding.Severity), []string{"approval:denied", "surface:exec"}, 0)
		fmt.Fprintf(os.Stderr, "[sidecar] DENIED exec approval: %s (%s)\n", cmdName, topFinding.Title)

		approval.result = "denied"
		approval.actorType = "policy"
		approval.reason = topFinding.Title
		approval.ruleIDs = []string{topFinding.RuleID}
		approval.dangerous = true
		approval.finishedAt = time.Now().UTC()
		_ = r.emitApprovalResolutionV8(approvalContext, approval)

		r.resolveApprovalAsync(payload.ID, false, "defenseclaw: command matched dangerous pattern")
		return
	}

	if r.autoApprove {
		fmt.Fprintf(os.Stderr, "[sidecar] AUTO-APPROVED exec: %s\n", cmdName)
		approval.result = "approved"
		approval.actorType = "automatic"
		approval.reason = "auto-approved safe command"
		approval.finishedAt = time.Now().UTC()
		_ = r.emitApprovalResolutionV8(approvalContext, approval)

		r.resolveApprovalAsync(payload.ID, true, "defenseclaw: auto-approved safe command")
		return
	}

	fmt.Fprintf(os.Stderr, "[sidecar] PENDING exec approval: %s (awaiting manual approval)\n", cmdName)
	approval.reason = "awaiting manual approval"
	_ = r.emitApprovalPendingMetricsV8(approvalContext, approval)
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
