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
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const (
	llmEventUserIDHeader   = "X-DefenseClaw-User-Id"
	llmEventUserNameHeader = "X-DefenseClaw-User-Name"
	maxLLMEventUserLength  = 256
)

type llmEventMeta struct {
	Source             string
	Provider           string
	Model              string
	SessionID          string
	RequestID          string
	RunID              string
	TurnID             string
	MessageID          string
	SourceEventID      string
	SourceSequence     string
	PromptID           string
	ResponseID         string
	ResponseIDReported bool
	AgentID            string
	AgentName          string
	AgentType          string
	RootAgentID        string
	ParentAgentID      string
	// ParentAgentReported distinguishes an upstream-native parent identity from
	// the deterministic placeholder synthesized for parent-session-only hooks.
	ParentAgentReported bool
	// ParentLineageResolved marks a fallback parent verified against retained
	// live state. Its topology remains inferred, but is newer authority than a
	// self-root placeholder observed before the parent lifecycle was known.
	ParentLineageResolved bool
	// LineageProvenance distinguishes connector-reported topology from
	// topology inferred by the hook bridge. It is empty only when neither
	// claim can be made truthfully.
	LineageProvenance string
	RootSessionID     string
	ParentSessionID   string
	LifecycleID       string
	ExecutionID       string
	LifecycleEvent    string
	LifecycleState    string
	LifecycleOutcome  string
	LifecycleDedupe   string
	Phase             string
	PreviousPhase     string
	OperationID       string
	Sequence          int64
	AgentDepth        int
	ReportedCostUSD   float64
	ReportedCost      bool
	ReportedCostSum   bool
	SessionSource     string
	SessionResumed    bool
	UserID            string
	UserName          string
	PolicyID          string
	DestinationApp    string
	ToolName          string
	ToolID            string
	ToolIDReported    bool
	FinishReasons     []string
	// TraceEventID scopes the short OTel anchor used for one hook delivery.
	// Session and agent identifiers remain stable across deliveries, but a
	// backend must not be asked to append children to a trace it has already
	// indexed and finalized.
	TraceEventID string
}

func (m llmEventMeta) reportedResponseID() string {
	if m.ResponseIDReported {
		return m.ResponseID
	}
	return ""
}

func (m llmEventMeta) reportedToolID() string {
	if m.ToolIDReported {
		return m.ToolID
	}
	return ""
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

func (a *APIServer) emitLLMPromptEventV8(ctx context.Context, meta llmEventMeta, prompt string, rawRequestBody []byte) string {
	if a == nil {
		return ""
	}
	return emitLLMPromptEventV8WithEmitter(ctx, a.observabilityV8RuntimeEmitter(), meta, prompt, rawRequestBody)
}

func emitLLMPromptEventV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	prompt string,
	rawRequestBody []byte,
) string {
	promptID, _, _ := emitLLMPromptEventV8WithEmitterStatus(ctx, emitter, meta, prompt, rawRequestBody)
	return promptID
}

func emitLLMPromptEventV8WithEmitterStatus(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	prompt string,
	rawRequestBody []byte,
) (string, bool, error) {
	if strings.TrimSpace(prompt) == "" && len(rawRequestBody) == 0 {
		return "", false, nil
	}
	if meta.PromptID == "" {
		meta.PromptID = stableLLMEventID("prompt", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID)
	}
	content := prompt
	if strings.TrimSpace(content) == "" {
		content = string(rawRequestBody)
	}
	persisted, err := emitHookModelRequestLogV8WithEmitter(ctx, emitter, meta, content)
	return meta.PromptID, persisted, err
}

func (a *APIServer) emitLLMResponseEventV8(
	ctx context.Context,
	meta llmEventMeta,
	response, rawResponseBody string,
	finishReasons []string,
) string {
	if a == nil {
		return ""
	}
	return emitLLMResponseEventV8WithEmitter(
		ctx, a.observabilityV8RuntimeEmitter(), meta, response, rawResponseBody, finishReasons,
	)
}

func emitLLMResponseEventV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	response, rawResponseBody string,
	finishReasons []string,
) string {
	responseID, _, _ := emitLLMResponseEventV8WithEmitterStatus(
		ctx, emitter, meta, response, rawResponseBody, finishReasons,
	)
	return responseID
}

func emitLLMResponseEventV8WithEmitterStatus(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	response, rawResponseBody string,
	finishReasons []string,
) (string, bool, error) {
	if strings.TrimSpace(response) == "" && rawResponseBody == "" && len(finishReasons) == 0 {
		return "", false, nil
	}
	if meta.ResponseID == "" {
		meta.ResponseID = stableLLMEventID("response", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID, meta.PromptID)
	}
	content := response
	if strings.TrimSpace(content) == "" {
		content = rawResponseBody
	}
	persisted, err := emitHookModelResponseLogV8WithEmitter(ctx, emitter, meta, content, finishReasons)
	return meta.ResponseID, persisted, err
}

func (p *GuardrailProxy) emitLLMPromptEventV8(
	ctx context.Context,
	meta llmEventMeta,
	prompt string,
	rawRequestBody []byte,
) string {
	emitter, _ := p.observabilityV8TraceRuntime().(sidecarRuntimeEmitter)
	if meta.PromptID == "" {
		meta.PromptID = stableLLMEventID("prompt", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID)
	}
	if spec, ok := p.proxyCorrelationSpecV8(); ok && p.store != nil && emitter != nil {
		correlated, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
			store: p.store, emitter: emitter, spec: spec,
			rail: audit.CorrelationRailProxy, surface: connector.CorrelationSurfaceProxy,
			lifecycle: connector.CorrelationLifecycleModelStart, meta: meta, rawPayload: llmRailRawPayload(rawRequestBody, prompt),
		})
		if err != nil {
			readLoopLogf("[correlation] proxy model-start persistence failed; telemetry emission skipped")
			return meta.PromptID
		}
		if correlated.suppressEmission {
			return correlated.meta.PromptID
		}
		promptID, persisted, emitErr := emitLLMPromptEventV8WithEmitterStatus(
			correlated.ctx, emitter, correlated.meta, prompt, rawRequestBody,
		)
		if err := finalizeLLMRailCanonicalEmission(
			correlated.ctx, p.store, correlated.receipt, persisted, emitErr,
		); err != nil {
			readLoopLogf("[correlation] proxy model-start canonical persistence incomplete")
		}
		return promptID
	}
	return emitLLMPromptEventV8WithEmitter(ctx, emitter, meta, prompt, rawRequestBody)
}

func (p *GuardrailProxy) emitLLMResponseEventV8(
	ctx context.Context,
	meta llmEventMeta,
	response, rawResponseBody string,
	finishReasons []string,
) string {
	emitter, _ := p.observabilityV8TraceRuntime().(sidecarRuntimeEmitter)
	if meta.ResponseID == "" {
		meta.ResponseID = stableLLMEventID("response", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID, meta.PromptID)
	}
	if spec, ok := p.proxyCorrelationSpecV8(); ok && p.store != nil && emitter != nil {
		correlated, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
			store: p.store, emitter: emitter, spec: spec,
			rail: audit.CorrelationRailProxy, surface: connector.CorrelationSurfaceProxy,
			lifecycle: connector.CorrelationLifecycleModelEnd, meta: meta,
			rawPayload: []byte(firstNonEmpty(rawResponseBody, response)),
		})
		if err != nil {
			readLoopLogf("[correlation] proxy model-end persistence failed; telemetry emission skipped")
			return meta.ResponseID
		}
		if correlated.suppressEmission {
			return correlated.meta.ResponseID
		}
		responseID, persisted, emitErr := emitLLMResponseEventV8WithEmitterStatus(
			correlated.ctx, emitter, correlated.meta, response, rawResponseBody, finishReasons,
		)
		if err := finalizeLLMRailCanonicalEmission(
			correlated.ctx, p.store, correlated.receipt, persisted, emitErr,
		); err != nil {
			readLoopLogf("[correlation] proxy model-end canonical persistence incomplete")
		}
		return responseID
	}
	return emitLLMResponseEventV8WithEmitter(ctx, emitter, meta, response, rawResponseBody, finishReasons)
}

func (r *EventRouter) emitLLMPromptEventV8(
	ctx context.Context,
	meta llmEventMeta,
	prompt string,
	rawRequestBody []byte,
) string {
	emitter := r.observabilityV8RuntimeEmitter()
	if meta.PromptID == "" {
		meta.PromptID = stableLLMEventID("prompt", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID)
	}
	if r.store != nil && emitter != nil {
		spec, ok := r.streamCorrelationSpecV8()
		if !ok {
			readLoopLogf("[correlation] stream model-start profile unavailable; telemetry emission skipped")
			return meta.PromptID
		}
		correlated, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
			store: r.store, emitter: emitter, spec: spec,
			rail: audit.CorrelationRailStream, surface: connector.CorrelationSurfaceStream,
			lifecycle: connector.CorrelationLifecycleModelStart, meta: meta, rawPayload: llmRailRawPayload(rawRequestBody, prompt),
		})
		if err != nil {
			readLoopLogf("[correlation] stream model-start persistence failed; telemetry emission skipped")
			return meta.PromptID
		}
		if correlated.suppressEmission {
			return correlated.meta.PromptID
		}
		promptID, persisted, emitErr := emitLLMPromptEventV8WithEmitterStatus(
			correlated.ctx, emitter, correlated.meta, prompt, rawRequestBody,
		)
		if err := finalizeLLMRailCanonicalEmission(
			correlated.ctx, r.store, correlated.receipt, persisted, emitErr,
		); err != nil {
			readLoopLogf("[correlation] stream model-start canonical persistence incomplete")
		}
		return promptID
	}
	return emitLLMPromptEventV8WithEmitter(ctx, emitter, meta, prompt, rawRequestBody)
}

func (r *EventRouter) emitLLMResponseEventV8(
	ctx context.Context,
	meta llmEventMeta,
	response, rawResponseBody string,
	finishReasons []string,
) string {
	responseID, _, _, _ := r.emitLLMResponseEventV8Correlated(ctx, meta, response, rawResponseBody, finishReasons)
	return responseID
}

func (r *EventRouter) emitLLMResponseEventV8Correlated(
	ctx context.Context,
	meta llmEventMeta,
	response, rawResponseBody string,
	finishReasons []string,
) (string, context.Context, llmEventMeta, bool) {
	emitter := r.observabilityV8RuntimeEmitter()
	if meta.ResponseID == "" {
		meta.ResponseID = stableLLMEventID("response", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID, meta.PromptID)
	}
	if r.store != nil && emitter != nil {
		spec, ok := r.streamCorrelationSpecV8()
		if !ok {
			readLoopLogf("[correlation] stream model-end profile unavailable; telemetry emission skipped")
			return meta.ResponseID, ctx, meta, false
		}
		correlated, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
			store: r.store, emitter: emitter, spec: spec,
			rail: audit.CorrelationRailStream, surface: connector.CorrelationSurfaceStream,
			lifecycle: connector.CorrelationLifecycleModelEnd, meta: meta,
			rawPayload: []byte(firstNonEmpty(rawResponseBody, response)),
		})
		if err != nil {
			readLoopLogf("[correlation] stream model-end persistence failed; telemetry emission skipped")
			return meta.ResponseID, ctx, meta, false
		}
		if correlated.suppressEmission {
			return correlated.meta.ResponseID, correlated.ctx, correlated.meta, false
		}
		responseID, persisted, emitErr := emitLLMResponseEventV8WithEmitterStatus(
			correlated.ctx, emitter, correlated.meta, response, rawResponseBody, finishReasons,
		)
		if err := finalizeLLMRailCanonicalEmission(
			correlated.ctx, r.store, correlated.receipt, persisted, emitErr,
		); err != nil {
			readLoopLogf("[correlation] stream model-end canonical persistence incomplete")
		}
		return responseID, correlated.ctx, correlated.meta, true
	}
	return emitLLMResponseEventV8WithEmitter(ctx, emitter, meta, response, rawResponseBody, finishReasons), ctx, meta, true
}

func (p *GuardrailProxy) proxyCorrelationSpecV8() (connector.CorrelationSpec, bool) {
	if p == nil || p.connector == nil {
		return connector.CorrelationSpec{}, false
	}
	var spec connector.CorrelationSpec
	if provider, ok := p.connector.(connector.CorrelationSpecProvider); ok {
		spec = provider.CorrelationSpec(p.setupOpts)
	} else {
		var found bool
		spec, found = connector.CorrelationSpecForConnector(p.connectorName(), "")
		if !found {
			return connector.CorrelationSpec{}, false
		}
	}
	if err := spec.Validate(); err != nil || !correlationSpecDeclaresSurface(spec, connector.CorrelationSurfaceProxy) {
		return connector.CorrelationSpec{}, false
	}
	return spec, true
}

func (r *EventRouter) streamCorrelationSpecV8() (connector.CorrelationSpec, bool) {
	if r == nil {
		return connector.CorrelationSpec{}, false
	}
	spec, ok := connector.CorrelationSpecForConnector("openclaw", "")
	if !ok || spec.Validate() != nil || !correlationSpecDeclaresSurface(spec, connector.CorrelationSurfaceStream) {
		return connector.CorrelationSpec{}, false
	}
	return spec, true
}

func llmRailRawPayload(raw []byte, content string) []byte {
	if len(raw) != 0 {
		return raw
	}
	return []byte(content)
}

func (a *APIServer) emitToolInvocationEventV8(
	ctx context.Context,
	meta llmEventMeta,
	phase, tool, input, output string,
	exitCode *int,
) {
	if strings.TrimSpace(tool) == "" || strings.TrimSpace(phase) == "" {
		return
	}
	if meta.ToolID == "" {
		meta.ToolID = stableLLMEventID("tool", meta.Source, meta.SessionID, meta.TurnID, meta.RequestID, tool, phase)
	}
	a.emitHookToolLogV8(ctx, meta, phase, tool, input, output, exitCode)
}

// inferAndEmitHookSpawnStart bridges Codex hook versions that omit
// SubagentStart. The synthetic transition is fully prepared and retained before
// the original first child event continues through the normal pipeline, so its
// tool/model/message records inherit the same execution and recursive lineage.
func (a *APIServer) inferAndEmitHookSpawnStart(
	ctx context.Context,
	meta llmEventMeta,
) llmEventMeta {
	if a == nil {
		return meta
	}
	// Serialize only the unseen-child inference boundary. Once the start is
	// retained, concurrent deliveries may proceed normally and will merge the
	// same execution/lineage instead of racing to create a self-root placeholder.
	a.hookSpawnLineageMu.Lock()
	defer a.hookSpawnLineageMu.Unlock()
	meta, start, inferred := a.inferHookSpawnFromFirstEvent(meta)
	if !inferred {
		return a.clearUnresolvedHookSpawnFallbackAt(meta, time.Now().UTC())
	}
	start = a.beginHookExecution(start)
	start.TraceEventID = hookTraceEventID(ctx, start)
	start = finalizeHookEventCorrelation(start, nil)
	start, recordLifecycle := a.prepareHookLifecycleTransition(start)
	a.rememberHookSessionState(ctx, start)
	lifecycleLogMeta := start
	lifecycleContext := ctx
	if recordLifecycle {
		start = a.normalizeHookReportedCost(start)
		lifecycleContext = a.emitHookLifecycleTransitionSpan(ctx, start)
	}
	a.emitHookLifecycleEvent(lifecycleContext, lifecycleLogMeta)
	if recordLifecycle {
		a.recordHookLifecycleMetric(lifecycleContext, start)
	}
	return meta
}

func (p *GuardrailProxy) emitOpenAIToolCallEvents(ctx context.Context, meta llmEventMeta, toolCallsJSON json.RawMessage) {
	if len(toolCallsJSON) == 0 {
		return
	}
	emitter, _ := p.observabilityV8TraceRuntime().(sidecarRuntimeEmitter)
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
		p.emitProxyToolStartV8(ctx, emitter, fallback, "unknown", string(toolCallsJSON))
		return
	}
	for i, tc := range toolCalls {
		toolName := firstNonEmpty(tc.Function.Name, tc.Type, "unknown")
		callMeta := meta
		callMeta.ToolName = toolName
		callMeta.ToolID = firstNonEmpty(tc.ID, stableLLMEventID("tool", meta.Source, meta.SessionID, meta.RequestID, meta.Model, intString(i)))
		callMeta.ToolIDReported = strings.TrimSpace(tc.ID) != ""
		p.emitProxyToolStartV8(ctx, emitter, callMeta, toolName, tc.Function.Arguments)
	}
}

func (p *GuardrailProxy) emitProxyToolStartV8(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	meta llmEventMeta,
	toolName string,
	arguments string,
) {
	if p == nil {
		return
	}
	// A missing store is a supported reduced/test configuration. Production
	// has a store and a validated proxy profile; once both are available the
	// occurrence must commit before any log is exported.
	if p.store == nil || emitter == nil {
		emitHookToolLogV8WithEmitter(ctx, emitter, meta, "call", toolName, arguments, "", nil)
		return
	}
	spec, ok := p.proxyCorrelationSpecV8()
	if !ok {
		// Connectors without a proxy correlation surface retain their previous
		// telemetry behavior. A connector declaring proxy correlation is
		// validated by proxyCorrelationSpecV8 and takes the fail-closed path
		// below on any persistence failure.
		emitHookToolLogV8WithEmitter(ctx, emitter, meta, "call", toolName, arguments, "", nil)
		return
	}
	correlated, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
		store: p.store, emitter: emitter, spec: spec,
		rail: audit.CorrelationRailProxy, surface: connector.CorrelationSurfaceProxy,
		lifecycle: connector.CorrelationLifecycleToolStart, meta: meta,
		rawPayload: []byte(arguments),
	})
	if err != nil {
		readLoopLogf("[correlation] proxy tool-start persistence failed; telemetry emission skipped")
		return
	}
	if correlated.suppressEmission {
		return
	}
	persisted, emitErr := emitHookToolLogV8WithEmitter(
		correlated.ctx, emitter, correlated.meta, "call", toolName, arguments, "", nil,
	)
	if err := finalizeLLMRailCanonicalEmission(
		correlated.ctx, p.store, correlated.receipt, persisted, emitErr,
	); err != nil {
		readLoopLogf("[correlation] proxy tool-start canonical persistence incomplete")
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
	meta = a.applyHookSpawnIntentLineage(meta, req.Payload)
	meta.FinishReasons = append([]string(nil), codexNotifyFinishReasons(req.Payload)...)
	meta = a.beginHookExecution(meta)
	meta = a.restoreHookSessionLifecycle(ctx, meta)
	meta = a.inferAndEmitHookSpawnStart(ctx, meta)
	meta = a.reconcileHookParent(meta)
	meta = a.mergeHookSessionLifecycle(meta)
	meta.TraceEventID = hookTraceEventID(ctx, meta)
	meta = finalizeHookEventCorrelation(meta, req.Payload)
	meta, recordLifecycle := a.prepareHookLifecycleTransition(meta)
	a.rememberHookSessionState(ctx, meta)
	lifecycleLogMeta := meta
	lifecycleContext := ctx
	if recordLifecycle {
		meta = a.normalizeHookReportedCost(meta)
		lifecycleContext = a.emitHookLifecycleTransitionSpan(ctx, meta)
	}
	a.emitHookLifecycleEvent(lifecycleContext, lifecycleLogMeta)
	if recordLifecycle {
		a.recordHookLifecycleMetric(lifecycleContext, meta)
	}
	a.rememberHookLLMSpanUsage(meta, extractHookPayloadTokenUsage(req.Payload))
	switch req.HookEventName {
	case "SessionStart":
		a.rememberHookSessionState(ctx, meta)
	case "UserPromptSubmit":
		meta.PromptID = hookPromptID("codex", req.SessionID, req.TurnID, req.Prompt, rawPayload)
		promptID := a.emitLLMPromptEventV8(ctx, meta, req.Prompt, rawPayload)
		a.rememberHookPromptID("codex", req.SessionID, req.TurnID, promptID)
		a.rememberHookLLMSpanPrompt(meta, req.Prompt)
		a.rememberHookSessionState(ctx, meta)
	case "SubagentStart":
		prompt := firstString(req.Payload, "task", "prompt", "description")
		if prompt == "" {
			prompt = hookLifecycleContent(meta, "subagent_input_not_reported")
		}
		meta.PromptID = hookPromptID("codex", req.SessionID, req.TurnID, prompt, rawPayload)
		a.emitLLMPromptEventV8(ctx, meta, prompt, rawPayload)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.rememberHookSessionState(ctx, meta)
	case "PreToolUse", "PermissionRequest":
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), codexToolName(req))
		a.emitToolInvocationEventV8(ctx, meta, "call", codexToolName(req), stringFromJSONRaw(codexToolArgs(req)), "", nil)
		a.rememberHookSessionState(ctx, meta)
		a.rememberHookSpawnIntent(meta, codexToolName(req), hookSpawnIntentRequested, stringFromJSONRaw(codexToolArgs(req)))
		a.rememberHookToolInvocation(meta, codexToolName(req), stringFromJSONRaw(codexToolArgs(req)))
	case "PostToolUse":
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), codexToolName(req))
		arguments := stringFromJSONRaw(codexToolArgs(req))
		response := codexToolResponseString(req.ToolResponse)
		a.rememberHookSpawnIntent(meta, codexToolName(req), hookSpawnIntentCompleted, arguments, response)
		completionContext := a.emitHookToolSpan(ctx, meta, codexToolName(req), arguments, response, nil)
		a.emitToolInvocationEventV8(completionContext, meta, "result", codexToolName(req), "", response, nil)
	case "Stop", "SubagentStop":
		if strings.TrimSpace(req.LastAssistantMessage) == "" {
			return
		}
		meta.PromptID = firstNonEmpty(a.lastHookPromptIDForTurn("codex", req.SessionID, req.TurnID), a.lastHookPromptID("codex", req.SessionID), promptIDForTurn("codex", req.SessionID, req.TurnID))
		meta.ResponseID = stableLLMEventID("response", "codex", req.SessionID, req.TurnID)
		completionContext := a.emitHookLLMSpan(ctx, meta, req.LastAssistantMessage)
		a.emitLLMResponseEventV8(completionContext, meta, req.LastAssistantMessage, string(rawPayload), nil)
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
//     pre_run_command, ...)    → generated tool.invocation.requested log
//   - result-like    (PostToolUse, AfterTool, postToolUseFailure,
//     post_tool_call, after_*, ...)
//     → generated tool.invocation.completed log
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
	meta = a.applyHookSpawnIntentLineage(meta, req.Payload)
	meta.FinishReasons = append([]string(nil), codexNotifyFinishReasons(req.Payload)...)
	meta = a.beginHookExecution(meta)
	meta = a.restoreHookSessionLifecycle(ctx, meta)
	meta = a.inferAndEmitHookSpawnStart(ctx, meta)
	meta = a.reconcileHookParent(meta)
	meta = a.mergeHookSessionLifecycle(meta)
	meta.TraceEventID = hookTraceEventID(ctx, meta)
	meta = finalizeHookEventCorrelation(meta, req.Payload)
	meta, recordLifecycle := a.prepareHookLifecycleTransition(meta)
	a.rememberHookSessionState(ctx, meta)
	lifecycleLogMeta := meta
	lifecycleContext := ctx
	if recordLifecycle {
		meta = a.normalizeHookReportedCost(meta)
		lifecycleContext = a.emitHookLifecycleTransitionSpan(ctx, meta)
	}
	a.emitHookLifecycleEvent(lifecycleContext, lifecycleLogMeta)
	if recordLifecycle {
		a.recordHookLifecycleMetric(lifecycleContext, meta)
	}
	a.rememberHookLLMSpanUsage(meta, extractHookPayloadTokenUsage(req.Payload))
	if meta.LifecycleEvent == "session_start" {
		a.rememberHookSessionState(ctx, meta)
		return
	}
	switch {
	case isPromptLikeEvent(req.HookEventName):
		prompt := req.Content
		meta.PromptID = hookPromptID(source, req.SessionID, req.TurnID, prompt, rawPayload)
		promptID := a.emitLLMPromptEventV8(ctx, meta, prompt, rawPayload)
		a.rememberHookPromptID(source, req.SessionID, req.TurnID, promptID)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.rememberHookSessionState(ctx, meta)
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
		completionContext := a.emitHookLLMSpan(ctx, meta, response)
		a.emitLLMResponseEventV8(completionContext, meta, response, string(rawPayload), nil)
	case isGenericToolInspectionEvent(req.HookEventName):
		meta.PromptID = firstNonEmpty(
			a.lastHookPromptIDForTurn(source, req.SessionID, req.TurnID),
			a.lastHookPromptID(source, req.SessionID),
			promptIDForTurn(source, req.SessionID, req.TurnID),
		)
		meta.ToolID = firstString(req.Payload, "tool_use_id", "toolUseId", "tool_call_id", "toolCallId")
		meta.DestinationApp = hookToolDestinationApp(payloadString(req.Payload, "mcp_server_name"), req.ToolName)
		a.emitToolInvocationEventV8(ctx, meta, "call", req.ToolName, stringFromJSONRaw(req.ToolArgs), "", nil)
		a.rememberHookSessionState(ctx, meta)
		a.rememberHookSpawnIntent(meta, req.ToolName, hookSpawnIntentRequested, stringFromJSONRaw(req.ToolArgs))
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
		spawnPhase := hookSpawnIntentCompleted
		if meta.LifecycleOutcome == "failed" || meta.LifecycleOutcome == "denied" || meta.LifecycleOutcome == "blocked" ||
			meta.LifecycleOutcome == "cancelled" || meta.LifecycleOutcome == "rejected" {
			spawnPhase = hookSpawnIntentFailed
		}
		a.rememberHookSpawnIntent(meta, req.ToolName, spawnPhase, stringFromJSONRaw(req.ToolArgs), req.Content)
		completionContext := a.emitHookToolSpan(ctx, meta, req.ToolName, stringFromJSONRaw(req.ToolArgs), req.Content, nil)
		a.emitToolInvocationEventV8(completionContext, meta, "result", req.ToolName, "", req.Content, nil)
		a.emitInferredDelegatedAgentTransitions(ctx, meta, req.ToolName, stringFromJSONRaw(req.ToolArgs), false)
	}
}

func (a *APIServer) emitClaudeCodeHookLLMEvent(ctx context.Context, req claudeCodeHookRequest, _ []string, rawPayload []byte) {
	meta := hookLLMEventMeta("claudecode", req.SessionID, req.TurnID, req.Model, req.Source, req.AgentID, payloadString(req.Payload, "agent_name"), req.AgentType, req.Payload)
	meta.ToolID = req.ToolUseID
	meta.ToolName = claudeCodeToolName(req)
	meta = applyHookEventMeta(meta, req.HookEventName, req.Payload)
	meta = a.applyHookSpawnIntentLineage(meta, req.Payload)
	meta.FinishReasons = append([]string(nil), codexNotifyFinishReasons(req.Payload)...)
	meta = a.beginHookExecution(meta)
	meta = a.restoreHookSessionLifecycle(ctx, meta)
	meta = a.inferAndEmitHookSpawnStart(ctx, meta)
	meta = a.reconcileHookParent(meta)
	meta = a.mergeHookSessionLifecycle(meta)
	meta.TraceEventID = hookTraceEventID(ctx, meta)
	meta = finalizeHookEventCorrelation(meta, req.Payload)
	meta, recordLifecycle := a.prepareHookLifecycleTransition(meta)
	a.rememberHookSessionState(ctx, meta)
	lifecycleLogMeta := meta
	lifecycleContext := ctx
	if recordLifecycle {
		meta = a.normalizeHookReportedCost(meta)
		lifecycleContext = a.emitHookLifecycleTransitionSpan(ctx, meta)
	}
	a.emitHookLifecycleEvent(lifecycleContext, lifecycleLogMeta)
	if recordLifecycle {
		a.recordHookLifecycleMetric(lifecycleContext, meta)
	}
	a.rememberHookLLMSpanUsage(meta, extractHookPayloadTokenUsage(req.Payload))
	switch req.HookEventName {
	case "SessionStart":
		a.rememberHookSessionState(ctx, meta)
	case "UserPromptSubmit", "UserPromptExpansion":
		prompt := claudeCodePromptContent(req)
		meta.PromptID = hookPromptID("claudecode", req.SessionID, "", prompt, rawPayload)
		promptID := a.emitLLMPromptEventV8(ctx, meta, prompt, rawPayload)
		a.rememberHookPromptID("claudecode", req.SessionID, "", promptID)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.rememberHookSessionState(ctx, meta)
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
		a.emitLLMResponseEventV8(ctx, meta, req.Delta, string(rawPayload), []string{finish})
	case "SubagentStart":
		prompt := firstString(req.Payload, "task", "prompt", "description")
		if prompt == "" {
			prompt = hookLifecycleContent(meta, "subagent_input_not_reported")
		}
		meta.PromptID = hookPromptID("claudecode", req.SessionID, "", prompt, rawPayload)
		a.emitLLMPromptEventV8(ctx, meta, prompt, rawPayload)
		a.rememberHookLLMSpanPrompt(meta, prompt)
		a.rememberHookSessionState(ctx, meta)
	case "PreToolUse", "PermissionRequest":
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(req.MCPServerName, claudeCodeToolName(req))
		a.emitToolInvocationEventV8(ctx, meta, "call", claudeCodeToolName(req), stringFromJSONRaw(claudeCodeToolArgs(req)), "", nil)
		a.rememberHookSessionState(ctx, meta)
		a.rememberHookSpawnIntent(meta, claudeCodeToolName(req), hookSpawnIntentRequested, stringFromJSONRaw(claudeCodeToolArgs(req)))
		a.rememberHookToolInvocation(meta, claudeCodeToolName(req), stringFromJSONRaw(claudeCodeToolArgs(req)))
	case "PermissionDenied":
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(req.MCPServerName, claudeCodeToolName(req))
		arguments := stringFromJSONRaw(claudeCodeToolArgs(req))
		output := claudeCodeToolOutput(req)
		a.rememberHookSpawnIntent(meta, claudeCodeToolName(req), hookSpawnIntentFailed, arguments, output)
		completionContext := a.emitHookToolSpan(ctx, meta, claudeCodeToolName(req), arguments, output, nil)
		a.emitToolInvocationEventV8(completionContext, meta, "result", claudeCodeToolName(req), arguments, output, nil)
	case "PostToolUse", "PostToolUseFailure", "PostToolBatch":
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ToolID = req.ToolUseID
		meta.DestinationApp = hookToolDestinationApp(req.MCPServerName, claudeCodeToolName(req))
		arguments := stringFromJSONRaw(claudeCodeToolArgs(req))
		output := claudeCodeToolOutput(req)
		spawnPhase := hookSpawnIntentCompleted
		if req.HookEventName == "PostToolUseFailure" {
			spawnPhase = hookSpawnIntentFailed
		}
		a.rememberHookSpawnIntent(meta, claudeCodeToolName(req), spawnPhase, arguments, output)
		completionContext := a.emitHookToolSpan(ctx, meta, claudeCodeToolName(req), arguments, output, nil)
		a.emitToolInvocationEventV8(completionContext, meta, "result", claudeCodeToolName(req), "", output, nil)
	case "StopFailure":
		if strings.TrimSpace(req.LastAssistantMessage) != "" {
			meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
			meta.ResponseID = stableLLMEventID("response", "claudecode", req.SessionID, req.TurnID, "failure")
			completionContext := a.emitHookLLMSpan(ctx, meta, req.LastAssistantMessage)
			a.emitLLMResponseEventV8(completionContext, meta, req.LastAssistantMessage, string(rawPayload), []string{"error"})
		}
	case "Stop", "SubagentStop", "SessionEnd":
		if strings.TrimSpace(req.LastAssistantMessage) == "" {
			return
		}
		meta.PromptID = a.lastHookPromptID("claudecode", req.SessionID)
		meta.ResponseID = stableLLMEventID("response", "claudecode", req.SessionID)
		completionContext := a.emitHookLLMSpan(ctx, meta, req.LastAssistantMessage)
		a.emitLLMResponseEventV8(completionContext, meta, req.LastAssistantMessage, string(rawPayload), nil)
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
	lineageProvenance := "inferred"
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
	reportedParentAgentID := firstNonEmpty(
		firstString(payload, "parent_agent_id", "parentAgentId", "parent_id", "parentId"),
		firstString(objectAt(payload, "extra"), "parent_subagent_id", "parentSubagentId", "parent_agent_id", "parentAgentId"),
	)
	parentAgentID := reportedParentAgentID
	reportedRootAgentID := firstNonEmpty(
		firstString(payload, "root_agent_id", "rootAgentId", "rootAgentID"),
		firstString(objectAt(payload, "extra"), "root_agent_id", "rootAgentId", "rootAgentID"),
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
		reportedRootAgentID,
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
	if reportedRootAgentID != "" && hookAgentDepthReported(payload) &&
		(parentAgentID == "" || reportedParentAgentID != "") {
		lineageProvenance = "reported"
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
		AgentName:           firstNonEmpty(agentName, agentType, source, agentID),
		AgentType:           firstNonEmpty(agentType, source),
		RootAgentID:         rootAgentID,
		ParentAgentID:       parentAgentID,
		ParentAgentReported: reportedParentAgentID != "",
		LineageProvenance:   lineageProvenance,
		RootSessionID:       rootSessionID,
		ParentSessionID:     parentSessionID,
		LifecycleID:         stableLLMEventID("lifecycle", source, sessionID, agentID),
		ExecutionID:         stableLLMEventID("execution", source, sessionID, agentID, executionSeed),
		LifecycleEvent:      lifecycleEvent,
		LifecycleState:      lifecycleState,
		AgentDepth:          depth,
		ReportedCostUSD:     reportedCost.USD,
		ReportedCost:        reportedCost.Present,
		ReportedCostSum:     reportedCost.Cumulative,
		SessionSource:       sessionSource,
		SessionResumed:      resumed,
		UserID:              userID,
		UserName:            userName,
	}
}

// applyHookEventMeta makes the normalized request event authoritative. Typed
// connector decoders keep the event outside Payload, while generic decoders
// usually leave it inside; relying only on Payload made those two paths produce
// different lifecycle attributes for the same upstream hook.
func applyHookEventMeta(meta llmEventMeta, event string, payload map[string]interface{}) llmEventMeta {
	meta.LifecycleEvent = canonicalHookLifecycleEvent(event)
	meta.LifecycleState = hookLifecycleState(meta.LifecycleEvent, payload)
	if canonicalEvent(event) == "stopfailure" {
		meta.LifecycleState = "failed"
	}
	meta.LifecycleOutcome = hookLifecycleOutcome(event, meta.LifecycleEvent, meta.LifecycleState, payload)
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
			meta.LineageProvenance = "inferred"
			if meta.AgentDepth == 0 {
				meta.AgentDepth = 1
			}
		}
	}
	return meta
}

// finalizeHookEventCorrelation derives identities only after execution and
// trace correlation are authoritative. Session starts may rotate an execution,
// and generic events need their per-delivery trace identity to avoid collapsing
// distinct operations.
func finalizeHookEventCorrelation(meta llmEventMeta, payload map[string]interface{}) llmEventMeta {
	meta.LifecycleDedupe = hookLifecycleDedupeKey(meta, payload)
	meta.OperationID = hookOperationID(meta)
	return meta
}

func hookAgentDepthReported(payload map[string]interface{}) bool {
	for _, key := range []string{"agent_depth", "agentDepth", "depth"} {
		if _, present := payload[key]; present {
			return true
		}
	}
	return false
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

// hookLifecycleOutcome retains the bounded terminal result that is otherwise
// lost when several raw connector events normalize to the same lifecycle
// event/state pair. The value is consumed by the generated compat family; the
// legacy gateway event remains byte-for-byte governed by its existing fields.
func hookLifecycleOutcome(rawEvent, event, state string, payload map[string]interface{}) string {
	switch event {
	case "session_start", "subagent_start", "turn_start", "tool_start", "compact_start":
		return "attempted"
	case "event":
		return ""
	}

	status := strings.ToLower(strings.Join([]string{
		canonicalEvent(rawEvent),
		state,
		firstString(payload, "status", "child_status", "reason", "outcome", "error", "error_details", "termination_reason", "terminationReason"),
	}, " "))
	if event == "tool_end" {
		switch {
		case strings.Contains(status, "permissiondenied") || strings.Contains(status, "denied"):
			return "denied"
		case strings.Contains(status, "blocked"):
			return "blocked"
		case strings.Contains(status, "reject"):
			return "rejected"
		case strings.Contains(status, "timeout") || strings.Contains(status, "timedout"):
			return "timed_out"
		case strings.Contains(status, "skip"):
			return "skipped"
		case strings.Contains(status, "partial"):
			return "partial"
		case strings.Contains(status, "cancel") || strings.Contains(status, "interrupt"):
			return "cancelled"
		case strings.Contains(status, "fail") || strings.Contains(status, "error"):
			return "failed"
		default:
			return "completed"
		}
	}
	if event == "compact_end" {
		switch {
		case strings.Contains(status, "nochange") || strings.Contains(status, "no_change"):
			return "no_change"
		case strings.Contains(status, "partial"):
			return "partial"
		case strings.Contains(status, "cancel") || strings.Contains(status, "interrupt"):
			return "cancelled"
		case strings.Contains(status, "fail") || strings.Contains(status, "error"):
			return "failed"
		default:
			return "completed"
		}
	}
	switch {
	case strings.Contains(status, "terminat"):
		return "terminated"
	case state == "interrupted" || strings.Contains(status, "cancel") || strings.Contains(status, "interrupt"):
		return "cancelled"
	case state == "failed" || strings.Contains(status, "fail") || strings.Contains(status, "error"):
		return "failed"
	default:
		return "completed"
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
		meta.Source, meta.SessionID, meta.AgentID, meta.LifecycleID, meta.ExecutionID, lifecycleEvent, identity,
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
	meta          llmEventMeta
	content       string
	originalBytes int64
	truncated     bool
	startedAt     time.Time
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
	id                     string
	meta                   llmEventMeta
	tool                   string
	arguments              string
	argumentsOriginalBytes int64
	argumentsTruncated     bool
	startedAt              time.Time
}

// hookSessionState retains only bounded lifecycle identity for one connector
// session. It never retains a span, runtime, generation lease, or content.
type hookSessionState struct {
	meta         llmEventMeta
	traceEventID string
}

// hookPhaseState backs both the bounded per-execution cursor and the canonical
// metadata retained for lifecycle replay dedupe. Neither form retains prompt
// or tool bodies.
type hookPhaseState struct {
	phase         string
	sequence      int64
	meta          llmEventMeta
	canonicalMeta llmEventMeta
	canonical     bool
}

const hookLifecycleCanonicalStatePrefix = "lifecycle-canonical\x00"

func hookPhaseStateKey(meta llmEventMeta) string {
	if strings.TrimSpace(meta.Source) == "" || strings.TrimSpace(meta.AgentID) == "" {
		return ""
	}
	return strings.Join([]string{
		meta.Source, meta.SessionID, meta.AgentID,
		firstNonEmpty(meta.ExecutionID, meta.LifecycleID),
	}, "\x00")
}

func hookLifecycleCanonicalStateKey(meta llmEventMeta) string {
	key := strings.TrimSpace(meta.LifecycleDedupe)
	if key == "" {
		return ""
	}
	return hookLifecycleCanonicalStatePrefix + key
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

func hookPhaseDefaults(meta llmEventMeta) llmEventMeta {
	if meta.Phase == "" {
		meta.Phase = hookLifecyclePhase("", meta.LifecycleEvent, meta.LifecycleState)
	}
	if phase, ok := gatewaylog.NormalizeAgentPhase(meta.Phase); ok {
		meta.Phase = phase
	}
	if meta.OperationID == "" {
		meta.OperationID = hookOperationID(meta)
	}
	return meta
}

func removeHookStateOrderKey(order *[]string, key string) {
	for i, candidate := range *order {
		if candidate != key {
			continue
		}
		copy((*order)[i:], (*order)[i+1:])
		*order = (*order)[:len(*order)-1]
		return
	}
}

func (a *APIServer) evictOldestHookPhaseStateLocked() bool {
	if len(a.hookPhaseStateOrder) == 0 {
		return false
	}
	oldest := a.hookPhaseStateOrder[0]
	a.hookPhaseStateOrder = a.hookPhaseStateOrder[1:]
	delete(a.hookPhaseStates, oldest)
	if strings.HasPrefix(oldest, hookLifecycleCanonicalStatePrefix) {
		dedupeKey := strings.TrimPrefix(oldest, hookLifecycleCanonicalStatePrefix)
		delete(a.hookLifecycleTransitions, dedupeKey)
		removeHookStateOrderKey(&a.hookLifecycleTransitionOrder, dedupeKey)
	}
	return true
}

func (a *APIServer) putHookPhaseStateLocked(key string, state hookPhaseState) {
	if _, exists := a.hookPhaseStates[key]; !exists {
		for len(a.hookPhaseStates) >= hookPromptCacheMaxEntries && a.evictOldestHookPhaseStateLocked() {
		}
		a.hookPhaseStateOrder = append(a.hookPhaseStateOrder, key)
	}
	a.hookPhaseStates[key] = state
}

func (a *APIServer) putHookPhaseCursorLocked(key string, state hookPhaseState) {
	if _, exists := a.hookPhaseStates[key]; exists {
		removeHookStateOrderKey(&a.hookPhaseStateOrder, key)
		a.hookPhaseStateOrder = append(a.hookPhaseStateOrder, key)
		a.hookPhaseStates[key] = state
		return
	}
	a.putHookPhaseStateLocked(key, state)
}

func (a *APIServer) enrichHookPhaseLocked(meta llmEventMeta, key string) llmEventMeta {
	state := a.hookPhaseStates[key]
	// The first observation has no reported previous phase. Keep that absence
	// truthful for logs and traces instead of fabricating an "unknown" phase:
	// their schemas omit the optional field, while the bounded Agent360 metric
	// projection independently maps an empty PreviousPhase to its required
	// low-cardinality "unknown" label.
	meta.PreviousPhase = state.phase
	state.sequence++
	state.phase = meta.Phase
	meta.Sequence = state.sequence
	state.meta = meta
	a.putHookPhaseCursorLocked(key, state)
	return meta
}

func (a *APIServer) enrichHookPhase(meta llmEventMeta) llmEventMeta {
	meta = hookPhaseDefaults(meta)
	key := hookPhaseStateKey(meta)
	if a == nil || key == "" {
		return meta
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookPhaseStates == nil {
		a.hookPhaseStates = make(map[string]hookPhaseState)
	}
	return a.enrichHookPhaseLocked(meta, key)
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
	if state, ok := a.hookPhaseStates[key]; ok && !state.canonical {
		return state.meta, true
	}
	// Starts rotate ExecutionID, so decision projections may only reconstruct
	// the stable identity. Use the newest non-canonical cursor for this session.
	for i := len(a.hookPhaseStateOrder) - 1; i >= 0; i-- {
		state, exists := a.hookPhaseStates[a.hookPhaseStateOrder[i]]
		if !exists || state.canonical || state.meta.Source != meta.Source || state.meta.SessionID != meta.SessionID {
			continue
		}
		if meta.AgentID != "" && state.meta.AgentID != meta.AgentID {
			continue
		}
		return state.meta, true
	}
	return llmEventMeta{}, false
}

// prepareHookLifecycleTransition atomically decides whether a normalized
// lifecycle transition is first-seen before advancing its per-execution phase
// cursor. Exact replays reuse the first transition's logical metadata while
// retaining the current delivery's trace anchor for raw lifecycle logging.
func (a *APIServer) prepareHookLifecycleTransition(meta llmEventMeta) (llmEventMeta, bool) {
	meta = hookPhaseDefaults(meta)
	cursorKey := hookPhaseStateKey(meta)
	canonicalKey := hookLifecycleCanonicalStateKey(meta)
	if a == nil || cursorKey == "" || canonicalKey == "" {
		meta = a.enrichHookPhase(meta)
		return meta, a.shouldRecordHookLifecycleTransition(meta)
	}

	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if a.hookPhaseStates == nil {
		a.hookPhaseStates = make(map[string]hookPhaseState)
	}
	if cached, ok := a.hookPhaseStates[canonicalKey]; ok && cached.canonical {
		canonical := cached.canonicalMeta
		canonical.TraceEventID = meta.TraceEventID
		return canonical, false
	}

	meta = a.enrichHookPhaseLocked(meta, cursorKey)
	a.putHookPhaseStateLocked(canonicalKey, hookPhaseState{
		canonicalMeta: meta,
		canonical:     true,
	})
	if a.hookLifecycleTransitions == nil {
		a.hookLifecycleTransitions = make(map[string]struct{})
	}
	putBoundedStructKey(
		a.hookLifecycleTransitions,
		&a.hookLifecycleTransitionOrder,
		meta.LifecycleDedupe,
		hookPromptCacheMaxEntries,
	)
	return meta, true
}

const hookSessionStartedOutput = "Live session started. Child operations stream as they complete."

func hookSessionStateKey(meta llmEventMeta) string {
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
	key := hookSessionStateKey(meta)
	if key == "" {
		return meta
	}
	meta.ExecutionID = newHookExecutionID(meta)
	a.llmPromptMu.Lock()
	delete(a.hookSessionStates, key)
	for i, candidate := range a.hookSessionStateOrder {
		if candidate == key {
			copy(a.hookSessionStateOrder[i:], a.hookSessionStateOrder[i+1:])
			a.hookSessionStateOrder = a.hookSessionStateOrder[:len(a.hookSessionStateOrder)-1]
			break
		}
	}
	a.llmPromptMu.Unlock()
	return meta
}

func newHookExecutionID(meta llmEventMeta) string {
	return stableLLMEventID(
		"execution", meta.Source, meta.SessionID, meta.AgentID,
		gatewaylog.ProcessRunID(), strconv.FormatInt(time.Now().UTC().UnixNano(), 10), uuid.NewString(),
	)
}

func (a *APIServer) mergeHookSessionLifecycle(meta llmEventMeta) llmEventMeta {
	if a == nil {
		return meta
	}
	key := hookSessionStateKey(meta)
	if key == "" {
		return meta
	}
	a.llmPromptMu.Lock()
	snapshot, ok := a.hookSessionStates[key]
	a.llmPromptMu.Unlock()
	if !ok {
		return meta
	}
	meta.LifecycleID = firstNonEmpty(meta.LifecycleID, snapshot.meta.LifecycleID)
	newExecutionStart := (meta.LifecycleEvent == "session_start" || meta.LifecycleEvent == "subagent_start") &&
		strings.TrimSpace(meta.ExecutionID) != ""
	if snapshot.meta.ExecutionID != "" && !newExecutionStart {
		meta.ExecutionID = snapshot.meta.ExecutionID
	}
	// Derived per-event defaults identify an explicit child as its own root.
	// Once that child's lifecycle has been retained, the stored lineage is the
	// authority unless a connector reports a complete authoritative lineage.
	switch {
	case meta.LineageProvenance == "reported":
		// Complete connector-reported topology is authoritative for every
		// lineage field.
		meta.RootAgentID = firstNonEmpty(meta.RootAgentID, snapshot.meta.RootAgentID, snapshot.meta.AgentID)
		meta.ParentAgentID = firstNonEmpty(meta.ParentAgentID, snapshot.meta.ParentAgentID)
		meta.RootSessionID = firstNonEmpty(meta.RootSessionID, snapshot.meta.RootSessionID, snapshot.meta.SessionID)
		meta.ParentSessionID = firstNonEmpty(meta.ParentSessionID, snapshot.meta.ParentSessionID)
	case meta.ParentAgentReported && hookLifecycleRetainedLineageVerified(snapshot.meta):
		// A parent-only report can refine the immediate edge, but its derived
		// root and depth are not authoritative for an already-retained nested
		// lineage.
		meta.RootAgentID = firstNonEmpty(snapshot.meta.RootAgentID, snapshot.meta.AgentID, meta.RootAgentID)
		meta.ParentAgentID = firstNonEmpty(meta.ParentAgentID, snapshot.meta.ParentAgentID)
		meta.LineageProvenance = firstNonEmpty(snapshot.meta.LineageProvenance, meta.LineageProvenance)
		meta.RootSessionID = firstNonEmpty(snapshot.meta.RootSessionID, snapshot.meta.SessionID, meta.RootSessionID)
		meta.ParentSessionID = firstNonEmpty(meta.ParentSessionID, snapshot.meta.ParentSessionID)
		meta.AgentDepth = snapshot.meta.AgentDepth
	case meta.ParentAgentReported:
		// An explicit live parent must replace an unresolved self-root
		// placeholder. Keep the incoming root/depth and use retained state only
		// to fill facts the current delivery did not provide.
		meta.RootAgentID = firstNonEmpty(meta.RootAgentID, snapshot.meta.RootAgentID, snapshot.meta.AgentID)
		meta.ParentAgentID = firstNonEmpty(meta.ParentAgentID, snapshot.meta.ParentAgentID)
		meta.RootSessionID = firstNonEmpty(meta.RootSessionID, snapshot.meta.RootSessionID, snapshot.meta.SessionID)
		meta.ParentSessionID = firstNonEmpty(meta.ParentSessionID, snapshot.meta.ParentSessionID)
	case hookLifecycleRetainedLineageVerified(snapshot.meta):
		// A prior spawn/session correlation is immutable unless the connector
		// reports a parent explicitly. In particular, do not let resolving the
		// shared root session on a later Codex SubagentStop flatten a verified
		// depth-two/depth-three edge. This also covers the separately emitted
		// hook_decision for the same delivery.
		meta = restoreRetainedHookLineage(meta, snapshot.meta)
	case meta.ParentLineageResolved:
		// The retained snapshot is still unverified, so a newly resolved parent
		// is the stronger available fact.
		meta.RootAgentID = firstNonEmpty(meta.RootAgentID, snapshot.meta.RootAgentID, snapshot.meta.AgentID)
		meta.ParentAgentID = firstNonEmpty(meta.ParentAgentID, snapshot.meta.ParentAgentID)
		meta.RootSessionID = firstNonEmpty(meta.RootSessionID, snapshot.meta.RootSessionID, snapshot.meta.SessionID)
		meta.ParentSessionID = firstNonEmpty(meta.ParentSessionID, snapshot.meta.ParentSessionID)
	default:
		meta.RootAgentID = firstNonEmpty(snapshot.meta.RootAgentID, snapshot.meta.AgentID, meta.RootAgentID)
		meta.ParentAgentID = firstNonEmpty(snapshot.meta.ParentAgentID, meta.ParentAgentID)
		meta.LineageProvenance = firstNonEmpty(snapshot.meta.LineageProvenance, meta.LineageProvenance)
		meta.RootSessionID = firstNonEmpty(snapshot.meta.RootSessionID, snapshot.meta.SessionID, meta.RootSessionID)
		meta.ParentSessionID = firstNonEmpty(snapshot.meta.ParentSessionID, meta.ParentSessionID)
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
	snapshot, ok := a.hookSessionStateSnapshot(source, sessionID, agentID)
	return snapshot.meta, ok
}

// hookSessionStateSnapshot resolves the current session even when an upstream
// child event knows only parent_session_id. An explicit agent ID is an exact
// identity constraint; only a caller without one may select the shallowest
// retained agent for that conversation.
func (a *APIServer) hookSessionStateSnapshot(source, sessionID, agentID string) (hookSessionState, bool) {
	if a == nil || strings.TrimSpace(source) == "" || strings.TrimSpace(sessionID) == "" {
		return hookSessionState{}, false
	}
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if agentID != "" {
		key := hookSessionStateKey(llmEventMeta{Source: source, SessionID: sessionID, AgentID: agentID})
		if snapshot, ok := a.hookSessionStates[key]; ok {
			return snapshot, true
		}
		return hookSessionState{}, false
	}
	var selected hookSessionState
	found := false
	for i := len(a.hookSessionStateOrder) - 1; i >= 0; i-- {
		snapshot, ok := a.hookSessionStates[a.hookSessionStateOrder[i]]
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
	snapshot, ok := a.hookSessionStateSnapshot(meta.Source, parentSessionID, meta.ParentAgentID)
	if !ok && strings.TrimSpace(meta.ParentSessionID) != "" && !meta.ParentAgentReported {
		// Some native connectors provide only parent_session_id. In that case,
		// and only that case, resolve the shallowest retained agent in the
		// explicitly named parent conversation.
		snapshot, ok = a.hookSessionStateSnapshot(meta.Source, parentSessionID, "")
	}
	if !ok {
		return meta
	}
	meta.ParentAgentID = snapshot.meta.AgentID
	meta.RootAgentID = firstNonEmpty(snapshot.meta.RootAgentID, snapshot.meta.AgentID)
	meta.RootSessionID = firstNonEmpty(snapshot.meta.RootSessionID, snapshot.meta.SessionID)
	meta.ParentLineageResolved = true
	if meta.AgentDepth <= snapshot.meta.AgentDepth {
		meta.AgentDepth = snapshot.meta.AgentDepth + 1
	}
	meta.UserID = firstNonEmpty(meta.UserID, snapshot.meta.UserID)
	meta.UserName = firstNonEmpty(meta.UserName, snapshot.meta.UserName)
	return meta
}

// applyHookLifecycleSpanAttributes enriches the still-active request guardrail
// span. Lifecycle/model/tool span ownership itself is generated-only.
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

func (a *APIServer) recordHookLifecycleMetric(ctx context.Context, meta llmEventMeta) {
	if a == nil || strings.TrimSpace(meta.AgentID) == "" {
		return
	}
	emitter := a.observabilityV8RuntimeEmitter()
	if runtime, ok := emitter.(hookLifecycleMetricV8Runtime); ok {
		_ = a.recordHookLifecycleMetricsV8(ctx, runtime, meta)
	}
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
			child.LifecycleOutcome = "attempted"
			child.Phase = "session"
		} else {
			child.LifecycleEvent = "subagent_stop"
			child.LifecycleState = "completed"
			child.LifecycleOutcome = "completed"
			child.Phase = "completed"
			child = a.mergeHookSessionLifecycle(child)
		}
		child = finalizeHookEventCorrelation(child, nil)
		child, recordLifecycle := a.prepareHookLifecycleTransition(child)
		if recordLifecycle {
			a.rememberHookSessionState(ctx, child)
		}
		childContext := ctx
		if recordLifecycle {
			childContext = a.emitHookLifecycleTransitionSpan(ctx, child)
		}
		a.emitHookLifecycleEvent(childContext, child)
		if recordLifecycle {
			a.recordHookLifecycleMetric(childContext, child)
		}
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
	case "agent", "task", "invokesubagent", "delegatetask", "delegate", "runsubagent", "spawnagent",
		"collaborationspawnagent", "functionsspawnagent":
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
		child.LineageProvenance = "inferred"
		child.ParentSessionID = ""
		child.AgentDepth = parent.AgentDepth + 1
		child.LifecycleID = stableLLMEventID("lifecycle", child.Source, child.SessionID, child.AgentID)
		child.ExecutionID = stableLLMEventID(
			"execution", child.Source, child.SessionID, child.AgentID,
			firstNonEmpty(parent.ExecutionID, gatewaylog.ProcessRunID()),
		)
		children = append(children, child)
	}
	return children
}

// rememberHookSessionState retains only bounded lifecycle identity. No trace or
// provider handle is created or cached: every generated span is request-bounded
// and owns its runtime generation independently.
func (a *APIServer) rememberHookSessionState(ctx context.Context, meta llmEventMeta) {
	if a == nil {
		return
	}
	key := hookSessionStateKey(meta)
	if key == "" {
		return
	}
	// Recursive parent state is retained after the top-level hook meta was
	// merged so a child observation cannot overwrite the parent's durable
	// execution/resume identity with a synthesized fallback.
	meta = a.mergeHookSessionLifecycle(meta)
	if meta.TraceEventID == "" {
		meta.TraceEventID = hookTraceEventID(ctx, meta)
	}

	if meta.AgentID != "" && meta.ParentAgentID != "" && meta.ParentAgentID != meta.AgentID {
		parentSessionID := firstNonEmpty(meta.ParentSessionID, meta.SessionID)
		if _, exists := a.hookSessionStateSnapshot(meta.Source, parentSessionID, meta.ParentAgentID); !exists {
			parentMeta := meta
			parentMeta.SessionID = parentSessionID
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
			a.rememberHookSessionState(ctx, parentMeta)
		}
	}

	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()
	if existing, ok := a.hookSessionStates[key]; ok {
		if existing.traceEventID == meta.TraceEventID {
			return
		}
		// Canonical lifecycle preparation assigns sequence numbers atomically,
		// but delivery handlers retain their snapshots after that lock is
		// released. A delayed replay (or a slower concurrent handler) must not
		// replace a newer cursor from the same execution. Equal-sequence exact
		// replays may still refresh the request-local trace anchor used by hook
		// decisions, and a new execution is allowed to restart at sequence one.
		if meta.ExecutionID == existing.meta.ExecutionID && meta.Sequence > 0 &&
			existing.meta.Sequence > meta.Sequence {
			return
		}
	}

	if a.hookSessionStates == nil {
		a.hookSessionStates = make(map[string]hookSessionState)
	}
	if _, exists := a.hookSessionStates[key]; !exists {
		for len(a.hookSessionStates) >= hookPromptCacheMaxEntries && len(a.hookSessionStateOrder) > 0 {
			oldest := a.hookSessionStateOrder[0]
			a.hookSessionStateOrder = a.hookSessionStateOrder[1:]
			delete(a.hookSessionStates, oldest)
		}
		a.hookSessionStateOrder = append(a.hookSessionStateOrder, key)
	}
	a.hookSessionStates[key] = hookSessionState{
		meta: meta, traceEventID: meta.TraceEventID,
	}
}

func hookToolInvocationKey(meta llmEventMeta, tool string) string {
	identity := strings.TrimSpace(meta.ToolID)
	if identity == "" {
		identity = strings.TrimSpace(meta.TurnID) + "\x00" + strings.TrimSpace(tool)
	}
	return strings.Join([]string{
		strings.TrimSpace(meta.Source), strings.TrimSpace(meta.SessionID),
		strings.TrimSpace(meta.AgentID), strings.TrimSpace(meta.ExecutionID), identity,
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
	boundedArguments := boundedHookLLMSpanContent(arguments)
	if queue := a.hookToolInvocations[key]; strings.TrimSpace(meta.ToolID) != "" && len(queue) > 0 {
		pending := queue[0]
		pending.meta = meta
		pending.tool = tool
		pending.arguments = boundedArguments
		pending.argumentsOriginalBytes = int64(len(arguments))
		pending.argumentsTruncated = len(boundedArguments) < len(arguments)
		a.hookToolInvocations[key] = []hookToolInvocation{pending}
		return
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
		meta: meta, tool: tool, arguments: boundedArguments,
		argumentsOriginalBytes: int64(len(arguments)),
		argumentsTruncated:     len(boundedArguments) < len(arguments),
		startedAt:              startedAt,
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
) context.Context {
	if a == nil || strings.TrimSpace(tool) == "" {
		return ctx
	}
	snapshot, emit := a.takeHookToolInvocation(meta, tool, result)
	if !emit {
		return ctx
	}
	arguments := snapshot.arguments
	if strings.TrimSpace(arguments) == "" {
		arguments = boundedHookLLMSpanContent(fallbackArguments)
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
	if emitter := a.observabilityV8RuntimeEmitter(); emitter != nil {
		observation := newHookToolV8Observation(snapshot, merged, tool, arguments, result, exitCode)
		metricRuntime, _ := emitter.(hookLifecycleMetricV8Runtime)
		if runtime, ok := emitter.(lifecycleV8Runtime); ok {
			return a.emitHookToolSpanV8(ctx, runtime, metricRuntime, observation)
		}
		a.recordHookToolMetricsV8(ctx, metricRuntime, observation)
		// Config-v8 runtime ownership is sticky. A missing generated trace
		// capability, collection drop, sampling decision, or build failure must
		// never resurrect the legacy SDK provider.
		return ctx
	}
	return ctx
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
	sessionKey := strings.Join([]string{
		source, sessionID, agentID, strings.TrimSpace(meta.ExecutionID),
	}, "\x00")
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
	bounded := boundedHookLLMSpanContent(prompt)
	snapshot := hookLLMSpanPrompt{
		meta: meta, content: bounded, originalBytes: int64(len(prompt)),
		truncated: len(bounded) < len(prompt), startedAt: time.Now(),
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

// takeHookLLMSpanPrompt atomically takes the best prompt snapshot: exact
// source/session/turn first, then the latest source/session prompt. It does not
// suppress repeated completions. Only the durable correlation receipt layer
// may suppress an exact delivery replay; without an exact, profile-declared
// receipt key, identical responses are independent observations.
func (a *APIServer) takeHookLLMSpanPrompt(meta llmEventMeta, response string) (hookLLMSpanPrompt, bool) {
	a.llmPromptMu.Lock()
	defer a.llmPromptMu.Unlock()

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
func (a *APIServer) emitHookLLMSpan(ctx context.Context, meta llmEventMeta, response string) context.Context {
	if a == nil || strings.TrimSpace(response) == "" {
		return ctx
	}
	snapshot, emit := a.takeHookLLMSpanPrompt(meta, response)
	if !emit {
		return ctx
	}
	if emitter := a.observabilityV8RuntimeEmitter(); emitter != nil {
		// Runtime ownership is sticky. Once config v8 is authoritative, a
		// missing generated capability, disabled collection, or sampled-out
		// trace must never resurrect the legacy SDK provider.
		metricRuntime, _ := emitter.(hookLifecycleMetricV8Runtime)
		if runtime, ok := emitter.(lifecycleV8Runtime); ok {
			return a.emitHookLLMSpanV8(ctx, runtime, metricRuntime, snapshot, meta, response)
		}
		observation := a.hookModelV8Observation(snapshot, meta, response)
		a.recordHookModelMetricsV8(ctx, metricRuntime, observation)
		return ctx
	}
	_ = a.takeHookLLMSpanUsage(meta)
	return ctx
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
