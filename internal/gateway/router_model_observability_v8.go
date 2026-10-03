// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"go.opentelemetry.io/otel/trace"
)

const (
	eventRouterModelV8Producer      = "gateway.event_router.model"
	eventRouterModelContextCapacity = 4096
	eventRouterModelContextTTL      = 10 * time.Minute
)

type eventRouterModelContextKey struct {
	sessionID string
	runID     string
}

type eventRouterModelContextEntry struct {
	ctx        context.Context
	observedAt time.Time
}

// emitEventRouterModelV8 converts one completed OpenClaw assistant message into
// a request-bounded generated model operation. The stream reports no model
// start instant, so the operation is deliberately zero-duration rather than
// fabricating latency. Its ended W3C context remains a valid parent token for a
// subsequent tool or approval observation without retaining a span handle or
// runtime generation.
func (r *EventRouter) emitEventRouterModelV8(
	ctx context.Context,
	meta llmEventMeta,
	provider string,
	model string,
	prompt string,
	response string,
	promptTokens int64,
	completionTokens int64,
	toolCallCount int64,
	finishReasons []string,
	observedAt time.Time,
) context.Context {
	if r == nil || ctx == nil || observedAt.IsZero() {
		return ctx
	}
	emitter, lifecycle, authoritative := r.observabilityV8CapabilitiesSnapshot()
	if !authoritative || lifecycle == nil {
		return ctx
	}
	model = strings.TrimSpace(model)
	if !hookModelV8Identifier(model) {
		return ctx
	}
	provider = firstNonEmpty(strings.TrimSpace(provider), inferSystem(provider, model), "unknown")
	meta.Source = eventRouterToolConnector
	meta.Provider = provider
	meta.Model = model
	observation := hookModelV8Observation{
		meta: meta, prompt: prompt, response: openClawReplyText(response),
		usage: hookLLMSpanUsage{
			promptTokens: promptTokens, completionTokens: completionTokens, model: model,
		},
		provider: provider, reportedModel: model, model: model, responseModel: model,
		agentName: firstNonEmpty(meta.AgentName, eventRouterToolConnector),
		agentType: firstNonEmpty(meta.AgentType, eventRouterToolConnector),
		agentID:   meta.AgentID, sessionID: meta.SessionID,
		startedAt: observedAt.UTC(), finishedAt: observedAt.UTC(),
		toolCallCount: toolCallCount,
		finishReasons: hookModelV8FinishReasons(finishReasons),
	}
	applyOpenClawPromptBlock(&observation)
	input := hookModelV8ModelInput(observation)
	input.Envelope.Provenance.Producer = eventRouterModelV8Producer
	metricRuntime, _ := emitter.(hookLifecycleMetricV8Runtime)
	// Every connector turn is rooted in a connector-named agent span
	// ("invoke_agent openclaw"), as the hook and proxy paths are, so OpenClaw
	// sessions can be found by agent in Galileo and Tempo (GAP-1452).
	agentInput := eventRouterAgentInputV8(observation)
	agentContext, agent, agentErr := lifecycle.StartAgentTrace(ctx, agentInput)
	if agentErr == nil && agent != nil {
		return emitEventRouterModelUnderAgentV8(ctx, agentContext, agent, agentInput, input, observation)
	}
	if agentErr == nil && hookModelV8AgentSamplingDeclined(ctx, agentContext) {
		recordGeneratedModelMetricsV8ForProducer(agentContext, metricRuntime, observation, eventRouterModelV8Producer)
		return agentContext
	}
	startedContext, span, err := lifecycle.StartModelTrace(ctx, input)
	if err != nil {
		recordGeneratedModelMetricsV8ForProducer(ctx, metricRuntime, observation, eventRouterModelV8Producer)
		return ctx
	}
	if span == nil {
		recordGeneratedModelMetricsV8ForProducer(ctx, metricRuntime, observation, eventRouterModelV8Producer)
		return startedContext
	}
	defer span.Abort()
	modelContext := span.Context()
	recordGeneratedModelMetricsV8ForProducer(modelContext, span, observation, eventRouterModelV8Producer)
	if err := span.End(input); err != nil {
		return ctx
	}
	return modelContext
}

// emitEventRouterModelUnderAgentV8 records the zero-duration model operation
// as the child of its agent root and returns the ended model context, the
// parent for a later tool or approval child.
func emitEventRouterModelUnderAgentV8(
	ctx context.Context,
	agentContext context.Context,
	agent *observabilityruntime.AgentTrace,
	agentInput observability.SpanAgentInvokeInput,
	input observability.SpanModelChatInput,
	observation hookModelV8Observation,
) context.Context {
	defer agent.Abort()
	if agentContext == nil {
		agentContext = agent.Context()
	}
	inheritProxyV8AgentIdentity(&input, agentInput)
	model, err := agent.StartModel(input)
	if err != nil || model == nil {
		recordGeneratedModelMetricsV8ForProducer(agentContext, agent, observation, eventRouterModelV8Producer)
		if agent.End(agentInput) != nil {
			return ctx
		}
		return agentContext
	}
	defer model.Abort()
	modelContext := model.Context()
	recordGeneratedModelMetricsV8ForProducer(modelContext, model, observation, eventRouterModelV8Producer)
	if model.End(input) != nil || agent.End(agentInput) != nil {
		return ctx
	}
	return modelContext
}

// eventRouterAgentInputV8 is the agent root of one OpenClaw assistant message.
// The stream reports no lifecycle or execution identity, so the root carries
// only what the message reports, like the proxy's agent root. The message is
// the turn's reply, so the root's output is that reply, as on the hook
// connectors' agent spans; without it Galileo showed a blank agent node for
// every OpenClaw turn (GAP-2495).
func eventRouterAgentInputV8(observation hookModelV8Observation) observability.SpanAgentInvokeInput {
	meta := observation.meta
	envelope := hookModelV8Envelope(observation, "invoke_agent")
	envelope.Provenance.Producer = eventRouterModelV8Producer
	outcome, technicalFailure, errorType := hookModelV8ObservationResult(observation)
	inputMessages, inputBytes, inputReported, inputState, inputStructured := hookModelV8InputMessages(
		observation.prompt, observation.promptOriginalBytes, observation.promptTruncated,
	)
	outputMessages, outputBytes, outputReported, outputState, outputStructured := hookModelV8OutputMessages(
		observation.response, observation.finishReasons,
	)
	input := observability.SpanAgentInvokeInput{
		Envelope: envelope, Outcome: outcome, Kind: "INTERNAL",
		StartTimeUnixNano:                  uint64(observation.startedAt.UnixNano()),
		EndTimeUnixNano:                    uint64(observation.finishedAt.UnixNano()),
		Status:                             observability.NewTraceStatusOK(),
		DefenseClawAgentType:               observation.agentType,
		DefenseClawTelemetryInputReported:  inputReported,
		DefenseClawContentInputState:       inputState,
		DefenseClawTelemetryOutputReported: outputReported,
		DefenseClawContentOutputState:      outputState,
		GenAIOperationName:                 observability.Present("invoke_agent"),
		ConditionConnectorKnown:            hookModelV8StableToken(meta.Source) != "",
		ConditionOperationTerminal:         true,
		ConditionTechnicalFailure:          technicalFailure,
	}
	if errorType != "" {
		input.ErrorType = observability.Present(errorType)
	}
	if technicalFailure {
		input.Status = observability.NewTraceStatusError(input.ErrorType)
	}
	if inputStructured {
		input.GenAIInputMessages = observability.Present(inputMessages)
	}
	if inputReported {
		input.DefenseClawContentInputOriginalBytes = observability.Present(inputBytes)
		input.DefenseClawContentInputMimeType = observability.Present("text/plain")
	}
	if outputStructured {
		input.GenAIOutputMessages = observability.Present(outputMessages)
	}
	if outputReported {
		input.DefenseClawContentOutputOriginalBytes = observability.Present(outputBytes)
		input.DefenseClawContentOutputMimeType = observability.Present("text/plain")
	}
	input.DefenseClawConnectorSource = hookModelV8OptionalID(meta.Source)
	input.UserID = hookModelV8OptionalID(meta.UserID)
	input.DefenseClawUserIDKind = v8UserIDKind(meta.UserIDKind)
	input.DefenseClawUserName = hookModelV8OptionalID(meta.UserName)
	input.DefenseClawRunID = hookModelV8OptionalID(meta.RunID)
	input.DefenseClawTurnID = hookModelV8OptionalID(meta.TurnID)
	input.DefenseClawPolicyID = hookModelV8OptionalID(meta.PolicyID)
	input.DefenseClawGuardrailAction, input.DefenseClawGuardrailRuleID, input.DefenseClawGuardrailSeverity =
		guardrailOutcomeAttributes(meta.Guardrail)
	input.GenAIConversationID = hookModelV8OptionalID(observation.sessionID)
	input.GenAIAgentID = hookModelV8OptionalID(observation.agentID)
	input.GenAIAgentName = hookModelV8OptionalID(observation.agentName)
	input.DefenseClawAgentRootID = hookModelV8OptionalID(observation.agentID)
	input.DefenseClawSessionRootID = hookModelV8OptionalID(observation.sessionID)
	if observation.agentID != "" {
		input.DefenseClawAgentLineageProvenance = observability.Present("reported")
		input.DefenseClawAgentDepth = observability.Present[int64](0)
	}
	input.DefenseClawAgentPhase = observability.Present("model")
	input.DefenseClawAgentPhaseCode = observability.Present[int64](3)
	if provider := strings.TrimSpace(observation.provider); provider != "" {
		input.GenAIProviderName = observability.Present(provider)
	}
	if observation.model != "" {
		input.GenAIRequestModel = observability.Present(observation.model)
		input.GenAIResponseModel = observability.Present(observation.model)
	}
	return input
}

func eventRouterModelMeta(
	r *EventRouter,
	sessionID string,
	runID string,
	messageID string,
	sequence int,
	provider string,
	model string,
) llmEventMeta {
	meta := streamLLMEventMeta(r, sessionID, runID, provider, model, "")
	meta.MessageID = proxyV8StableID(messageID)
	meta.SourceEventID = meta.MessageID
	meta.SourceSequence = intString(sequence)
	meta.ResponseID = stableLLMEventID(
		"response", eventRouterToolConnector, sessionID, messageID, intString(sequence),
	)
	meta.AgentID = proxyV8StableID(SharedAgentRegistry().AgentID())
	meta.AgentName = proxyV8StableID(r.agentNameForStream(""))
	meta.AgentType = meta.AgentName
	_, meta.PolicyID = r.defaultRoutingMetadata()
	meta.PolicyID = proxyV8StableID(meta.PolicyID)
	meta.SessionID = proxyV8StableID(meta.SessionID)
	meta.RunID = proxyV8StableID(meta.RunID)
	meta.ResponseID = proxyV8StableID(meta.ResponseID)
	return meta
}

func (r *EventRouter) rememberEventRouterModelContext(
	sessionID string,
	runID string,
	ctx context.Context,
	observedAt time.Time,
) {
	if r == nil || strings.TrimSpace(sessionID) == "" || ctx == nil ||
		!trace.SpanContextFromContext(ctx).IsValid() {
		return
	}
	if observedAt.IsZero() {
		observedAt = time.Now().UTC()
	}
	key := eventRouterModelContextKey{
		sessionID: strings.TrimSpace(sessionID), runID: strings.TrimSpace(runID),
	}
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	if r.activeLLMContexts == nil {
		r.activeLLMContexts = make(map[eventRouterModelContextKey]eventRouterModelContextEntry)
	}
	r.evictEventRouterModelContextsLocked(observedAt)
	if len(r.activeLLMContexts) >= eventRouterModelContextCapacity {
		r.evictOldestEventRouterModelContextLocked()
	}
	r.activeLLMContexts[key] = eventRouterModelContextEntry{ctx: ctx, observedAt: observedAt}
}

// getToolParentCtx returns an ended model span context only when it shares a
// source-backed session identity with the child. A run match wins when both
// sides report it; a unique session match is the truthful fallback for
// OpenClaw message frames that omit runId.
func (r *EventRouter) getToolParentCtx(sessionID, runID string) context.Context {
	if r == nil || strings.TrimSpace(sessionID) == "" {
		return context.Background()
	}
	now := time.Now().UTC()
	key := eventRouterModelContextKey{
		sessionID: strings.TrimSpace(sessionID), runID: strings.TrimSpace(runID),
	}
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	r.evictEventRouterModelContextsLocked(now)
	if entry, ok := r.activeLLMContexts[key]; ok && entry.ctx != nil {
		return entry.ctx
	}
	var candidate eventRouterModelContextEntry
	matches := 0
	for candidateKey, entry := range r.activeLLMContexts {
		if candidateKey.sessionID != key.sessionID || entry.ctx == nil {
			continue
		}
		matches++
		if candidate.ctx == nil || entry.observedAt.After(candidate.observedAt) {
			candidate = entry
		}
	}
	if matches == 1 && candidate.ctx != nil {
		return candidate.ctx
	}
	return context.Background()
}

func (r *EventRouter) clearEventRouterModelContexts(sessionID, runID string) {
	if r == nil {
		return
	}
	sessionID = strings.TrimSpace(sessionID)
	runID = strings.TrimSpace(runID)
	if sessionID == "" && runID == "" {
		return
	}
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	for key := range r.activeLLMContexts {
		if sessionID != "" && key.sessionID != sessionID {
			continue
		}
		if sessionID == "" && key.runID != runID {
			continue
		}
		if sessionID != "" && runID != "" && key.runID != "" && key.runID != runID {
			continue
		}
		delete(r.activeLLMContexts, key)
	}
}

func (r *EventRouter) evictEventRouterModelContextsLocked(now time.Time) {
	cutoff := now.Add(-eventRouterModelContextTTL)
	for key, entry := range r.activeLLMContexts {
		if !entry.observedAt.After(cutoff) {
			delete(r.activeLLMContexts, key)
		}
	}
}

func (r *EventRouter) evictOldestEventRouterModelContextLocked() {
	var oldestKey eventRouterModelContextKey
	var oldestAt time.Time
	found := false
	for key, entry := range r.activeLLMContexts {
		if !found || entry.observedAt.Before(oldestAt) {
			oldestKey, oldestAt, found = key, entry.observedAt, true
		}
	}
	if found {
		delete(r.activeLLMContexts, oldestKey)
	}
}

type eventRouterPendingPrompt struct {
	text       string
	observedAt time.Time
}

// rememberEventRouterPrompt keeps a session's newest user prompt for the
// assistant message that answers it. The stream reports the prompt and the
// reply as separate frames, and a blocked prompt's turn has no tool child
// either, so without this its spans showed only the block text (GAP-2408).
func (r *EventRouter) rememberEventRouterPrompt(sessionID, prompt string, observedAt time.Time) {
	sessionID, prompt = strings.TrimSpace(sessionID), strings.TrimSpace(prompt)
	if r == nil || sessionID == "" || prompt == "" {
		return
	}
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	if r.pendingPrompts == nil {
		r.pendingPrompts = make(map[string]eventRouterPendingPrompt)
	}
	cutoff := observedAt.Add(-eventRouterModelContextTTL)
	for key, entry := range r.pendingPrompts {
		if !entry.observedAt.After(cutoff) {
			delete(r.pendingPrompts, key)
		}
	}
	if _, ok := r.pendingPrompts[sessionID]; !ok && len(r.pendingPrompts) >= eventRouterModelContextCapacity {
		return
	}
	r.pendingPrompts[sessionID] = eventRouterPendingPrompt{text: prompt, observedAt: observedAt}
}

// takeEventRouterPrompt hands the pending prompt to the first assistant
// message after it. Later messages of the same turn answer tool results, not
// the prompt, so they do not repeat it.
func (r *EventRouter) takeEventRouterPrompt(sessionID string, now time.Time) string {
	sessionID = strings.TrimSpace(sessionID)
	if r == nil || sessionID == "" {
		return ""
	}
	r.spanMu.Lock()
	defer r.spanMu.Unlock()
	entry, ok := r.pendingPrompts[sessionID]
	if !ok {
		return ""
	}
	delete(r.pendingPrompts, sessionID)
	if !entry.observedAt.After(now.Add(-eventRouterModelContextTTL)) {
		return ""
	}
	return entry.text
}
