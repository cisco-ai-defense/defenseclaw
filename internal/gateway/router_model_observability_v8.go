// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

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
		meta: meta, response: response,
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
	input := hookModelV8ModelInput(observation)
	input.Envelope.Provenance.Producer = eventRouterModelV8Producer
	startedContext, span, err := lifecycle.StartModelTrace(ctx, input)
	metricRuntime, _ := emitter.(hookLifecycleMetricV8Runtime)
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
	meta.TurnID = firstNonEmpty(messageID, intString(sequence))
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
	meta.TurnID = proxyV8StableID(meta.TurnID)
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
