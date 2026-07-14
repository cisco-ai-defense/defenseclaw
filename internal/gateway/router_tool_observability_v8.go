// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"math"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/gateway/connector"
	"github.com/defenseclaw/defenseclaw/internal/gatewaylog"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityrouter "github.com/defenseclaw/defenseclaw/internal/observability/router"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/version"
	"github.com/google/uuid"
	"go.opentelemetry.io/otel/trace"
)

const (
	eventRouterToolV8Producer     = "gateway.event_router.tool"
	eventRouterToolConnector      = "openclaw"
	eventRouterToolProvider       = "builtin"
	eventRouterToolCapacity       = 4096
	eventRouterToolTTL            = 10 * time.Minute
	eventRouterToolMaxContentByte = 64 * 1024
)

type eventRouterToolObservation struct {
	observation generatedToolV8Observation
	insertedAt  time.Time
}

type eventRouterToolObservationCacheEntry struct {
	id         string
	insertedAt time.Time
}

type eventRouterToolLogKind uint8

type eventRouterCorrelationState uint8

const (
	eventRouterToolLogRequested eventRouterToolLogKind = iota
	eventRouterToolLogCompleted
	eventRouterToolLogFailed
	eventRouterToolLogBlocked
)

const (
	eventRouterCorrelationUnavailable eventRouterCorrelationState = iota
	eventRouterCorrelationCommitted
	eventRouterCorrelationFailed
)

func (r *EventRouter) observeEventRouterToolCallV8(
	payload ToolCallPayload,
	startedAt time.Time,
	dangerous bool,
) generatedToolV8Observation {
	observation := r.newEventRouterToolObservation(
		payload.Tool, payload.ID, payload.SessionID, payload.RunID, payload.AgentName,
		string(payload.Args), "", nil, startedAt, startedAt,
	)
	observation.dangerous = dangerous
	observation.meta.ToolIDReported = observation.meta.ToolID != ""
	correlated, correlationState := r.correlateEventRouterToolV8(
		context.Background(), connector.CorrelationLifecycleToolStart, observation,
		[]byte(observation.arguments),
	)
	switch correlationState {
	case eventRouterCorrelationCommitted:
		observation.meta = correlated.meta
		observation.correlationCtx = correlated.ctx
		if !correlated.suppressEmission {
			persisted, emitErr := r.emitEventRouterToolLogV8(
				correlated.ctx, eventRouterToolLogRequested, observation,
			)
			if err := finalizeLLMRailCanonicalEmission(
				correlated.ctx, r.store, correlated.receipt, persisted, emitErr,
			); err != nil {
				readLoopLogf("[correlation] stream tool-start canonical persistence incomplete")
			}
		}
	case eventRouterCorrelationUnavailable:
		// Reduced test/runtime configurations may intentionally bind v8
		// emission without an audit store. Preserve the pre-correlation
		// behavior there; production, which has both, takes the committed
		// path above.
		_, _ = r.emitEventRouterToolLogV8(context.Background(), eventRouterToolLogRequested, observation)
	case eventRouterCorrelationFailed:
		// A configured coordinator failed before export. The occurrence was
		// not durably accepted, so fail closed and emit no orphan telemetry.
	}
	return observation
}

func (r *EventRouter) rememberEventRouterToolCallV8(observation generatedToolV8Observation) bool {
	if r == nil || !hookModelV8Identifier(observation.meta.ToolID) ||
		!hookModelV8Identifier(observation.tool) || observation.startedAt.IsZero() {
		return false
	}
	now := time.Now()
	if r.toolObservationNow != nil {
		now = r.toolObservationNow()
	}
	r.toolObservationMu.Lock()
	defer r.toolObservationMu.Unlock()
	if r.toolObservations == nil {
		r.toolObservations = make(map[string]eventRouterToolObservation)
	}
	r.evictEventRouterToolCallsLocked(now)
	if _, duplicate := r.toolObservations[observation.meta.ToolID]; duplicate {
		return false
	}
	for len(r.toolObservations) >= eventRouterToolCapacity {
		if !r.evictOldestEventRouterToolCallLocked() {
			return false
		}
	}
	entry := eventRouterToolObservation{observation: observation, insertedAt: now}
	r.toolObservations[observation.meta.ToolID] = entry
	r.toolObservationOrder = append(r.toolObservationOrder, eventRouterToolObservationCacheEntry{
		id: observation.meta.ToolID, insertedAt: now,
	})
	return true
}

func (r *EventRouter) completeEventRouterToolCallV8(
	payload ToolResultPayload,
	finishedAt time.Time,
) generatedToolV8Observation {
	var observation generatedToolV8Observation
	paired := false
	if hookModelV8Identifier(payload.ID) {
		observation, paired = r.takeEventRouterToolCallV8(payload.ID)
	}
	if paired && conflictingEventRouterToolResult(observation, payload) {
		paired = false
	}
	if !paired {
		observation = r.newEventRouterToolObservation(
			payload.Tool, payload.ID, payload.SessionID, payload.RunID, payload.AgentName,
			"", payload.Output, payload.ExitCode, finishedAt, finishedAt,
		)
	} else {
		observation.result = boundedEventRouterToolContent(payload.Output)
		observation.exitCode = cloneEventRouterExitCode(payload.ExitCode)
		observation.finishedAt = finishedAt
		if observation.meta.SessionID == "" {
			observation.meta.SessionID = payload.SessionID
			observation.sessionID = payload.SessionID
		}
		if observation.meta.RunID == "" {
			observation.meta.RunID = payload.RunID
		}
		if observation.agentName == "" {
			observation.meta.AgentName = payload.AgentName
			observation.agentName = payload.AgentName
		}
	}
	if observation.finishedAt.Before(observation.startedAt) {
		observation.finishedAt = observation.startedAt
	}
	return observation
}

func (r *EventRouter) emitEventRouterToolTerminalV8(observation generatedToolV8Observation) {
	if r == nil || !hookModelV8Identifier(observation.tool) {
		return
	}
	emitter, lifecycle, authoritative := r.observabilityV8CapabilitiesSnapshot()
	if !authoritative {
		return
	}
	observation.meta.ToolIDReported = observation.meta.ToolID != ""
	correlated, correlationState := r.correlateEventRouterToolV8(
		context.Background(), connector.CorrelationLifecycleToolEnd, observation,
		[]byte(observation.result),
	)
	if correlationState == eventRouterCorrelationFailed {
		return
	}
	correlationContext := observation.correlationCtx
	if correlationContext == nil {
		correlationContext = context.Background()
	}
	if correlationState == eventRouterCorrelationCommitted {
		observation.meta = correlated.meta
		observation.correlationCtx = correlated.ctx
		correlationContext = correlated.ctx
	}
	outcome, _, _, _ := generatedToolV8Result(observation)
	logKind := eventRouterToolLogCompleted
	switch outcome {
	case observability.OutcomeBlocked:
		logKind = eventRouterToolLogBlocked
	case observability.OutcomeCompleted:
		logKind = eventRouterToolLogCompleted
	default:
		logKind = eventRouterToolLogFailed
	}
	if emitter != nil && (correlationState != eventRouterCorrelationCommitted || !correlated.suppressEmission) {
		persisted, emitErr := r.emitEventRouterToolLogV8WithEmitter(
			correlationContext, emitter, logKind, observation,
		)
		if correlationState == eventRouterCorrelationCommitted {
			if err := finalizeLLMRailCanonicalEmission(
				correlationContext, r.store, correlated.receipt, persisted, emitErr,
			); err != nil {
				readLoopLogf("[correlation] stream tool-end canonical persistence incomplete")
				return
			}
		} else if emitErr != nil {
			return
		}
	}
	if correlationState == eventRouterCorrelationCommitted && correlated.suppressEmission {
		return
	}
	metricRuntime, _ := emitter.(hookLifecycleMetricV8Runtime)
	parent := r.getToolParentCtx(observation.meta.SessionID, observation.meta.RunID)
	if parentSpan := trace.SpanContextFromContext(parent); parentSpan.IsValid() {
		parent = trace.ContextWithSpanContext(correlationContext, parentSpan)
	} else {
		parent = correlationContext
	}
	emitGeneratedToolSpanV8(parent, lifecycle, metricRuntime, observation)
}

func (r *EventRouter) correlateEventRouterToolV8(
	ctx context.Context,
	lifecycle connector.CorrelationLifecycle,
	observation generatedToolV8Observation,
	raw []byte,
) (llmRailCorrelationResult, eventRouterCorrelationState) {
	emitter := r.observabilityV8RuntimeEmitter()
	if r.store == nil || emitter == nil {
		return llmRailCorrelationResult{}, eventRouterCorrelationUnavailable
	}
	spec, ok := r.streamCorrelationSpecV8()
	if !ok {
		readLoopLogf("[correlation] stream tool profile unavailable; telemetry emission skipped")
		return llmRailCorrelationResult{}, eventRouterCorrelationFailed
	}
	correlated, err := correlateLLMRailOccurrence(ctx, llmRailCorrelationInput{
		store: r.store, emitter: emitter, spec: spec,
		rail: audit.CorrelationRailStream, surface: connector.CorrelationSurfaceStream,
		lifecycle: lifecycle, meta: observation.meta, rawPayload: raw,
	})
	if err != nil {
		readLoopLogf("[correlation] stream tool persistence failed; telemetry emission skipped")
		return llmRailCorrelationResult{}, eventRouterCorrelationFailed
	}
	return correlated, eventRouterCorrelationCommitted
}

func (r *EventRouter) newEventRouterToolObservation(
	tool, id, sessionID, runID, agentName, arguments, result string,
	exitCode *int,
	startedAt, finishedAt time.Time,
) generatedToolV8Observation {
	if startedAt.IsZero() {
		startedAt = time.Now().UTC()
	}
	if finishedAt.IsZero() || finishedAt.Before(startedAt) {
		finishedAt = startedAt
	}
	argumentsOriginalBytes := int64(len(arguments))
	boundedArguments := boundedEventRouterToolContent(arguments)
	_, policyID := r.defaultRoutingMetadata()
	meta := llmEventMeta{
		Source: eventRouterToolConnector, Provider: eventRouterToolProvider,
		SessionID: sessionID, RunID: runID, AgentName: agentName,
		AgentID:  SharedAgentRegistry().AgentID(),
		PolicyID: policyID, DestinationApp: eventRouterToolProvider,
		ToolName: strings.TrimSpace(tool), ToolID: strings.TrimSpace(id),
		ToolIDReported: strings.TrimSpace(id) != "",
	}
	return generatedToolV8Observation{
		meta: meta, producer: eventRouterToolV8Producer,
		tool: strings.TrimSpace(tool), arguments: boundedArguments,
		result: boundedEventRouterToolContent(result), toolProvider: eventRouterToolProvider,
		exitCode: cloneEventRouterExitCode(exitCode), startedAt: startedAt.UTC(), finishedAt: finishedAt.UTC(),
		argumentsOriginalBytes: argumentsOriginalBytes,
		argumentsTruncated:     len(boundedArguments) != len(arguments),
		agentName:              agentName,
		sessionID:              sessionID,
	}
}

func (r *EventRouter) takeEventRouterToolCallV8(id string) (generatedToolV8Observation, bool) {
	if r == nil {
		return generatedToolV8Observation{}, false
	}
	now := time.Now()
	if r.toolObservationNow != nil {
		now = r.toolObservationNow()
	}
	r.toolObservationMu.Lock()
	defer r.toolObservationMu.Unlock()
	r.evictEventRouterToolCallsLocked(now)
	entry, ok := r.toolObservations[id]
	if !ok {
		return generatedToolV8Observation{}, false
	}
	delete(r.toolObservations, id)
	return entry.observation, true
}

func (r *EventRouter) evictEventRouterToolCallsLocked(now time.Time) {
	cutoff := now.Add(-eventRouterToolTTL)
	for len(r.toolObservationOrder) > 0 {
		oldest := r.toolObservationOrder[0]
		entry, current := r.toolObservations[oldest.id]
		if !current || !entry.insertedAt.Equal(oldest.insertedAt) {
			r.toolObservationOrder = r.toolObservationOrder[1:]
			continue
		}
		if entry.insertedAt.After(cutoff) {
			break
		}
		delete(r.toolObservations, oldest.id)
		r.toolObservationOrder = r.toolObservationOrder[1:]
	}
}

func (r *EventRouter) evictOldestEventRouterToolCallLocked() bool {
	for len(r.toolObservationOrder) > 0 {
		oldest := r.toolObservationOrder[0]
		r.toolObservationOrder = r.toolObservationOrder[1:]
		entry, current := r.toolObservations[oldest.id]
		if !current || !entry.insertedAt.Equal(oldest.insertedAt) {
			continue
		}
		delete(r.toolObservations, oldest.id)
		return true
	}
	return false
}

func conflictingEventRouterToolResult(
	observation generatedToolV8Observation,
	payload ToolResultPayload,
) bool {
	return (payload.Tool != "" && payload.Tool != observation.tool) ||
		(payload.SessionID != "" && observation.meta.SessionID != "" &&
			payload.SessionID != observation.meta.SessionID) ||
		(payload.RunID != "" && observation.meta.RunID != "" &&
			payload.RunID != observation.meta.RunID)
}

func boundedEventRouterToolContent(value string) string {
	return truncateToRuneBoundary(strings.ToValidUTF8(value, "\uFFFD"), eventRouterToolMaxContentByte)
}

func cloneEventRouterExitCode(value *int) *int {
	if value == nil {
		return nil
	}
	cloned := *value
	return &cloned
}

func (r *EventRouter) emitEventRouterToolLogV8(
	ctx context.Context,
	kind eventRouterToolLogKind,
	observation generatedToolV8Observation,
) (bool, error) {
	emitter, _, authoritative := r.observabilityV8CapabilitiesSnapshot()
	if !authoritative || emitter == nil {
		return false, nil
	}
	return r.emitEventRouterToolLogV8WithEmitter(ctx, emitter, kind, observation)
}

func (r *EventRouter) emitEventRouterToolLogV8WithEmitter(
	ctx context.Context,
	emitter sidecarRuntimeEmitter,
	kind eventRouterToolLogKind,
	observation generatedToolV8Observation,
) (bool, error) {
	eventName, rawSeverity, ok := eventRouterToolLogIdentity(kind)
	if r == nil || ctx == nil || emitter == nil || !ok || !hookModelV8Identifier(observation.tool) {
		return false, nil
	}
	producerKey := observability.ProducerKey(gatewaylog.EventToolInvocation)
	metadata, err := observabilityrouter.NewClassifiedLogMetadata(
		observability.ProducerGatewayEvent,
		producerKey,
		observability.ClassificationContext{
			Bucket: observability.BucketToolActivity, EventName: eventName, RawSeverity: rawSeverity,
		},
		observability.SourceConnector,
		eventRouterToolConnector,
		producerKey,
	)
	if err != nil {
		return false, err
	}
	outcome, err := emitter.Emit(ctx, metadata, func(
		snapshot observabilityruntime.EmitContext,
		admission observabilityrouter.Admission,
	) (observability.Record, error) {
		if admission != observabilityrouter.AdmissionOrdinary || snapshot.Generation() > math.MaxInt64 {
			return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
		}
		builder, buildErr := observability.NewFamilyBuilder(
			observability.ClockFunc(func() time.Time { return observation.finishedAt }),
			observability.OccurrenceIDGeneratorFunc(func() (string, error) { return uuid.NewString(), nil }),
		)
		if buildErr != nil {
			return observability.Record{}, buildErr
		}
		spanInput := generatedToolV8Input(observation)
		spanInput.Envelope.ObservedAt = observability.Present(observation.finishedAt)
		spanInput.Envelope.Action = string(producerKey)
		spanInput.Envelope.Phase = "tool"
		spanInput.Envelope.Provenance = observability.FamilyProvenanceInput{
			Producer: eventRouterToolV8Producer, BinaryVersion: version.Current().BinaryVersion,
			ConfigGeneration: int64(snapshot.Generation()), ConfigDigest: snapshot.Digest(),
		}
		return buildEventRouterToolLog(builder, kind, spanInput)
	})
	if err != nil {
		return false, err
	}
	return outcome.LocalPersisted(), nil
}

func eventRouterToolLogIdentity(
	kind eventRouterToolLogKind,
) (observability.EventName, string, bool) {
	switch kind {
	case eventRouterToolLogRequested:
		return observability.EventName(observability.TelemetryEventToolInvocationRequested), "INFO", true
	case eventRouterToolLogCompleted:
		return observability.EventName(observability.TelemetryEventToolInvocationCompleted), "INFO", true
	case eventRouterToolLogFailed:
		return observability.EventName(observability.TelemetryEventToolInvocationFailed), "ERROR", true
	case eventRouterToolLogBlocked:
		return observability.EventName(observability.TelemetryEventToolInvocationBlocked), "HIGH", true
	default:
		return "", "", false
	}
}

type eventRouterToolLogFields struct {
	envelope       observability.FamilyEnvelopeInput
	severity       observability.Optional[observability.Severity]
	logLevel       observability.Optional[observability.LogLevel]
	outcome        observability.Outcome
	runID          observability.Optional[string]
	policyID       observability.Optional[string]
	destinationApp observability.Optional[string]
	conversationID observability.Optional[string]
	agentName      observability.Optional[string]
	operationName  observability.Optional[string]
	toolName       observability.Optional[string]
	toolType       observability.Optional[string]
	toolCallID     observability.Optional[string]
	arguments      observability.Optional[observability.TelemetryStructuredGenAIToolCallArguments]
	result         observability.Optional[observability.TelemetryStructuredGenAIToolCallResult]
	toolID         observability.Optional[string]
	provider       observability.Optional[string]
	dangerous      observability.Optional[bool]
	exitCode       observability.Optional[int64]
	status         observability.Optional[string]
	argsLength     observability.Optional[int64]
	outputLength   observability.Optional[int64]
	inputReported  bool
	outputReported bool
}

func eventRouterToolFields(
	kind eventRouterToolLogKind,
	input observability.SpanToolExecuteInput,
) eventRouterToolLogFields {
	severity := observability.SeverityInfo
	level := observability.LogLevelInfo
	if kind == eventRouterToolLogBlocked {
		severity, level = observability.SeverityHigh, observability.LogLevelWarn
	} else if kind == eventRouterToolLogFailed {
		severity, level = observability.SeverityHigh, observability.LogLevelError
	}
	return eventRouterToolLogFields{
		envelope: input.Envelope, severity: observability.Present(severity), logLevel: observability.Present(level),
		outcome: input.Outcome, runID: input.DefenseClawRunID, policyID: input.DefenseClawPolicyID,
		destinationApp: input.DefenseClawDestinationApp, conversationID: input.GenAIConversationID,
		agentName: input.GenAIAgentName, operationName: input.GenAIOperationName,
		toolName: observability.Present(input.GenAIToolName), toolType: input.GenAIToolType, toolCallID: input.GenAIToolCallID,
		arguments: input.GenAIToolCallArguments, result: input.GenAIToolCallResult,
		toolID: input.DefenseClawToolID, provider: input.DefenseClawToolProvider,
		dangerous: input.DefenseClawToolDangerous, exitCode: input.DefenseClawToolExitCode,
		status: input.DefenseClawToolStatus, argsLength: input.DefenseClawToolArgsLength,
		outputLength:  input.DefenseClawToolOutputLength,
		inputReported: input.DefenseClawTelemetryInputReported, outputReported: input.DefenseClawTelemetryOutputReported,
	}
}

func buildEventRouterToolLog(
	builder *observability.FamilyBuilder,
	kind eventRouterToolLogKind,
	spanInput observability.SpanToolExecuteInput,
) (observability.Record, error) {
	f := eventRouterToolFields(kind, spanInput)
	switch kind {
	case eventRouterToolLogRequested:
		return builder.BuildLogToolInvocationRequested(observability.LogToolInvocationRequestedInput{
			Envelope: f.envelope, Severity: f.severity, LogLevel: f.logLevel, Outcome: observability.OutcomeAttempted,
			DefenseClawRunID: f.runID, DefenseClawPolicyID: f.policyID, DefenseClawDestinationApp: f.destinationApp,
			GenAIConversationID: f.conversationID, GenAIAgentName: f.agentName,
			GenAIOperationName: f.operationName, GenAIToolName: f.toolName, GenAIToolType: f.toolType,
			GenAIToolCallID: f.toolCallID, GenAIToolCallArguments: f.arguments,
			DefenseClawToolID: f.toolID, DefenseClawToolProvider: f.provider,
			DefenseClawToolDangerous: f.dangerous, DefenseClawToolStatus: observability.Present("requested"),
			DefenseClawToolArgsLength:         f.argsLength,
			DefenseClawTelemetryInputReported: f.inputReported, DefenseClawTelemetryOutputReported: false,
		})
	case eventRouterToolLogCompleted:
		return builder.BuildLogToolInvocationCompleted(observability.LogToolInvocationCompletedInput{
			Envelope: f.envelope, Severity: f.severity, LogLevel: f.logLevel, Outcome: observability.OutcomeCompleted,
			DefenseClawRunID: f.runID, DefenseClawPolicyID: f.policyID, DefenseClawDestinationApp: f.destinationApp,
			GenAIConversationID: f.conversationID, GenAIAgentName: f.agentName,
			GenAIOperationName: f.operationName, GenAIToolName: f.toolName, GenAIToolType: f.toolType,
			GenAIToolCallID: f.toolCallID, GenAIToolCallArguments: f.arguments, GenAIToolCallResult: f.result,
			DefenseClawToolID: f.toolID, DefenseClawToolProvider: f.provider,
			DefenseClawToolDangerous: f.dangerous, DefenseClawToolExitCode: f.exitCode,
			DefenseClawToolStatus: f.status, DefenseClawToolArgsLength: f.argsLength,
			DefenseClawToolOutputLength:       f.outputLength,
			DefenseClawTelemetryInputReported: f.inputReported, DefenseClawTelemetryOutputReported: f.outputReported,
		})
	case eventRouterToolLogFailed:
		return builder.BuildLogToolInvocationFailed(observability.LogToolInvocationFailedInput{
			Envelope: f.envelope, Severity: f.severity, LogLevel: f.logLevel, Outcome: f.outcome,
			DefenseClawRunID: f.runID, DefenseClawPolicyID: f.policyID, DefenseClawDestinationApp: f.destinationApp,
			GenAIConversationID: f.conversationID, GenAIAgentName: f.agentName,
			GenAIOperationName: f.operationName, GenAIToolName: f.toolName, GenAIToolType: f.toolType,
			GenAIToolCallID: f.toolCallID, GenAIToolCallArguments: f.arguments, GenAIToolCallResult: f.result,
			DefenseClawToolID: f.toolID, DefenseClawToolProvider: f.provider,
			DefenseClawToolDangerous: f.dangerous, DefenseClawToolExitCode: f.exitCode,
			DefenseClawToolStatus: f.status, DefenseClawToolArgsLength: f.argsLength,
			DefenseClawToolOutputLength:       f.outputLength,
			DefenseClawTelemetryInputReported: f.inputReported, DefenseClawTelemetryOutputReported: f.outputReported,
		})
	case eventRouterToolLogBlocked:
		return builder.BuildLogToolInvocationBlocked(observability.LogToolInvocationBlockedInput{
			Envelope: f.envelope, Severity: f.severity, LogLevel: f.logLevel, Outcome: observability.OutcomeBlocked,
			DefenseClawRunID: f.runID, DefenseClawPolicyID: f.policyID, DefenseClawDestinationApp: f.destinationApp,
			GenAIConversationID: f.conversationID, GenAIAgentName: f.agentName,
			GenAIOperationName: f.operationName, GenAIToolName: f.toolName, GenAIToolType: f.toolType,
			GenAIToolCallID: f.toolCallID, GenAIToolCallArguments: f.arguments,
			DefenseClawToolID: f.toolID, DefenseClawToolProvider: f.provider,
			DefenseClawToolDangerous: f.dangerous, DefenseClawToolStatus: f.status,
			DefenseClawToolArgsLength:         f.argsLength,
			DefenseClawTelemetryInputReported: f.inputReported, DefenseClawTelemetryOutputReported: false,
		})
	default:
		return observability.Record{}, &sidecarObservabilityError{code: sidecarObservabilityBuildFailed}
	}
}
