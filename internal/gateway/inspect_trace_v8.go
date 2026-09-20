// Copyright 2026 Cisco Systems, Inc. and its affiliates
// SPDX-License-Identifier: Apache-2.0

package gateway

import (
	"context"
	"strings"
	"time"

	"github.com/defenseclaw/defenseclaw/internal/audit"
	"github.com/defenseclaw/defenseclaw/internal/observability"
	observabilityruntime "github.com/defenseclaw/defenseclaw/internal/observability/runtime"
	"github.com/defenseclaw/defenseclaw/internal/telemetry"
)

const inspectTraceV8Producer = "gateway.inspect.trace"

type inspectTraceV8Runtime interface {
	StartGuardrailApplyTrace(
		context.Context,
		observability.SpanGuardrailApplyInput,
	) (context.Context, *observabilityruntime.GuardrailApplyTrace, error)
}

func (a *APIServer) emitInspectTraceV8(
	ctx context.Context,
	tool string,
	targetType string,
	verdict *ToolInspectVerdict,
	elapsed time.Duration,
	evaluation hookEvaluationContext,
) {
	if a == nil || ctx == nil || verdict == nil {
		return
	}
	runtime, ok := a.observabilityV8RuntimeEmitter().(inspectTraceV8Runtime)
	if !ok || runtime == nil {
		return
	}
	input, ok := a.inspectTraceV8Input(ctx, tool, targetType, verdict, elapsed, evaluation)
	if !ok {
		return
	}
	_, span, err := runtime.StartGuardrailApplyTrace(ctx, input)
	if err != nil || span == nil {
		return
	}
	defer span.Abort()
	_ = span.End(input)
}

func (a *APIServer) inspectTraceV8Input(
	ctx context.Context,
	tool string,
	targetType string,
	verdict *ToolInspectVerdict,
	elapsed time.Duration,
	evaluation hookEvaluationContext,
) (observability.SpanGuardrailApplyInput, bool) {
	if verdict == nil {
		return observability.SpanGuardrailApplyInput{}, false
	}
	severity := observability.NormalizeSeverity(firstNonEmpty(verdict.Severity, "NONE"))
	if !severity.Valid || !severity.Present {
		return observability.SpanGuardrailApplyInput{}, false
	}
	connector := hookDecisionMetricConnector(a.connectorName())
	connectorKnown := connector != "unknown"
	envelopeConnector := connector
	if !connectorKnown {
		envelopeConnector = ""
	}
	auditEnvelope := audit.EnvelopeFromContext(ctx)
	identity := AgentIdentityFromContext(ctx)
	meta := a.inspectTraceV8Meta(ctx, connector)
	finishedAt := time.Now().UTC()
	if elapsed < 0 {
		elapsed = 0
	}
	startedAt := finishedAt.Add(-elapsed)
	targetType = strings.TrimSpace(targetType)
	if targetType == "" {
		targetType = "tool_call"
	}

	input := observability.SpanGuardrailApplyInput{
		Envelope: observability.FamilyEnvelopeInput{
			Source: observability.SourceGateway, Connector: envelopeConnector,
			Action: "inspect", Phase: "finalize",
			Correlation: observability.Correlation{
				RunID: meta.RunID, RequestID: meta.RequestID,
				SessionID: meta.SessionID, TurnID: meta.TurnID,
				AgentID:         meta.AgentID,
				AgentInstanceID: firstNonEmpty(identity.AgentInstanceID, auditEnvelope.AgentInstanceID),
				PolicyID:        meta.PolicyID, ToolInvocationID: auditEnvelope.ToolID,
				ConnectorID: envelopeConnector,
			},
			Provenance: observability.FamilyProvenanceInput{Producer: inspectTraceV8Producer},
		},
		Outcome:           inspectTraceV8Outcome(verdict.Action),
		Kind:              "INTERNAL",
		StartTimeUnixNano: uint64(startedAt.UnixNano()),
		EndTimeUnixNano:   uint64(finishedAt.UnixNano()),
		Status:            observability.NewTraceStatusOK(),

		DefenseClawConnectorSource:          hookV8OptionalIdentifier(envelopeConnector),
		DefenseClawRunID:                    hookV8OptionalIdentifier(meta.RunID),
		DefenseClawOperationID:              hookV8OptionalIdentifier(meta.OperationID),
		DefenseClawRequestID:                hookV8OptionalIdentifier(meta.RequestID),
		DefenseClawTurnID:                   hookV8OptionalIdentifier(meta.TurnID),
		GenAIConversationID:                 hookV8OptionalIdentifier(meta.SessionID),
		GenAIAgentID:                        hookV8OptionalIdentifier(meta.AgentID),
		GenAIAgentName:                      inspectTraceV8AgentName(meta.AgentName),
		DefenseClawAgentType:                hookV8OptionalText(meta.AgentType, 4096),
		DefenseClawAgentInstanceID:          hookV8OptionalIdentifier(firstNonEmpty(identity.AgentInstanceID, auditEnvelope.AgentInstanceID)),
		DefenseClawAgentRootID:              hookV8OptionalIdentifier(meta.RootAgentID),
		DefenseClawAgentParentID:            hookV8OptionalIdentifier(meta.ParentAgentID),
		DefenseClawAgentLineageProvenance:   hookV8OptionalLineageProvenance(meta.LineageProvenance),
		DefenseClawSessionRootID:            hookV8OptionalIdentifier(meta.RootSessionID),
		DefenseClawSessionParentID:          hookV8OptionalIdentifier(meta.ParentSessionID),
		DefenseClawAgentLifecycleID:         hookV8OptionalIdentifier(meta.LifecycleID),
		DefenseClawAgentExecutionID:         hookV8OptionalIdentifier(meta.ExecutionID),
		DefenseClawAgentDepth:               inspectTraceV8Depth(meta),
		DefenseClawAgentLifecycleEvent:      hookV8OptionalText(meta.LifecycleEvent, 4096),
		DefenseClawAgentLifecycleState:      hookV8OptionalText(meta.LifecycleState, 4096),
		DefenseClawAgentPhase:               hookV8OptionalPhase(meta.Phase),
		DefenseClawAgentPhasePrevious:       hookV8OptionalPhase(meta.PreviousPhase),
		DefenseClawAgentPhaseCode:           hookV8OptionalPhaseCode(meta.Phase),
		DefenseClawAgentSequence:            hookV8OptionalPositiveInt64(meta.Sequence),
		DefenseClawSessionSource:            hookV8OptionalSessionSource(meta.SessionSource),
		DefenseClawSessionResumed:           hookV8OptionalSessionResumed(meta),
		DefenseClawToolID:                   hookV8OptionalIdentifier(auditEnvelope.ToolID),
		GenAIToolName:                       hookV8OptionalText(tool, 4096),
		GenAIToolCallID:                     hookV8OptionalIdentifier(auditEnvelope.ToolID),
		DefenseClawDestinationApp:           hookV8OptionalIdentifier(meta.DestinationApp),
		DefenseClawEvaluationID:             hookV8OptionalIdentifier(evaluation.EvaluationID),
		DefenseClawPolicyID:                 hookV8OptionalIdentifier(meta.PolicyID),
		DefenseClawGuardrailName:            "inspect",
		DefenseClawGuardrailStage:           observability.Present("finalize"),
		DefenseClawGuardrailPhase:           observability.Present("finalize"),
		DefenseClawGuardrailDirection:       observability.Present(inspectTraceV8Direction(targetType)),
		DefenseClawGuardrailTargetType:      targetType,
		DefenseClawGuardrailLatencyMs:       observability.Present(float64(elapsed) / float64(time.Millisecond)),
		DefenseClawGuardrailRuleIds:         inspectTraceV8RuleIDs(evaluation.RuleIDs),
		DefenseClawGuardrailFindingCount:    observability.Present(int64(len(verdict.DetailedFindings))),
		DefenseClawGuardrailDecision:        observability.Present(inspectTraceV8Decision(verdict.Action)),
		DefenseClawGuardrailRawAction:       hookV8OptionalText(verdict.RawAction, 4096),
		DefenseClawGuardrailEffectiveAction: hookV8OptionalText(verdict.Action, 4096),
		DefenseClawGuardrailMode:            observability.Present(hookDecisionV8Mode(verdict.Mode)),
		DefenseClawGuardrailWouldBlock:      observability.Present(verdict.WouldBlock),
		DefenseClawSecuritySeverity:         observability.Present(string(severity.Severity)),
		DefenseClawGuardrailReason:          hookV8OptionalText(verdict.Reason, 65536),
		ConditionConnectorKnown:             connectorKnown,
		ConditionOperationTerminal:          true,
	}
	if verdict.Confidence > 0 && verdict.Confidence <= 1 {
		input.DefenseClawGuardrailConfidence = observability.Present(verdict.Confidence)
	}
	return input, true
}

// inspectTraceV8Meta joins request-scoped correlation with the last observed
// hook lifecycle identity for the same connector/session/agent. It never
// synthesizes topology: absent lifecycle state stays absent on the span.
func (a *APIServer) inspectTraceV8Meta(ctx context.Context, connector string) llmEventMeta {
	meta := hookDecisionMetricMeta(ctx, connector)
	snapshot, ok := a.hookLifecycleSnapshot(connector, meta.SessionID, meta.AgentID)
	if !ok {
		return meta
	}
	meta.AgentID = firstNonEmpty(meta.AgentID, snapshot.AgentID)
	meta.AgentName = firstNonEmpty(meta.AgentName, snapshot.AgentName)
	meta.AgentType = firstNonEmpty(meta.AgentType, snapshot.AgentType)
	meta.RootAgentID = snapshot.RootAgentID
	meta.ParentAgentID = snapshot.ParentAgentID
	meta.LineageProvenance = snapshot.LineageProvenance
	meta.RootSessionID = snapshot.RootSessionID
	meta.ParentSessionID = snapshot.ParentSessionID
	meta.LifecycleID = snapshot.LifecycleID
	meta.ExecutionID = snapshot.ExecutionID
	meta.LifecycleEvent = snapshot.LifecycleEvent
	meta.LifecycleState = snapshot.LifecycleState
	meta.OperationID = snapshot.OperationID
	meta.Phase = snapshot.Phase
	meta.PreviousPhase = snapshot.PreviousPhase
	meta.Sequence = snapshot.Sequence
	meta.AgentDepth = snapshot.AgentDepth
	meta.SessionSource = snapshot.SessionSource
	meta.SessionResumed = snapshot.SessionResumed
	return meta
}

func inspectTraceV8Depth(meta llmEventMeta) observability.Optional[int64] {
	if meta.LifecycleID == "" || meta.AgentDepth < 0 || meta.AgentDepth > 64 {
		return observability.Absent[int64]()
	}
	return observability.Present(int64(meta.AgentDepth))
}

func inspectTraceV8Outcome(action string) observability.Outcome {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow":
		return observability.OutcomeAllowed
	case "block":
		return observability.OutcomeBlocked
	case "deny":
		return observability.OutcomeDenied
	case "redact":
		return observability.OutcomeRedacted
	case "confirm":
		return observability.OutcomePartial
	default:
		return observability.OutcomeCompleted
	}
}

func inspectTraceV8Decision(action string) string {
	switch strings.ToLower(strings.TrimSpace(action)) {
	case "allow", "block", "deny", "redact":
		return strings.ToLower(strings.TrimSpace(action))
	default:
		return "review"
	}
}

func inspectTraceV8Direction(targetType string) string {
	switch strings.ToLower(strings.TrimSpace(targetType)) {
	case "prompt":
		return "input"
	case "completion":
		return "output"
	default:
		return "tool"
	}
}

func inspectTraceV8RuleIDs(values []string) observability.Optional[[]string] {
	if len(values) == 0 {
		return observability.Absent[[]string]()
	}
	if len(values) > 8 {
		values = values[:8]
	}
	result := make([]string, 0, len(values))
	for _, value := range values {
		if optional := hookV8OptionalIdentifier(value); optional.IsPresent() {
			result = append(result, value)
		}
	}
	if len(result) == 0 {
		return observability.Absent[[]string]()
	}
	return observability.Present(result)
}

func inspectTraceV8AgentName(value string) observability.Optional[string] {
	if strings.TrimSpace(value) == "" {
		return observability.Absent[string]()
	}
	return hookV8OptionalIdentifier(telemetry.NormalizeMetricTextLabel(value))
}
